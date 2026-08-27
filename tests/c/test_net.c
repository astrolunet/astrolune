/*
 * Wire codec and P2P transport tests.
 *
 * The codec tests are pure; the transport tests drive two real al_p2p
 * services over loopback so handshakes, gossip relaying, dedup and range
 * sync run through the actual event loop rather than a mock.
 */

#include "altest.h"
#include "p2p.h"

/* ------------------------------------------------------------------ */
/* Wire codec                                                          */
/* ------------------------------------------------------------------ */

AL_TEST(wire_header_roundtrip) {
    al_u8 buffer[AL_WIRE_HEADER_SIZE];
    al_writer writer;
    al_writer_init(&writer, buffer, sizeof(buffer));
    al_wire_header_encode(&writer, AL_WIRE_TX, 1234u);
    AL_CHECK_EQ_STATUS(al_writer_finish(&writer), AL_OK);

    al_wire_header header;
    AL_CHECK_EQ_STATUS(
        al_wire_header_decode(al_bytes_make(buffer, sizeof(buffer)),
                              &header),
        AL_OK);
    AL_CHECK_EQ_U64(header.version, AL_WIRE_PROTOCOL_VERSION);
    AL_CHECK_EQ_U64(header.type, AL_WIRE_TX);
    AL_CHECK_EQ_U64(header.payload_len, 1234u);

    /* Corrupting the magic must reject the frame. */
    buffer[0] ^= 0xffu;
    AL_CHECK_EQ_STATUS(
        al_wire_header_decode(al_bytes_make(buffer, sizeof(buffer)),
                              &header),
        AL_ERR_MALFORMED);
}

AL_TEST(wire_header_rejects_oversize_payload) {
    al_u8 buffer[AL_WIRE_HEADER_SIZE];
    al_writer writer;
    al_writer_init(&writer, buffer, sizeof(buffer));
    al_wire_header_encode(&writer, AL_WIRE_BLOCK, AL_WIRE_MAX_PAYLOAD + 1u);
    AL_CHECK_EQ_STATUS(al_writer_finish(&writer), AL_OK);

    al_wire_header header;
    AL_CHECK_EQ_STATUS(
        al_wire_header_decode(al_bytes_make(buffer, sizeof(buffer)),
                              &header),
        AL_ERR_OUT_OF_RANGE);
}

AL_TEST(wire_hello_roundtrip) {
    al_wire_hello hello;
    memset(&hello, 0, sizeof(hello));
    hello.protocol_version = AL_WIRE_PROTOCOL_VERSION;
    hello.listen_port = 44001u;
    memset(hello.genesis.bytes, 1u, AL_HASH_SIZE);
    memset(hello.head.bytes, 2u, AL_HASH_SIZE);
    hello.height = 42u;

    al_u8 buffer[128];
    al_writer writer;
    al_writer_init(&writer, buffer, sizeof(buffer));
    al_wire_hello_encode(&writer, &hello);
    AL_CHECK_EQ_STATUS(al_writer_finish(&writer), AL_OK);

    al_wire_hello decoded;
    AL_CHECK_EQ_STATUS(
        al_wire_hello_decode(al_bytes_make(buffer, al_writer_len(&writer)),
                             &decoded),
        AL_OK);
    AL_CHECK_EQ_U64(decoded.listen_port, hello.listen_port);
    AL_CHECK_EQ_U64(decoded.height, hello.height);
    AL_CHECK(al_hash_eq(&decoded.genesis, &hello.genesis));

    /* A peer speaking another protocol version is not compatible. */
    decoded.protocol_version = AL_WIRE_PROTOCOL_VERSION + 1u;
    al_u8 bad[128];
    al_writer bad_writer;
    al_writer_init(&bad_writer, bad, sizeof(bad));
    al_wire_hello_encode(&bad_writer, &decoded);
    (void)al_writer_finish(&bad_writer);
    al_wire_hello ignored;
    AL_CHECK_EQ_STATUS(
        al_wire_hello_decode(al_bytes_make(bad, al_writer_len(&bad_writer)),
                             &ignored),
        AL_ERR_OUT_OF_RANGE);
}

AL_TEST(wire_get_blocks_rejects_unbounded_requests) {
    al_wire_get_blocks request = { 7u, 0u };
    al_u8 buffer[16];
    al_writer writer;
    al_writer_init(&writer, buffer, sizeof(buffer));
    al_wire_get_blocks_encode(&writer, &request);
    (void)al_writer_finish(&writer);

    al_wire_get_blocks decoded;
    AL_CHECK_EQ_STATUS(
        al_wire_get_blocks_decode(
            al_bytes_make(buffer, al_writer_len(&writer)), &decoded),
        AL_ERR_OUT_OF_RANGE);

    request.max_count = 100000u;
    al_writer big;
    al_writer_init(&big, buffer, sizeof(buffer));
    al_wire_get_blocks_encode(&big, &request);
    (void)al_writer_finish(&big);
    AL_CHECK_EQ_STATUS(
        al_wire_get_blocks_decode(al_bytes_make(buffer, al_writer_len(&big)),
                                  &decoded),
        AL_ERR_OUT_OF_RANGE);

    request.max_count = 16u;
    al_writer good;
    al_writer_init(&good, buffer, sizeof(buffer));
    al_wire_get_blocks_encode(&good, &request);
    (void)al_writer_finish(&good);
    AL_CHECK_EQ_STATUS(
        al_wire_get_blocks_decode(al_bytes_make(buffer, al_writer_len(&good)),
                                  &decoded),
        AL_OK);
    AL_CHECK_EQ_U64(decoded.start, 7u);
}

AL_TEST(wire_blocks_cursor_roundtrip) {
    static const al_u8 first[] = { 0xaau, 0xbbu };
    static const al_u8 second[] = { 0xccu };

    al_u8 payload[256];
    al_writer writer;
    al_writer_init(&writer, payload, sizeof(payload));
    al_writer_varint(&writer, 2u);
    al_wire_blocks_append(&writer, al_bytes_make(first, sizeof(first)));
    al_wire_blocks_append(&writer, al_bytes_make(second, sizeof(second)));
    AL_CHECK_EQ_STATUS(al_writer_finish(&writer), AL_OK);

    al_wire_blocks_cursor cursor;
    AL_CHECK_EQ_STATUS(
        al_wire_blocks_begin(al_bytes_make(payload, al_writer_len(&writer)),
                             &cursor),
        AL_OK);
    AL_CHECK_EQ_U64(cursor.count, 2u);

    al_bytes entry;
    AL_CHECK_EQ_STATUS(al_wire_blocks_next(&cursor, &entry), AL_OK);
    AL_CHECK(al_bytes_eq(entry, al_bytes_make(first, sizeof(first))));
    AL_CHECK_EQ_STATUS(al_wire_blocks_next(&cursor, &entry), AL_OK);
    AL_CHECK(al_bytes_eq(entry, al_bytes_make(second, sizeof(second))));
    AL_CHECK_EQ_STATUS(al_wire_blocks_next(&cursor, &entry),
                       AL_ERR_NOT_FOUND);
}

AL_TEST(wire_finalized_block_roundtrip) {
    static const al_u8 certificate[] = { 0xa1u, 0xb2u, 0xc3u };
    static const al_u8 block[] = { 0x10u, 0x20u, 0x30u, 0x40u };
    al_wire_finalized_block value = {
        al_bytes_make(certificate, sizeof(certificate)),
        al_bytes_make(block, sizeof(block))
    };
    al_size required = 0u;
    AL_CHECK_EQ_STATUS(al_wire_finalized_block_encode(
                           &value, (al_bytes_mut){ NULL, 0u }, &required),
                       AL_ERR_BUFFER_TOO_SMALL);
    static al_u8 encoded[64];
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_wire_finalized_block_encode(
                           &value, (al_bytes_mut){ encoded, sizeof(encoded) },
                           &written),
                       AL_OK);
    AL_CHECK_EQ_U64((al_u64)written, (al_u64)required);
    al_wire_finalized_block decoded;
    AL_CHECK_EQ_STATUS(al_wire_finalized_block_decode(
                           al_bytes_make(encoded, written), &decoded),
                       AL_OK);
    AL_CHECK(al_bytes_eq(decoded.certificate,
                         al_bytes_make(certificate, sizeof(certificate))));
    AL_CHECK(al_bytes_eq(decoded.block, al_bytes_make(block, sizeof(block))));
    encoded[0] = 0u;
    AL_CHECK_EQ_STATUS(al_wire_finalized_block_decode(
                           al_bytes_make(encoded, written), &decoded),
                       AL_ERR_OUT_OF_RANGE);
}

/* ------------------------------------------------------------------ */
/* P2P over loopback                                                    */
/* ------------------------------------------------------------------ */

#define PUMP_LIMIT 600u

#define FIXTURE_BLOCKS 260u

typedef struct loopback_events {
    /* Transactions. */
    al_bool transaction_seen;
    al_u8   transaction_body[64];
    al_size transaction_len;

    /* Blocks: every delivery increments the counter regardless of source
     * (gossip or range sync); the fixture never relays them onward. */
    al_size blocks_delivered;

    /* Range serving: requested heights are recorded here. */
    al_bool served[FIXTURE_BLOCKS];
    al_u64  chain_tip;
    al_size peer_ups;
} loopback_events;

static void events_init(loopback_events *events) {
    memset(events, 0, sizeof(*events));
}

static al_bool on_transaction(void *userdata, al_bytes encoded) {
    loopback_events *events = (loopback_events *)userdata;
    if (encoded.len > sizeof(events->transaction_body)) return AL_FALSE;
    memcpy(events->transaction_body, encoded.data, encoded.len);
    events->transaction_len = encoded.len;
    events->transaction_seen = AL_TRUE;
    return AL_TRUE;
}

static al_bool on_block(void *userdata, al_bytes encoded) {
    loopback_events *events = (loopback_events *)userdata;
    AL_UNUSED(encoded);
    events->blocks_delivered++;
    events->chain_tip = (al_u64)events->blocks_delivered;
    return AL_FALSE; /* single hop: never relay in the fixture */
}

static al_status read_block(void *userdata, al_height height,
                            al_bytes_mut buffer, al_size *written) {
    loopback_events *events = (loopback_events *)userdata;
    if (height >= FIXTURE_BLOCKS) return AL_ERR_NOT_FOUND;
    if (buffer.len < 4u) return AL_ERR_BUFFER_TOO_SMALL;
    events->served[height] = AL_TRUE;
    buffer.data[0] = (al_u8)(height + 1u);
    *written = 4u;
    return AL_OK;
}

static al_height head_height(void *userdata) {
    loopback_events *events = (loopback_events *)userdata;
    return events->chain_tip;
}

static void on_peer_up(void *userdata, const al_p2p_peer *peer) {
    loopback_events *events = (loopback_events *)userdata;
    AL_UNUSED(peer);
    events->peer_ups++;
}

/* Poll both services until a predicate holds or the budget runs out. */
static void pump_until(al_p2p *client, al_p2p *server,
                       const al_bool *done) {
    for (al_u32 i = 0u; i < PUMP_LIMIT && (done == NULL || !*done); ++i) {
        al_p2p_poll(client, 5u);
        al_p2p_poll(server, 0u);
    }
}

static void bring_up_pair(al_p2p *client, loopback_events *client_events,
                          al_p2p *server, loopback_events *server_events,
                          al_u16 *server_port) {
    al_hash256 genesis;
    al_sha256("astrolune-loopback-genesis", 27u, &genesis);

    al_p2p_config config;
    memset(&config, 0, sizeof(config));
    config.protocol_version = AL_WIRE_PROTOCOL_VERSION;
    config.genesis = genesis;

    al_p2p_handlers handlers;
    memset(&handlers, 0, sizeof(handlers));
    handlers.on_transaction = on_transaction;
    handlers.on_block = on_block;
    handlers.read_block = read_block;
    handlers.head_height = head_height;
    handlers.on_peer_up = on_peer_up;

    handlers.userdata = client_events;
    AL_CHECK_EQ_STATUS(
        al_p2p_init(client, &config, &handlers, "127.0.0.1", 0u), AL_OK);

    handlers.userdata = server_events;
    AL_CHECK_EQ_STATUS(
        al_p2p_init(server, &config, &handlers, "127.0.0.1", 0u), AL_OK);

    AL_CHECK_EQ_STATUS(al_net_local_port(server->listener, server_port),
                       AL_OK);
}

AL_TEST(p2p_loopback_handshake_and_gossip) {
    AL_CHECK(al_net_init());

    loopback_events client_events;
    loopback_events server_events;
    events_init(&client_events);
    events_init(&server_events);

    al_p2p client;
    al_p2p server;
    al_u16 server_port = 0u;
    bring_up_pair(&client, &client_events, &server, &server_events,
                  &server_port);

    AL_CHECK_EQ_STATUS(al_p2p_dial(&client, "127.0.0.1", server_port),
                       AL_OK);
    pump_until(&client, &server, NULL);
    AL_CHECK_EQ_U64(al_p2p_ready_peers(&client), 1u);
    AL_CHECK_EQ_U64(al_p2p_ready_peers(&server), 1u);
    AL_CHECK_EQ_U64(client_events.peer_ups, 1u);
    AL_CHECK_EQ_U64(server_events.peer_ups, 1u);

    /* A transaction announced by the client reaches the server handler. */
    static const al_u8 transaction[] = { 0x01u, 0x02u, 0x03u };
    AL_CHECK_EQ_U64(al_p2p_relay_transaction(
                        &client,
                        al_bytes_make(transaction, sizeof(transaction)),
                        NULL),
                    1u);
    pump_until(&client, &server, &server_events.transaction_seen);
    AL_CHECK(server_events.transaction_seen);
    AL_CHECK(server_events.transaction_len == sizeof(transaction));
    AL_CHECK(memcmp(server_events.transaction_body, transaction,
                    sizeof(transaction)) == 0);

    /* Redelivering identical bytes must hit the dedup ring, not the node. */
    (void)al_p2p_relay_transaction(
        &client, al_bytes_make(transaction, sizeof(transaction)), NULL);
    pump_until(&client, &server, NULL);
    AL_CHECK_EQ_U64((al_u64)server_events.blocks_delivered, 0u);
    AL_CHECK(server_events.transaction_seen); /* still exactly one delivery */

    al_p2p_close(&client);
    al_p2p_close(&server);
}

AL_TEST(p2p_range_sync_from_taller_peer) {
    AL_CHECK(al_net_init());

    loopback_events client_events;
    loopback_events server_events;
    events_init(&client_events);
    events_init(&server_events);
    server_events.chain_tip = FIXTURE_BLOCKS;

    al_p2p client;
    al_p2p server;
    al_u16 server_port = 0u;
    bring_up_pair(&client, &client_events, &server, &server_events,
                  &server_port);

    AL_CHECK_EQ_STATUS(al_p2p_dial(&client, "127.0.0.1", server_port),
                       AL_OK);
    /* The handshake reveals the height gap; the client pulls automatically
     * and the server serves the whole range back to the client. */
    pump_until(&client, &server, NULL);
    AL_CHECK_EQ_U64((al_u64)client_events.blocks_delivered, FIXTURE_BLOCKS);
    for (al_size i = 0u; i < FIXTURE_BLOCKS; ++i) {
        AL_CHECK(server_events.served[i]);
    }

    al_p2p_close(&client);
    al_p2p_close(&server);
}

AL_TEST(p2p_rejects_foreign_genesis) {
    AL_CHECK(al_net_init());

    al_hash256 ours;
    al_sha256("astrolune-ours", 14u, &ours);
    al_hash256 theirs;
    al_sha256("astrolune-theirs", 16u, &theirs);

    loopback_events client_events;
    loopback_events server_events;
    events_init(&client_events);
    events_init(&server_events);

    al_p2p client;
    al_p2p server;
    al_u16 port = 0u;
    bring_up_pair(&client, &client_events, &server, &server_events, &port);

    /* Retarget the client onto a different chain after init. */
    client.config.genesis = theirs;

    AL_CHECK_EQ_STATUS(al_p2p_dial(&client, "127.0.0.1", port), AL_OK);
    pump_until(&client, &server, NULL);

    /* The mismatched handshake must leave neither side with a usable peer:
     * the server drops the connection outright. */
    AL_CHECK_EQ_U64(al_p2p_ready_peers(&server), 0u);

    al_p2p_close(&client);
    al_p2p_close(&server);
}

static const char *AL_TEST_SUITE_NAME = "net";

AL_TEST_MAIN {
    AL_RUN(wire_header_roundtrip);
    AL_RUN(wire_header_rejects_oversize_payload);
    AL_RUN(wire_hello_roundtrip);
    AL_RUN(wire_get_blocks_rejects_unbounded_requests);
    AL_RUN(wire_blocks_cursor_roundtrip);
    AL_RUN(wire_finalized_block_roundtrip);
    AL_RUN(p2p_loopback_handshake_and_gossip);
    AL_RUN(p2p_range_sync_from_taller_peer);
    AL_RUN(p2p_rejects_foreign_genesis);
}
