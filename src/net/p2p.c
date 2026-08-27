/* Peer manager implementation. See p2p.h for the design notes. */

#include "p2p.h"
#include "internal/common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One uniform snprintf spelling across platforms. */
#if defined(AL_OS_WINDOWS)
#  define net_snprintf sprintf_s
#else
#  define net_snprintf snprintf
#endif

/* Defaults for a config the caller did not tune. */
#define P2P_HANDSHAKE_TIMEOUT_MS 10000u
#define P2P_PING_INTERVAL_MS     25000u
#define P2P_IDLE_TIMEOUT_MS      90000u

/* Serving is clamped so the leading count varint stays a single byte and one
 * reply can never approach the wire payload bound on its own. */
#define P2P_MAX_SERVED_BLOCKS    128u

/* Worst-case varint width, used to reserve room for entry length prefixes. */
#define P2P_VARINT_MAX           10u

static al_socket invalid_socket(void) {
#if defined(AL_OS_WINDOWS)
    al_socket s = { INVALID_SOCKET };
#else
    al_socket s = { -1 };
#endif
    return s;
}

/* Peer slots are compacted on removal, so an address is not a stable
 * identity. The socket handle remains unique for the lifetime of a peer. */
static al_bool same_socket(al_socket a, al_socket b) {
    return a.handle == b.handle ? AL_TRUE : AL_FALSE;
}

/* Release every dynamically allocated buffer owned by a peer. Called when a
 * peer leaves the table; nothing is reused across connections. */
static void peer_release_buffers(al_p2p_peer *peer) {
    free(peer->rx_buffer);
    free(peer->tx_queue);
}

static void peer_init(al_p2p_peer *peer) {
    al_memzero(peer, sizeof(*peer));
    peer->socket = invalid_socket();
}

static void peer_close(al_p2p *network, al_size index) {
    al_p2p_peer *peer = &network->peers[index];
    char endpoint[AL_P2P_ENDPOINT_SIZE];
    al_bool notify = peer->state != AL_P2P_CONNECTING &&
                     network->handlers.on_peer_down != NULL;
    if (notify) {
        memcpy(endpoint, peer->endpoint, sizeof(endpoint));
    }

    al_net_close(peer->socket);
    peer_release_buffers(peer);

    /* Preserve connection order: cheap at this capacity and keeps iteration
     * stable for callers that index into the array. */
    for (al_size i = index; i + 1u < network->peer_count; ++i) {
        network->peers[i] = network->peers[i + 1u];
    }
    network->peer_count--;
    al_p2p_peer *vacated = &network->peers[network->peer_count];
    al_memzero(vacated, sizeof(*vacated));
    vacated->socket = invalid_socket();

    if (notify) {
        network->handlers.on_peer_down(network->handlers.userdata, endpoint);
    }
}

static al_bool seen_contains(const al_hash256 *ring, const al_hash256 *hash) {
    for (al_size i = 0u; i < AL_P2P_DEDUP_RING; ++i) {
        if (al_hash_eq(&ring[i], hash)) return AL_TRUE;
    }
    return AL_FALSE;
}

static void seen_insert(al_hash256 *ring, al_size *next,
                        const al_hash256 *hash) {
    ring[*next] = *hash;
    *next = (*next + 1u) % AL_P2P_DEDUP_RING;
}

/* --- Outbound queueing ------------------------------------------------------ */

static al_status peer_queue(al_p2p_peer *peer, const void *data, al_size len) {
    if (len == 0u) return AL_OK;
    if (peer->tx_len + len > AL_P2P_MAX_OUTBOX ||
        peer->tx_len + len < peer->tx_len) {
        /* A link that cannot drain this much queued canonical data is not
         * worth keeping; the poller drops the peer on the next flush. */
        return AL_ERR_RESOURCE_LIMIT;
    }
    if (peer->tx_cap < peer->tx_len + len) {
        al_size cap = peer->tx_cap != 0u ? peer->tx_cap : (al_size)64 * 1024u;
        while (cap < peer->tx_len + len) cap *= 2u;
        al_u8 *grown = (al_u8 *)realloc(peer->tx_queue, cap);
        if (grown == NULL) return AL_ERR_OUT_OF_MEMORY;
        peer->tx_queue = grown;
        peer->tx_cap = cap;
    }
    al_memcpy(peer->tx_queue + peer->tx_len, data, len);
    peer->tx_len += len;
    return AL_OK;
}

static al_status peer_send_frame(al_p2p_peer *peer, al_wire_type type,
                                 const void *payload, al_size payload_len) {
    al_u8 header[AL_WIRE_HEADER_SIZE];
    al_writer writer;
    al_writer_init(&writer, header, sizeof(header));
    al_wire_header_encode(&writer, type, (al_u32)payload_len);
    if (al_writer_finish(&writer) != AL_OK) return AL_ERR_INVALID_ARG;

    AL_TRY(peer_queue(peer, header, sizeof(header)));
    return peer_queue(peer, payload, payload_len);
}

static al_status peer_send_get_blocks(al_p2p_peer *peer, al_height start,
                                      al_u32 max_count) {
    al_wire_get_blocks request = { start, max_count };
    al_u8 payload[16];
    al_writer writer;
    al_writer_init(&writer, payload, sizeof(payload));
    al_wire_get_blocks_encode(&writer, &request);
    AL_TRY(al_writer_finish(&writer));
    return peer_send_frame(peer, AL_WIRE_GET_BLOCKS, payload,
                           al_writer_len(&writer));
}

/* --- Object handling ---------------------------------------------------------- */

/*
 * Handle one canonical transaction/block arriving from `origin`. The dedup
 * ring runs before the node callback: a rejected object must not be able to
 * burn validation time twice, and an accepted object must not echo back to
 * its origin.
 */
static void handle_transaction(al_p2p *network, al_p2p_peer *origin,
                               al_bytes payload) {
    al_hash256 hash;
    al_sha256_bytes(payload, &hash);
    if (seen_contains(network->seen_transactions, &hash)) return;
    seen_insert(network->seen_transactions,
                &network->seen_transaction_next, &hash);

    if (network->handlers.on_transaction == NULL ||
        !network->handlers.on_transaction(network->handlers.userdata,
                                          payload)) {
        return;
    }
    (void)al_p2p_relay_transaction(network, payload, origin);
}

static void handle_block(al_p2p *network, al_p2p_peer *origin,
                         al_bytes payload) {
    al_hash256 hash;
    al_sha256_bytes(payload, &hash);
    if (seen_contains(network->seen_blocks, &hash)) return;
    seen_insert(network->seen_blocks, &network->seen_block_next, &hash);

    if (network->handlers.on_block == NULL ||
        !network->handlers.on_block(network->handlers.userdata, payload)) {
        return;
    }
    (void)al_p2p_relay_block(network, payload, origin);
}

static void handle_consensus(al_p2p *network, al_p2p_peer *origin,
                             al_wire_type type, al_bytes payload) {
    al_hash256 hash;
    al_sha256_ctx context;
    al_sha256_init(&context);
    al_u8 type_byte = (al_u8)type;
    al_sha256_update(&context, &type_byte, sizeof(type_byte));
    al_sha256_update(&context, payload.data, payload.len);
    al_sha256_final(&context, &hash);
    if (seen_contains(network->seen_consensus, &hash)) return;
    seen_insert(network->seen_consensus, &network->seen_consensus_next, &hash);
    if (network->handlers.on_consensus == NULL ||
        !network->handlers.on_consensus(network->handlers.userdata, type,
                                        payload)) {
        return;
    }
    (void)al_p2p_relay_consensus(network, type, payload, origin);
}

static al_bool handle_finalized_block(al_p2p *network,
                                      al_p2p_peer *origin,
                                      al_bytes payload, al_bool relay) {
    al_hash256 hash;
    al_sha256_bytes(payload, &hash);
    if (seen_contains(network->seen_consensus, &hash)) return AL_TRUE;
    seen_insert(network->seen_consensus, &network->seen_consensus_next, &hash);
    if (network->handlers.on_finalized_block == NULL ||
        !network->handlers.on_finalized_block(network->handlers.userdata,
                                              payload)) {
        return AL_FALSE;
    }
    if (relay) {
        (void)al_p2p_relay_consensus(network, AL_WIRE_FINALITY, payload,
                                     origin);
    }
    return AL_TRUE;
}

/* Serve GET_BLOCKS from durable storage. Each entry is assembled directly in
 * the shared reply buffer: length varint first, then the block bytes read in
 * behind it, with a single compaction step when the real prefix is shorter
 * than the reserved worst case. */
static void handle_get_blocks(al_p2p *network, al_p2p_peer *peer,
                              al_bytes payload) {
    al_wire_get_blocks request;
    if (al_wire_get_blocks_decode(payload, &request) != AL_OK ||
        (network->handlers.read_finalized_block == NULL &&
         network->handlers.read_block == NULL)) {
        return;
    }
    if (request.max_count > P2P_MAX_SERVED_BLOCKS) {
        request.max_count = P2P_MAX_SERVED_BLOCKS;
    }

    if (network->reply_buffer == NULL) {
        network->reply_capacity = 4u * 1024u * 1024u;
        network->reply_buffer = (al_u8 *)malloc(network->reply_capacity);
        if (network->reply_buffer == NULL) return;
    }

    al_status (*read_entry)(void *, al_height, al_bytes_mut, al_size *) =
        network->handlers.read_finalized_block != NULL
            ? network->handlers.read_finalized_block
            : network->handlers.read_block;
    al_size used = P2P_VARINT_MAX;
    al_size served = 0u;
    al_height height = request.start;
    while (served < request.max_count &&
           used + P2P_VARINT_MAX <= network->reply_capacity) {
        /* Reserve the worst-case prefix and read the block behind it. */
        al_size data_offset = used + P2P_VARINT_MAX;
        al_size written = 0u;
        al_bytes_mut room = {
            network->reply_buffer + data_offset,
            network->reply_capacity - data_offset
        };
        if (read_entry(network->handlers.userdata, height, room, &written) !=
            AL_OK) {
            break;
        }
        al_u8 prefix[P2P_VARINT_MAX];
        al_writer prefix_writer;
        al_writer_init(&prefix_writer, prefix, sizeof(prefix));
        al_writer_varint(&prefix_writer, (al_u64)written);
        al_size prefix_len = al_writer_len(&prefix_writer);

        if (prefix_len != P2P_VARINT_MAX) {
            memmove(network->reply_buffer + used + prefix_len,
                    network->reply_buffer + data_offset, written);
        }
        memcpy(network->reply_buffer + used, prefix, prefix_len);
        used += prefix_len + written;
        served++;
        height++;
    }

    if (served != 0u) {
        al_u8 count_prefix[P2P_VARINT_MAX];
        al_writer count_writer;
        al_writer_init(&count_writer, count_prefix, sizeof(count_prefix));
        al_writer_varint(&count_writer, served);
        al_size count_len = al_writer_len(&count_writer);
        memmove(network->reply_buffer + count_len,
                network->reply_buffer + P2P_VARINT_MAX,
                used - P2P_VARINT_MAX);
        memcpy(network->reply_buffer, count_prefix, count_len);
        used = count_len + used - P2P_VARINT_MAX;
        (void)peer_send_frame(peer, AL_WIRE_BLOCKS, network->reply_buffer,
                              used);
    }
}
static void handle_blocks(al_p2p *network, al_p2p_peer *origin,
                          al_bytes payload) {
    al_wire_blocks_cursor cursor;
    if (al_wire_blocks_begin(payload, &cursor) != AL_OK) return;
    al_bytes entry;
    while (al_wire_blocks_next(&cursor, &entry) == AL_OK) {
        if (network->handlers.on_finalized_block != NULL) {
            if (!handle_finalized_block(network, origin, entry, AL_FALSE)) {
                return;
            }
        } else {
            handle_block(network, origin, entry);
        }
    }
    al_height known_blocks =
        network->handlers.head_height != NULL
            ? network->handlers.head_height(network->handlers.userdata)
            : 0u;
    if (cursor.count == P2P_MAX_SERVED_BLOCKS && known_blocks < origin->height) {
        (void)peer_send_get_blocks(origin, known_blocks,
                                   P2P_MAX_SERVED_BLOCKS);
    }
}

static void send_hello(al_p2p *network, al_p2p_peer *peer) {
    al_wire_hello hello;
    hello.protocol_version = network->config.protocol_version;
    hello.listen_port = network->config.listen_port;
    hello.genesis = network->config.genesis;
    hello.head = al_hash_zero();
    hello.height = network->handlers.head_height != NULL
                       ? network->handlers.head_height(
                             network->handlers.userdata)
                       : 0u;
    al_u8 payload[sizeof(hello.protocol_version) +
                  sizeof(hello.listen_port) + AL_HASH_SIZE + AL_HASH_SIZE +
                  sizeof(al_u64)];
    al_writer writer;
    al_writer_init(&writer, payload, sizeof(payload));
    al_wire_hello_encode(&writer, &hello);
    if (al_writer_finish(&writer) == AL_OK) {
        (void)peer_send_frame(peer, AL_WIRE_HELLO, payload,
                              al_writer_len(&writer));
    }
}

static void peer_canonical_endpoint(al_p2p_peer *peer, al_u16 listen_port) {
    const char *separator = strrchr(peer->endpoint, ':');
    if (separator == NULL) return;
    al_size host_length = (al_size)(separator - peer->endpoint);
    if (host_length == 0u || host_length >= sizeof(peer->endpoint)) return;
    char endpoint[AL_P2P_ENDPOINT_SIZE];
    (void)net_snprintf(endpoint, sizeof(endpoint), "%.*s:%u",
                       (int)host_length, peer->endpoint,
                       (unsigned)listen_port);
    memcpy(peer->endpoint, endpoint, sizeof(peer->endpoint));
}

static al_bool peer_drop_duplicate(al_p2p *network, al_p2p_peer **current) {
    al_p2p_peer *peer = *current;
    if (network->config.listen_port == 0u || peer->listen_port == 0u ||
        network->config.listen_port == peer->listen_port) {
        return AL_FALSE;
    }
    al_bool prefer_inbound =
        network->config.listen_port > peer->listen_port ? AL_TRUE : AL_FALSE;
    al_socket identity = peer->socket;
    al_size current_index = (al_size)(peer - network->peers);
    for (al_size i = 0u; i < network->peer_count; ++i) {
        al_p2p_peer *other = &network->peers[i];
        if (i == current_index || other->state != AL_P2P_READY ||
            strcmp(other->endpoint, peer->endpoint) != 0 ||
            other->inbound == peer->inbound) {
            continue;
        }
        if (peer->inbound != prefer_inbound) {
            peer_close(network, current_index);
            return AL_TRUE;
        }
        peer_close(network, i);
        for (al_size j = 0u; j < network->peer_count; ++j) {
            if (same_socket(network->peers[j].socket, identity)) {
                *current = &network->peers[j];
                return AL_FALSE;
            }
        }
        return AL_TRUE;
    }
    return AL_FALSE;
}

static void handle_hello(al_p2p *network, al_p2p_peer *peer,
                         al_bytes payload, al_u64 now_ms) {
    al_wire_hello hello;
    if (al_wire_hello_decode(payload, &hello) != AL_OK ||
        !al_hash_eq(&hello.genesis, &network->config.genesis)) {
        peer_close(network, (al_size)(peer - network->peers));
        return;
    }
    al_bool first_hello = peer->state != AL_P2P_READY ? AL_TRUE : AL_FALSE;
    peer->genesis = hello.genesis;
    peer->head = hello.head;
    peer->height = hello.height;
    peer->listen_port = hello.listen_port;

    /* The handshake is an exchange: an inbound peer that has not introduced
     * itself yet receives our HELLO here, so both sides reach READY. */
    if (first_hello && peer->inbound) {
        send_hello(network, peer);
    }
    peer->state = AL_P2P_READY;
    peer->last_recv_ms = now_ms;
    peer_canonical_endpoint(peer, hello.listen_port);

    if (!first_hello || peer_drop_duplicate(network, &peer)) return;

    if (network->handlers.on_peer_up != NULL) {
        network->handlers.on_peer_up(network->handlers.userdata, peer);
    }

    /* Pull from a taller peer immediately rather than waiting for gossip to
     * discover the gap one announcement at a time. Heights on the wire are
     * "known block counts", so our own count is exactly where we must start
     * requesting. */
    al_height known_blocks =
        network->handlers.head_height != NULL
            ? network->handlers.head_height(network->handlers.userdata)
            : 0u;
    if (hello.height > known_blocks) {
        (void)peer_send_get_blocks(peer, known_blocks,
                                   P2P_MAX_SERVED_BLOCKS);
    }
}

static void dispatch_frame(al_p2p *network, al_p2p_peer *peer,
                           al_wire_type type, al_bytes payload,
                           al_u64 now_ms) {
    peer->last_recv_ms = now_ms;

    /* Until a peer proves it shares our genesis it gets exactly one chance to
     * say HELLO and nothing else. */
    if (peer->state != AL_P2P_READY && type != AL_WIRE_HELLO) {
        peer_close(network, (al_size)(peer - network->peers));
        return;
    }

    switch (type) {
    case AL_WIRE_HELLO:
        handle_hello(network, peer, payload, now_ms);
        break;
    case AL_WIRE_PING: {
        al_wire_ping ping;
        if (al_wire_ping_decode(payload, &ping) == AL_OK) {
            (void)peer_send_frame(peer, AL_WIRE_PONG, &ping.nonce,
                                  sizeof(ping.nonce));
        }
        break;
    }
    case AL_WIRE_PONG:
        break; /* liveness is tracked through last_recv_ms */
    case AL_WIRE_TX:
        handle_transaction(network, peer, payload);
        break;
    case AL_WIRE_BLOCK:
        handle_block(network, peer, payload);
        break;
    case AL_WIRE_GET_BLOCKS:
        handle_get_blocks(network, peer, payload);
        break;
    case AL_WIRE_BLOCKS:
        handle_blocks(network, peer, payload);
        break;
    case AL_WIRE_PROPOSAL:
    case AL_WIRE_VOTE:
        handle_consensus(network, peer, type, payload);
        break;
    case AL_WIRE_FINALITY:
        (void)handle_finalized_block(network, peer, payload, AL_TRUE);
        break;
    default:
        peer_close(network, (al_size)(peer - network->peers));
        break;
    }
}

/* --- Socket event handling ---------------------------------------------------- */

#define AL_VARINT_MAX 10

/*
 * Assemble frames from a freshly received chunk. A frame completes either
 * immediately after its header (empty payload) or when the tail byte of its
 * payload lands - which may be several receive chunks later, so the decoded
 * type is carried in the peer state. Dispatch can remove the peer (protocol
 * violation, shutdown), so every completion site re-validates the slot before
 * touching it again.
 */
static void feed_bytes(al_p2p *network, al_size index, al_bytes chunk,
                       al_u64 now_ms) {
    al_p2p_peer *peer = &network->peers[index];
    al_size offset = 0u;
    while (offset < chunk.len) {
        if (peer->rx_header_have < AL_WIRE_HEADER_SIZE) {
            al_size take = AL_WIRE_HEADER_SIZE - peer->rx_header_have;
            if (take > chunk.len - offset) take = chunk.len - offset;
            al_memcpy(peer->rx_header + peer->rx_header_have,
                      chunk.data + offset, take);
            peer->rx_header_have += take;
            offset += take;
            if (peer->rx_header_have < AL_WIRE_HEADER_SIZE) return;
        }

        if (peer->rx_buffer == NULL) {
            al_wire_header header;
            if (al_wire_header_decode(
                    al_bytes_make(peer->rx_header, AL_WIRE_HEADER_SIZE),
                    &header) != AL_OK) {
                peer_close(network, index);
                return;
            }
            peer->rx_type = (al_u8)header.type;
            if (header.payload_len == 0u) {
                al_socket identity = peer->socket;
                dispatch_frame(network, peer, header.type, al_bytes_empty(),
                               now_ms);
                if (index >= network->peer_count ||
                    !same_socket(network->peers[index].socket, identity)) {
                    return;
                }
                peer->rx_header_have = 0u;
                continue;
            }
            peer->rx_buffer = (al_u8 *)malloc(header.payload_len);
            if (peer->rx_buffer == NULL) {
                peer_close(network, index);
                return;
            }
            peer->rx_buffer_cap = header.payload_len;
            peer->rx_have = 0u;
        }

        al_size take = peer->rx_buffer_cap - peer->rx_have;
        if (take > chunk.len - offset) take = chunk.len - offset;
        al_memcpy(peer->rx_buffer + peer->rx_have, chunk.data + offset, take);
        peer->rx_have += take;
        offset += take;
        if (peer->rx_have < peer->rx_buffer_cap) return;

        al_bytes payload = al_bytes_make(peer->rx_buffer, peer->rx_buffer_cap);
        al_socket identity = peer->socket;
        dispatch_frame(network, peer, (al_wire_type)peer->rx_type, payload,
                       now_ms);
        if (index >= network->peer_count ||
            !same_socket(network->peers[index].socket, identity)) {
            return; /* peer_close released the buffer and compacted the table */
        }
        free(peer->rx_buffer);
        peer->rx_buffer = NULL;
        peer->rx_buffer_cap = 0u;
        peer->rx_have = 0u;
        peer->rx_header_have = 0u;
    }
}

static void peer_readable(al_p2p *network, al_size index, al_u64 now_ms) {
    al_u8 chunk[16384];
    while (index < network->peer_count) {
        al_size received = 0u;
        al_status status = al_net_recv(
            network->peers[index].socket,
            (al_bytes_mut){ chunk, sizeof(chunk) }, &received);
        if (status == AL_ERR_WOULD_BLOCK) return;
        if (status == AL_ERR_CLOSED) {
            peer_close(network, index);
            return;
        }
        feed_bytes(network, index, al_bytes_make(chunk, received), now_ms);
        if (index >= network->peer_count) return; /* dropped mid-batch */
    }
}

static void peer_writable(al_p2p *network, al_size index) {
    al_p2p_peer *peer = &network->peers[index];

    /* Complete a pending outbound dial. */
    if (peer->state == AL_P2P_CONNECTING) {
        if (al_net_connect_result(peer->socket) != AL_OK) {
            peer_close(network, index);
            return;
        }
        peer->state = AL_P2P_HANDSHAKING;
        peer->connected_ms = al_net_now_ms();
        peer->last_recv_ms = peer->connected_ms;
        send_hello(network, peer);
        return;
    }

    while (peer->tx_sent < peer->tx_len) {
        al_size sent = 0u;
        al_status status = al_net_send(
            peer->socket,
            al_bytes_make(peer->tx_queue + peer->tx_sent,
                          peer->tx_len - peer->tx_sent),
            &sent);
        if (status == AL_ERR_WOULD_BLOCK) return;
        if (status == AL_ERR_CLOSED) {
            peer_close(network, index);
            return;
        }
        peer->tx_sent += sent;
    }
    peer->tx_sent = 0u;
    peer->tx_len = 0u;
}

static void enforce_timeouts(al_p2p *network, al_u64 now_ms) {
    /* Reverse iteration keeps removal during the walk well-defined. */
    for (al_size i = network->peer_count; i-- > 0u;) {
        al_p2p_peer *peer = &network->peers[i];
        if (peer->state == AL_P2P_CONNECTING) {
            if (now_ms - peer->connected_ms >
                network->config.handshake_timeout_ms) {
                peer_close(network, i);
            }
            continue;
        }
        if (peer->state == AL_P2P_HANDSHAKING) {
            if (now_ms - peer->connected_ms >
                network->config.handshake_timeout_ms) {
                peer_close(network, i);
            }
            continue;
        }
        if (now_ms - peer->last_recv_ms > network->config.idle_timeout_ms) {
            peer_close(network, i);
            continue;
        }
        if (now_ms - peer->last_ping_ms > network->config.ping_interval_ms) {
            al_wire_ping ping = { now_ms };
            (void)peer_send_frame(peer, AL_WIRE_PING, &ping.nonce,
                                  sizeof(ping.nonce));
            peer->last_ping_ms = now_ms;
        }
    }
}

/* --- Public API --------------------------------------------------------------- */

al_status al_p2p_init(al_p2p *network, const al_p2p_config *config,
                      const al_p2p_handlers *handlers, const char *listen_host,
                      al_u16 listen_port) {
    if (network == NULL || config == NULL || handlers == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_memzero(network, sizeof(*network));
    network->config = *config;
    network->handlers = *handlers;
    if (network->config.max_peers == 0u ||
        network->config.max_peers > AL_P2P_MAX_PEERS) {
        network->config.max_peers = AL_P2P_MAX_PEERS;
    }
    if (network->config.handshake_timeout_ms == 0u) {
        network->config.handshake_timeout_ms = P2P_HANDSHAKE_TIMEOUT_MS;
    }
    if (network->config.ping_interval_ms == 0u) {
        network->config.ping_interval_ms = P2P_PING_INTERVAL_MS;
    }
    if (network->config.idle_timeout_ms == 0u) {
        network->config.idle_timeout_ms = P2P_IDLE_TIMEOUT_MS;
    }

    al_status status =
        al_net_listen(listen_host, listen_port, &network->listener);
    if (status == AL_OK) {
        network->has_listener = AL_TRUE;
    } else {
        network->listener = invalid_socket();
    }
    return status;
}

void al_p2p_close(al_p2p *network) {
    if (network == NULL) return;
    for (al_size i = network->peer_count; i-- > 0u;) {
        peer_close(network, i);
    }
    if (network->has_listener) {
        al_net_close(network->listener);
        network->has_listener = AL_FALSE;
    }
    free(network->reply_buffer);
    network->reply_buffer = NULL;
    network->reply_capacity = 0u;
}

al_status al_p2p_dial(al_p2p *network, const char *host, al_u16 port) {
    if (network == NULL || host == NULL) return AL_ERR_INVALID_ARG;
    if (network->peer_count >= network->config.max_peers) {
        return AL_ERR_RESOURCE_LIMIT;
    }

    char endpoint[AL_P2P_ENDPOINT_SIZE];
    (void)net_snprintf(endpoint, sizeof(endpoint), "%s:%u", host,
                       (unsigned)port);
    /* One connection per endpoint: repeated bootstrap attempts stay
     * idempotent instead of piling up half-open sockets. */
    for (al_size i = 0u; i < network->peer_count; ++i) {
        if (strncmp(network->peers[i].endpoint, endpoint,
                    sizeof(endpoint)) == 0) {
            return AL_ERR_ALREADY_EXISTS;
        }
    }

    al_socket socket;
    AL_TRY(al_net_connect(host, port, &socket));

    al_p2p_peer *peer = &network->peers[network->peer_count];
    peer_init(peer);
    peer->socket = socket;
    peer->inbound = AL_FALSE;
    peer->state = AL_P2P_CONNECTING;
    peer->connected_ms = al_net_now_ms();
    peer->last_recv_ms = peer->connected_ms;
    memcpy(peer->endpoint, endpoint, sizeof(peer->endpoint));
    network->peer_count++;
    return AL_OK;
}

void al_p2p_poll(al_p2p *network, al_u32 timeout_ms) {
    if (network == NULL) return;
    al_u64 now_ms = al_net_now_ms();

    al_net_set readable;
    al_net_set writable;
    al_net_set_init(&readable);
    al_net_set_init(&writable);
    if (network->has_listener &&
        network->peer_count < network->config.max_peers) {
        al_net_set_add(&readable, network->listener);
    }
    for (al_size i = 0u; i < network->peer_count; ++i) {
        const al_p2p_peer *peer = &network->peers[i];
        al_net_set_add(&readable, peer->socket);
        if (peer->tx_len > peer->tx_sent || peer->state == AL_P2P_CONNECTING) {
            al_net_set_add(&writable, peer->socket);
        }
    }

    (void)al_net_select(&readable, &writable, timeout_ms);

    /* Accept inbound connections while there is room. */
    if (network->has_listener &&
        al_net_set_contains(&readable, network->listener)) {
        while (network->peer_count < network->config.max_peers) {
            al_socket accepted;
            char endpoint[AL_P2P_ENDPOINT_SIZE];
            if (al_net_accept(network->listener, &accepted, endpoint,
                              sizeof(endpoint)) != AL_OK) {
                break;
            }
            al_p2p_peer *peer = &network->peers[network->peer_count];
            peer_init(peer);
            peer->socket = accepted;
            peer->inbound = AL_TRUE;
            peer->state = AL_P2P_HANDSHAKING;
            peer->connected_ms = now_ms;
            peer->last_recv_ms = now_ms;
            memcpy(peer->endpoint, endpoint, sizeof(endpoint));
            network->peer_count++;
        }
    }

    /* Handle writable/readable events. Handlers may close peers, which shifts
     * the array down, so the loop only advances past a slot that still holds
     * the peer it started with. */
    for (al_size i = 0u; i < network->peer_count;) {
        const al_p2p_peer *current = &network->peers[i];
        al_socket socket = current->socket;

        if (al_net_set_contains(&writable, socket)) {
            peer_writable(network, i);
        }
        if (i < network->peer_count &&
            same_socket(network->peers[i].socket, socket) &&
            al_net_set_contains(&readable, socket)) {
            peer_readable(network, i, now_ms);
        }
        if (i < network->peer_count &&
            same_socket(network->peers[i].socket, socket)) {
            i++;
        }
    }

    enforce_timeouts(network, al_net_now_ms());
}

al_size al_p2p_relay_transaction(al_p2p *network, al_bytes encoded,
                                 const al_p2p_peer *origin) {
    if (network == NULL) return 0u;
    al_size queued = 0u;
    for (al_size i = 0u; i < network->peer_count; ++i) {
        al_p2p_peer *peer = &network->peers[i];
        if (&network->peers[i] == origin || peer->state != AL_P2P_READY) {
            continue;
        }
        if (peer_send_frame(peer, AL_WIRE_TX, encoded.data, encoded.len) ==
            AL_OK) {
            queued++;
        }
    }
    return queued;
}

al_size al_p2p_relay_block(al_p2p *network, al_bytes encoded,
                           const al_p2p_peer *origin) {
    if (network == NULL) return 0u;
    al_size queued = 0u;
    for (al_size i = 0u; i < network->peer_count; ++i) {
        al_p2p_peer *peer = &network->peers[i];
        if (&network->peers[i] == origin || peer->state != AL_P2P_READY) {
            continue;
        }
        if (peer_send_frame(peer, AL_WIRE_BLOCK, encoded.data, encoded.len) ==
            AL_OK) {
            queued++;
        }
    }
    return queued;
}

al_size al_p2p_relay_consensus(al_p2p *network, al_wire_type type,
                               al_bytes encoded,
                               const al_p2p_peer *origin) {
    if (network == NULL ||
        (type != AL_WIRE_PROPOSAL && type != AL_WIRE_VOTE &&
         type != AL_WIRE_FINALITY)) {
        return 0u;
    }
    al_size queued = 0u;
    for (al_size i = 0u; i < network->peer_count; ++i) {
        al_p2p_peer *peer = &network->peers[i];
        if (&network->peers[i] == origin || peer->state != AL_P2P_READY) {
            continue;
        }
        if (peer_send_frame(peer, type, encoded.data, encoded.len) == AL_OK) {
            queued++;
        }
    }
    return queued;
}

al_size al_p2p_ready_peers(const al_p2p *network) {
    if (network == NULL) return 0u;
    al_size ready = 0u;
    for (al_size i = 0u; i < network->peer_count; ++i) {
        if (network->peers[i].state == AL_P2P_READY) ready++;
    }
    return ready;
}
