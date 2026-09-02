/* P2P inbound message handling: transaction/block/consensus/handshake dispatch. */

#include "p2p_internal.h"

void handle_transaction(al_p2p *network, al_p2p_peer *origin,
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
    al_size relayed = al_p2p_relay_transaction(network, payload, origin);
    (void)relayed;
}

void handle_block(al_p2p *network, al_p2p_peer *origin,
                  al_bytes payload) {
    al_hash256 hash;
    al_sha256_bytes(payload, &hash);
    if (seen_contains(network->seen_blocks, &hash)) return;
    seen_insert(network->seen_blocks, &network->seen_block_next, &hash);

    if (network->handlers.on_block == NULL ||
        !network->handlers.on_block(network->handlers.userdata, payload)) {
        return;
    }
    al_size relayed = al_p2p_relay_block(network, payload, origin);
    (void)relayed;
}

void handle_consensus(al_p2p *network, al_p2p_peer *origin,
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
    al_size relayed = al_p2p_relay_consensus(network, type, payload, origin);
    (void)relayed;
}

al_bool handle_finalized_block(al_p2p *network, al_p2p_peer *origin,
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
        al_size relayed = al_p2p_relay_consensus(
            network, AL_WIRE_FINALITY, payload, origin);
        (void)relayed;
    }
    return AL_TRUE;
}

void handle_get_blocks(al_p2p *network, al_p2p_peer *peer,
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

void handle_blocks(al_p2p *network, al_p2p_peer *origin,
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

void send_hello(al_p2p *network, al_p2p_peer *peer) {
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

void handle_hello(al_p2p *network, al_p2p_peer *peer,
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

    if (first_hello && peer->inbound) {
        send_hello(network, peer);
    }
    peer->state = AL_P2P_READY;
    peer->last_recv_ms = now_ms;
    peer_canonical_endpoint(peer, hello.listen_port);

    if (first_hello) {
        al_wire_key_exchange kx;
        al_memcpy(kx.ephemeral_pk, network->local_kx.pk,
                  AL_KX_PUBLIC_KEY_SIZE);
        al_u8 buf[sizeof(al_wire_header) + AL_KX_PUBLIC_KEY_SIZE];
        al_writer writer;
        al_writer_init(&writer, buf, sizeof(buf));
        al_wire_key_exchange_encode(&writer, &kx);
        al_size kx_len = al_writer_len(&writer);
        if (al_writer_finish(&writer) != AL_OK) {
            peer_close(network, (al_size)(peer - network->peers));
            return;
        }
        (void)peer_send_frame(peer, AL_WIRE_KEY_EXCHANGE, buf, kx_len);
    }

    if (!first_hello || peer_drop_duplicate(network, &peer)) return;

    if (network->handlers.on_peer_up != NULL) {
        network->handlers.on_peer_up(network->handlers.userdata, peer);
    }

    al_height known_blocks =
        network->handlers.head_height != NULL
            ? network->handlers.head_height(network->handlers.userdata)
            : 0u;
    if (hello.height > known_blocks) {
        (void)peer_send_get_blocks(peer, known_blocks,
                                   P2P_MAX_SERVED_BLOCKS);
    }
}

void handle_key_exchange(al_p2p *network, al_p2p_peer *peer,
                         al_bytes payload) {
    al_wire_key_exchange kx;
    if (al_wire_key_exchange_decode(payload, &kx) != AL_OK) {
        peer_close(network, (al_size)(peer - network->peers));
        return;
    }
    if (!network->config.require_encryption) return;

    al_status estatus = al_kx_shared(&network->local_kx, kx.ephemeral_pk,
                                     peer->shared_key);
    if (estatus != AL_OK) {
        peer_close(network, (al_size)(peer - network->peers));
        return;
    }
    peer->encryption_enabled = AL_TRUE;
    peer->tx_nonce_counter = 0u;
    peer->rx_nonce_counter = 0u;
}

void dispatch_frame(al_p2p *network, al_p2p_peer *peer,
                    al_wire_type type, al_bytes payload,
                    al_u64 now_ms) {
    peer->last_recv_ms = now_ms;

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
        break;
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
    case AL_WIRE_EVIDENCE:
        handle_consensus(network, peer, type, payload);
        break;
    case AL_WIRE_KEY_EXCHANGE:
        handle_key_exchange(network, peer, payload);
        break;
    case AL_WIRE_FINALITY:
        (void)handle_finalized_block(network, peer, payload, AL_TRUE);
        break;
    case AL_WIRE_TYPE_SENTINEL:
    default:
        peer_close(network, (al_size)(peer - network->peers));
        break;
    }
}
