/* P2P inbound message handling: transaction/block/consensus/handshake dispatch. */

/*
 * Copyright (c) 2026 Astrolune contributors
 * SPDX-License-Identifier: MIT
 */

#include "p2p_internal.h"

void handle_transaction(al_p2p *network, al_p2p_peer *origin,
                        al_bytes payload) {
    /* Rate limit: reject flood from this peer. */
    if (origin != NULL &&
        !rate_limit_check(&origin->rate_tx_tokens, origin->rate_tx_max,
                          &origin->rate_tx_refill_ms, al_net_now_ms())) {
        return;
    }
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
    /* Rate limit: reject flood from this peer. */
    if (origin != NULL &&
        !rate_limit_check(&origin->rate_block_tokens, origin->rate_block_max,
                          &origin->rate_block_refill_ms, al_net_now_ms())) {
        return;
    }
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
    /* Rate limit: reject flood from this peer. */
    if (origin != NULL &&
        !rate_limit_check(&origin->rate_consensus_tokens,
                          origin->rate_consensus_max,
                          &origin->rate_consensus_refill_ms, al_net_now_ms())) {
        return;
    }
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
    hello.identity = network->identity.pk;
    al_u8 payload[sizeof(hello.protocol_version) +
                  sizeof(hello.listen_port) + AL_HASH_SIZE + AL_HASH_SIZE +
                  sizeof(al_u64) + AL_PUBKEY_SIZE];
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

    /* Normalise the IP address through inet_pton/inet_ntop so that different
     * textual representations of the same address (e.g. "010.000.001.001"
     * vs "10.0.1.1") compare equal in peer_drop_duplicate. */
    char host_buf[64];
    if (host_length >= sizeof(host_buf)) return;
    memcpy(host_buf, peer->endpoint, host_length);
    host_buf[host_length] = '\0';

    struct in_addr addr;
    if (inet_pton(AF_INET, host_buf, &addr) == 1) {
        char normalised[INET_ADDRSTRLEN];
#if defined(AL_OS_WINDOWS)
        (void)InetNtopA(AF_INET, &addr, normalised, sizeof(normalised));
#else
        (void)inet_ntop(AF_INET, &addr, normalised, sizeof(normalised));
#endif
        char endpoint[AL_P2P_ENDPOINT_SIZE];
        (void)net_snprintf(endpoint, sizeof(endpoint), "%s:%u",
                           normalised, (unsigned)listen_port);
        memcpy(peer->endpoint, endpoint, sizeof(peer->endpoint));
    } else {
        /* Non-IP hostname — keep as-is but canonicalise the port. */
        char endpoint[AL_P2P_ENDPOINT_SIZE];
        (void)net_snprintf(endpoint, sizeof(endpoint), "%.*s:%u",
                           (int)host_length, peer->endpoint,
                           (unsigned)listen_port);
        memcpy(peer->endpoint, endpoint, sizeof(peer->endpoint));
    }
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
    peer->identity = hello.identity;

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
        
        /* Sign the ephemeral key with our Ed25519 identity key.
         * This binds the transport encryption key to our consensus identity. */
        al_status sign_status = al_sign(&network->identity.sk,
                                        al_bytes_make(kx.ephemeral_pk,
                                                      AL_KX_PUBLIC_KEY_SIZE),
                                        &kx.signature);
        if (sign_status != AL_OK) {
            peer_close(network, (al_size)(peer - network->peers));
            return;
        }
        
        al_u8 buf[sizeof(al_wire_header) + AL_KX_PUBLIC_KEY_SIZE + AL_SIGNATURE_SIZE];
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

    /* Verify the signature binding the ephemeral key to the peer's identity.
     * This prevents an attacker from intercepting the key exchange. */
    if (network->config.require_identity) {
        al_status verify_status = al_verify(
            &peer->identity,
            al_bytes_make(kx.ephemeral_pk, AL_KX_PUBLIC_KEY_SIZE),
            &kx.signature);
        if (verify_status != AL_OK) {
            peer_close(network, (al_size)(peer - network->peers));
            return;
        }
    }

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

/* PEX: Peer Exchange */

void pex_send_known_peers(al_p2p *network, al_p2p_peer *peer) {
    if (network->peer_count <= 1u) return;
    
    al_wire_addresses addrs;
    addrs.count = 0u;
    
    /* Collect known peer addresses, excluding the target peer and
     * only including peers in READY state. */
    for (al_size i = 0u; i < network->peer_count && addrs.count < AL_WIRE_MAX_PEX_ADDRS; ++i) {
        al_p2p_peer *p = &network->peers[i];
        if (p == peer || p->state != AL_P2P_READY) continue;
        if (p->listen_port == 0u) continue;
        
        /* Extract host from endpoint (before the colon). */
        const char *colon = strrchr(p->endpoint, ':');
        if (colon == NULL) continue;
        al_size host_len = (al_size)(colon - p->endpoint);
        if (host_len >= AL_WIRE_MAX_ENDPOINT_LEN) continue;
        
        memcpy(addrs.addrs[addrs.count].endpoint, p->endpoint, host_len);
        addrs.addrs[addrs.count].endpoint[host_len] = '\0';
        addrs.addrs[addrs.count].listen_port = p->listen_port;
        addrs.count++;
    }
    
    if (addrs.count == 0u) return;
    
    al_u8 buf[sizeof(al_wire_header) + 1u + AL_WIRE_MAX_PEX_ADDRS * (1u + AL_WIRE_MAX_ENDPOINT_LEN + 2u)];
    al_writer writer;
    al_writer_init(&writer, buf, sizeof(buf));
    al_wire_addresses_encode(&writer, &addrs);
    al_size len = al_writer_len(&writer);
    if (al_writer_finish(&writer) == AL_OK) {
        (void)peer_send_frame(peer, AL_WIRE_ADDRESSES, buf, len);
    }
}

void handle_addresses(al_p2p *network, al_p2p_peer *peer,
                      al_bytes payload) {
    AL_UNUSED(peer);
    al_wire_addresses addrs;
    if (al_wire_addresses_decode(payload, &addrs) != AL_OK) return;
    
    if (!network->config.require_identity) return;
    
    /* Attempt to connect to newly discovered peers. */
    for (al_u8 i = 0u; i < addrs.count; ++i) {
        if (network->peer_count >= network->config.max_peers) break;
        
        /* Skip if we're already connected to this endpoint. */
        al_bool known = AL_FALSE;
        for (al_size j = 0u; j < network->peer_count; ++j) {
            if (strncmp(network->peers[j].endpoint, addrs.addrs[i].endpoint,
                        AL_WIRE_MAX_ENDPOINT_LEN) == 0) {
                known = AL_TRUE;
                break;
            }
        }
        if (known) continue;
        
        /* Parse host:port and dial. */
        char host[64];
        const char *colon = strrchr(addrs.addrs[i].endpoint, ':');
        if (colon == NULL) continue;
        al_size host_len = (al_size)(colon - addrs.addrs[i].endpoint);
        if (host_len >= sizeof(host)) continue;
        memcpy(host, addrs.addrs[i].endpoint, host_len);
        host[host_len] = '\0';
        
        al_status dial_status = al_p2p_dial(network, host, addrs.addrs[i].listen_port);
        AL_UNUSED(dial_status);
    }
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
    case AL_WIRE_ADDRESSES:
        handle_addresses(network, peer, payload);
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
