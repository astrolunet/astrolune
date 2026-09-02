/* Peer manager: core helpers, peer lifecycle, send primitives, public API. */

#include "p2p_internal.h"

al_socket invalid_socket(void) {
#if defined(AL_OS_WINDOWS)
    al_socket s = { INVALID_SOCKET };
#else
    al_socket s = { -1 };
#endif
    return s;
}

al_bool same_socket(al_socket a, al_socket b) {
    return a.handle == b.handle ? AL_TRUE : AL_FALSE;
}

void peer_release_buffers(al_p2p_peer *peer) {
    free(peer->rx_buffer);
    free(peer->tx_queue);
}

void peer_init(al_p2p_peer *peer) {
    al_memzero(peer, sizeof(*peer));
    peer->socket = invalid_socket();
}

void peer_close(al_p2p *network, al_size index) {
    al_p2p_peer *peer = &network->peers[index];
    char endpoint[AL_P2P_ENDPOINT_SIZE];
    al_bool notify = peer->state != AL_P2P_CONNECTING &&
                     network->handlers.on_peer_down != NULL;
    if (notify) {
        memcpy(endpoint, peer->endpoint, sizeof(endpoint));
    }

    al_net_close(peer->socket);
    peer_release_buffers(peer);

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

al_bool seen_contains(const al_hash256 *ring, const al_hash256 *hash) {
    for (al_size i = 0u; i < AL_P2P_DEDUP_RING; ++i) {
        if (al_hash_eq(&ring[i], hash)) return AL_TRUE;
    }
    return AL_FALSE;
}

void seen_insert(al_hash256 *ring, al_size *next,
                 const al_hash256 *hash) {
    ring[*next] = *hash;
    *next = (*next + 1u) % AL_P2P_DEDUP_RING;
}

/* --- Outbound queueing ------------------------------------------------------ */

al_status peer_queue(al_p2p_peer *peer, const void *data, al_size len) {
    if (len == 0u) return AL_OK;
    if (peer->tx_len + len > AL_P2P_MAX_OUTBOX ||
        peer->tx_len + len < peer->tx_len) {
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

al_status peer_send_frame(al_p2p_peer *peer, al_wire_type type,
                          const void *payload, al_size payload_len) {
    al_u8 header[AL_WIRE_HEADER_SIZE];
    al_writer writer;
    al_writer_init(&writer, header, sizeof(header));
    al_wire_header_encode(&writer, type, (al_u32)payload_len);
    if (al_writer_finish(&writer) != AL_OK) return AL_ERR_INVALID_ARG;

    if (peer->encryption_enabled && payload_len > 0u) {
        al_u8 nonce_bytes[AL_AEAD_NONCE_SIZE];
        al_memzero(nonce_bytes, sizeof(nonce_bytes));
        al_store_le64(nonce_bytes, peer->tx_nonce_counter);
        peer->tx_nonce_counter++;

        al_size ct_len = payload_len + AL_AEAD_TAG_SIZE;
        al_u8 *ct = (al_u8 *)malloc(ct_len);
        if (ct == NULL) return AL_ERR_OUT_OF_MEMORY;

        al_size written = 0u;
        al_status estatus = al_aead_encrypt(
            peer->shared_key, nonce_bytes,
            header, AL_WIRE_HEADER_SIZE,
            (const al_u8 *)payload, payload_len,
            ct, &written);
        if (estatus != AL_OK) {
            free(ct);
            return estatus;
        }
        al_writer_init(&writer, header, sizeof(header));
        al_wire_header_encode(&writer, type, (al_u32)written);
        if (al_writer_finish(&writer) != AL_OK) {
            free(ct);
            return AL_ERR_INVALID_ARG;
        }
        al_status qstatus = peer_queue(peer, header, sizeof(header));
        if (qstatus != AL_OK) {
            free(ct);
            return qstatus;
        }
        qstatus = peer_queue(peer, ct, written);
        free(ct);
        return qstatus;
    }

    AL_TRY(peer_queue(peer, header, sizeof(header)));
    return peer_queue(peer, payload, payload_len);
}

al_status peer_send_get_blocks(al_p2p_peer *peer, al_height start,
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

    al_status kx_status = al_kx_keygen(&network->local_kx);
    if (kx_status != AL_OK) return kx_status;

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

    if (al_net_select(&readable, &writable, timeout_ms) < 0) return;

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
         type != AL_WIRE_FINALITY && type != AL_WIRE_EVIDENCE)) {
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
