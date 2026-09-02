/* P2P socket I/O: frame assembly, read/write, timeout enforcement. */

#include "p2p_internal.h"

void feed_bytes(al_p2p *network, al_size index, al_bytes chunk,
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

        if (peer->encryption_enabled && peer->rx_buffer_cap > 0u &&
            (al_wire_type)peer->rx_type != AL_WIRE_KEY_EXCHANGE) {
            al_u8 nonce_bytes[AL_AEAD_NONCE_SIZE];
            al_memzero(nonce_bytes, sizeof(nonce_bytes));
            al_store_le64(nonce_bytes, peer->rx_nonce_counter);
            peer->rx_nonce_counter++;

            al_u8 hdr[AL_WIRE_HEADER_SIZE];
            al_writer hw;
            al_writer_init(&hw, hdr, sizeof(hdr));
            al_wire_header_encode(&hw, (al_wire_type)peer->rx_type,
                                  (al_u32)peer->rx_buffer_cap);
            (void)al_writer_finish(&hw);

            al_u8 *pt = (al_u8 *)malloc(peer->rx_buffer_cap);
            if (pt == NULL) {
                peer_close(network, index);
                return;
            }
            al_size pt_len = 0u;
            al_status dstatus = al_aead_decrypt(
                peer->shared_key, nonce_bytes,
                hdr, AL_WIRE_HEADER_SIZE,
                peer->rx_buffer, peer->rx_buffer_cap,
                pt, &pt_len);
            if (dstatus != AL_OK) {
                free(pt);
                peer_close(network, index);
                return;
            }
            free(peer->rx_buffer);
            peer->rx_buffer = pt;
            peer->rx_buffer_cap = pt_len;
            peer->rx_have = pt_len;
            payload = al_bytes_make(pt, pt_len);
        }

        al_socket identity = peer->socket;
        dispatch_frame(network, peer, (al_wire_type)peer->rx_type, payload,
                       now_ms);
        if (index >= network->peer_count ||
            !same_socket(network->peers[index].socket, identity)) {
            return;
        }
        free(peer->rx_buffer);
        peer->rx_buffer = NULL;
        peer->rx_buffer_cap = 0u;
        peer->rx_have = 0u;
        peer->rx_header_have = 0u;
    }
}

void peer_readable(al_p2p *network, al_size index, al_u64 now_ms) {
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
        if (index >= network->peer_count) return;
    }
}

void peer_writable(al_p2p *network, al_size index) {
    al_p2p_peer *peer = &network->peers[index];

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

void enforce_timeouts(al_p2p *network, al_u64 now_ms) {
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
