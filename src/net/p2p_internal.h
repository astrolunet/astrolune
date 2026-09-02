/*
 * Internal P2P declarations shared across p2p*.c translation units.
 * NOT part of the public API.
 */

#ifndef ASTROLUNE_P2P_INTERNAL_H
#define ASTROLUNE_P2P_INTERNAL_H

#include "p2p.h"
#include "internal/common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(AL_OS_WINDOWS)
#  define net_snprintf sprintf_s
#else
#  define net_snprintf snprintf
#endif

#define P2P_HANDSHAKE_TIMEOUT_MS 10000u
#define P2P_PING_INTERVAL_MS     25000u
#define P2P_IDLE_TIMEOUT_MS      90000u
#define P2P_MAX_SERVED_BLOCKS    128u
#define P2P_VARINT_MAX           10u
#define AL_VARINT_MAX            10

/* p2p.c — peer management and send primitives */
al_socket invalid_socket(void);
al_bool    same_socket(al_socket a, al_socket b);
void       peer_release_buffers(al_p2p_peer *peer);
void       peer_init(al_p2p_peer *peer);
void       peer_close(al_p2p *network, al_size index);
al_bool    seen_contains(const al_hash256 *ring, const al_hash256 *hash);
void       seen_insert(al_hash256 *ring, al_size *next,
                       const al_hash256 *hash);
al_status  peer_queue(al_p2p_peer *peer, const void *data, al_size len);
al_status  peer_send_frame(al_p2p_peer *peer, al_wire_type type,
                           const void *payload, al_size payload_len);
al_status  peer_send_get_blocks(al_p2p_peer *peer, al_height start,
                                al_u32 max_count);

/* p2p_handlers.c — inbound message handling */
void handle_transaction(al_p2p *network, al_p2p_peer *origin,
                        al_bytes payload);
void handle_block(al_p2p *network, al_p2p_peer *origin,
                  al_bytes payload);
void handle_consensus(al_p2p *network, al_p2p_peer *origin,
                      al_wire_type type, al_bytes payload);
al_bool handle_finalized_block(al_p2p *network, al_p2p_peer *origin,
                               al_bytes payload, al_bool relay);
void handle_get_blocks(al_p2p *network, al_p2p_peer *peer,
                       al_bytes payload);
void handle_blocks(al_p2p *network, al_p2p_peer *origin,
                   al_bytes payload);
void send_hello(al_p2p *network, al_p2p_peer *peer);
void handle_hello(al_p2p *network, al_p2p_peer *peer,
                  al_bytes payload, al_u64 now_ms);
void handle_key_exchange(al_p2p *network, al_p2p_peer *peer,
                         al_bytes payload);
void dispatch_frame(al_p2p *network, al_p2p_peer *peer,
                    al_wire_type type, al_bytes payload, al_u64 now_ms);

/* p2p_io.c — socket I/O and frame assembly */
void feed_bytes(al_p2p *network, al_size index, al_bytes chunk,
                al_u64 now_ms);
void peer_readable(al_p2p *network, al_size index, al_u64 now_ms);
void peer_writable(al_p2p *network, al_size index);
void enforce_timeouts(al_p2p *network, al_u64 now_ms);

#endif /* ASTROLUNE_P2P_INTERNAL_H */
