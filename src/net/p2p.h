/*
 * Peer manager for the P2P transport.
 *
 * One instance owns the listener, every connection, and the gossip policy:
 *
 *   - peers must introduce themselves with a HELLO bound to our genesis,
 *     otherwise they are dropped without ever reaching the dispatcher;
 *   - transactions and blocks are relayed only when the node accepts them,
 *     so invalid data dies at the first honest hop;
 *   - recently seen objects are remembered in a small ring, which bounds the
 *     cost of duplicate gossip without keeping a full index;
 *   - lagging peers are offered block ranges and can pull from ours, and we
 *     pull from taller peers after the handshake.
 *
 * The whole service is single-threaded and driven by al_p2p_poll(). There is
 * no internal thread, lock or hidden allocation beyond each peer's frame
 * buffers; embedding is by value so a host process controls placement.
 */

#ifndef ASTROLUNE_NET_P2P_H
#define ASTROLUNE_NET_P2P_H

#include "net.h"
#include "wire.h"

AL_EXTERN_C_BEGIN

/* Fixed capacity. A devnet committee is ~100 nodes; 64 connections plus the
 * listener covers that topology with headroom for stragglers. */
#define AL_P2P_MAX_PEERS   64u
/* Recent-object rings. 1024 entries comfortably covers one block interval of
 * gossip at the target block rate while costing only 64 KiB. */
#define AL_P2P_DEDUP_RING  1024u
/* Per-peer outbound bound. A peer whose link cannot drain this much queued
 * canonical data is dropped rather than allowed to grow memory unboundedly. */
#define AL_P2P_MAX_OUTBOX  (4u * 1024u * 1024u)

#define AL_P2P_ENDPOINT_SIZE 64u

typedef enum al_p2p_state {
    /* Outbound TCP attempt still completing. */
    AL_P2P_CONNECTING = 1,
    /* Connected; waiting for a valid HELLO. */
    AL_P2P_HANDSHAKING = 2,
    /* Handshake complete; carries traffic. */
    AL_P2P_READY = 3,
    AL_P2P_STATE_SENTINEL = 0x7fffffff
} al_p2p_state;

typedef struct al_p2p_peer {
    al_socket socket;
    al_bool   inbound;
    char      endpoint[AL_P2P_ENDPOINT_SIZE];

    al_p2p_state state;

    /* Remote claims from HELLO. */
    al_hash256 genesis;
    al_hash256 head;
    al_height  height;
    al_u16     listen_port;

    /* Inbound frame assembly: fixed header staging, then a buffer sized to
     * the announced payload length and freed when the frame dispatches.
     * Frames routinely span several receive chunks, so the decoded type is
     * kept alongside the staging area. */
    al_size rx_header_have;
    al_u8   rx_header[AL_WIRE_HEADER_SIZE];
    al_u8   rx_type;
    al_u8  *rx_buffer;
    al_size rx_buffer_cap;
    al_size rx_have;

    /* Outbound queue. [tx_sent, tx_len) is pending in tx_queue. */
    al_u8  *tx_queue;
    al_size tx_cap;
    al_size tx_len;
    al_size tx_sent;

    al_u64 connected_ms;
    al_u64 last_recv_ms;
    al_u64 last_ping_ms;
} al_p2p_peer;

typedef struct al_p2p_handlers {
    void *userdata;
    /* Return AL_TRUE to accept an object; only accepted objects are relayed.
     * Both receive canonical bytes owned by the transport for the call. */
    al_bool (*on_transaction)(void *userdata, al_bytes encoded);
    al_bool (*on_block)(void *userdata, al_bytes encoded);
    al_bool (*on_consensus)(void *userdata, al_wire_type type,
                            al_bytes encoded);
    al_bool (*on_finalized_block)(void *userdata, al_bytes encoded);
    /* Serve durable blocks for GET_BLOCKS. Write into buffer, set written;
     * return AL_ERR_NOT_FOUND when the height is unavailable. */
    al_status (*read_block)(void *userdata, al_height height,
                            al_bytes_mut buffer, al_size *written);
    al_status (*read_finalized_block)(void *userdata, al_height height,
                                      al_bytes_mut buffer, al_size *written);
    /* Current local head height, used for sync decisions. */
    al_height (*head_height)(void *userdata);
    void (*on_peer_up)(void *userdata, const al_p2p_peer *peer);
    void (*on_peer_down)(void *userdata, const char *endpoint);
} al_p2p_handlers;

typedef struct al_p2p_config {
    al_u16     listen_port;       /* advertised to peers                  */
    al_u32     protocol_version;  /* must equal AL_WIRE_PROTOCOL_VERSION  */
    al_hash256 genesis;           /* chain binding for handshakes         */
    al_size    max_peers;         /* clamped to AL_P2P_MAX_PEERS          */
    al_u32     handshake_timeout_ms;
    al_u32     ping_interval_ms;
    al_u32     idle_timeout_ms;
} al_p2p_config;

typedef struct al_p2p {
    al_p2p_config   config;
    al_p2p_handlers handlers;
    al_socket       listener;
    al_bool         has_listener;
    al_size         peer_count;
    al_p2p_peer     peers[AL_P2P_MAX_PEERS];

    al_hash256 seen_transactions[AL_P2P_DEDUP_RING];
    al_size    seen_transaction_next;
    al_hash256 seen_blocks[AL_P2P_DEDUP_RING];
    al_size    seen_block_next;
    al_hash256 seen_consensus[AL_P2P_DEDUP_RING];
    al_size    seen_consensus_next;

    /* Scratch used to assemble BLOCKS replies; allocated on first use. */
    al_u8  *reply_buffer;
    al_size reply_capacity;
} al_p2p;

/*
 * Bind the listener and prepare the service. `listen_host` may be NULL for
 * any-interface. Filling config with zeros yields sane defaults except for
 * `genesis`, which the caller must always supply.
 */
AL_NODISCARD al_status al_p2p_init(al_p2p *network, const al_p2p_config *config,
                                   const al_p2p_handlers *handlers,
                                   const char *listen_host, al_u16 listen_port);
void al_p2p_close(al_p2p *network);

/* Begin an outbound connection. Completion happens inside poll(). */
AL_NODISCARD al_status al_p2p_dial(al_p2p *network, const char *host,
                                   al_u16 port);

/* Run one service tick: accept, read, write, enforce timeouts, serve ranges. */
void al_p2p_poll(al_p2p *network, al_u32 timeout_ms);

/* Queue an object to every ready peer. Returns the number queued. */
AL_NODISCARD al_size al_p2p_relay_transaction(al_p2p *network,
                                              al_bytes encoded,
                                              const al_p2p_peer *origin);
AL_NODISCARD al_size al_p2p_relay_block(al_p2p *network, al_bytes encoded,
                                        const al_p2p_peer *origin);
AL_NODISCARD al_size al_p2p_relay_consensus(
    al_p2p *network, al_wire_type type, al_bytes encoded,
    const al_p2p_peer *origin);

AL_NODISCARD al_size al_p2p_ready_peers(const al_p2p *network);

AL_EXTERN_C_END

#endif /* ASTROLUNE_NET_P2P_H */
