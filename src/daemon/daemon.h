/*
 * The Astrolune node daemon.
 *
 * The daemon is the glue that turns the library stack into a running network
 * participant: it owns durable storage and the local node runtime, drives a
 * P2P transport and an RPC server through one single-threaded event loop, and
 * produces blocks on a fixed interval whenever its mempool is non-empty.
 *
 * Everything here is node policy, not consensus: validity comes from
 * Astrolune::node, and the daemon only decides what to do with valid data -
 * store it, relay it, answer range requests with it.
 */

#ifndef ASTROLUNE_DAEMON_DAEMON_H
#define ASTROLUNE_DAEMON_DAEMON_H

#include "astrolune/block.h"

AL_EXTERN_C_BEGIN

#define AL_DAEMON_MAX_BOOTSTRAP 16u
#define AL_DAEMON_MAX_VALIDATORS AL_POTB_MAX_COMMITTEE

/* Mempool backing store. The runtime requires caller-owned buffers; these
 * bounds hold roughly a full block of worst-case transactions. */
#define AL_DAEMON_MEMPOOL_ENTRIES 4096u
#define AL_DAEMON_MEMPOOL_BYTES   (16u * 1024u * 1024u)

typedef struct al_daemon_config {
    /* Required: directory holding (or receiving) the bound node store. */
    const char *data_dir;

    al_bool     enable_p2p;
    const char *p2p_host;      /* NULL listens on any interface */
    al_u16      p2p_port;

    al_bool     enable_rpc;
    const char *rpc_host;      /* NULL listens on any interface */
    al_u16      rpc_port;
    /* Privileged methods that use the proposer key or stop the node. */
    al_bool     enable_unsafe_rpc;

    /* Explicit override for a backend that fails the deployment gate. */
    al_bool     allow_insecure_crypto;

    /* Endpoints ("host:port") dialed at startup and re-dialed when idle. */
    const char *bootstrap[AL_DAEMON_MAX_BOOTSTRAP];
    al_size     bootstrap_count;

    /* Canonical validator public keys shared by every node on the network. */
    const char *validators[AL_DAEMON_MAX_VALIDATORS];
    al_size     validator_count;

    /* Optional 64-hex-char seed overriding the proposer key file. Intended
     * for reproducible devnets and tests; production operators should rely
     * on the generated key file instead. */
    const char *proposer_seed;

    al_u32 block_interval_ms;   /* 0 disables timed production entirely */
    al_u32 round_timeout_ms;    /* consensus leader/view timeout */
    al_bool produce_empty_blocks;

    /* Optional external stop switch checked every tick (e.g. SIGINT flag). */
    const volatile int *stop_flag;
} al_daemon_config;

typedef struct al_daemon al_daemon;

/*
 * Open (or create) the node directory, load genesis from `genesis_path`,
 * load or create the proposer key, and bring up the configured services.
 * On failure *out is untouched.
 */
AL_NODISCARD al_status al_daemon_open(const al_daemon_config *config,
                                      const char *genesis_path,
                                      al_daemon **out);

void al_daemon_close(al_daemon *daemon);

/* Event loop until stop_flag fires or RPC `stop` is called. AL_TRUE when the
 * loop ended cleanly. */
AL_NODISCARD al_bool al_daemon_run(al_daemon *daemon);

/* Request loop exit from another thread; safe because it only writes a flag. */
void al_daemon_request_stop(al_daemon *daemon);

/* Hex address of the proposer key this daemon signs blocks with. */
const char *al_daemon_proposer_address(const al_daemon *daemon);

AL_EXTERN_C_END

#endif /* ASTROLUNE_DAEMON_DAEMON_H */
