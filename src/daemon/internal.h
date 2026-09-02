/*
 * Internal daemon declarations shared across *.c translation units.
 *
 * This header is NOT part of the public API. It exists solely so the daemon
 * can be split into multiple .c files while keeping the struct definition and
 * cross-file function calls in one place.
 */

#ifndef ASTROLUNE_INTERNAL_H
#define ASTROLUNE_INTERNAL_H

#include "daemon.h"

#include "internal/common.h"
#include "json.h"
#include "node.h"
#include "p2p.h"
#include "random.h"
#include "server.h"
#include "signing_journal.h"
#include "storage.h"
#include "finality.h"

#include "astrolune/log.h"
#include "astrolune/signer.h"
#include "astrolune/validator_set.h"
#include "astrolune/evidence.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DAEMON_LOG(daemon, text) daemon_log((daemon), (text))

#define PROPOSER_KEY_FILE  "proposer.key"
#define PROPOSER_SEED_SIZE 32u

struct al_daemon {
    al_daemon_config config;

    al_genesis            genesis;
    al_genesis_allocation allocations[AL_GENESIS_MAX_ALLOCATIONS];

    al_arena        state_arena;
    al_node_storage storage;
    al_state        state;

    al_arena               execution_arena;
    al_node_mempool_entry *mempool_entries;
    al_u8                 *mempool_bytes;
    al_transaction        *block_transactions;
    al_receipt            *receipts;

    al_node node;

    al_potb_record        validator_records[AL_DAEMON_MAX_VALIDATORS];
    const al_potb_record *validator_index[AL_DAEMON_MAX_VALIDATORS];
    al_potb_network_stats validator_stats;
    al_potb_committee     committee;
    al_hash256            committee_hash;
    al_vote_set           prevotes;
    al_vote_set           precommits;
    al_u8                *pending_block;
    al_size               pending_block_size;
    al_hash256            pending_block_hash;
    al_height             pending_height;
    al_u32                consensus_round;
    al_bool               consensus_ready;
    al_bool               local_validator;
    al_bool               pending_proposal;
    al_bool               local_prevote_sent;
    al_bool               local_precommit_sent;
    al_signing_journal    signing_journal;
    al_bool               signing_journal_ready;
    al_state_snapshot     round_state;
    al_block_header       round_head;
    al_node_stats         round_stats;
    al_node_mempool_entry *round_mempool_entries;
    al_u8                 *round_mempool_bytes;
    al_size               round_mempool_count;
    al_size               round_mempool_bytes_used;
    al_size               round_receipt_count;
    al_bool               round_had_head;
    al_bool               round_checkpoint_valid;
    al_u64                round_deadline_ms;

    al_signer *signer;
    al_keypair proposer;
    al_address proposer_address;
    char       proposer_hex[AL_ADDRESS_HEX_SIZE];
    char       genesis_hex[AL_HASH_HEX_SIZE];

    al_p2p        p2p;
    al_bool       p2p_ready;
    al_rpc_server rpc;
    al_bool       rpc_ready;

    al_u8  *block_scratch;
    al_size block_scratch_capacity;

    al_u64  next_block_ms;
    al_u64  next_bootstrap_ms;
    al_bool stop_requested;
};

/* daemon.c — small helpers */
void daemon_log(const al_daemon *daemon, const char *message);
int  daemon_pubkey_cmp(const al_pubkey *a, const al_pubkey *b);
al_status daemon_parse_validator_key(const char *text, al_pubkey *out);
al_status daemon_consensus_init(al_daemon *daemon);
al_status read_whole_file(const char *path, al_u8 **data_out,
                          al_size *size_out, al_size max_size);
al_status path_join(const char *directory, const char *name,
                    char *out, al_size cap);
al_bool   parse_endpoint(const char *endpoint, char *host,
                         al_size cap, al_u16 *port);
al_status load_or_create_proposer(al_daemon *daemon);

/* consensus.c — consensus state machine */
al_status daemon_round_checkpoint_take(al_daemon *daemon);
al_status daemon_round_checkpoint_restore(al_daemon *daemon);
al_status daemon_pending_clear(al_daemon *daemon);
al_status daemon_pending_begin(al_daemon *daemon, al_bytes block,
                               const al_hash256 *block_hash,
                               al_height height, al_u32 round);
al_status daemon_emit_vote(al_daemon *daemon, al_consensus_phase phase);
al_status daemon_finalize_pending(al_daemon *daemon,
                                  const al_finality_certificate *received);
al_status daemon_consensus_advance(al_daemon *daemon);
al_status daemon_consensus_prevote(al_daemon *daemon);

/* p2p_handlers.c — P2P callbacks */
al_bool   daemon_on_transaction(void *userdata, al_bytes encoded);
al_bool   daemon_on_block(void *userdata, al_bytes encoded);
al_status daemon_read_block(void *userdata, al_height height,
                            al_bytes_mut buffer, al_size *written);
al_status daemon_read_finalized_block(void *userdata, al_height height,
                                      al_bytes_mut buffer, al_size *written);
al_height daemon_known_blocks(void *userdata);
void      daemon_peer_up(void *userdata, const al_p2p_peer *peer);
void      daemon_peer_down(void *userdata, const char *endpoint);

/* block_producer.c */
al_status daemon_produce_block(al_daemon *daemon);

/* rpc.c — JSON-RPC surface */
al_status daemon_rpc_handler(void *userdata, const al_json_value *request,
                             al_json_writer *body);

/* event_loop.c — event loop and consensus wire handlers */
void      daemon_dial_bootstraps(al_daemon *daemon);
al_status daemon_consensus_timeout(al_daemon *daemon, al_u64 now_ms);
al_bool   daemon_on_proposal(al_daemon *daemon, al_bytes encoded);
al_bool   daemon_on_vote(al_daemon *daemon, al_bytes encoded);
al_bool   daemon_on_finality(void *userdata, al_bytes encoded);
al_bool   daemon_on_evidence(al_daemon *daemon, al_bytes encoded);
al_bool   daemon_on_consensus(void *userdata, al_wire_type type,
                              al_bytes encoded);

/* lifecycle.c — open/close */
void daemon_free_scratch(al_daemon *daemon);

#endif /* ASTROLUNE_INTERNAL_H */
