/*
 * alnode.h — shared types and declarations for the alnode CLI modules.
 */

#ifndef ALNODE_H
#define ALNODE_H

#include "astrolune/block.h"
#include "astrolune/bytes.h"
#include "astrolune/crypto.h"
#include "astrolune/hash.h"
#include "astrolune/log.h"
#include "astrolune/state.h"

#include "config.h"
#include "daemon.h"
#include "net.h"
#include "node.h"
#include "storage.h"

#include <stdio.h>

#define ALNODE_MAX_INPUT_SIZE       (64u * 1024u * 1024u)
#define ALNODE_STATE_NODE_CAPACITY  262144u
#define ALNODE_STATE_VALUE_CAPACITY 16384u

/* Shared runtime */

typedef struct alnode_runtime {
    al_genesis genesis;
    al_genesis_allocation allocations[AL_GENESIS_MAX_ALLOCATIONS];

    al_arena               arena;
    al_state_memory_node  *nodes;
    al_state_memory_value  *values;
    al_state_memory_store   memory;
    al_state_store          store;
    al_state                state;
    al_node_storage         storage;
    al_bool                 durable;

    al_arena        execution_arena;
    al_transaction *transactions;
    al_receipt     *receipts;
    al_node         node;
} alnode_runtime;

int  report_status(const char *operation, al_status status);
void warn_insecure_crypto(void);

al_status runtime_open(alnode_runtime *runtime, const char *genesis_path,
                       const char *data_directory);
void      runtime_destroy(alnode_runtime *runtime);

/* File I/O */

al_status write_file(const char *path, al_bytes bytes);
al_status read_file(const char *path, al_u8 **data_out, al_size *size_out);

/* Parsing helpers */

al_status parse_chain_id(const char *text, al_u32 *out);
al_status parse_u64_arg(const char *text, uint64_t *out);
al_status parse_address_text(const char *text, al_address *out);

void store_le64_local(al_u8 *p, uint64_t v);

/* Chain commands */

void print_head(const al_node *node);
al_status replay_blocks(alnode_runtime *runtime, int block_count,
                        char **block_paths, al_bool print_blocks);

int command_init_genesis(const char *path, const char *chain_id_text,
                         int allocation_count, char **allocations_raw);
int command_verify_chain(int file_count, char **files);
int command_produce_block(const char *genesis_path, const char *output_path,
                          int block_count, char **block_paths,
                          const char *data_directory);
int command_init_node(const char *genesis_path, const char *data_directory);
int command_import_blocks(const char *genesis_path, const char *data_directory,
                          int block_count, char **block_paths);
int command_node_head(const char *genesis_path, const char *data_directory);

/* Key management */

int command_keygen(const char *seed_text);

/* Transaction construction and simulation */

al_status resolve_signer(const char *seed_text, const al_genesis *genesis,
                         al_keypair *out);

typedef struct tx_options {
    const char *seed;
    const char *output;
    uint64_t    nonce;
    uint64_t    value;
    al_u32      chain_id;
    al_bool     chain_id_set;
    al_bool     entrypoint_set;
    uint64_t    args[64];
    al_size     arg_count;
    const char *target;
    uint64_t    entrypoint;
} tx_options;

void  tx_defaults(tx_options *options);
al_bool tx_parse(int argc, char **argv, int start, tx_options *options,
                 const char *positionals[], int positional_cap,
                 int *pos_count);
al_status sign_and_encode(al_transaction *tx, const al_keypair *kp,
                          const char *output_path);

int command_make_tx(int argc, char **argv);
int command_contract_address(int argc, char **argv);
int command_simulate(int argc, char **argv);

/* Daemon command */

typedef struct run_options {
    const char *genesis_path;
    const char *config_path;
    al_bool     no_config;
    const char *data_dir;
    char        p2p_host_storage[64];
    const char *p2p_host;
    al_u16      p2p_port;
    al_bool     enable_p2p;
    char        rpc_host_storage[64];
    const char *rpc_host;
    al_u16      rpc_port;
    al_bool     enable_rpc;
    al_bool     enable_unsafe_rpc;
    al_bool     allow_insecure_crypto;
    const char *rpc_token;
    const char *bootstrap[AL_DAEMON_MAX_BOOTSTRAP];
    al_size     bootstrap_count;
    const char *validators[AL_DAEMON_MAX_VALIDATORS];
    al_size     validator_count;
    const char *proposer_seed;
    const char *proposer_passphrase;
    al_u32      block_interval_ms;
    al_u32      round_timeout_ms;
    al_bool     produce_empty_blocks;
    const char *log_level;
} run_options;

al_bool parse_port(const char *text, al_u16 *out);
al_bool parse_endpoint_option(const char *text, char *host_storage,
                              al_size capacity, const char **host,
                              al_u16 *port);
int     command_run(const run_options *options);

#endif
