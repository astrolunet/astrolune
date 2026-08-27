/*
 * astrolune/state.h - committed account state and sparse Merkle proofs.
 *
 * The core owns no persistent memory. A node supplies a content-addressed
 * store and an arena; the state handle contains only the current commitment.
 * This keeps the consensus algorithm independent from the eventual disk
 * engine while preserving atomic rollback through immutable roots.
 */

#ifndef ASTROLUNE_STATE_H
#define ASTROLUNE_STATE_H

#include "astrolune/arena.h"
#include "astrolune/base.h"
#include "astrolune/bytes.h"
#include "astrolune/crypto.h"
#include "astrolune/hash.h"

AL_EXTERN_C_BEGIN

#define AL_STATE_TREE_DEPTH 256u
#define AL_STATE_MAX_KEY_SIZE 256u
#define AL_STATE_MAX_VALUE_SIZE (64u * 1024u)
#define AL_STATE_MAX_CODE_SIZE (1024u * 1024u)

typedef struct al_account {
    al_address address;
    al_amount  balance;
    al_nonce   nonce;
    al_hash256 code_hash;
    al_hash256 storage_root;
    al_u64     storage_bytes;
    al_amount  storage_deposit;
} al_account;

typedef enum al_state_node_kind {
    AL_STATE_NODE_BRANCH = 1,
    AL_STATE_NODE_LEAF = 2,
    AL_STATE_NODE_KIND_SENTINEL = 0x7fffffff
} al_state_node_kind;

/* Branches use `first`/`second` as left/right hashes. Leaves use them as the
 * complete 256-bit key and the tagged value hash. */
typedef struct al_state_node {
    al_state_node_kind kind;
    al_hash256         first;
    al_hash256         second;
} al_state_node;

typedef al_status (*al_state_node_get_fn)(
    void *context, const al_hash256 *hash, al_state_node *out);
typedef al_status (*al_state_node_put_fn)(
    void *context, const al_hash256 *hash, const al_state_node *node);
typedef al_status (*al_state_value_get_fn)(
    void *context, const al_hash256 *hash, al_bytes *out);
typedef al_status (*al_state_value_put_fn)(
    void *context, const al_hash256 *hash, al_bytes value);

typedef struct al_state_store {
    void                  *context;
    al_state_node_get_fn   node_get;
    al_state_node_put_fn   node_put;
    al_state_value_get_fn  value_get;
    al_state_value_put_fn  value_put;
} al_state_store;

typedef struct al_state {
    void       *impl;
    al_height  height;
    al_hash256 root;
} al_state;

typedef struct al_state_txn {
    al_state     *state;
    al_hash256    root;
    al_resources resources;
    al_bool       active;
} al_state_txn;

typedef struct al_state_snapshot {
    al_height  height;
    al_hash256 root;
} al_state_snapshot;

/* Siblings are stored root-to-leaf. A set bitmap bit means the corresponding
 * sibling differs from that depth's deterministic empty hash. */
typedef struct al_smt_proof {
    al_hash256  key;
    al_hash256  value_hash;
    al_u8       sibling_bitmap[AL_STATE_TREE_DEPTH / 8u];
    al_hash256 *siblings;
    al_size     sibling_count;
    al_size     sibling_capacity;
    al_bool     exists;
} al_smt_proof;

typedef struct al_state_memory_node {
    al_hash256    hash;
    al_state_node node;
} al_state_memory_node;

typedef struct al_state_memory_value {
    al_hash256 hash;
    al_bytes   value;
} al_state_memory_value;

/* A deterministic linear backend intended for tests, fixtures and small
 * simulations. Production nodes provide the same interface over a disk store. */
typedef struct al_state_memory_store {
    al_state_memory_node  *nodes;
    al_size                node_count;
    al_size                node_capacity;
    al_state_memory_value *values;
    al_size                value_count;
    al_size                value_capacity;
    al_arena              *arena;
} al_state_memory_store;

AL_PUBLIC AL_NODISCARD al_status al_state_memory_store_init(
    al_state_memory_store *memory, al_state_memory_node *nodes,
    al_size node_capacity, al_state_memory_value *values,
    al_size value_capacity, al_arena *arena);
AL_PUBLIC al_state_store al_state_memory_store_interface(
    al_state_memory_store *memory);

AL_PUBLIC AL_NODISCARD al_status al_state_init(
    al_state *state, const al_state_store *store, al_arena *arena,
    al_amount storage_deposit_per_byte);
AL_PUBLIC AL_NODISCARD al_status al_state_open(
    al_state *state, const al_state_store *store, al_arena *arena,
    al_amount storage_deposit_per_byte, al_height height,
    const al_hash256 *root);
AL_PUBLIC void al_state_clear(al_state *state);
AL_PUBLIC AL_NODISCARD al_status al_state_get(const al_state *state,
                                              const al_address *address,
                                              al_account *out);
AL_PUBLIC AL_NODISCARD al_status al_state_upsert(al_state *state,
                                                 const al_account *account);
AL_PUBLIC AL_NODISCARD al_status al_state_remove(al_state *state,
                                                 const al_address *address);
AL_PUBLIC AL_NODISCARD al_status al_state_transfer(
    al_state *state, const al_address *from, const al_address *to,
    al_amount amount);
AL_PUBLIC al_hash256 al_state_root(const al_state *state);
AL_PUBLIC al_state_snapshot al_state_snapshot_take(const al_state *state);
AL_PUBLIC AL_NODISCARD al_status al_state_snapshot_restore(
    al_state *state, al_state_snapshot snapshot);

AL_PUBLIC AL_NODISCARD al_status al_state_txn_begin(al_state *state,
                                                    al_state_txn *txn);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_get(const al_state_txn *txn,
                                                  const al_address *address,
                                                  al_account *out);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_upsert(
    al_state_txn *txn, const al_account *account);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_remove(
    al_state_txn *txn, const al_address *address);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_transfer(
    al_state_txn *txn, const al_address *from, const al_address *to,
    al_amount amount);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_deploy(
    al_state_txn *txn, const al_address *address, al_amount balance,
    al_bytes code);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_code_get(
    const al_state_txn *txn, const al_address *contract, al_bytes *out);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_storage_get(
    const al_state_txn *txn, const al_address *contract, al_bytes key,
    al_arena *arena, al_bytes *out);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_storage_set(
    al_state_txn *txn, const al_address *contract, al_bytes key,
    al_bytes value);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_storage_delete(
    al_state_txn *txn, const al_address *contract, al_bytes key);
/* Native consensus transitions use this bridge for the reserved PoTB account.
 * Bytecode cannot reach these functions through the VM host interface. */
AL_PUBLIC AL_NODISCARD al_status al_state_txn_system_storage_get(
    const al_state_txn *txn, al_bytes key, al_arena *arena, al_bytes *out);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_system_storage_set(
    al_state_txn *txn, al_bytes key, al_bytes value);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_system_storage_delete(
    al_state_txn *txn, al_bytes key);
AL_PUBLIC AL_NODISCARD al_status al_state_txn_commit(al_state_txn *txn);
AL_PUBLIC void al_state_txn_rollback(al_state_txn *txn);

AL_PUBLIC AL_NODISCARD al_status al_state_prove_account(
    const al_state *state, const al_address *address, al_smt_proof *proof);
AL_PUBLIC AL_NODISCARD al_bool al_smt_proof_verify(
    const al_hash256 *root, const al_smt_proof *proof);
AL_PUBLIC AL_NODISCARD al_status al_smt_proof_encode(
    const al_smt_proof *proof, al_bytes_mut out, al_size *written);
AL_PUBLIC AL_NODISCARD al_status al_smt_proof_decode(
    al_bytes encoded, al_hash256 *sibling_storage, al_size sibling_capacity,
    al_smt_proof *out);

/* Reserved account used by native PoTB transitions. Contract bytecode cannot
 * address this namespace through the ordinary storage host calls. */
AL_PUBLIC al_address al_state_potb_system_address(void);

AL_EXTERN_C_END

#endif /* ASTROLUNE_STATE_H */
