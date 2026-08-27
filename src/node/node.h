/*
 * Astrolune node runtime.
 *
 * This layer sits between transport/RPC and the consensus core. It owns local
 * policy such as mempool admission and chain-head tracking, while block
 * validity and execution remain delegated to astrolune/block.h.
 *
 * The API is intentionally outside include/astrolune/: node policy is not a
 * consensus ABI and may evolve before the first network protocol is frozen.
 */

#ifndef ASTROLUNE_NODE_NODE_H
#define ASTROLUNE_NODE_NODE_H

#include "astrolune/arena.h"
#include "astrolune/block.h"

AL_EXTERN_C_BEGIN

typedef struct al_node_mempool_entry {
    al_transaction transaction;
    al_hash256     hash;
    al_amount      maximum_debit;
    al_size        encoded_offset;
    al_size        encoded_size;
} al_node_mempool_entry;

typedef struct al_node_buffers {
    al_node_mempool_entry *mempool_entries;
    al_size                mempool_capacity;
    al_u8                 *mempool_bytes;
    al_size                mempool_bytes_capacity;

    /* Scratch decoded transactions are valid only during block acceptance. */
    al_transaction *block_transactions;
    al_size         block_transaction_capacity;
    al_receipt     *receipts;
    al_size         receipt_capacity;
} al_node_buffers;

typedef struct al_node_stats {
    al_u64 blocks_produced;
    al_u64 blocks_accepted;
    al_u64 blocks_rejected;
    al_u64 transactions_accepted;
    al_u64 transactions_rejected;
    al_u64 mempool_removed;
} al_node_stats;

typedef struct al_node_proposal {
    al_u32     protocol_day;
    al_pubkey  proposer;
    al_address tip_flat;
    al_address tip_weighted;
    al_address tip_bonded;
    al_size    transaction_limit;
} al_node_proposal;

typedef struct al_node {
    al_genesis        genesis;
    al_state         *state;
    al_arena         *execution_arena;
    al_node_buffers   buffers;
    al_block_header   head;
    al_node_stats     stats;
    al_size           mempool_count;
    al_size           mempool_bytes_used;
    al_size           receipt_count;
    al_bool           has_head;
} al_node;

/* Initialize around an already-open state. The state's root must match
 * genesis.initial_state_root; state storage and execution_arena must have
 * independent lifetimes. */
AL_NODISCARD al_status al_node_init(
    al_node *node, const al_genesis *genesis, al_state *state,
    al_arena *execution_arena, al_node_buffers buffers);

/* Resume around a state opened at a durable chain head. Passing NULL is
 * equivalent to al_node_init; otherwise height and state root must match the
 * supplied header exactly. The mempool intentionally starts empty. */
AL_NODISCARD al_status al_node_open(
    al_node *node, const al_genesis *genesis, al_state *state,
    al_arena *execution_arena, al_node_buffers buffers,
    const al_block_header *head);

/* Admit one canonical transaction. Per sender, pending nonces must be contiguous
 * from the committed account nonce. Replacement is deliberately not supported
 * yet: a duplicate hash or sender/nonce pair returns AL_ERR_ALREADY_EXISTS. */
AL_NODISCARD al_status al_node_submit_transaction(
    al_node *node, al_bytes encoded, al_hash256 *hash_out);

/* Decode, verify and atomically execute a canonical block. Receipt data remains
 * valid until the next block attempt resets execution_arena. */
AL_NODISCARD al_status al_node_accept_block(al_node *node,
                                             const al_block *block);
AL_NODISCARD al_status al_node_accept_encoded_block(al_node *node,
                                                     al_bytes encoded);

/* Produce, encode and publish the next local block. Transactions are selected
 * in mempool order and conservatively bounded by their declared resources.
 * A zero transaction_limit intentionally creates an empty block. */
AL_NODISCARD al_status al_node_produce_block(
    al_node *node, const al_node_proposal *proposal, al_bytes_mut encoded_out,
    al_size *written);

AL_NODISCARD al_height al_node_next_height(const al_node *node);
AL_NODISCARD const al_block_header *al_node_head(const al_node *node);
AL_NODISCARD const al_node_mempool_entry *al_node_mempool_at(
    const al_node *node, al_size index);
AL_NODISCARD const al_receipt *al_node_receipts(const al_node *node,
                                                al_size *count_out);

AL_EXTERN_C_END

#endif /* ASTROLUNE_NODE_NODE_H */
