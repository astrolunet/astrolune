/* astrolune/block.h - canonical genesis, blocks and deterministic execution. */

#ifndef ASTROLUNE_BLOCK_H
#define ASTROLUNE_BLOCK_H

#include "astrolune/arena.h"
#include "astrolune/base.h"
#include "astrolune/bytes.h"
#include "astrolune/crypto.h"
#include "astrolune/hash.h"
#include "astrolune/potb.h"
#include "astrolune/state.h"
#include "astrolune/tx.h"
#include "astrolune/vm.h"

AL_EXTERN_C_BEGIN

#define AL_GENESIS_VERSION 2u
#define AL_BLOCK_VERSION 1u
#define AL_BLOCK_HEADER_ENCODED_SIZE 338u
#define AL_BLOCK_MAX_TRANSACTIONS 65536u

/* Genesis allocations pre-fund accounts at height zero, before any block.
 * Every validator replays the same table onto an empty tree and must arrive at
 * genesis.initial_state_root, so the table is part of the consensus input. */
typedef struct al_genesis_allocation {
    al_address address;
    al_amount  balance;
} al_genesis_allocation;

#define AL_GENESIS_MAX_ALLOCATIONS 1024u

typedef struct al_genesis {
    al_u16                  version;
    al_u32                  chain_id;
    al_hash256              initial_state_root;
    al_fee_params           fees;
    al_vm_resource_schedule schedule;
    al_size                 vm_stack_limit;
    al_size                 vm_memory_limit;
    al_size                 vm_call_depth_limit;
    al_potb_params          potb;
    /* Borrowed view over the caller's allocation table. May be NULL when the
     * chain starts empty. Kept outside the encoded parameter block above so
     * that simulation code can attach tables without copying them. */
    const al_genesis_allocation *allocations;
    al_size                 allocation_count;
} al_genesis;

typedef struct al_block_header {
    al_u16       version;
    al_u32       chain_id;
    al_height    height;
    al_u32       protocol_day;
    al_hash256   parent_hash;
    al_hash256   state_root;
    al_hash256   tx_root;
    al_hash256   receipt_root;
    al_resources resources;
    al_resources base_prices;
    al_pubkey    proposer;
    al_address   tip_flat;
    al_address   tip_weighted;
    al_address   tip_bonded;
} al_block_header;

typedef struct al_block {
    al_block_header       header;
    const al_transaction *transactions;
    al_size               transaction_count;
} al_block;

AL_PUBLIC AL_NODISCARD al_status al_genesis_validate(
    const al_genesis *genesis);
AL_PUBLIC AL_NODISCARD al_status al_genesis_encode(
    const al_genesis *genesis, al_bytes_mut out, al_size *written);
/*
 * Decode a canonical genesis. `allocation_storage` receives the allocation
 * table and out->allocations borrows it; pass NULL/0 to learn the required
 * capacity through out->allocation_count, in which case the call returns
 * AL_ERR_BUFFER_TOO_SMALL after validating everything else it can.
 */
AL_PUBLIC AL_NODISCARD al_status al_genesis_decode(
    al_bytes encoded, al_genesis_allocation *allocation_storage,
    al_size allocation_capacity, al_genesis *out);
AL_PUBLIC void al_genesis_hash(const al_genesis *genesis, al_hash256 *out);

AL_PUBLIC void al_block_header_hash(const al_block_header *header,
                                    al_hash256 *out);
AL_PUBLIC AL_NODISCARD al_status al_block_header_encode(
    const al_block_header *header, al_bytes_mut out, al_size *written);
AL_PUBLIC AL_NODISCARD al_status al_block_header_decode(
    al_bytes encoded, al_block_header *out);
AL_PUBLIC AL_NODISCARD al_status al_block_encode(
    const al_block *block, al_bytes_mut out, al_size *written);
AL_PUBLIC AL_NODISCARD al_status al_block_decode(
    al_bytes encoded, al_transaction *transaction_storage,
    al_size transaction_capacity, al_block *out);
AL_PUBLIC void al_block_transaction_root(const al_block *block,
                                         al_hash256 *out);
AL_PUBLIC void al_block_receipt_root(const al_receipt *receipts, al_size count,
                                     al_hash256 *out);

/* Build and atomically execute a locally proposed block. The caller supplies
 * protocol_day, proposer, tip recipients and the ordered transaction body;
 * every other header field is derived from parent, genesis and execution.
 * Parent is NULL only for height zero. Receipt data remains in arena. */
AL_PUBLIC AL_NODISCARD al_status al_block_produce(
    al_block *block, const al_block_header *parent, const al_genesis *genesis,
    al_state *state, al_receipt *receipts, al_size receipt_capacity,
    al_arena *arena);

/* Parent is NULL only for height zero. Block application is atomic: state and
 * height are restored when any declared commitment differs from execution. */
AL_PUBLIC AL_NODISCARD al_status al_block_execute(
    const al_block *block, const al_block_header *parent,
    const al_genesis *genesis, al_state *state, al_receipt *receipts,
    al_size receipt_capacity, al_arena *arena);

AL_EXTERN_C_END
#endif /* ASTROLUNE_BLOCK_H */
