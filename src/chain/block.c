#include "astrolune/block.h"
#include "internal/common.h"

#include <string.h>

/* Worst case genesis encoding: the fixed parameter block plus a full
 * allocation table. al_genesis_hash relies on this fitting on the stack. */
#define AL_GENESIS_MAX_ENCODED_SIZE                                             \
    (1024u + AL_GENESIS_MAX_ALLOCATIONS * sizeof(al_genesis_allocation))

static void write_resources(al_writer *writer, al_resources value) {
    al_writer_u64(writer, value.compute);
    al_writer_u64(writer, value.memory);
    al_writer_u64(writer, value.storage);
    al_writer_u64(writer, value.bandwidth);
}

static al_resources read_resources(al_reader *reader) {
    al_resources value;
    value.compute = al_reader_u64(reader);
    value.memory = al_reader_u64(reader);
    value.storage = al_reader_u64(reader);
    value.bandwidth = al_reader_u64(reader);
    return value;
}

static void write_potb(al_writer *writer, const al_potb_params *p) {
    al_writer_u32(writer, p->loyalty_threshold_days);
    al_writer_u64(writer, (al_u64)p->loyalty_rate_per_day);
    al_writer_u64(writer, (al_u64)p->cap_loyalty);
    al_writer_u32(writer, p->grace_period_days);
    al_writer_u32(writer, p->decay_half_life_days);
    al_writer_u64(writer, (al_u64)p->cap_tbs);
    al_writer_u64(writer, (al_u64)p->cap_tgw);
    al_writer_u64(writer, (al_u64)p->sybil_cluster_threshold);
    al_writer_u32(writer, p->sybil_cluster_max_size);
    al_writer_u64(writer, (al_u64)p->tdi_suspicious_below);
    al_writer_u32(writer, p->committee_size);
    al_writer_u32(writer, p->committee_lifetime_blocks);
    al_writer_u64(writer, (al_u64)p->rotation_fraction);
    al_writer_u64(writer, (al_u64)p->min_tbs_candidate);
    al_writer_u64(writer, (al_u64)p->min_tbs_validator);
    al_writer_u64(writer, (al_u64)p->min_tgw_validator);
    al_writer_u64(writer, (al_u64)p->candidate_weight_factor);
    al_writer_u32(writer, p->epoch_days);
    al_writer_u16(writer, p->reward_flat_bp);
    al_writer_u16(writer, p->reward_weighted_bp);
    al_writer_u16(writer, p->reward_bonded_bp);
    al_writer_u64(writer, (al_u64)p->reward_max_multiple);
}

static void read_potb(al_reader *reader, al_potb_params *p) {
    p->loyalty_threshold_days = al_reader_u32(reader);
    p->loyalty_rate_per_day = (al_fixed)al_reader_u64(reader);
    p->cap_loyalty = (al_fixed)al_reader_u64(reader);
    p->grace_period_days = al_reader_u32(reader);
    p->decay_half_life_days = al_reader_u32(reader);
    p->cap_tbs = (al_fixed)al_reader_u64(reader);
    p->cap_tgw = (al_fixed)al_reader_u64(reader);
    p->sybil_cluster_threshold = (al_fixed)al_reader_u64(reader);
    p->sybil_cluster_max_size = al_reader_u32(reader);
    p->tdi_suspicious_below = (al_fixed)al_reader_u64(reader);
    p->committee_size = al_reader_u32(reader);
    p->committee_lifetime_blocks = al_reader_u32(reader);
    p->rotation_fraction = (al_fixed)al_reader_u64(reader);
    p->min_tbs_candidate = (al_fixed)al_reader_u64(reader);
    p->min_tbs_validator = (al_fixed)al_reader_u64(reader);
    p->min_tgw_validator = (al_fixed)al_reader_u64(reader);
    p->candidate_weight_factor = (al_fixed)al_reader_u64(reader);
    p->epoch_days = al_reader_u32(reader);
    p->reward_flat_bp = al_reader_u16(reader);
    p->reward_weighted_bp = al_reader_u16(reader);
    p->reward_bonded_bp = al_reader_u16(reader);
    p->reward_max_multiple = (al_fixed)al_reader_u64(reader);
}

static void genesis_write(const al_genesis *genesis, al_writer *writer) {
    al_writer_u16(writer, genesis->version);
    al_writer_u32(writer, genesis->chain_id);
    al_writer_hash(writer, &genesis->initial_state_root);
    write_resources(writer, genesis->fees.block_limit);
    write_resources(writer, genesis->fees.target);
    write_resources(writer, genesis->fees.initial_base_price);
    al_writer_u64(writer, genesis->fees.storage_deposit_per_byte);
    for (al_size i = 0u; i < AL_VM_OPCODE_COUNT; ++i)
        al_writer_u64(writer, genesis->schedule.opcode[i]);
    for (al_size i = 0u; i < AL_VM_HOST_COUNT; ++i)
        al_writer_u64(writer, genesis->schedule.host[i]);
    al_writer_u64(writer, genesis->vm_stack_limit);
    al_writer_u64(writer, genesis->vm_memory_limit);
    al_writer_u64(writer, genesis->vm_call_depth_limit);
    write_potb(writer, &genesis->potb);
    al_writer_varint(writer, (al_u64)genesis->allocation_count);
    for (al_size i = 0u; i < genesis->allocation_count; ++i) {
        al_writer_address(writer, &genesis->allocations[i].address);
        al_writer_u64(writer, genesis->allocations[i].balance);
    }
}

static al_bool resources_nonzero(al_resources value) {
    return (value.compute != 0u && value.memory != 0u &&
            value.storage != 0u && value.bandwidth != 0u) ? AL_TRUE : AL_FALSE;
}

al_status al_genesis_validate(const al_genesis *genesis) {
    if (genesis == NULL || genesis->version != AL_GENESIS_VERSION ||
        genesis->chain_id == 0u || genesis->vm_stack_limit == 0u ||
        genesis->vm_memory_limit == 0u ||
        genesis->vm_call_depth_limit == 0u ||
        !resources_nonzero(genesis->fees.block_limit) ||
        !resources_nonzero(genesis->fees.target) ||
        !resources_nonzero(genesis->fees.initial_base_price) ||
        !al_resources_within(genesis->fees.target, genesis->fees.block_limit))
        return AL_ERR_INVALID_ARG;
    for (al_size i = 0u; i < AL_VM_OPCODE_COUNT; ++i)
        if (genesis->schedule.opcode[i] == 0u ||
            genesis->schedule.opcode[i] == UINT64_MAX) return AL_ERR_INVALID_ARG;
    for (al_size i = 0u; i < AL_VM_HOST_COUNT; ++i)
        if (genesis->schedule.host[i] == 0u ||
            genesis->schedule.host[i] == UINT64_MAX) return AL_ERR_INVALID_ARG;
    /* The allocation table must be canonical: sorted and free of duplicates,
     * or two orderings of one chain start would hash differently. */
    if (genesis->allocation_count > AL_GENESIS_MAX_ALLOCATIONS ||
        (genesis->allocation_count != 0u && genesis->allocations == NULL))
        return AL_ERR_INVALID_ARG;
    for (al_size i = 0u; i < genesis->allocation_count; ++i) {
        const al_genesis_allocation *entry = &genesis->allocations[i];
        if (entry->balance == 0u || al_address_is_zero(&entry->address))
            return AL_ERR_INVALID_ARG;
        if (i > 0u &&
            al_address_cmp(&genesis->allocations[i - 1u].address,
                           &entry->address) >= 0)
            return AL_ERR_INVALID_ARG;
    }
    return al_potb_params_validate(&genesis->potb);
}

al_status al_genesis_encode(const al_genesis *genesis, al_bytes_mut out,
                            al_size *written) {
    if (written == NULL) return AL_ERR_INVALID_ARG;
    *written = 0u;
    AL_TRY(al_genesis_validate(genesis));
    al_writer writer; al_writer_init(&writer, out.data, out.len);
    genesis_write(genesis, &writer);
    *written = al_writer_len(&writer);
    return al_writer_finish(&writer);
}

al_status al_genesis_decode(al_bytes encoded,
                            al_genesis_allocation *allocation_storage,
                            al_size allocation_capacity, al_genesis *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    al_reader reader; al_reader_init(&reader, encoded);
    al_memzero(out, sizeof(*out));
    out->version = al_reader_u16(&reader);
    out->chain_id = al_reader_u32(&reader);
    al_reader_hash(&reader, &out->initial_state_root);
    out->fees.block_limit = read_resources(&reader);
    out->fees.target = read_resources(&reader);
    out->fees.initial_base_price = read_resources(&reader);
    out->fees.storage_deposit_per_byte = al_reader_u64(&reader);
    for (al_size i = 0u; i < AL_VM_OPCODE_COUNT; ++i)
        out->schedule.opcode[i] = al_reader_u64(&reader);
    for (al_size i = 0u; i < AL_VM_HOST_COUNT; ++i)
        out->schedule.host[i] = al_reader_u64(&reader);
    al_u64 stack = al_reader_u64(&reader);
    al_u64 memory = al_reader_u64(&reader);
    al_u64 depth = al_reader_u64(&reader);
    if (stack > SIZE_MAX || memory > SIZE_MAX || depth > SIZE_MAX)
        al_reader_fail(&reader, AL_ERR_OUT_OF_RANGE);
    out->vm_stack_limit = (al_size)stack;
    out->vm_memory_limit = (al_size)memory;
    out->vm_call_depth_limit = (al_size)depth;
    read_potb(&reader, &out->potb);

    al_u64 allocation_count = al_reader_varint(&reader);
    if (allocation_count > AL_GENESIS_MAX_ALLOCATIONS)
        al_reader_fail(&reader, AL_ERR_OUT_OF_RANGE);
    out->allocation_count = (al_size)allocation_count;
    if (allocation_count > allocation_capacity) {
        /* Capacity probe: report the required size and stop before writing
         * anywhere the caller did not provide room for. */
        return AL_ERR_BUFFER_TOO_SMALL;
    }
    for (al_size i = 0u; i < out->allocation_count; ++i) {
        al_reader_address(&reader, &allocation_storage[i].address);
        allocation_storage[i].balance = al_reader_u64(&reader);
    }
    out->allocations = allocation_storage;

    AL_TRY(al_reader_finish(&reader));
    return al_genesis_validate(out);
}

void al_genesis_hash(const al_genesis *genesis, al_hash256 *out) {
    if (out == NULL) return;
    if (al_genesis_validate(genesis) != AL_OK) {
        *out = al_hash_zero(); return;
    }
    al_u8 encoded[AL_GENESIS_MAX_ENCODED_SIZE];
    al_size written = 0u;
    al_status status = al_genesis_encode(
        genesis, (al_bytes_mut){ encoded, sizeof(encoded) }, &written);
    AL_ASSERT(status == AL_OK);
    if (status != AL_OK) {
        *out = al_hash_zero();
        return;
    }
    al_hash_tagged(AL_TAG_GENESIS, encoded, written, out);
}

static void header_write(const al_block_header *header, al_writer *writer) {
    al_writer_u16(writer, header->version);
    al_writer_u32(writer, header->chain_id);
    al_writer_u64(writer, header->height);
    al_writer_u32(writer, header->protocol_day);
    al_writer_hash(writer, &header->parent_hash);
    al_writer_hash(writer, &header->state_root);
    al_writer_hash(writer, &header->tx_root);
    al_writer_hash(writer, &header->receipt_root);
    write_resources(writer, header->resources);
    write_resources(writer, header->base_prices);
    al_writer_raw(writer, header->proposer.bytes, AL_PUBKEY_SIZE);
    al_writer_address(writer, &header->tip_flat);
    al_writer_address(writer, &header->tip_weighted);
    al_writer_address(writer, &header->tip_bonded);
}

void al_block_header_hash(const al_block_header *header, al_hash256 *out) {
    if (header == NULL || out == NULL) return;
    al_u8 encoded[AL_BLOCK_HEADER_ENCODED_SIZE];
    al_writer writer; al_writer_init(&writer, encoded, sizeof(encoded));
    header_write(header, &writer);
    AL_ASSERT(al_writer_finish(&writer) == AL_OK);
    al_hash_tagged(AL_TAG_HEADER, encoded, sizeof(encoded), out);
}

al_status al_block_header_encode(const al_block_header *header,
                                 al_bytes_mut out, al_size *written) {
    if (header == NULL || written == NULL) return AL_ERR_INVALID_ARG;
    *written = 0u;
    if (header->version != AL_BLOCK_VERSION) return AL_ERR_UNSUPPORTED;
    al_writer writer; al_writer_init(&writer, out.data, out.len);
    header_write(header, &writer);
    *written = al_writer_len(&writer);
    return al_writer_finish(&writer);
}

al_status al_block_header_decode(al_bytes encoded, al_block_header *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    al_reader reader; al_reader_init(&reader, encoded);
    al_memzero(out, sizeof(*out));
    out->version = al_reader_u16(&reader);
    out->chain_id = al_reader_u32(&reader);
    out->height = al_reader_u64(&reader);
    out->protocol_day = al_reader_u32(&reader);
    al_reader_hash(&reader, &out->parent_hash);
    al_reader_hash(&reader, &out->state_root);
    al_reader_hash(&reader, &out->tx_root);
    al_reader_hash(&reader, &out->receipt_root);
    out->resources = read_resources(&reader);
    out->base_prices = read_resources(&reader);
    al_reader_bytes(&reader, out->proposer.bytes, AL_PUBKEY_SIZE);
    al_reader_address(&reader, &out->tip_flat);
    al_reader_address(&reader, &out->tip_weighted);
    al_reader_address(&reader, &out->tip_bonded);
    AL_TRY(al_reader_finish(&reader));
    return (out->version == AL_BLOCK_VERSION) ? AL_OK : AL_ERR_UNSUPPORTED;
}

al_status al_block_encode(const al_block *block, al_bytes_mut out,
                          al_size *written) {
    if (written == NULL) return AL_ERR_INVALID_ARG;
    *written = 0u;
    if (block == NULL || block->transaction_count > AL_BLOCK_MAX_TRANSACTIONS ||
        (block->transactions == NULL && block->transaction_count != 0u))
        return AL_ERR_INVALID_ARG;
    al_size required = AL_BLOCK_HEADER_ENCODED_SIZE +
                       al_varint_size(block->transaction_count);
    for (al_size i = 0u; i < block->transaction_count; ++i) {
        AL_TRY(al_tx_validate_shape(&block->transactions[i]));
        al_size size = al_tx_encoded_size(&block->transactions[i]);
        if (SIZE_MAX - required < al_varint_size(size) + size)
            return AL_ERR_ARITH_OVERFLOW;
        required += al_varint_size(size) + size;
    }
    if (out.data == NULL || out.len < required) return AL_ERR_BUFFER_TOO_SMALL;
    al_writer writer; al_writer_init(&writer, out.data, out.len);
    header_write(&block->header, &writer);
    al_writer_varint(&writer, block->transaction_count);
    for (al_size i = 0u; i < block->transaction_count; ++i) {
        al_size size = al_tx_encoded_size(&block->transactions[i]);
        al_writer_varint(&writer, size);
        al_size encoded = 0u;
        AL_TRY(al_tx_encode(&block->transactions[i],
            (al_bytes_mut){ writer.data + writer.pos, writer.cap - writer.pos },
            &encoded));
        writer.pos += encoded;
    }
    *written = writer.pos;
    return al_writer_finish(&writer);
}

al_status al_block_decode(al_bytes encoded, al_transaction *storage,
                          al_size capacity, al_block *out) {
    if (out == NULL || (storage == NULL && capacity != 0u))
        return AL_ERR_INVALID_ARG;
    al_reader reader; al_reader_init(&reader, encoded);
    al_memzero(out, sizeof(*out));
    al_bytes header = al_reader_take(&reader, AL_BLOCK_HEADER_ENCODED_SIZE);
    if (al_reader_status(&reader) == AL_OK)
        AL_TRY(al_block_header_decode(header, &out->header));
    al_u64 count = al_reader_varint(&reader);
    if (count > AL_BLOCK_MAX_TRANSACTIONS || count > capacity) {
        al_reader_fail(&reader, AL_ERR_OUT_OF_RANGE);
        count = 0u;
    }
    for (al_size i = 0u; i < (al_size)count; ++i) {
        al_u64 length = al_reader_varint(&reader);
        if (length > AL_TX_MAX_SIZE || length > SIZE_MAX) {
            al_reader_fail(&reader, AL_ERR_OUT_OF_RANGE);
            break;
        }
        al_bytes bytes = al_reader_take(&reader, (al_size)length);
        if (al_reader_status(&reader) == AL_OK)
            AL_TRY(al_tx_decode(bytes, &storage[i]));
    }
    AL_TRY(al_reader_finish(&reader));
    out->transactions = storage;
    out->transaction_count = (al_size)count;
    return AL_OK;
}

static void merkle_append(al_hash256 peaks[64], al_u64 *mask,
                          al_hash256 leaf) {
    al_size level = 0u;
    while ((*mask & (UINT64_C(1) << level)) != 0u) {
        al_hash_tagged_pair(AL_TAG_MERKLE_NODE, &peaks[level], &leaf, &leaf);
        *mask &= ~(UINT64_C(1) << level);
        ++level;
    }
    peaks[level] = leaf;
    *mask |= UINT64_C(1) << level;
}

static al_hash256 merkle_finish(const al_hash256 peaks[64], al_u64 mask) {
    al_hash256 root = al_hash_zero();
    al_bool set = AL_FALSE;
    for (al_size level = 0u; level < 64u; ++level) {
        if ((mask & (UINT64_C(1) << level)) == 0u) continue;
        if (!set) {
            root = peaks[level]; set = AL_TRUE;
        } else {
            al_hash_tagged_pair(AL_TAG_MERKLE_NODE, &peaks[level], &root, &root);
        }
    }
    return root;
}

void al_block_transaction_root(const al_block *block, al_hash256 *out) {
    if (out == NULL) return;
    if (block == NULL || (block->transactions == NULL &&
                          block->transaction_count != 0u)) {
        *out = al_hash_zero(); return;
    }
    al_hash256 peaks[64]; al_u64 mask = 0u;
    for (al_size i = 0u; i < block->transaction_count; ++i) {
        al_hash256 hash; al_tx_hash(&block->transactions[i], &hash);
        merkle_append(peaks, &mask, hash);
    }
    *out = merkle_finish(peaks, mask);
}

void al_block_receipt_root(const al_receipt *receipts, al_size count,
                           al_hash256 *out) {
    if (out == NULL) return;
    if (receipts == NULL && count != 0u) { *out = al_hash_zero(); return; }
    al_hash256 peaks[64]; al_u64 mask = 0u;
    for (al_size i = 0u; i < count; ++i) {
        al_hash256 hash; al_receipt_hash(&receipts[i], &hash);
        merkle_append(peaks, &mask, hash);
    }
    *out = merkle_finish(peaks, mask);
}

static al_bool resources_equal(al_resources a, al_resources b) {
    return (a.compute == b.compute && a.memory == b.memory &&
            a.storage == b.storage && a.bandwidth == b.bandwidth)
               ? AL_TRUE : AL_FALSE;
}

static al_status block_derive_header(al_block *block,
                                     const al_block_header *parent,
                                     const al_genesis *genesis,
                                     const al_state *state) {
    block->header.version = AL_BLOCK_VERSION;
    block->header.chain_id = genesis->chain_id;

    if (parent == NULL) {
        if (!al_hash_eq(&state->root, &genesis->initial_state_root)) {
            return AL_ERR_CONSENSUS_VIOLATION;
        }
        block->header.height = 0u;
        block->header.parent_hash = al_hash_zero();
        block->header.base_prices = genesis->fees.initial_base_price;
    } else {
        if (parent->height == UINT64_MAX) {
            return AL_ERR_ARITH_OVERFLOW;
        }
        block->header.height = parent->height + 1u;
        al_block_header_hash(parent, &block->header.parent_hash);
        AL_TRY(al_fee_next_base_prices(parent->base_prices, parent->resources,
                                       genesis->fees.target,
                                       &block->header.base_prices));
    }

    al_block_transaction_root(block, &block->header.tx_root);
    return AL_OK;
}

static al_status block_apply_transactions(
    const al_block *block, const al_genesis *genesis, al_state *state,
    al_receipt *receipts, al_arena *arena, al_resources *resources_out) {
    al_resources total = al_resources_zero();
    al_tx_context context;
    al_memzero(&context, sizeof(context));
    context.chain_id = genesis->chain_id;
    context.block_height = block->header.height;
    context.protocol_day = block->header.protocol_day;
    context.base_prices = block->header.base_prices;
    context.tip_flat = block->header.tip_flat;
    context.tip_weighted = block->header.tip_weighted;
    context.tip_bonded = block->header.tip_bonded;
    context.vm.stack_limit = genesis->vm_stack_limit;
    context.vm.memory_limit = genesis->vm_memory_limit;
    context.vm.call_depth_limit = genesis->vm_call_depth_limit;
    context.vm.resource_limit = genesis->fees.block_limit;
    context.vm.schedule = &genesis->schedule;

    for (al_size i = 0u; i < block->transaction_count; ++i) {
        context.arena = arena;
        AL_TRY(al_tx_apply(&block->transactions[i], state, &context,
                           &receipts[i]));
        AL_TRY(al_resources_add(total, receipts[i].resources, &total));
        if (!al_resources_within(total, genesis->fees.block_limit)) {
            return AL_ERR_RESOURCE_LIMIT;
        }
    }

    *resources_out = total;
    return AL_OK;
}

static al_status block_restore(al_state *state, al_state_snapshot snapshot,
                               al_arena *arena, al_arena_mark mark,
                               al_status status) {
    al_status restore_status = al_state_snapshot_restore(state, snapshot);
    al_arena_restore(arena, mark);
    return restore_status == AL_OK ? status : restore_status;
}

al_status al_block_produce(al_block *block, const al_block_header *parent,
                           const al_genesis *genesis, al_state *state,
                           al_receipt *receipts, al_size receipt_capacity,
                           al_arena *arena) {
    if (block == NULL || genesis == NULL || state == NULL || arena == NULL ||
        block->transaction_count > AL_BLOCK_MAX_TRANSACTIONS ||
        block->transaction_count > receipt_capacity ||
        (block->transactions == NULL && block->transaction_count != 0u) ||
        (receipts == NULL && block->transaction_count != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    AL_TRY(al_genesis_validate(genesis));
    AL_TRY(block_derive_header(block, parent, genesis, state));

    al_state_snapshot snapshot = al_state_snapshot_take(state);
    al_arena_mark mark = al_arena_save(arena);
    al_resources resources = al_resources_zero();
    al_status status = block_apply_transactions(
        block, genesis, state, receipts, arena, &resources);
    if (status != AL_OK) {
        return block_restore(state, snapshot, arena, mark, status);
    }

    block->header.state_root = state->root;
    block->header.resources = resources;
    al_block_receipt_root(receipts, block->transaction_count,
                          &block->header.receipt_root);
    state->height = block->header.height;
    return AL_OK;
}

al_status al_block_execute(const al_block *block, const al_block_header *parent,
                           const al_genesis *genesis, al_state *state,
                           al_receipt *receipts, al_size receipt_capacity,
                           al_arena *arena) {
    if (block == NULL || genesis == NULL || state == NULL || arena == NULL ||
        block->transaction_count > AL_BLOCK_MAX_TRANSACTIONS ||
        block->transaction_count > receipt_capacity ||
        (receipts == NULL && block->transaction_count != 0u))
        return AL_ERR_INVALID_ARG;
    AL_TRY(al_genesis_validate(genesis));
    if (block->header.version != AL_BLOCK_VERSION ||
        block->header.chain_id != genesis->chain_id)
        return AL_ERR_CONSENSUS_VIOLATION;

    al_resources expected_prices;
    if (parent == NULL) {
        if (block->header.height != 0u ||
            !al_hash_is_zero(&block->header.parent_hash) ||
            !al_hash_eq(&state->root, &genesis->initial_state_root))
            return AL_ERR_CONSENSUS_VIOLATION;
        expected_prices = genesis->fees.initial_base_price;
    } else {
        al_hash256 parent_hash; al_block_header_hash(parent, &parent_hash);
        if (parent->version != AL_BLOCK_VERSION ||
            parent->chain_id != genesis->chain_id ||
            parent->height == UINT64_MAX ||
            block->header.height != parent->height + 1u ||
            !al_hash_eq(&block->header.parent_hash, &parent_hash))
            return AL_ERR_CONSENSUS_VIOLATION;
        AL_TRY(al_fee_next_base_prices(parent->base_prices, parent->resources,
                                       genesis->fees.target, &expected_prices));
    }
    if (!resources_equal(expected_prices, block->header.base_prices))
        return AL_ERR_CONSENSUS_VIOLATION;
    al_hash256 tx_root; al_block_transaction_root(block, &tx_root);
    if (!al_hash_eq(&tx_root, &block->header.tx_root))
        return AL_ERR_CONSENSUS_VIOLATION;

    al_state_snapshot snapshot = al_state_snapshot_take(state);
    al_arena_mark mark = al_arena_save(arena);
    al_resources total = al_resources_zero();
    al_status status = block_apply_transactions(
        block, genesis, state, receipts, arena, &total);
    if (status != AL_OK)
        return block_restore(state, snapshot, arena, mark, status);

    al_hash256 receipt_root;
    al_block_receipt_root(receipts, block->transaction_count, &receipt_root);
    if (!al_hash_eq(&state->root, &block->header.state_root) ||
        !al_hash_eq(&receipt_root, &block->header.receipt_root) ||
        !resources_equal(total, block->header.resources)) {
        return block_restore(state, snapshot, arena, mark,
                             AL_ERR_CONSENSUS_VIOLATION);
    }
    state->height = block->header.height;
    return AL_OK;
}
