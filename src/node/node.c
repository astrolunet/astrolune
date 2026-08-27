/* Local node policy and the canonical block-ingress pipeline. */

#include "node.h"

#include "internal/common.h"

#include <string.h>

static al_bool node_buffers_valid(al_node_buffers buffers) {
    return ((buffers.mempool_entries != NULL ||
             buffers.mempool_capacity == 0u) &&
            (buffers.mempool_bytes != NULL ||
             buffers.mempool_bytes_capacity == 0u) &&
            (buffers.block_transactions != NULL ||
             buffers.block_transaction_capacity == 0u) &&
            (buffers.receipts != NULL || buffers.receipt_capacity == 0u) &&
            buffers.receipt_capacity >= buffers.block_transaction_capacity)
               ? AL_TRUE
               : AL_FALSE;
}

static al_bool public_keys_equal(const al_pubkey *a, const al_pubkey *b) {
    return memcmp(a->bytes, b->bytes, AL_PUBKEY_SIZE) == 0 ? AL_TRUE
                                                           : AL_FALSE;
}

static al_bool prices_cover(al_resources caps, al_resources prices) {
    return (caps.compute >= prices.compute && caps.memory >= prices.memory &&
            caps.storage >= prices.storage &&
            caps.bandwidth >= prices.bandwidth)
               ? AL_TRUE
               : AL_FALSE;
}

static al_amount transaction_value(const al_transaction *transaction) {
    switch (transaction->type) {
    case AL_TX_TRANSFER:
        return transaction->body.transfer.amount;
    case AL_TX_DEPLOY:
        return transaction->body.deploy.value;
    case AL_TX_CALL:
        return transaction->body.call.value;
    case AL_TX_POTB:
    case AL_TX_TYPE_SENTINEL:
        return 0u;
    }
    return 0u;
}

static al_status maximum_debit(const al_transaction *transaction,
                               al_amount *out) {
    al_amount fee = 0u;
    AL_TRY(al_resources_fee(transaction->resource_limit,
                            transaction->max_base_price, &fee));

    al_amount debit = 0u;
    if (al_add_overflow_u64(fee, transaction->tip, &debit) ||
        al_add_overflow_u64(debit, transaction_value(transaction), &debit)) {
        return AL_ERR_ARITH_OVERFLOW;
    }
    *out = debit;
    return AL_OK;
}

static al_status next_base_prices(const al_node *node, al_resources *out) {
    if (!node->has_head) {
        *out = node->genesis.fees.initial_base_price;
        return AL_OK;
    }
    return al_fee_next_base_prices(node->head.base_prices,
                                   node->head.resources,
                                   node->genesis.fees.target, out);
}

static al_status next_height_checked(const al_node *node, al_height *out) {
    if (!node->has_head) {
        *out = 0u;
        return AL_OK;
    }
    if (node->head.height == UINT64_MAX) {
        return AL_ERR_ARITH_OVERFLOW;
    }
    *out = node->head.height + 1u;
    return AL_OK;
}

al_status al_node_open(al_node *node, const al_genesis *genesis,
                       al_state *state, al_arena *execution_arena,
                       al_node_buffers buffers,
                       const al_block_header *head) {
    if (node == NULL || genesis == NULL || state == NULL ||
        execution_arena == NULL || !node_buffers_valid(buffers)) {
        return AL_ERR_INVALID_ARG;
    }
    AL_TRY(al_genesis_validate(genesis));
    if (head == NULL) {
        if (!al_hash_eq(&state->root, &genesis->initial_state_root)) {
            return AL_ERR_CONSENSUS_VIOLATION;
        }
    } else if (head->version != AL_BLOCK_VERSION ||
               head->chain_id != genesis->chain_id ||
               head->height != state->height ||
               !al_hash_eq(&head->state_root, &state->root)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }

    al_memzero(node, sizeof(*node));
    node->genesis = *genesis;
    node->state = state;
    node->execution_arena = execution_arena;
    node->buffers = buffers;
    if (head != NULL) {
        node->head = *head;
        node->has_head = AL_TRUE;
    }
    return AL_OK;
}

al_status al_node_init(al_node *node, const al_genesis *genesis,
                       al_state *state, al_arena *execution_arena,
                       al_node_buffers buffers) {
    return al_node_open(node, genesis, state, execution_arena, buffers, NULL);
}

static al_status mempool_reservation(const al_node *node,
                                     const al_pubkey *sender,
                                     al_nonce committed_nonce,
                                     al_nonce *next_nonce,
                                     al_amount *reserved) {
    al_nonce expected = committed_nonce;
    al_amount total = 0u;

    for (al_size i = 0u; i < node->mempool_count; ++i) {
        const al_node_mempool_entry *entry = &node->buffers.mempool_entries[i];
        if (!public_keys_equal(&entry->transaction.sender, sender)) {
            continue;
        }
        if (entry->transaction.nonce != expected) {
            return AL_ERR_STATE_CORRUPT;
        }
        if (expected == UINT64_MAX ||
            al_add_overflow_u64(total, entry->maximum_debit, &total)) {
            return AL_ERR_ARITH_OVERFLOW;
        }
        ++expected;
    }

    *next_nonce = expected;
    *reserved = total;
    return AL_OK;
}

al_status al_node_submit_transaction(al_node *node, al_bytes encoded,
                                     al_hash256 *hash_out) {
    if (node == NULL || encoded.data == NULL || encoded.len == 0u ||
        encoded.len > AL_TX_MAX_SIZE) {
        return AL_ERR_INVALID_ARG;
    }

    al_transaction transaction;
    al_status status = al_tx_decode(encoded, &transaction);
    if (status != AL_OK) {
        ++node->stats.transactions_rejected;
        return status;
    }

    al_hash256 hash;
    al_tx_hash(&transaction, &hash);
    for (al_size i = 0u; i < node->mempool_count; ++i) {
        const al_node_mempool_entry *entry = &node->buffers.mempool_entries[i];
        if (al_hash_eq(&entry->hash, &hash) ||
            (entry->transaction.nonce == transaction.nonce &&
             public_keys_equal(&entry->transaction.sender,
                               &transaction.sender))) {
            ++node->stats.transactions_rejected;
            return AL_ERR_ALREADY_EXISTS;
        }
    }

    if (node->mempool_count == node->buffers.mempool_capacity ||
        encoded.len > node->buffers.mempool_bytes_capacity -
                          node->mempool_bytes_used) {
        ++node->stats.transactions_rejected;
        return AL_ERR_OUT_OF_MEMORY;
    }

    al_height next_height = 0u;
    status = next_height_checked(node, &next_height);
    if (status == AL_OK && transaction.chain_id != node->genesis.chain_id) {
        status = AL_ERR_CONSENSUS_VIOLATION;
    }
    if (status == AL_OK && transaction.expiry_height < next_height) {
        status = AL_ERR_EXPIRED;
    }

    al_resources prices = al_resources_zero();
    if (status == AL_OK) {
        status = next_base_prices(node, &prices);
    }
    if (status == AL_OK &&
        (transaction.resource_limit.bandwidth < encoded.len ||
         !prices_cover(transaction.max_base_price, prices))) {
        status = AL_ERR_RESOURCE_LIMIT;
    }
    if (status == AL_OK) {
        status = al_tx_verify(&transaction);
    }

    al_address sender_address;
    al_account sender_account;
    al_memzero(&sender_account, sizeof(sender_account));
    if (status == AL_OK) {
        al_address_from_pubkey(&transaction.sender, &sender_address);
        status = al_state_get(node->state, &sender_address, &sender_account);
    }

    al_nonce expected_nonce = 0u;
    al_amount reserved = 0u;
    if (status == AL_OK) {
        status = mempool_reservation(node, &transaction.sender,
                                     sender_account.nonce, &expected_nonce,
                                     &reserved);
    }
    if (status == AL_OK && transaction.nonce != expected_nonce) {
        status = AL_ERR_BAD_NONCE;
    }

    al_amount debit = 0u;
    if (status == AL_OK) {
        status = maximum_debit(&transaction, &debit);
    }
    if (status == AL_OK) {
        al_amount total_reservation = 0u;
        if (al_add_overflow_u64(reserved, debit, &total_reservation)) {
            status = AL_ERR_ARITH_OVERFLOW;
        } else if (total_reservation > sender_account.balance) {
            status = AL_ERR_INSUFFICIENT_FUNDS;
        }
    }
    if (status != AL_OK) {
        ++node->stats.transactions_rejected;
        return status;
    }

    al_size offset = node->mempool_bytes_used;
    al_u8 *destination = node->buffers.mempool_bytes + offset;
    memmove(destination, encoded.data, encoded.len);

    al_node_mempool_entry *entry =
        &node->buffers.mempool_entries[node->mempool_count];
    al_memzero(entry, sizeof(*entry));
    status = al_tx_decode(al_bytes_make(destination, encoded.len),
                          &entry->transaction);
    if (status != AL_OK) {
        ++node->stats.transactions_rejected;
        return AL_ERR_STATE_CORRUPT;
    }
    entry->hash = hash;
    entry->maximum_debit = debit;
    entry->encoded_offset = offset;
    entry->encoded_size = encoded.len;

    node->mempool_bytes_used += encoded.len;
    ++node->mempool_count;
    ++node->stats.transactions_accepted;
    if (hash_out != NULL) {
        *hash_out = hash;
    }
    return AL_OK;
}

static al_bytes *transaction_payload(al_transaction *transaction) {
    switch (transaction->type) {
    case AL_TX_DEPLOY:
        return &transaction->body.deploy.container;
    case AL_TX_CALL:
        return &transaction->body.call.calldata;
    case AL_TX_POTB:
        return &transaction->body.potb.data;
    case AL_TX_TRANSFER:
    case AL_TX_TYPE_SENTINEL:
        return NULL;
    }
    return NULL;
}

static al_bool mempool_entry_is_live(const al_node *node,
                                     const al_node_mempool_entry *entry,
                                     al_height next_height) {
    if (entry->transaction.expiry_height < next_height) {
        return AL_FALSE;
    }

    al_address sender;
    al_address_from_pubkey(&entry->transaction.sender, &sender);
    al_account account;
    al_status status = al_state_get(node->state, &sender, &account);
    if (status == AL_ERR_NOT_FOUND) {
        return AL_FALSE;
    }
    if (status != AL_OK) {
        /* A transient store error must not silently discard a transaction. */
        return AL_TRUE;
    }
    return entry->transaction.nonce >= account.nonce ? AL_TRUE : AL_FALSE;
}

static void mempool_compact(al_node *node) {
    al_height next_height = 0u;
    if (next_height_checked(node, &next_height) != AL_OK) {
        return;
    }

    al_size output_count = 0u;
    al_size output_bytes = 0u;
    for (al_size i = 0u; i < node->mempool_count; ++i) {
        al_node_mempool_entry entry = node->buffers.mempool_entries[i];
        if (!mempool_entry_is_live(node, &entry, next_height)) {
            ++node->stats.mempool_removed;
            continue;
        }

        al_u8 *old_base = node->buffers.mempool_bytes + entry.encoded_offset;
        al_bytes *payload = transaction_payload(&entry.transaction);
        al_size payload_offset = 0u;
        if (payload != NULL) {
            payload_offset = (al_size)(payload->data - old_base);
        }

        al_u8 *new_base = node->buffers.mempool_bytes + output_bytes;
        memmove(new_base, old_base, entry.encoded_size);
        entry.encoded_offset = output_bytes;
        if (payload != NULL) {
            al_bytes *moved_payload = transaction_payload(&entry.transaction);
            moved_payload->data = new_base + payload_offset;
        }
        node->buffers.mempool_entries[output_count] = entry;
        output_bytes += entry.encoded_size;
        ++output_count;
    }

    node->mempool_count = output_count;
    node->mempool_bytes_used = output_bytes;
}

al_status al_node_accept_block(al_node *node, const al_block *block) {
    if (node == NULL || block == NULL) {
        return AL_ERR_INVALID_ARG;
    }

    node->receipt_count = 0u;
    al_arena_reset(node->execution_arena);
    const al_block_header *parent = node->has_head ? &node->head : NULL;
    al_status status = al_block_execute(
        block, parent, &node->genesis, node->state, node->buffers.receipts,
        node->buffers.receipt_capacity, node->execution_arena);
    if (status != AL_OK) {
        al_arena_reset(node->execution_arena);
        ++node->stats.blocks_rejected;
        return status;
    }

    node->head = block->header;
    node->has_head = AL_TRUE;
    node->receipt_count = block->transaction_count;
    ++node->stats.blocks_accepted;
    mempool_compact(node);
    return AL_OK;
}

al_status al_node_accept_encoded_block(al_node *node, al_bytes encoded) {
    if (node == NULL || encoded.data == NULL || encoded.len == 0u) {
        return AL_ERR_INVALID_ARG;
    }

    al_block block;
    al_status status = al_block_decode(
        encoded, node->buffers.block_transactions,
        node->buffers.block_transaction_capacity, &block);
    if (status != AL_OK) {
        ++node->stats.blocks_rejected;
        return status;
    }
    return al_node_accept_block(node, &block);
}

static al_size node_select_transactions(al_node *node, al_size limit) {
    al_size available = node->mempool_count;
    if (available > node->buffers.block_transaction_capacity) {
        available = node->buffers.block_transaction_capacity;
    }
    if (available > limit) {
        available = limit;
    }

    al_resources reserved = al_resources_zero();
    al_size selected = 0u;
    while (selected < available) {
        const al_transaction *transaction =
            &node->buffers.mempool_entries[selected].transaction;
        al_resources next = al_resources_zero();
        if (al_resources_add(reserved, transaction->resource_limit, &next) !=
                AL_OK ||
            !al_resources_within(next, node->genesis.fees.block_limit)) {
            break;
        }

        node->buffers.block_transactions[selected] = *transaction;
        reserved = next;
        ++selected;
    }
    return selected;
}

al_status al_node_produce_block(al_node *node,
                                const al_node_proposal *proposal,
                                al_bytes_mut encoded_out, al_size *written) {
    if (written == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    *written = 0u;
    if (node == NULL || proposal == NULL ||
        (encoded_out.data == NULL && encoded_out.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }

    mempool_compact(node);
    al_arena_reset(node->execution_arena);
    node->receipt_count = 0u;

    al_block block;
    al_memzero(&block, sizeof(block));
    block.header.protocol_day = proposal->protocol_day;
    block.header.proposer = proposal->proposer;
    block.header.tip_flat = proposal->tip_flat;
    block.header.tip_weighted = proposal->tip_weighted;
    block.header.tip_bonded = proposal->tip_bonded;
    block.transaction_count = node_select_transactions(
        node, proposal->transaction_limit);
    block.transactions = node->buffers.block_transactions;

    al_state_snapshot snapshot = al_state_snapshot_take(node->state);
    const al_block_header *parent = node->has_head ? &node->head : NULL;
    al_status status = al_block_produce(
        &block, parent, &node->genesis, node->state, node->buffers.receipts,
        node->buffers.receipt_capacity, node->execution_arena);
    if (status == AL_OK) {
        status = al_block_encode(&block, encoded_out, written);
    }
    if (status != AL_OK) {
        al_status restore_status =
            al_state_snapshot_restore(node->state, snapshot);
        al_arena_reset(node->execution_arena);
        node->receipt_count = 0u;
        return restore_status == AL_OK ? status : restore_status;
    }

    node->head = block.header;
    node->has_head = AL_TRUE;
    node->receipt_count = block.transaction_count;
    ++node->stats.blocks_produced;
    ++node->stats.blocks_accepted;
    mempool_compact(node);
    return AL_OK;
}

al_height al_node_next_height(const al_node *node) {
    al_height height = 0u;
    return node != NULL && next_height_checked(node, &height) == AL_OK
               ? height
               : UINT64_MAX;
}

const al_block_header *al_node_head(const al_node *node) {
    return node != NULL && node->has_head ? &node->head : NULL;
}

const al_node_mempool_entry *al_node_mempool_at(const al_node *node,
                                                al_size index) {
    return node != NULL && index < node->mempool_count
               ? &node->buffers.mempool_entries[index]
               : NULL;
}

const al_receipt *al_node_receipts(const al_node *node, al_size *count_out) {
    if (count_out != NULL) {
        *count_out = node != NULL ? node->receipt_count : 0u;
    }
    return node != NULL && node->receipt_count != 0u
               ? node->buffers.receipts
               : NULL;
}
