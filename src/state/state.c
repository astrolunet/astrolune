#include "astrolune/state.h"
#include "internal/common.h"

#include <string.h>

#define AL_ACCOUNT_ENCODED_SIZE 128u

typedef struct al_state_impl {
    al_state_store store;
    al_amount      storage_deposit_per_byte;
    al_hash256     empty[AL_STATE_TREE_DEPTH + 1u];
} al_state_impl;

static al_bool hash_equal(const al_hash256 *a, const al_hash256 *b) {
    return al_hash_eq(a, b);
}

static void state_node_hash(const al_state_node *node, al_hash256 *out) {
    if (node->kind == AL_STATE_NODE_BRANCH) {
        al_hash_tagged_pair(AL_TAG_SMT_NODE, &node->first, &node->second, out);
    } else if (node->kind == AL_STATE_NODE_LEAF) {
        al_hash_tagged_pair(AL_TAG_SMT_LEAF, &node->first, &node->second, out);
    } else {
        *out = al_hash_zero();
    }
}

static al_bool node_equal(const al_state_node *a, const al_state_node *b) {
    return (a->kind == b->kind && hash_equal(&a->first, &b->first) &&
            hash_equal(&a->second, &b->second)) ? AL_TRUE : AL_FALSE;
}

static al_status memory_node_get(void *context, const al_hash256 *hash,
                                 al_state_node *out) {
    al_state_memory_store *memory = (al_state_memory_store *)context;
    if (memory == NULL || hash == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    for (al_size i = 0u; i < memory->node_count; ++i) {
        if (hash_equal(hash, &memory->nodes[i].hash)) {
            *out = memory->nodes[i].node;
            return AL_OK;
        }
    }
    return AL_ERR_NOT_FOUND;
}

static al_status memory_node_put(void *context, const al_hash256 *hash,
                                 const al_state_node *node) {
    al_state_memory_store *memory = (al_state_memory_store *)context;
    if (memory == NULL || hash == NULL || node == NULL) {
        return AL_ERR_INVALID_ARG;
    }

    al_hash256 actual;
    state_node_hash(node, &actual);
    if (!hash_equal(hash, &actual)) {
        return AL_ERR_STATE_CORRUPT;
    }
    for (al_size i = 0u; i < memory->node_count; ++i) {
        if (hash_equal(hash, &memory->nodes[i].hash)) {
            return node_equal(node, &memory->nodes[i].node)
                       ? AL_OK : AL_ERR_STATE_CORRUPT;
        }
    }
    if (memory->node_count == memory->node_capacity) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    memory->nodes[memory->node_count].hash = *hash;
    memory->nodes[memory->node_count].node = *node;
    ++memory->node_count;
    return AL_OK;
}

static al_status memory_value_get(void *context, const al_hash256 *hash,
                                  al_bytes *out) {
    al_state_memory_store *memory = (al_state_memory_store *)context;
    if (memory == NULL || hash == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    for (al_size i = 0u; i < memory->value_count; ++i) {
        if (hash_equal(hash, &memory->values[i].hash)) {
            *out = memory->values[i].value;
            return AL_OK;
        }
    }
    return AL_ERR_NOT_FOUND;
}

static al_status memory_value_put(void *context, const al_hash256 *hash,
                                  al_bytes value) {
    al_state_memory_store *memory = (al_state_memory_store *)context;
    if (memory == NULL || hash == NULL ||
        (value.data == NULL && value.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    for (al_size i = 0u; i < memory->value_count; ++i) {
        if (hash_equal(hash, &memory->values[i].hash)) {
            return al_bytes_eq(memory->values[i].value, value)
                       ? AL_OK : AL_ERR_STATE_CORRUPT;
        }
    }
    if (memory->value_count == memory->value_capacity) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    al_u8 *copy = (al_u8 *)al_arena_dup(memory->arena, value.data, value.len);
    if (copy == NULL && value.len != 0u) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    memory->values[memory->value_count].hash = *hash;
    memory->values[memory->value_count].value =
        al_bytes_make(copy, value.len);
    ++memory->value_count;
    return AL_OK;
}

al_status al_state_memory_store_init(al_state_memory_store *memory,
                                     al_state_memory_node *nodes,
                                     al_size node_capacity,
                                     al_state_memory_value *values,
                                     al_size value_capacity,
                                     al_arena *arena) {
    if (memory == NULL || arena == NULL ||
        (nodes == NULL && node_capacity != 0u) ||
        (values == NULL && value_capacity != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    memory->nodes = nodes;
    memory->node_count = 0u;
    memory->node_capacity = node_capacity;
    memory->values = values;
    memory->value_count = 0u;
    memory->value_capacity = value_capacity;
    memory->arena = arena;
    return AL_OK;
}

al_state_store al_state_memory_store_interface(al_state_memory_store *memory) {
    al_state_store store;
    store.context = memory;
    store.node_get = memory_node_get;
    store.node_put = memory_node_put;
    store.value_get = memory_value_get;
    store.value_put = memory_value_put;
    return store;
}

static al_bool store_valid(const al_state_store *store) {
    return (store != NULL && store->node_get != NULL &&
            store->node_put != NULL && store->value_get != NULL &&
            store->value_put != NULL) ? AL_TRUE : AL_FALSE;
}

static void empty_hashes_init(al_hash256 empty[AL_STATE_TREE_DEPTH + 1u]) {
    empty[AL_STATE_TREE_DEPTH] = al_hash_zero();
    for (al_size depth = AL_STATE_TREE_DEPTH; depth-- > 0u;) {
        al_hash_tagged_pair(AL_TAG_SMT_NODE, &empty[depth + 1u],
                            &empty[depth + 1u], &empty[depth]);
    }
}

static al_state_impl *state_impl(const al_state *state) {
    return (state != NULL) ? (al_state_impl *)state->impl : NULL;
}

static al_status checked_node_get(const al_state_impl *impl,
                                  const al_hash256 *hash,
                                  al_state_node_kind kind,
                                  al_state_node *out) {
    al_status status = impl->store.node_get(impl->store.context, hash, out);
    if (status != AL_OK) {
        return (status == AL_ERR_NOT_FOUND) ? AL_ERR_STATE_CORRUPT : status;
    }
    al_hash256 actual;
    state_node_hash(out, &actual);
    if (out->kind != kind || !hash_equal(hash, &actual)) {
        return AL_ERR_STATE_CORRUPT;
    }
    return AL_OK;
}

static al_status smt_lookup(const al_state_impl *impl,
                            const al_hash256 *root,
                            const al_hash256 *key,
                            al_hash256 *value_hash,
                            al_smt_proof *proof) {
    al_hash256 current = *root;
    if (proof != NULL) {
        memset(proof->sibling_bitmap, 0, sizeof(proof->sibling_bitmap));
        proof->key = *key;
        proof->value_hash = al_hash_zero();
        proof->sibling_count = 0u;
        proof->exists = AL_FALSE;
    }

    for (al_size depth = 0u; depth < AL_STATE_TREE_DEPTH; ++depth) {
        al_hash256 sibling = impl->empty[depth + 1u];
        if (!hash_equal(&current, &impl->empty[depth])) {
            al_state_node branch;
            AL_TRY(checked_node_get(impl, &current, AL_STATE_NODE_BRANCH,
                                    &branch));
            if (al_hash_bit(key, depth)) {
                current = branch.second;
                sibling = branch.first;
            } else {
                current = branch.first;
                sibling = branch.second;
            }
        } else {
            current = impl->empty[depth + 1u];
        }

        if (proof != NULL &&
            !hash_equal(&sibling, &impl->empty[depth + 1u])) {
            if (proof->siblings == NULL ||
                proof->sibling_count == proof->sibling_capacity) {
                return AL_ERR_BUFFER_TOO_SMALL;
            }
            proof->sibling_bitmap[depth / 8u] |=
                (al_u8)(0x80u >> (depth % 8u));
            proof->siblings[proof->sibling_count++] = sibling;
        }
    }

    if (hash_equal(&current, &impl->empty[AL_STATE_TREE_DEPTH])) {
        if (value_hash != NULL) {
            *value_hash = al_hash_zero();
        }
        return AL_ERR_NOT_FOUND;
    }

    al_state_node leaf;
    AL_TRY(checked_node_get(impl, &current, AL_STATE_NODE_LEAF, &leaf));
    if (!hash_equal(&leaf.first, key)) {
        return AL_ERR_STATE_CORRUPT;
    }
    if (value_hash != NULL) {
        *value_hash = leaf.second;
    }
    if (proof != NULL) {
        proof->value_hash = leaf.second;
        proof->exists = AL_TRUE;
    }
    return AL_OK;
}

static al_status smt_update(const al_state_impl *impl,
                            const al_hash256 *root,
                            const al_hash256 *key,
                            const al_hash256 *value_hash,
                            al_hash256 *new_root) {
    al_hash256 siblings[AL_STATE_TREE_DEPTH];
    al_hash256 current = *root;

    for (al_size depth = 0u; depth < AL_STATE_TREE_DEPTH; ++depth) {
        siblings[depth] = impl->empty[depth + 1u];
        if (!hash_equal(&current, &impl->empty[depth])) {
            al_state_node branch;
            AL_TRY(checked_node_get(impl, &current, AL_STATE_NODE_BRANCH,
                                    &branch));
            if (al_hash_bit(key, depth)) {
                current = branch.second;
                siblings[depth] = branch.first;
            } else {
                current = branch.first;
                siblings[depth] = branch.second;
            }
        } else {
            current = impl->empty[depth + 1u];
        }
    }

    if (!hash_equal(&current, &impl->empty[AL_STATE_TREE_DEPTH])) {
        al_state_node old_leaf;
        AL_TRY(checked_node_get(impl, &current, AL_STATE_NODE_LEAF,
                                &old_leaf));
        if (!hash_equal(&old_leaf.first, key)) {
            return AL_ERR_STATE_CORRUPT;
        }
    }

    if (al_hash_is_zero(value_hash)) {
        current = impl->empty[AL_STATE_TREE_DEPTH];
    } else {
        const al_state_node leaf = { AL_STATE_NODE_LEAF, *key, *value_hash };
        state_node_hash(&leaf, &current);
        AL_TRY(impl->store.node_put(impl->store.context, &current, &leaf));
    }

    for (al_size depth = AL_STATE_TREE_DEPTH; depth-- > 0u;) {
        al_state_node branch;
        branch.kind = AL_STATE_NODE_BRANCH;
        if (al_hash_bit(key, depth)) {
            branch.first = siblings[depth];
            branch.second = current;
        } else {
            branch.first = current;
            branch.second = siblings[depth];
        }
        state_node_hash(&branch, &current);
        if (!hash_equal(&current, &impl->empty[depth])) {
            AL_TRY(impl->store.node_put(impl->store.context, &current,
                                        &branch));
        }
    }
    *new_root = current;
    return AL_OK;
}

static void account_key(const al_address *address, al_hash256 *out) {
    al_hash_tagged(AL_TAG_ACCOUNT_KEY, address->bytes, AL_ADDRESS_SIZE, out);
}

static al_status account_encode(const al_account *account,
                                al_u8 out[AL_ACCOUNT_ENCODED_SIZE]) {
    al_writer writer;
    al_writer_init(&writer, out, AL_ACCOUNT_ENCODED_SIZE);
    al_writer_address(&writer, &account->address);
    al_writer_u64(&writer, account->balance);
    al_writer_u64(&writer, account->nonce);
    al_writer_hash(&writer, &account->code_hash);
    al_writer_hash(&writer, &account->storage_root);
    al_writer_u64(&writer, account->storage_bytes);
    al_writer_u64(&writer, account->storage_deposit);
    return al_writer_finish(&writer);
}

static al_status account_decode(al_bytes encoded, al_account *out) {
    if (out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_reader reader;
    al_reader_init(&reader, encoded);
    al_memzero(out, sizeof(*out));
    al_reader_address(&reader, &out->address);
    out->balance = al_reader_u64(&reader);
    out->nonce = al_reader_u64(&reader);
    al_reader_hash(&reader, &out->code_hash);
    al_reader_hash(&reader, &out->storage_root);
    out->storage_bytes = al_reader_u64(&reader);
    out->storage_deposit = al_reader_u64(&reader);
    return al_reader_finish(&reader);
}

static al_status account_get_at(const al_state *state,
                                const al_hash256 *root,
                                const al_address *address,
                                al_account *out) {
    al_state_impl *impl = state_impl(state);
    if (impl == NULL || root == NULL || address == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_hash256 key;
    al_hash256 value_hash;
    account_key(address, &key);
    AL_TRY(smt_lookup(impl, root, &key, &value_hash, NULL));

    al_bytes encoded;
    al_status status = impl->store.value_get(impl->store.context, &value_hash,
                                             &encoded);
    if (status != AL_OK) {
        return (status == AL_ERR_NOT_FOUND) ? AL_ERR_STATE_CORRUPT : status;
    }
    if (encoded.len != AL_ACCOUNT_ENCODED_SIZE) {
        return AL_ERR_STATE_CORRUPT;
    }
    AL_TRY(account_decode(encoded, out));
    return al_address_eq(&out->address, address) ? AL_OK
                                                 : AL_ERR_STATE_CORRUPT;
}

static al_status account_put_at(al_state *state, al_hash256 *root,
                                const al_account *account) {
    al_state_impl *impl = state_impl(state);
    if (impl == NULL || root == NULL || account == NULL ||
        al_address_is_zero(&account->address)) {
        return AL_ERR_INVALID_ARG;
    }

    al_u8 encoded[AL_ACCOUNT_ENCODED_SIZE];
    AL_TRY(account_encode(account, encoded));
    al_hash256 value_hash;
    al_hash_tagged(AL_TAG_ACCOUNT_VALUE, encoded, sizeof(encoded),
                   &value_hash);
    AL_TRY(impl->store.value_put(impl->store.context, &value_hash,
                                 al_bytes_make(encoded, sizeof(encoded))));
    al_hash256 key;
    account_key(&account->address, &key);
    return smt_update(impl, root, &key, &value_hash, root);
}

static al_status account_remove_at(al_state *state, al_hash256 *root,
                                   const al_address *address) {
    al_state_impl *impl = state_impl(state);
    if (impl == NULL || root == NULL || address == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_hash256 key;
    al_hash256 existing;
    account_key(address, &key);
    AL_TRY(smt_lookup(impl, root, &key, &existing, NULL));
    const al_hash256 zero = al_hash_zero();
    return smt_update(impl, root, &key, &zero, root);
}

al_status al_state_open(al_state *state, const al_state_store *store,
                        al_arena *arena,
                        al_amount storage_deposit_per_byte,
                        al_height height, const al_hash256 *root) {
    if (state == NULL || !store_valid(store) || arena == NULL || root == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_state_impl *impl = AL_ARENA_NEW(arena, al_state_impl);
    if (impl == NULL) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    impl->store = *store;
    impl->storage_deposit_per_byte = storage_deposit_per_byte;
    empty_hashes_init(impl->empty);
    if (!hash_equal(root, &impl->empty[0])) {
        al_state_node node;
        AL_TRY(checked_node_get(impl, root, AL_STATE_NODE_BRANCH, &node));
    }
    state->impl = impl;
    state->height = height;
    state->root = *root;
    return AL_OK;
}

al_status al_state_init(al_state *state, const al_state_store *store,
                        al_arena *arena,
                        al_amount storage_deposit_per_byte) {
    if (state == NULL || !store_valid(store) || arena == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_hash256 empty[AL_STATE_TREE_DEPTH + 1u];
    empty_hashes_init(empty);
    return al_state_open(state, store, arena, storage_deposit_per_byte, 0u,
                         &empty[0]);
}

void al_state_clear(al_state *state) {
    al_state_impl *impl = state_impl(state);
    if (impl != NULL) {
        state->height = 0u;
        state->root = impl->empty[0];
    }
}

al_status al_state_get(const al_state *state, const al_address *address,
                       al_account *out) {
    return account_get_at(state, (state != NULL) ? &state->root : NULL,
                          address, out);
}

al_status al_state_upsert(al_state *state, const al_account *account) {
    if (state == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    return account_put_at(state, &state->root, account);
}

al_status al_state_remove(al_state *state, const al_address *address) {
    if (state == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    return account_remove_at(state, &state->root, address);
}

al_status al_state_transfer(al_state *state, const al_address *from,
                            const al_address *to, al_amount amount) {
    al_state_txn txn;
    AL_TRY(al_state_txn_begin(state, &txn));
    al_status status = al_state_txn_transfer(&txn, from, to, amount);
    if (status == AL_OK) {
        status = al_state_txn_commit(&txn);
    } else {
        al_state_txn_rollback(&txn);
    }
    return status;
}

al_hash256 al_state_root(const al_state *state) {
    return (state != NULL) ? state->root : al_hash_zero();
}

al_state_snapshot al_state_snapshot_take(const al_state *state) {
    al_state_snapshot snapshot;
    snapshot.height = (state != NULL) ? state->height : 0u;
    snapshot.root = (state != NULL) ? state->root : al_hash_zero();
    return snapshot;
}

al_status al_state_snapshot_restore(al_state *state,
                                    al_state_snapshot snapshot) {
    al_state_impl *impl = state_impl(state);
    if (impl == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    if (!hash_equal(&snapshot.root, &impl->empty[0])) {
        al_state_node node;
        AL_TRY(checked_node_get(impl, &snapshot.root, AL_STATE_NODE_BRANCH,
                                &node));
    }
    state->height = snapshot.height;
    state->root = snapshot.root;
    return AL_OK;
}

al_status al_state_txn_begin(al_state *state, al_state_txn *txn) {
    if (state_impl(state) == NULL || txn == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    txn->state = state;
    txn->root = state->root;
    txn->resources = al_resources_zero();
    txn->active = AL_TRUE;
    return AL_OK;
}

static al_bool txn_valid(const al_state_txn *txn) {
    return (txn != NULL && txn->active && state_impl(txn->state) != NULL)
               ? AL_TRUE : AL_FALSE;
}

al_status al_state_txn_get(const al_state_txn *txn,
                           const al_address *address, al_account *out) {
    if (!txn_valid(txn)) {
        return AL_ERR_INVALID_ARG;
    }
    return account_get_at(txn->state, &txn->root, address, out);
}

al_status al_state_txn_upsert(al_state_txn *txn,
                              const al_account *account) {
    if (!txn_valid(txn)) {
        return AL_ERR_INVALID_ARG;
    }
    return account_put_at(txn->state, &txn->root, account);
}

al_status al_state_txn_remove(al_state_txn *txn,
                              const al_address *address) {
    if (!txn_valid(txn)) {
        return AL_ERR_INVALID_ARG;
    }
    return account_remove_at(txn->state, &txn->root, address);
}

al_status al_state_txn_transfer(al_state_txn *txn,
                                const al_address *from,
                                const al_address *to, al_amount amount) {
    if (!txn_valid(txn) || from == NULL || to == NULL ||
        al_address_is_zero(to) || al_address_eq(from, to)) {
        return AL_ERR_INVALID_ARG;
    }
    al_account source;
    AL_TRY(al_state_txn_get(txn, from, &source));
    if (source.balance < amount) {
        return AL_ERR_INSUFFICIENT_FUNDS;
    }

    al_account destination;
    al_status status = al_state_txn_get(txn, to, &destination);
    if (status == AL_ERR_NOT_FOUND) {
        al_memzero(&destination, sizeof(destination));
        destination.address = *to;
        destination.storage_root = state_impl(txn->state)->empty[0];
    } else if (status != AL_OK) {
        return status;
    }
    if (UINT64_MAX - destination.balance < amount) {
        return AL_ERR_ARITH_OVERFLOW;
    }
    source.balance -= amount;
    destination.balance += amount;
    AL_TRY(al_state_txn_upsert(txn, &source));
    return al_state_txn_upsert(txn, &destination);
}

al_status al_state_txn_deploy(al_state_txn *txn, const al_address *address,
                              al_amount balance, al_bytes code) {
    al_address system = al_state_potb_system_address();
    if (!txn_valid(txn) || address == NULL || al_address_is_zero(address) ||
        al_address_eq(address, &system) || code.data == NULL || code.len == 0u ||
        code.len > AL_STATE_MAX_CODE_SIZE) {
        return AL_ERR_INVALID_ARG;
    }
    al_account existing;
    al_status status = al_state_txn_get(txn, address, &existing);
    if (status == AL_OK) {
        return AL_ERR_ALREADY_EXISTS;
    }
    if (status != AL_ERR_NOT_FOUND) {
        return status;
    }

    al_account account;
    al_memzero(&account, sizeof(account));
    account.address = *address;
    account.balance = balance;
    account.storage_root = state_impl(txn->state)->empty[0];
    al_sha256_bytes(code, &account.code_hash);
    AL_TRY(state_impl(txn->state)->store.value_put(
        state_impl(txn->state)->store.context, &account.code_hash, code));
    return al_state_txn_upsert(txn, &account);
}

al_status al_state_txn_code_get(const al_state_txn *txn,
                                const al_address *contract, al_bytes *out) {
    if (!txn_valid(txn) || contract == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_account account;
    AL_TRY(al_state_txn_get(txn, contract, &account));
    if (al_hash_is_zero(&account.code_hash)) {
        return AL_ERR_NOT_FOUND;
    }
    al_state_impl *impl = state_impl(txn->state);
    AL_TRY(impl->store.value_get(impl->store.context, &account.code_hash, out));
    al_hash256 actual;
    al_sha256_bytes(*out, &actual);
    return al_hash_eq(&actual, &account.code_hash) ? AL_OK
                                                   : AL_ERR_STATE_CORRUPT;
}

static void storage_key_hash(al_bytes key, al_hash256 *out) {
    al_hash_tagged_bytes(AL_TAG_STORAGE_KEY, key, out);
}

static al_status storage_lookup(const al_state_txn *txn,
                                const al_account *contract, al_bytes key,
                                al_hash256 *value_hash) {
    al_state_impl *impl = state_impl(txn->state);
    al_hash256 key_hash;
    storage_key_hash(key, &key_hash);
    const al_hash256 *root = al_hash_is_zero(&contract->storage_root)
                                 ? &impl->empty[0] : &contract->storage_root;
    return smt_lookup(impl, root, &key_hash, value_hash, NULL);
}

al_status al_state_txn_storage_get(const al_state_txn *txn,
                                   const al_address *contract_address,
                                   al_bytes key, al_arena *arena,
                                   al_bytes *out) {
    al_address system = al_state_potb_system_address();
    if (!txn_valid(txn) || contract_address == NULL || arena == NULL ||
        out == NULL || key.len == 0u || key.len > AL_STATE_MAX_KEY_SIZE ||
        (key.data == NULL && key.len != 0u) ||
        al_address_eq(contract_address, &system)) {
        return AL_ERR_INVALID_ARG;
    }
    al_account contract;
    AL_TRY(al_state_txn_get(txn, contract_address, &contract));
    if (al_hash_is_zero(&contract.code_hash)) {
        return AL_ERR_UNSUPPORTED;
    }
    al_hash256 value_hash;
    AL_TRY(storage_lookup(txn, &contract, key, &value_hash));
    al_bytes borrowed;
    al_state_impl *impl = state_impl(txn->state);
    al_status status = impl->store.value_get(impl->store.context, &value_hash,
                                             &borrowed);
    if (status != AL_OK) {
        return (status == AL_ERR_NOT_FOUND) ? AL_ERR_STATE_CORRUPT : status;
    }
    al_u8 *copy = (al_u8 *)al_arena_dup(arena, borrowed.data, borrowed.len);
    if (copy == NULL && borrowed.len != 0u) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    *out = al_bytes_make(copy, borrowed.len);
    return AL_OK;
}

static al_status storage_change(al_state_txn *txn,
                                const al_address *contract_address,
                                al_bytes key, al_bytes value,
                                al_bool deleting) {
    al_address system = al_state_potb_system_address();
    if (!txn_valid(txn) || contract_address == NULL || key.len == 0u ||
        key.len > AL_STATE_MAX_KEY_SIZE || value.len > AL_STATE_MAX_VALUE_SIZE ||
        (key.data == NULL && key.len != 0u) ||
        (value.data == NULL && value.len != 0u) ||
        al_address_eq(contract_address, &system)) {
        return AL_ERR_INVALID_ARG;
    }

    al_account contract;
    AL_TRY(al_state_txn_get(txn, contract_address, &contract));
    if (al_hash_is_zero(&contract.code_hash)) {
        return AL_ERR_UNSUPPORTED;
    }
    al_state_impl *impl = state_impl(txn->state);
    if (al_hash_is_zero(&contract.storage_root)) {
        contract.storage_root = impl->empty[0];
    }

    al_size old_len = 0u;
    al_hash256 old_hash;
    al_status status = storage_lookup(txn, &contract, key, &old_hash);
    if (status == AL_OK) {
        al_bytes old_value;
        status = impl->store.value_get(impl->store.context, &old_hash,
                                       &old_value);
        if (status != AL_OK) {
            return (status == AL_ERR_NOT_FOUND) ? AL_ERR_STATE_CORRUPT
                                                : status;
        }
        old_len = old_value.len;
    } else if (status != AL_ERR_NOT_FOUND) {
        return status;
    } else if (deleting) {
        return AL_ERR_NOT_FOUND;
    }

    al_size new_len = deleting ? 0u : value.len;
    if (new_len > old_len) {
        al_u64 growth = (al_u64)(new_len - old_len);
        al_u64 deposit = 0u;
        if (al_mul_overflow_u64(growth, impl->storage_deposit_per_byte,
                                &deposit) || contract.balance < deposit ||
            UINT64_MAX - contract.storage_deposit < deposit) {
            return (contract.balance < deposit) ? AL_ERR_INSUFFICIENT_FUNDS
                                                : AL_ERR_ARITH_OVERFLOW;
        }
        contract.balance -= deposit;
        contract.storage_deposit += deposit;
        contract.storage_bytes += growth;
    } else if (old_len > new_len) {
        al_u64 shrink = (al_u64)(old_len - new_len);
        al_u64 refund = 0u;
        if (al_mul_overflow_u64(shrink, impl->storage_deposit_per_byte,
                                &refund) || contract.storage_bytes < shrink ||
            contract.storage_deposit < refund ||
            UINT64_MAX - contract.balance < refund) {
            return AL_ERR_STATE_CORRUPT;
        }
        contract.balance += refund;
        contract.storage_deposit -= refund;
        contract.storage_bytes -= shrink;
    }

    al_hash256 key_hash;
    storage_key_hash(key, &key_hash);
    al_hash256 value_hash = al_hash_zero();
    if (!deleting) {
        al_hash_tagged_bytes(AL_TAG_STORAGE_VALUE, value, &value_hash);
        AL_TRY(impl->store.value_put(impl->store.context, &value_hash, value));
    }
    AL_TRY(smt_update(impl, &contract.storage_root, &key_hash, &value_hash,
                      &contract.storage_root));
    AL_TRY(al_state_txn_upsert(txn, &contract));

    al_resources extra = al_resources_zero();
    extra.storage = (al_u64)key.len + (al_u64)old_len + (al_u64)new_len;
    return al_resources_add(txn->resources, extra, &txn->resources);
}

static al_status system_storage_get(const al_state_txn *txn, al_bytes key,
                                    al_arena *arena, al_bytes *out) {
    if (!txn_valid(txn) || out == NULL || key.len == 0u ||
        key.len > AL_STATE_MAX_KEY_SIZE || key.data == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_address system = al_state_potb_system_address();
    al_account account;
    AL_TRY(al_state_txn_get(txn, &system, &account));
    al_hash256 value_hash;
    AL_TRY(storage_lookup(txn, &account, key, &value_hash));
    al_bytes borrowed;
    al_state_impl *impl = state_impl(txn->state);
    AL_TRY(impl->store.value_get(impl->store.context, &value_hash, &borrowed));
    al_u8 *copy = (al_u8 *)al_arena_dup(arena, borrowed.data, borrowed.len);
    if (copy == NULL && borrowed.len != 0u) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    *out = al_bytes_make(copy, borrowed.len);
    return AL_OK;
}

static al_status system_storage_change(al_state_txn *txn, al_bytes key,
                                       al_bytes value, al_bool deleting) {
    if (!txn_valid(txn) || key.len == 0u || key.len > AL_STATE_MAX_KEY_SIZE ||
        key.data == NULL || value.len > AL_STATE_MAX_VALUE_SIZE ||
        (value.data == NULL && value.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    al_address system = al_state_potb_system_address();
    al_account account;
    al_status status = al_state_txn_get(txn, &system, &account);
    if (status == AL_ERR_NOT_FOUND) {
        if (deleting) return AL_ERR_NOT_FOUND;
        al_memzero(&account, sizeof(account));
        account.address = system;
        account.storage_root = state_impl(txn->state)->empty[0];
    } else if (status != AL_OK) {
        return status;
    }

    al_hash256 old_hash;
    al_size old_len = 0u;
    status = storage_lookup(txn, &account, key, &old_hash);
    if (status == AL_OK) {
        al_bytes old_value;
        AL_TRY(state_impl(txn->state)->store.value_get(
            state_impl(txn->state)->store.context, &old_hash, &old_value));
        old_len = old_value.len;
    } else if (status == AL_ERR_NOT_FOUND) {
        if (deleting) return AL_ERR_NOT_FOUND;
    } else {
        return status;
    }

    al_hash256 key_hash;
    storage_key_hash(key, &key_hash);
    al_hash256 value_hash = al_hash_zero();
    if (!deleting) {
        al_hash_tagged_bytes(AL_TAG_STORAGE_VALUE, value, &value_hash);
        AL_TRY(state_impl(txn->state)->store.value_put(
            state_impl(txn->state)->store.context, &value_hash, value));
    }
    AL_TRY(smt_update(state_impl(txn->state), &account.storage_root, &key_hash,
                      &value_hash, &account.storage_root));
    if (account.storage_bytes < (al_u64)old_len ||
        UINT64_MAX - (account.storage_bytes - (al_u64)old_len) <
            (deleting ? 0u : (al_u64)value.len)) {
        return AL_ERR_STATE_CORRUPT;
    }
    account.storage_bytes -= (al_u64)old_len;
    account.storage_bytes += deleting ? 0u : (al_u64)value.len;
    AL_TRY(al_state_txn_upsert(txn, &account));
    al_resources extra = al_resources_zero();
    extra.storage = (al_u64)key.len + (al_u64)old_len +
                    (deleting ? 0u : (al_u64)value.len);
    return al_resources_add(txn->resources, extra, &txn->resources);
}

al_status al_state_txn_storage_set(al_state_txn *txn,
                                   const al_address *contract,
                                   al_bytes key, al_bytes value) {
    return storage_change(txn, contract, key, value, AL_FALSE);
}

al_status al_state_txn_storage_delete(al_state_txn *txn,
                                      const al_address *contract,
                                      al_bytes key) {
    return storage_change(txn, contract, key, al_bytes_empty(), AL_TRUE);
}

al_status al_state_txn_system_storage_get(const al_state_txn *txn,
                                          al_bytes key, al_arena *arena,
                                          al_bytes *out) {
    return system_storage_get(txn, key, arena, out);
}

al_status al_state_txn_system_storage_set(al_state_txn *txn, al_bytes key,
                                          al_bytes value) {
    return system_storage_change(txn, key, value, AL_FALSE);
}

al_status al_state_txn_system_storage_delete(al_state_txn *txn, al_bytes key) {
    return system_storage_change(txn, key, al_bytes_empty(), AL_TRUE);
}

al_status al_state_txn_commit(al_state_txn *txn) {
    if (!txn_valid(txn)) {
        return AL_ERR_INVALID_ARG;
    }
    txn->state->root = txn->root;
    txn->active = AL_FALSE;
    return AL_OK;
}

void al_state_txn_rollback(al_state_txn *txn) {
    if (txn != NULL) {
        txn->active = AL_FALSE;
    }
}

al_status al_state_prove_account(const al_state *state,
                                 const al_address *address,
                                 al_smt_proof *proof) {
    al_state_impl *impl = state_impl(state);
    if (impl == NULL || address == NULL || proof == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_hash256 key;
    account_key(address, &key);
    al_status status = smt_lookup(impl, &state->root, &key, NULL, proof);
    return (status == AL_ERR_NOT_FOUND) ? AL_OK : status;
}

static al_bool proof_bit(const al_u8 bitmap[AL_STATE_TREE_DEPTH / 8u],
                         al_size depth) {
    return (bitmap[depth / 8u] & (al_u8)(0x80u >> (depth % 8u))) != 0u
               ? AL_TRUE : AL_FALSE;
}

al_bool al_smt_proof_verify(const al_hash256 *root,
                            const al_smt_proof *proof) {
    if (root == NULL || proof == NULL ||
        (proof->siblings == NULL && proof->sibling_count != 0u) ||
        proof->sibling_count > AL_STATE_TREE_DEPTH || proof->exists > AL_TRUE) {
        return AL_FALSE;
    }

    al_hash256 empty[AL_STATE_TREE_DEPTH + 1u];
    al_hash256 siblings[AL_STATE_TREE_DEPTH];
    empty_hashes_init(empty);
    al_size next = 0u;
    for (al_size depth = 0u; depth < AL_STATE_TREE_DEPTH; ++depth) {
        siblings[depth] = empty[depth + 1u];
        if (proof_bit(proof->sibling_bitmap, depth)) {
            if (next == proof->sibling_count) {
                return AL_FALSE;
            }
            siblings[depth] = proof->siblings[next++];
        }
    }
    if (next != proof->sibling_count) {
        return AL_FALSE;
    }

    al_hash256 current = empty[AL_STATE_TREE_DEPTH];
    if (proof->exists) {
        const al_state_node leaf = {
            AL_STATE_NODE_LEAF, proof->key, proof->value_hash
        };
        if (al_hash_is_zero(&proof->value_hash)) {
            return AL_FALSE;
        }
        state_node_hash(&leaf, &current);
    }
    for (al_size depth = AL_STATE_TREE_DEPTH; depth-- > 0u;) {
        if (al_hash_bit(&proof->key, depth)) {
            al_hash_tagged_pair(AL_TAG_SMT_NODE, &siblings[depth], &current,
                                &current);
        } else {
            al_hash_tagged_pair(AL_TAG_SMT_NODE, &current, &siblings[depth],
                                &current);
        }
    }
    return hash_equal(&current, root);
}

al_status al_smt_proof_encode(const al_smt_proof *proof, al_bytes_mut out,
                              al_size *written) {
    if (proof == NULL || written == NULL || proof->exists > AL_TRUE ||
        proof->sibling_count > AL_STATE_TREE_DEPTH ||
        (proof->siblings == NULL && proof->sibling_count != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    *written = 0u;
    al_writer writer;
    al_writer_init(&writer, out.data, out.len);
    al_writer_hash(&writer, &proof->key);
    al_writer_u8(&writer, proof->exists);
    al_writer_hash(&writer, &proof->value_hash);
    al_writer_raw(&writer, proof->sibling_bitmap,
                  sizeof(proof->sibling_bitmap));
    al_writer_varint(&writer, proof->sibling_count);
    for (al_size i = 0u; i < proof->sibling_count; ++i) {
        al_writer_hash(&writer, &proof->siblings[i]);
    }
    *written = al_writer_len(&writer);
    return al_writer_finish(&writer);
}

al_status al_smt_proof_decode(al_bytes encoded,
                              al_hash256 *sibling_storage,
                              al_size sibling_capacity,
                              al_smt_proof *out) {
    if (out == NULL ||
        (sibling_storage == NULL && sibling_capacity != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    al_reader reader;
    al_reader_init(&reader, encoded);
    al_memzero(out, sizeof(*out));
    out->siblings = sibling_storage;
    out->sibling_capacity = sibling_capacity;
    al_reader_hash(&reader, &out->key);
    out->exists = al_reader_u8(&reader);
    al_reader_hash(&reader, &out->value_hash);
    al_reader_bytes(&reader, out->sibling_bitmap,
                    sizeof(out->sibling_bitmap));
    al_u64 count = al_reader_varint(&reader);
    if (count > AL_STATE_TREE_DEPTH || count > sibling_capacity) {
        al_reader_fail(&reader, AL_ERR_BUFFER_TOO_SMALL);
        count = 0u;
    }
    out->sibling_count = (al_size)count;
    for (al_size i = 0u; i < out->sibling_count; ++i) {
        al_reader_hash(&reader, &out->siblings[i]);
    }
    AL_TRY(al_reader_finish(&reader));
    if (out->exists > AL_TRUE) {
        return AL_ERR_NOT_CANONICAL;
    }
    al_size bitmap_count = 0u;
    for (al_size depth = 0u; depth < AL_STATE_TREE_DEPTH; ++depth) {
        bitmap_count += proof_bit(out->sibling_bitmap, depth) ? 1u : 0u;
    }
    if (bitmap_count != out->sibling_count ||
        (!out->exists && !al_hash_is_zero(&out->value_hash))) {
        return AL_ERR_NOT_CANONICAL;
    }
    return AL_OK;
}

al_address al_state_potb_system_address(void) {
    static const char label[] = "astrolune.potb.system.v1";
    al_hash256 hash;
    al_address address;
    al_hash_tagged(AL_TAG_POTB_RECORD, label, sizeof(label) - 1u, &hash);
    memcpy(address.bytes, hash.bytes, sizeof(address.bytes));
    return address;
}
