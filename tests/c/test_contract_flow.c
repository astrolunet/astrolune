/*
 * Full contract flow against the real transaction host:
 * compile-free - the container here is hand-assembled with the same encoder
 * the toolchain uses, then deployed through al_node and invoked through a
 * CALL transaction, exercising al_state_txn storage exactly as production.
 */

#include "altest.h"
#include "astrolune/block.h"
#include "astrolune/vm.h"
#include "internal/common.h"
#include "node.h"
#include "state_fixture.h"

/* --- container builder (mirrors tools/trocto lowering conventions) ------- */

static void push_u64(al_u8 *code, al_size *len, al_u64 v) {
    code[(*len)++] = AL_VM_PUSH64;
    for (al_u32 i = 0u; i < 8u; ++i)
        code[(*len)++] = (al_u8)((v >> (i * 8u)) & 0xffu);
}
static void push_op(al_u8 *code, al_size *len, al_vm_opcode op) {
    code[(*len)++] = (al_u8)op;
}

/*
 * Two functions:
 *   f0 (default entry): STOP
 *   f1 set_and_get():   calldata = 8-byte value V
 *                       storage["k"] += V ; return storage["k"]
 * The storage key is 32 zero bytes - unique enough for one contract.
 */
static al_status build_counter_container(al_u8 *out, al_size cap,
                                         al_size *written) {
    al_u8 code[512];
    al_size len = 0;

    /* f0 @0: STOP */
    push_op(code, &len, AL_VM_STOP);

    /* f1 @1 */
    const al_u32 f1_offset = (al_u32)len;
    /* required = 8; actual = CALLDATA_SIZE; if actual < required revert(1) */
    push_op(code, &len, AL_VM_CALLDATA_SIZE);
    push_u64(code, &len, 8u);
    push_op(code, &len, AL_VM_GE);
    /* jump-if over the revert: target patched below */
    al_size jumpi_at = len;
    push_op(code, &len, AL_VM_JUMPI);
    for (al_u32 i = 0u; i < 4u; ++i) code[len++] = 0u;
    push_u64(code, &len, 1u);           /* revert code 1 */
    push_u64(code, &len, 32u);          /* scratch */
    push_op(code, &len, AL_VM_STORE64);
    push_u64(code, &len, 32u);
    push_u64(code, &len, 8u);
    push_op(code, &len, AL_VM_REVERT);
    const al_u32 after_revert = (al_u32)len;
    code[jumpi_at + 1u] = (al_u8)(after_revert & 0xffu);
    code[jumpi_at + 2u] = (al_u8)((after_revert >> 8u) & 0xffu);
    code[jumpi_at + 3u] = (al_u8)((after_revert >> 16u) & 0xffu);
    code[jumpi_at + 4u] = (al_u8)((after_revert >> 24u) & 0xffu);

    /* copy arg into frame slot 72 */
    push_u64(code, &len, 0u);
    push_u64(code, &len, 72u);
    push_u64(code, &len, 8u);
    push_op(code, &len, AL_VM_CALLDATA_COPY);

    /* zero value buffer at 32 */
    push_u64(code, &len, 0u);
    push_u64(code, &len, 32u);
    push_op(code, &len, AL_VM_STORE64);

    /* storage_get(key@0,32 -> out@32,32): key is 32 zero bytes already */
    push_u64(code, &len, 0u);
    push_u64(code, &len, 32u);
    push_u64(code, &len, 32u);
    push_u64(code, &len, 32u);
    push_op(code, &len, AL_VM_HOST);
    code[len++] = (al_u8)(AL_VM_HOST_STORAGE_GET & 0xffu);
    code[len++] = (al_u8)(AL_VM_HOST_STORAGE_GET >> 8u);
    push_op(code, &len, AL_VM_DROP);    /* stored length */

    /* value += arg */
    push_u64(code, &len, 32u);
    push_op(code, &len, AL_VM_LOAD64);
    push_u64(code, &len, 72u);
    push_op(code, &len, AL_VM_LOAD64);
    push_op(code, &len, AL_VM_ADD);
    push_u64(code, &len, 32u);
    push_op(code, &len, AL_VM_STORE64);

    /* storage_set(key@0,32, val@32,8) */
    push_u64(code, &len, 0u);
    push_u64(code, &len, 32u);
    push_u64(code, &len, 32u);
    push_u64(code, &len, 8u);
    push_op(code, &len, AL_VM_HOST);
    code[len++] = (al_u8)(AL_VM_HOST_STORAGE_SET & 0xffu);
    code[len++] = (al_u8)(AL_VM_HOST_STORAGE_SET >> 8u);

    /* return value */
    push_u64(code, &len, 32u);
    push_op(code, &len, AL_VM_LOAD64);
    push_u64(code, &len, 64u);
    push_op(code, &len, AL_VM_STORE64);
    push_u64(code, &len, 64u);
    push_u64(code, &len, 8u);
    push_op(code, &len, AL_VM_RETURN);

    al_vm_function functions[2] = {
        { 0u, 0u, 0u, 4u, 0u },
        { f1_offset, 0u, 1u, 6u, 0u },
    };
    return al_vm_container_encode(functions, 2u,
                                  al_bytes_make(code, len),
                                  (al_bytes_mut){ out, cap }, written);
}

/* --- fixtures ------------------------------------------------------------- */

typedef struct flow_fixture {
    al_test_state_fixture states;
    al_genesis genesis;
    al_arena execution_arena;
    al_transaction transactions[16];
    al_receipt receipts[16];
    al_node_mempool_entry mempool_entries[16];
    al_u8 mempool_bytes[256u * 1024u];
    al_node node;
} flow_fixture;

static al_status flow_fixture_init(flow_fixture *f) {
    memset(f, 0, sizeof(*f));
    al_test_state_fixture_init(&f->states, 1u);
    f->genesis.version = AL_GENESIS_VERSION;
    f->genesis.chain_id = 17u;
    /* initial_state_root is bound later, after the caller has written the
     * devnet-style allocations into the tree - exactly what init-genesis
     * does for prefunded accounts. */
    f->genesis.initial_state_root = f->states.state.root;
    al_resources limit = { 1000000u, 1000000u, 1000000u, 1000000u };
    f->genesis.fees.block_limit = limit;
    al_resources target = { 500000u, 500000u, 500000u, 500000u };
    f->genesis.fees.target = target;
    al_resources price = { 1u, 1u, 1u, 1u };
    f->genesis.fees.initial_base_price = price;
    f->genesis.fees.storage_deposit_per_byte = 1u;
    f->genesis.schedule = al_vm_resource_schedule_default();
    f->genesis.vm_stack_limit = AL_VM_DEFAULT_STACK;
    f->genesis.vm_memory_limit = AL_VM_DEFAULT_MEMORY;
    f->genesis.vm_call_depth_limit = AL_VM_DEFAULT_CALL_DEPTH;
    f->genesis.potb = al_potb_params_default();

    AL_TRY(al_arena_init(&f->execution_arena, 1024u * 1024u));
    return AL_OK;
}

/* Bind the node once the caller finished writing genesis allocations; the
 * first produced block requires state.root == genesis.initial_state_root. */
static al_status flow_fixture_bind_node(flow_fixture *f) {
    f->genesis.initial_state_root = al_state_root(&f->states.state);

    al_node_buffers buffers;
    memset(&buffers, 0, sizeof(buffers));
    buffers.mempool_entries = f->mempool_entries;
    buffers.mempool_capacity = 16u;
    buffers.mempool_bytes = f->mempool_bytes;
    buffers.mempool_bytes_capacity = sizeof(f->mempool_bytes);
    buffers.block_transactions = f->transactions;
    buffers.block_transaction_capacity = 16u;
    buffers.receipts = f->receipts;
    buffers.receipt_capacity = 16u;
    return al_node_init(&f->node, &f->genesis, &f->states.state,
                        &f->execution_arena, buffers);
}

static void flow_fixture_free(flow_fixture *f) {
    al_arena_destroy(&f->execution_arena);
    al_test_state_fixture_destroy(&f->states);
}

/* Fund `address` directly in committed state (devnet-style allocation). */
static al_status fund(flow_fixture *f, const al_address *address,
                      al_amount balance) {
    al_account account;
    memset(&account, 0, sizeof(account));
    account.address = *address;
    account.balance = balance;
    return al_state_upsert(&f->states.state, &account);
}

/* Sign+submit helper for the two shapes this test needs. */
static al_status submit_call_or_deploy(flow_fixture *f, const al_keypair *kp,
                                       al_nonce nonce, int deploy,
                                       const al_address *target,
                                       al_u16 entrypoint, al_u64 argument) {
    al_transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = AL_TX_VERSION;
    tx.chain_id = f->genesis.chain_id;
    tx.expiry_height = nonce + 100u;
    tx.sender = kp->pk;
    tx.nonce = nonce;
    tx.resource_limit.compute = 400000u;
    tx.resource_limit.memory = 400000u;
    tx.resource_limit.storage = 400000u;
    tx.resource_limit.bandwidth = 400000u;
    tx.max_base_price.compute = 100u;
    tx.max_base_price.memory = 100u;
    tx.max_base_price.storage = 100u;
    tx.max_base_price.bandwidth = 100u;

    static al_u8 payload[4096];
    al_size payload_len = 0u;
    if (deploy) {
        al_status status = build_counter_container(
            payload, sizeof(payload), &payload_len);
        if (status != AL_OK) return status;
        tx.type = AL_TX_DEPLOY;
        /* Endow the contract so it can pay storage deposits. */
        tx.body.deploy.value = UINT64_C(1000000);
        tx.body.deploy.container =
            al_bytes_make(payload, payload_len);
    } else {
        tx.type = AL_TX_CALL;
        tx.body.call.contract = *target;
        tx.body.call.entrypoint = entrypoint;
        al_store_le64(payload, argument);
        tx.body.call.calldata = al_bytes_make(payload, 8u);
    }
    AL_TRY(al_tx_sign(&tx, &kp->sk));

    static al_u8 encoded[AL_TX_MAX_SIZE];
    al_size encoded_len = 0u;
    AL_TRY(al_tx_encode(&tx, (al_bytes_mut){ encoded, sizeof(encoded) },
                        &encoded_len));
    return al_node_submit_transaction(
        &f->node, al_bytes_make(encoded, encoded_len), NULL);
}

/* Produce a block including everything currently admitted. */
static al_status produce_one(flow_fixture *f, const al_keypair *proposer) {
    al_node_proposal proposal;
    memset(&proposal, 0, sizeof(proposal));
    proposal.proposer = proposer->pk;
    al_address_from_pubkey(&proposer->pk, &proposal.tip_flat);
    proposal.tip_weighted = proposal.tip_flat;
    proposal.tip_bonded = proposal.tip_flat;
    proposal.transaction_limit = f->node.mempool_count;

    static al_u8 encoded[512u * 1024u];
    al_size written = 0u;
    al_status status = al_node_produce_block(
        &f->node, &proposal, (al_bytes_mut){ encoded, sizeof(encoded) },
        &written);
    return status;
}

/* Read the counter through a dry-run style staged apply: snapshot, execute
 * an internal read by calling the contract's own storage path is not needed
 * here - inspect via al_state_txn_storage_get directly. */
static al_status read_counter(flow_fixture *f, const al_address *contract,
                              al_u64 *out) {
    al_account account;
    al_status status = al_state_get(&f->states.state, contract, &account);
    if (status != AL_OK) return status;
    if (al_hash_is_zero(&account.storage_root)) {
        *out = 0u;
        return AL_OK;
    }

    /* Storage lives under the contract's sub-tree; reach it through a
     * staged transaction using the public system API with a zero key. */
    al_state_txn txn;
    AL_TRY(al_state_txn_begin(&f->states.state, &txn));
    al_u8 key[32];
    memset(key, 0, sizeof(key));
    al_bytes value;
    status = al_state_txn_storage_get(&txn, contract,
                                      al_bytes_make(key, sizeof(key)),
                                      &f->execution_arena, &value);
    al_state_txn_rollback(&txn);
    if (status == AL_ERR_NOT_FOUND) {
        *out = 0u;
        return AL_OK;
    }
    if (status != AL_OK) return status;
    if (value.len < 8u) return AL_ERR_STATE_CORRUPT;
    *out = al_load_le64(value.data);
    return AL_OK;
}

/* --- the test --------------------------------------------------------------- */

AL_TEST(deploy_then_call_updates_contract_storage) {
    flow_fixture f;
    AL_CHECK_EQ_STATUS(flow_fixture_init(&f), AL_OK);

    /* Deployer/funder identity from a deterministic seed. */
    al_u8 seed[32] = { 7u };
    al_keypair deployer;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &deployer), AL_OK);
    al_address deployer_address;
    al_address_from_pubkey(&deployer.pk, &deployer_address);
    AL_CHECK_EQ_STATUS(fund(&f, &deployer_address,
                            UINT64_C(1000000000000)), AL_OK);
    AL_CHECK_EQ_STATUS(flow_fixture_bind_node(&f), AL_OK);

    /* Deploy. */
    AL_CHECK_EQ_STATUS(submit_call_or_deploy(&f, &deployer, 0u, 1, NULL, 0u,
                                             0u), AL_OK);
    AL_CHECK_EQ_STATUS(produce_one(&f, &deployer), AL_OK);

    /* Derive the contract address exactly as the core did at deployment. */
    al_hash256 code_hash;
    {
        static al_u8 container[4096];
        al_size container_len = 0u;
        AL_CHECK_EQ_STATUS(build_counter_container(
            container, sizeof(container), &container_len), AL_OK);
        al_sha256_bytes(al_bytes_make(container, container_len), &code_hash);
    }
    al_address contract;
    al_address_for_contract(&deployer_address, 0u, &code_hash, &contract);

    al_account deployed;
    AL_CHECK_EQ_STATUS(al_state_get(&f.states.state, &contract, &deployed),
                       AL_OK);
    AL_CHECK(!al_hash_is_zero(&deployed.code_hash));

    /* Call set_and_get(5): the counter must become 5 on chain. */
    AL_CHECK_EQ_STATUS(submit_call_or_deploy(&f, &deployer, 1u, 0, &contract,
                                             1u, 5u), AL_OK);
    AL_CHECK_EQ_STATUS(produce_one(&f, &deployer), AL_OK);
    AL_CHECK_EQ_U64(f.node.receipt_count >= 1u ? 1u : 0u, 1u);
    if (f.node.receipt_count >= 1u) {
        AL_CHECK_EQ_STATUS(f.receipts[0].status, AL_OK);
    }

    al_u64 counter = 0u;
    AL_CHECK_EQ_STATUS(read_counter(&f, &contract, &counter), AL_OK);
    AL_CHECK_EQ_U64(counter, 5u);

    /* And again: 5 + 7 = 12 proves persistence across blocks. */
    AL_CHECK_EQ_STATUS(submit_call_or_deploy(&f, &deployer, 2u, 0, &contract,
                                             1u, 7u), AL_OK);
    AL_CHECK_EQ_STATUS(produce_one(&f, &deployer), AL_OK);
    AL_CHECK_EQ_STATUS(read_counter(&f, &contract, &counter), AL_OK);
    AL_CHECK_EQ_U64(counter, 12u);

    flow_fixture_free(&f);
}

static const char *AL_TEST_SUITE_NAME = "contract_flow";

AL_TEST_MAIN {
    AL_RUN(deploy_then_call_updates_contract_storage);
}
