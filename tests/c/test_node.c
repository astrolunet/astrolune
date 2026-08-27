#include "altest.h"
#include "node.h"
#include "state_fixture.h"

#define AL_NODE_TEST_MEMPOOL_CAPACITY 8u
#define AL_NODE_TEST_MEMPOOL_BYTES    8192u
#define AL_NODE_TEST_BLOCK_CAPACITY   4u

typedef struct al_test_node_fixture {
    al_arena               execution_arena;
    al_node_mempool_entry  mempool[AL_NODE_TEST_MEMPOOL_CAPACITY];
    al_u8                  mempool_bytes[AL_NODE_TEST_MEMPOOL_BYTES];
    al_transaction         block_transactions[AL_NODE_TEST_BLOCK_CAPACITY];
    al_receipt             receipts[AL_NODE_TEST_BLOCK_CAPACITY];
    al_node                node;
} al_test_node_fixture;

static al_address address_with(al_u8 value) {
    al_address address;
    memset(address.bytes, value, sizeof(address.bytes));
    return address;
}

static al_resources resources_with(al_u64 value) {
    al_resources resources = { value, value, value, value };
    return resources;
}

static al_genesis make_genesis(al_hash256 initial_root) {
    al_genesis genesis;
    memset(&genesis, 0, sizeof(genesis));
    genesis.version = AL_GENESIS_VERSION;
    genesis.chain_id = 17u;
    genesis.initial_state_root = initial_root;
    genesis.fees.block_limit = resources_with(1000000u);
    genesis.fees.target = resources_with(500000u);
    genesis.fees.initial_base_price = resources_with(1u);
    genesis.fees.storage_deposit_per_byte = 1u;
    genesis.schedule = al_vm_resource_schedule_default();
    genesis.vm_stack_limit = AL_VM_DEFAULT_STACK;
    genesis.vm_memory_limit = AL_VM_DEFAULT_MEMORY;
    genesis.vm_call_depth_limit = AL_VM_DEFAULT_CALL_DEPTH;
    genesis.potb = al_potb_params_default();
    return genesis;
}

static al_keypair add_sender(al_state *state, al_amount balance,
                             al_u8 seed_byte) {
    al_u8 seed[32] = { 0u };
    seed[0] = seed_byte;
    al_keypair keypair;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &keypair), AL_OK);

    al_account account;
    memset(&account, 0, sizeof(account));
    al_address_from_pubkey(&keypair.pk, &account.address);
    account.balance = balance;
    AL_CHECK_EQ_STATUS(al_state_upsert(state, &account), AL_OK);
    return keypair;
}

static al_transaction make_transfer(const al_keypair *keypair,
                                    al_nonce nonce) {
    al_transaction transaction;
    memset(&transaction, 0, sizeof(transaction));
    transaction.version = AL_TX_VERSION;
    transaction.chain_id = 17u;
    transaction.expiry_height = 5u;
    transaction.sender = keypair->pk;
    transaction.nonce = nonce;
    transaction.resource_limit = resources_with(1000u);
    transaction.max_base_price = resources_with(1u);
    transaction.tip = 100u;
    transaction.type = AL_TX_TRANSFER;
    transaction.body.transfer.recipient = address_with(0x51u);
    transaction.body.transfer.amount = 500u;
    AL_CHECK_EQ_STATUS(al_tx_sign(&transaction, &keypair->sk), AL_OK);
    return transaction;
}

static al_size encode_transaction(const al_transaction *transaction,
                                  al_u8 *out, al_size capacity) {
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_tx_encode(
        transaction, (al_bytes_mut){ out, capacity }, &written), AL_OK);
    return written;
}

static void node_fixture_init(al_test_node_fixture *fixture,
                              const al_genesis *genesis, al_state *state) {
    memset(fixture, 0, sizeof(*fixture));
    AL_CHECK_EQ_STATUS(al_arena_init(&fixture->execution_arena, 0u), AL_OK);

    al_node_buffers buffers;
    memset(&buffers, 0, sizeof(buffers));
    buffers.mempool_entries = fixture->mempool;
    buffers.mempool_capacity = AL_NODE_TEST_MEMPOOL_CAPACITY;
    buffers.mempool_bytes = fixture->mempool_bytes;
    buffers.mempool_bytes_capacity = sizeof(fixture->mempool_bytes);
    buffers.block_transactions = fixture->block_transactions;
    buffers.block_transaction_capacity = AL_NODE_TEST_BLOCK_CAPACITY;
    buffers.receipts = fixture->receipts;
    buffers.receipt_capacity = AL_NODE_TEST_BLOCK_CAPACITY;
    AL_CHECK_EQ_STATUS(al_node_init(&fixture->node, genesis, state,
                                    &fixture->execution_arena, buffers), AL_OK);
}

static void node_fixture_destroy(al_test_node_fixture *fixture) {
    al_arena_destroy(&fixture->execution_arena);
}

AL_TEST(initialization_pins_genesis_state) {
    al_test_state_fixture state;
    al_test_state_fixture_init(&state, 1u);
    al_genesis genesis = make_genesis(state.state.root);

    al_test_node_fixture node;
    node_fixture_init(&node, &genesis, &state.state);
    AL_CHECK(al_node_head(&node.node) == NULL);
    AL_CHECK_EQ_U64(al_node_next_height(&node.node), 0u);
    AL_CHECK_EQ_U64(node.node.mempool_count, 0u);

    al_genesis wrong = genesis;
    wrong.initial_state_root.bytes[0] ^= 1u;
    AL_CHECK_EQ_STATUS(al_node_init(&node.node, &wrong, &state.state,
                                    &node.execution_arena, node.node.buffers),
                       AL_ERR_CONSENSUS_VIOLATION);

    al_node_buffers bad_buffers = node.node.buffers;
    bad_buffers.receipt_capacity =
        bad_buffers.block_transaction_capacity - 1u;
    AL_CHECK_EQ_STATUS(al_node_init(&node.node, &genesis, &state.state,
                                    &node.execution_arena, bad_buffers),
                       AL_ERR_INVALID_ARG);
    node_fixture_destroy(&node);
    al_test_state_fixture_destroy(&state);
}

AL_TEST(mempool_enforces_nonce_reservation_and_duplicates) {
    al_test_state_fixture state;
    al_test_state_fixture_init(&state, 1u);
    al_keypair keypair = add_sender(&state.state, 20000u, 9u);
    al_genesis genesis = make_genesis(state.state.root);
    al_test_node_fixture node;
    node_fixture_init(&node, &genesis, &state.state);

    al_u8 encoded[2048];
    al_transaction nonce0 = make_transfer(&keypair, 0u);
    al_size size = encode_transaction(&nonce0, encoded, sizeof(encoded));
    al_hash256 hash;
    AL_CHECK_EQ_STATUS(al_node_submit_transaction(
                           &node.node, al_bytes_make(encoded, size), &hash),
                       AL_OK);
    AL_CHECK(!al_hash_is_zero(&hash));
    AL_CHECK_EQ_U64(node.node.mempool_count, 1u);

    AL_CHECK_EQ_STATUS(al_node_submit_transaction(
                           &node.node, al_bytes_make(encoded, size), NULL),
                       AL_ERR_ALREADY_EXISTS);

    al_transaction conflict = nonce0;
    conflict.tip = 101u;
    AL_CHECK_EQ_STATUS(al_tx_sign(&conflict, &keypair.sk), AL_OK);
    size = encode_transaction(&conflict, encoded, sizeof(encoded));
    AL_CHECK_EQ_STATUS(al_node_submit_transaction(
                           &node.node, al_bytes_make(encoded, size), NULL),
                       AL_ERR_ALREADY_EXISTS);

    al_transaction gap = make_transfer(&keypair, 2u);
    size = encode_transaction(&gap, encoded, sizeof(encoded));
    AL_CHECK_EQ_STATUS(al_node_submit_transaction(
                           &node.node, al_bytes_make(encoded, size), NULL),
                       AL_ERR_BAD_NONCE);

    al_transaction nonce1 = make_transfer(&keypair, 1u);
    size = encode_transaction(&nonce1, encoded, sizeof(encoded));
    AL_CHECK_EQ_STATUS(al_node_submit_transaction(
                           &node.node, al_bytes_make(encoded, size), NULL),
                       AL_OK);
    AL_CHECK_EQ_U64(node.node.mempool_count, 2u);
    AL_CHECK_EQ_U64(node.node.stats.transactions_accepted, 2u);
    AL_CHECK_EQ_U64(node.node.stats.transactions_rejected, 3u);

    node_fixture_destroy(&node);
    al_test_state_fixture_destroy(&state);
}

AL_TEST(mempool_owns_variable_payload) {
    al_test_state_fixture state;
    al_test_state_fixture_init(&state, 1u);
    al_keypair keypair = add_sender(&state.state, 20000u, 9u);
    al_genesis genesis = make_genesis(state.state.root);
    al_test_node_fixture node;
    node_fixture_init(&node, &genesis, &state.state);

    al_u8 calldata[] = { 0x11u, 0x22u, 0x33u, 0x44u };
    al_transaction call;
    memset(&call, 0, sizeof(call));
    call.version = AL_TX_VERSION;
    call.chain_id = genesis.chain_id;
    call.expiry_height = 5u;
    call.sender = keypair.pk;
    call.resource_limit = resources_with(1000u);
    call.max_base_price = resources_with(1u);
    call.type = AL_TX_CALL;
    call.body.call.contract = address_with(0x71u);
    call.body.call.entrypoint = 3u;
    call.body.call.calldata = al_bytes_make(calldata, sizeof(calldata));
    AL_CHECK_EQ_STATUS(al_tx_sign(&call, &keypair.sk), AL_OK);

    al_u8 encoded[2048];
    al_size size = encode_transaction(&call, encoded, sizeof(encoded));
    AL_CHECK_EQ_STATUS(al_node_submit_transaction(
                           &node.node, al_bytes_make(encoded, size), NULL),
                       AL_OK);
    memset(encoded, 0, size);
    memset(calldata, 0, sizeof(calldata));

    const al_node_mempool_entry *stored = al_node_mempool_at(&node.node, 0u);
    AL_CHECK(stored != NULL);
    AL_CHECK_HEX(stored->transaction.body.call.calldata.data,
                 stored->transaction.body.call.calldata.len, "11223344");
    AL_CHECK(al_node_mempool_at(&node.node, 1u) == NULL);

    node_fixture_destroy(&node);
    al_test_state_fixture_destroy(&state);
}

AL_TEST(block_acceptance_updates_head_and_prunes_mempool) {
    al_test_state_fixture state;
    al_test_state_fixture_init(&state, 1u);
    al_keypair keypair = add_sender(&state.state, 100000u, 9u);
    al_keypair pending_keypair = add_sender(&state.state, 100000u, 10u);
    al_state_snapshot initial = al_state_snapshot_take(&state.state);
    al_genesis genesis = make_genesis(initial.root);
    al_test_node_fixture node;
    node_fixture_init(&node, &genesis, &state.state);

    al_transaction transaction = make_transfer(&keypair, 0u);
    al_u8 encoded_transaction[2048];
    al_size transaction_size = encode_transaction(
        &transaction, encoded_transaction, sizeof(encoded_transaction));
    AL_CHECK_EQ_STATUS(al_node_submit_transaction(
                           &node.node,
                           al_bytes_make(encoded_transaction, transaction_size),
                           NULL), AL_OK);

    al_u8 pending_calldata[] = { 0xdeu, 0xadu, 0xbeu, 0xefu };
    al_transaction pending;
    memset(&pending, 0, sizeof(pending));
    pending.version = AL_TX_VERSION;
    pending.chain_id = genesis.chain_id;
    pending.expiry_height = 5u;
    pending.sender = pending_keypair.pk;
    pending.resource_limit = resources_with(1000u);
    pending.max_base_price = resources_with(1u);
    pending.type = AL_TX_CALL;
    pending.body.call.contract = address_with(0x72u);
    pending.body.call.calldata =
        al_bytes_make(pending_calldata, sizeof(pending_calldata));
    AL_CHECK_EQ_STATUS(al_tx_sign(&pending, &pending_keypair.sk), AL_OK);
    transaction_size = encode_transaction(
        &pending, encoded_transaction, sizeof(encoded_transaction));
    AL_CHECK_EQ_STATUS(al_node_submit_transaction(
                           &node.node,
                           al_bytes_make(encoded_transaction, transaction_size),
                           NULL), AL_OK);

    al_block block;
    memset(&block, 0, sizeof(block));
    block.header.version = AL_BLOCK_VERSION;
    block.header.chain_id = genesis.chain_id;
    block.header.height = 0u;
    block.header.base_prices = genesis.fees.initial_base_price;
    block.header.tip_flat = address_with(0xa1u);
    block.header.tip_weighted = address_with(0xa2u);
    block.header.tip_bonded = address_with(0xa3u);
    block.transactions = &transaction;
    block.transaction_count = 1u;
    al_block_transaction_root(&block, &block.header.tx_root);

    al_tx_context context;
    memset(&context, 0, sizeof(context));
    context.chain_id = genesis.chain_id;
    context.block_height = block.header.height;
    context.base_prices = block.header.base_prices;
    context.tip_flat = block.header.tip_flat;
    context.tip_weighted = block.header.tip_weighted;
    context.tip_bonded = block.header.tip_bonded;
    context.vm = al_vm_config_default();
    context.vm.schedule = &genesis.schedule;
    context.arena = &node.execution_arena;

    al_receipt expected;
    AL_CHECK_EQ_STATUS(al_tx_apply(&transaction, &state.state, &context,
                                   &expected), AL_OK);
    block.header.state_root = state.state.root;
    block.header.resources = expected.resources;
    al_block_receipt_root(&expected, 1u, &block.header.receipt_root);
    AL_CHECK_EQ_STATUS(al_state_snapshot_restore(&state.state, initial), AL_OK);
    al_arena_reset(&node.execution_arena);

    al_u8 encoded_block[4096];
    al_size block_size = 0u;
    AL_CHECK_EQ_STATUS(al_block_encode(
        &block, (al_bytes_mut){ encoded_block, sizeof(encoded_block) },
        &block_size), AL_OK);
    AL_CHECK_EQ_STATUS(al_node_accept_encoded_block(
                           &node.node,
                           al_bytes_make(encoded_block, block_size)), AL_OK);

    AL_CHECK(al_node_head(&node.node) != NULL);
    AL_CHECK_EQ_U64(node.node.head.height, 0u);
    AL_CHECK_EQ_U64(al_node_next_height(&node.node), 1u);
    AL_CHECK_EQ_U64(node.node.mempool_count, 1u);
    AL_CHECK_EQ_U64(node.node.stats.mempool_removed, 1u);
    const al_node_mempool_entry *remaining =
        al_node_mempool_at(&node.node, 0u);
    AL_CHECK(remaining != NULL);
    AL_CHECK_HEX(remaining->transaction.body.call.calldata.data,
                 remaining->transaction.body.call.calldata.len, "deadbeef");
    al_size receipt_count = 0u;
    AL_CHECK(al_node_receipts(&node.node, &receipt_count) != NULL);
    AL_CHECK_EQ_U64(receipt_count, 1u);

    al_hash256 accepted_root = state.state.root;
    al_block_header accepted_head = node.node.head;
    al_block invalid;
    memset(&invalid, 0, sizeof(invalid));
    invalid.header.version = AL_BLOCK_VERSION;
    invalid.header.chain_id = genesis.chain_id;
    invalid.header.height = 1u;
    invalid.header.state_root = accepted_root;
    AL_CHECK_EQ_STATUS(al_fee_next_base_prices(
        accepted_head.base_prices, accepted_head.resources,
        genesis.fees.target, &invalid.header.base_prices), AL_OK);
    invalid.header.parent_hash.bytes[0] = 1u;

    AL_CHECK_EQ_STATUS(al_node_accept_block(&node.node, &invalid),
                       AL_ERR_CONSENSUS_VIOLATION);
    AL_CHECK(al_hash_eq(&state.state.root, &accepted_root));
    AL_CHECK_EQ_U64(node.node.head.height, accepted_head.height);
    AL_CHECK_EQ_U64(node.node.stats.blocks_accepted, 1u);
    AL_CHECK_EQ_U64(node.node.stats.blocks_rejected, 1u);

    node_fixture_destroy(&node);
    al_test_state_fixture_destroy(&state);
}

#define AL_TEST_SUITE_NAME "test_node"
AL_TEST_MAIN {
    AL_RUN(initialization_pins_genesis_state);
    AL_RUN(mempool_enforces_nonce_reservation_and_duplicates);
    AL_RUN(mempool_owns_variable_payload);
    AL_RUN(block_acceptance_updates_head_and_prunes_mempool);
}
