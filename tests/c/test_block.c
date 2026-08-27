#include "altest.h"
#include "astrolune/block.h"
#include "state_fixture.h"

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

static al_keypair add_sender(al_state *state, al_amount balance) {
    al_u8 seed[32] = { 9u };
    al_keypair keypair;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &keypair), AL_OK);
    al_account account;
    memset(&account, 0, sizeof(account));
    al_address_from_pubkey(&keypair.pk, &account.address);
    account.balance = balance;
    AL_CHECK_EQ_STATUS(al_state_upsert(state, &account), AL_OK);
    return keypair;
}

static al_transaction make_transfer(const al_keypair *keypair) {
    al_transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = AL_TX_VERSION;
    tx.chain_id = 17u;
    tx.expiry_height = 5u;
    tx.sender = keypair->pk;
    tx.resource_limit = resources_with(1000u);
    tx.max_base_price = resources_with(1u);
    tx.tip = 100u;
    tx.type = AL_TX_TRANSFER;
    tx.body.transfer.recipient = address_with(0x51u);
    tx.body.transfer.amount = 500u;
    AL_CHECK_EQ_STATUS(al_tx_sign(&tx, &keypair->sk), AL_OK);
    return tx;
}

static al_block_header base_header(void) {
    al_block_header header;
    memset(&header, 0, sizeof(header));
    header.version = AL_BLOCK_VERSION;
    header.chain_id = 17u;
    header.base_prices = resources_with(1u);
    header.tip_flat = address_with(0xa1u);
    header.tip_weighted = address_with(0xa2u);
    header.tip_bonded = address_with(0xa3u);
    return header;
}

AL_TEST(genesis_round_trip_and_validation) {
    al_genesis genesis = make_genesis(al_hash_zero());
    AL_CHECK_EQ_STATUS(al_genesis_validate(&genesis), AL_OK);
    al_u8 encoded[1024];
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_genesis_encode(
        &genesis, (al_bytes_mut){ encoded, sizeof(encoded) }, &written), AL_OK);
    AL_CHECK(written > 600u);
    al_genesis decoded;
    al_genesis_allocation decoded_allocations[AL_GENESIS_MAX_ALLOCATIONS];
    AL_CHECK_EQ_STATUS(al_genesis_decode(al_bytes_make(encoded, written),
                                         decoded_allocations,
                                         AL_COUNTOF(decoded_allocations),
                                         &decoded), AL_OK);
    /* An empty allocation table fits any buffer, so the probe succeeds and
     * reports zero entries. */
    al_genesis probed;
    AL_CHECK_EQ_STATUS(al_genesis_decode(al_bytes_make(encoded, written),
                                         NULL, 0u, &probed), AL_OK);
    AL_CHECK(probed.allocation_count == 0u);
    AL_CHECK_EQ_U64(decoded.chain_id, genesis.chain_id);
    AL_CHECK_EQ_U64(decoded.schedule.host[AL_VM_HOST_CALL_CONTRACT],
                    genesis.schedule.host[AL_VM_HOST_CALL_CONTRACT]);
    AL_CHECK_EQ_U64(decoded.potb.committee_size,
                    genesis.potb.committee_size);
    al_hash256 hash;
    al_genesis_hash(&genesis, &hash);
    AL_CHECK(!al_hash_is_zero(&hash));

    genesis.fees.initial_base_price.compute = 0u;
    AL_CHECK_EQ_STATUS(al_genesis_validate(&genesis), AL_ERR_INVALID_ARG);
}

AL_TEST(genesis_allocations_round_trip) {
    al_genesis genesis = make_genesis(al_hash_zero());

    /* Two prefunded accounts in strictly increasing address order, which is
     * the canonical form validation requires. */
    al_genesis_allocation allocations[2];
    memset(&allocations[0], 0, sizeof(allocations[0]));
    memset(allocations[0].address.bytes + 31u, 1u, 1u);
    allocations[0].balance = 1000u;
    memset(&allocations[1], 0, sizeof(allocations[1]));
    memset(allocations[1].address.bytes + 31u, 2u, 1u);
    allocations[1].balance = UINT64_C(999999999999);

    genesis.allocations = allocations;
    genesis.allocation_count = 2u;
    AL_CHECK_EQ_STATUS(al_genesis_validate(&genesis), AL_OK);

    al_u8 encoded[2048];
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_genesis_encode(
        &genesis, (al_bytes_mut){ encoded, sizeof(encoded) }, &written),
        AL_OK);

    al_genesis decoded;
    al_genesis_allocation decoded_table[AL_GENESIS_MAX_ALLOCATIONS];
    AL_CHECK_EQ_STATUS(al_genesis_decode(al_bytes_make(encoded, written),
                                         decoded_table,
                                         AL_COUNTOF(decoded_table), &decoded),
                       AL_OK);
    AL_CHECK_EQ_U64(decoded.allocation_count, 2u);
    AL_CHECK(decoded.allocations == decoded_table);
    AL_CHECK(al_address_eq(&decoded.allocations[0].address,
                           &allocations[0].address));
    AL_CHECK_EQ_U64(decoded.allocations[1].balance,
                    allocations[1].balance);

    /* The same table in a different order must not validate: two encodings
     * of one chain start would otherwise hash differently. */
    al_genesis shuffled = genesis;
    al_genesis_allocation reversed[2] = { allocations[1], allocations[0] };
    shuffled.allocations = reversed;
    AL_CHECK_EQ_STATUS(al_genesis_validate(&shuffled), AL_ERR_INVALID_ARG);

    /* A capacity probe reports the required count without filling storage. */
    al_genesis probed;
    AL_CHECK_EQ_STATUS(al_genesis_decode(al_bytes_make(encoded, written),
                                         NULL, 0u, &probed),
                       AL_ERR_BUFFER_TOO_SMALL);
    AL_CHECK(probed.allocation_count == 2u);
}

AL_TEST(header_and_body_round_trip) {
    al_u8 seed[32] = { 3u };
    al_keypair keypair;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &keypair), AL_OK);
    al_transaction tx = make_transfer(&keypair);
    al_block block;
    memset(&block, 0, sizeof(block));
    block.header = base_header();
    block.transactions = &tx;
    block.transaction_count = 1u;
    al_block_transaction_root(&block, &block.header.tx_root);

    al_u8 encoded[2048];
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_block_encode(
        &block, (al_bytes_mut){ encoded, sizeof(encoded) }, &written), AL_OK);
    AL_CHECK(written > 338u);
    al_transaction decoded_tx[1];
    al_block decoded;
    AL_CHECK_EQ_STATUS(al_block_decode(al_bytes_make(encoded, written),
        decoded_tx, 1u, &decoded), AL_OK);
    AL_CHECK_EQ_U64(decoded.transaction_count, 1u);
    AL_CHECK_EQ_U64(decoded.transactions[0].body.transfer.amount, 500u);
    AL_CHECK(al_hash_eq(&decoded.header.tx_root, &block.header.tx_root));

    encoded[written] = 0u;
    AL_CHECK_EQ_STATUS(al_block_decode(al_bytes_make(encoded, written + 1u),
        decoded_tx, 1u, &decoded), AL_ERR_TRAILING_BYTES);
}

AL_TEST(execution_checks_every_commitment) {
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 1u);
    al_keypair keypair = add_sender(&fixture.state, 100000u);
    al_state_snapshot initial = al_state_snapshot_take(&fixture.state);
    al_genesis genesis = make_genesis(initial.root);
    al_transaction tx = make_transfer(&keypair);

    al_block block;
    memset(&block, 0, sizeof(block));
    block.header = base_header();
    block.header.height = 0u;
    block.transactions = &tx;
    block.transaction_count = 1u;
    al_block_transaction_root(&block, &block.header.tx_root);

    al_tx_context context;
    memset(&context, 0, sizeof(context));
    context.chain_id = genesis.chain_id;
    context.block_height = 0u;
    context.base_prices = block.header.base_prices;
    context.tip_flat = block.header.tip_flat;
    context.tip_weighted = block.header.tip_weighted;
    context.tip_bonded = block.header.tip_bonded;
    context.vm = al_vm_config_default();
    context.vm.schedule = &genesis.schedule;
    context.arena = &fixture.arena;
    al_receipt expected;
    AL_CHECK_EQ_STATUS(al_tx_apply(&tx, &fixture.state, &context, &expected),
                       AL_OK);
    block.header.state_root = fixture.state.root;
    block.header.resources = expected.resources;
    al_block_receipt_root(&expected, 1u, &block.header.receipt_root);
    AL_CHECK_EQ_STATUS(al_state_snapshot_restore(&fixture.state, initial), AL_OK);

    al_receipt actual[1];
    AL_CHECK_EQ_STATUS(al_block_execute(&block, NULL, &genesis, &fixture.state,
                                       actual, 1u, &fixture.arena), AL_OK);
    AL_CHECK(al_hash_eq(&fixture.state.root, &block.header.state_root));
    AL_CHECK_EQ_U64(fixture.state.height, 0u);

    AL_CHECK_EQ_STATUS(al_state_snapshot_restore(&fixture.state, initial), AL_OK);
    al_hash256 good_root = block.header.receipt_root;
    block.header.receipt_root.bytes[0] ^= 1u;
    AL_CHECK_EQ_STATUS(al_block_execute(&block, NULL, &genesis, &fixture.state,
        actual, 1u, &fixture.arena), AL_ERR_CONSENSUS_VIOLATION);
    AL_CHECK(al_hash_eq(&fixture.state.root, &initial.root));
    block.header.receipt_root = good_root;
    al_test_state_fixture_destroy(&fixture);
}

AL_TEST(parent_price_transition) {
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 1u);
    al_genesis genesis = make_genesis(fixture.state.root);
    al_block_header parent = base_header();
    parent.height = 4u;
    parent.base_prices = resources_with(8u);
    parent.resources = resources_with(1000000u);
    al_block block;
    memset(&block, 0, sizeof(block));
    block.header = base_header();
    block.header.height = 5u;
    al_block_header_hash(&parent, &block.header.parent_hash);
    AL_CHECK_EQ_STATUS(al_fee_next_base_prices(
        parent.base_prices, parent.resources, genesis.fees.target,
        &block.header.base_prices), AL_OK);
    block.header.state_root = fixture.state.root;

    al_receipt unused;
    AL_CHECK_EQ_STATUS(al_block_execute(&block, &parent, &genesis,
        &fixture.state, &unused, 1u, &fixture.arena), AL_OK);
    AL_CHECK_EQ_U64(block.header.base_prices.compute, 9u);
    al_test_state_fixture_destroy(&fixture);
}

#define AL_TEST_SUITE_NAME "test_block"
AL_TEST_MAIN {
    AL_RUN(genesis_round_trip_and_validation);
    AL_RUN(genesis_allocations_round_trip);
    AL_RUN(header_and_body_round_trip);
    AL_RUN(execution_checks_every_commitment);
    AL_RUN(parent_price_transition);
}
