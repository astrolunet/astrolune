#include "astrolune/block.h"

#include <stdio.h>
#include <string.h>

#define FIXTURE_NODE_CAPACITY 8192u
#define FIXTURE_VALUE_CAPACITY 512u

static al_address address_with(al_u8 value) {
    al_address address;
    memset(address.bytes, value, sizeof(address.bytes));
    return address;
}

static al_resources resources_with(al_u64 value) {
    al_resources resources = { value, value, value, value };
    return resources;
}

static al_status execute_fixture(al_hash256 *digest) {
    al_status status;
    al_arena arena;
    status = al_arena_init(&arena, 0u);
    if (status != AL_OK) return status;
    al_state_memory_node *nodes = AL_ARENA_NEW_ARRAY(
        &arena, al_state_memory_node, FIXTURE_NODE_CAPACITY);
    al_state_memory_value *values = AL_ARENA_NEW_ARRAY(
        &arena, al_state_memory_value, FIXTURE_VALUE_CAPACITY);
    if (nodes == NULL || values == NULL) {
        al_arena_destroy(&arena); return AL_ERR_OUT_OF_MEMORY;
    }
    al_state_memory_store memory;
    status = al_state_memory_store_init(&memory, nodes, FIXTURE_NODE_CAPACITY,
                                        values, FIXTURE_VALUE_CAPACITY, &arena);
    if (status != AL_OK) { al_arena_destroy(&arena); return status; }
    al_state_store store = al_state_memory_store_interface(&memory);
    al_state state;
    status = al_state_init(&state, &store, &arena, 1u);
    if (status != AL_OK) { al_arena_destroy(&arena); return status; }

    al_u8 seed[32] = { 0x42u };
    al_keypair keypair;
    status = al_keypair_from_seed(seed, &keypair);
    if (status != AL_OK) { al_arena_destroy(&arena); return status; }
    al_account sender;
    memset(&sender, 0, sizeof(sender));
    al_address_from_pubkey(&keypair.pk, &sender.address);
    sender.balance = 1000000u;
    status = al_state_upsert(&state, &sender);
    if (status != AL_OK) { al_arena_destroy(&arena); return status; }
    al_state_snapshot initial = al_state_snapshot_take(&state);

    al_genesis genesis;
    memset(&genesis, 0, sizeof(genesis));
    genesis.version = AL_GENESIS_VERSION;
    genesis.chain_id = 0x41535452u;
    genesis.initial_state_root = initial.root;
    genesis.fees.block_limit = resources_with(1000000u);
    genesis.fees.target = resources_with(500000u);
    genesis.fees.initial_base_price = resources_with(1u);
    genesis.fees.storage_deposit_per_byte = 2u;
    genesis.schedule = al_vm_resource_schedule_default();
    genesis.vm_stack_limit = AL_VM_DEFAULT_STACK;
    genesis.vm_memory_limit = AL_VM_DEFAULT_MEMORY;
    genesis.vm_call_depth_limit = AL_VM_DEFAULT_CALL_DEPTH;
    genesis.potb = al_potb_params_default();

    al_transaction transaction;
    memset(&transaction, 0, sizeof(transaction));
    transaction.version = AL_TX_VERSION;
    transaction.chain_id = genesis.chain_id;
    transaction.expiry_height = 10u;
    transaction.sender = keypair.pk;
    transaction.resource_limit = resources_with(1000u);
    transaction.max_base_price = resources_with(1u);
    transaction.tip = 100u;
    transaction.type = AL_TX_TRANSFER;
    transaction.body.transfer.recipient = address_with(0x51u);
    transaction.body.transfer.amount = 12345u;
    status = al_tx_sign(&transaction, &keypair.sk);
    if (status != AL_OK) { al_arena_destroy(&arena); return status; }

    al_block block;
    memset(&block, 0, sizeof(block));
    block.header.version = AL_BLOCK_VERSION;
    block.header.chain_id = genesis.chain_id;
    block.header.protocol_day = 7u;
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
    context.protocol_day = block.header.protocol_day;
    context.base_prices = block.header.base_prices;
    context.tip_flat = block.header.tip_flat;
    context.tip_weighted = block.header.tip_weighted;
    context.tip_bonded = block.header.tip_bonded;
    context.vm = al_vm_config_default();
    context.vm.schedule = &genesis.schedule;
    context.arena = &arena;
    al_receipt expected;
    status = al_tx_apply(&transaction, &state, &context, &expected);
    if (status != AL_OK) { al_arena_destroy(&arena); return status; }
    block.header.state_root = state.root;
    block.header.resources = expected.resources;
    al_block_receipt_root(&expected, 1u, &block.header.receipt_root);
    status = al_state_snapshot_restore(&state, initial);
    if (status != AL_OK) { al_arena_destroy(&arena); return status; }

    al_receipt actual;
    status = al_block_execute(&block, NULL, &genesis, &state, &actual, 1u,
                              &arena);
    if (status == AL_OK) al_block_header_hash(&block.header, digest);
    al_arena_destroy(&arena);
    return status;
}

int main(void) {
    al_hash256 digest;
    al_status status = execute_fixture(&digest);
    if (status != AL_OK) {
        (void)fprintf(stderr, "determinism fixture failed: %s\n",
                      al_status_str(status));
        return 1;
    }
    char hex[AL_HASH_HEX_SIZE];
    al_hash_to_hex(&digest, hex);
    (void)puts(hex);
    return 0;
}
