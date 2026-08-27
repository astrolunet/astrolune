#include "altest.h"
#include "astrolune/tx.h"
#include "state_fixture.h"

static al_address address_with(al_u8 value) {
    al_address address;
    memset(address.bytes, value, sizeof(address.bytes));
    return address;
}

static al_keypair keypair_with(al_u8 value) {
    al_u8 seed[32] = { 0u };
    seed[0] = value;
    al_keypair keypair;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &keypair), AL_OK);
    return keypair;
}

static al_address add_sender(al_state *state, const al_keypair *keypair,
                             al_amount balance, al_nonce nonce) {
    al_account account;
    memset(&account, 0, sizeof(account));
    al_address_from_pubkey(&keypair->pk, &account.address);
    account.balance = balance;
    account.nonce = nonce;
    AL_CHECK_EQ_STATUS(al_state_upsert(state, &account), AL_OK);
    return account.address;
}

static al_resources resources_with(al_u64 value) {
    al_resources resources = { value, value, value, value };
    return resources;
}

static al_tx_context make_context(al_arena *arena) {
    al_tx_context context;
    memset(&context, 0, sizeof(context));
    context.chain_id = 7u;
    context.block_height = 10u;
    context.protocol_day = 2u;
    context.base_prices = resources_with(1u);
    context.tip_flat = address_with(0xa1u);
    context.tip_weighted = address_with(0xa2u);
    context.tip_bonded = address_with(0xa3u);
    context.vm = al_vm_config_default();
    context.arena = arena;
    return context;
}

static al_transaction make_transfer(const al_keypair *keypair, al_nonce nonce) {
    al_transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = AL_TX_VERSION;
    tx.chain_id = 7u;
    tx.expiry_height = 20u;
    tx.sender = keypair->pk;
    tx.nonce = nonce;
    tx.resource_limit = resources_with(1000u);
    tx.max_base_price = resources_with(2u);
    tx.tip = 100u;
    tx.type = AL_TX_TRANSFER;
    tx.body.transfer.recipient = address_with(0x44u);
    tx.body.transfer.amount = 250u;
    return tx;
}

static al_bytes make_container(al_u8 terminator, al_u8 *storage,
                               al_size capacity) {
    al_u8 code[19];
    al_size code_len = 0u;
    if (terminator == AL_VM_REVERT) {
        code[code_len++] = AL_VM_PUSH64;
        memset(code + code_len, 0, 8u);
        code_len += 8u;
        code[code_len++] = AL_VM_PUSH64;
        memset(code + code_len, 0, 8u);
        code_len += 8u;
    }
    code[code_len++] = terminator;
    al_vm_function function = { 0u, 0u, 0u, 2u, 0u };
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_vm_container_encode(
        &function, 1u, al_bytes_make(code, code_len),
        (al_bytes_mut){ storage, capacity }, &written), AL_OK);
    return al_bytes_make(storage, written);
}

typedef struct tx_code_builder {
    al_u8   data[512];
    al_size len;
} tx_code_builder;

static void tx_emit_u8(tx_code_builder *builder, al_u8 value) {
    builder->data[builder->len++] = value;
}

static void tx_emit_push(tx_code_builder *builder, al_u64 value) {
    tx_emit_u8(builder, AL_VM_PUSH64);
    for (al_u32 i = 0u; i < 8u; ++i)
        tx_emit_u8(builder, (al_u8)(value >> (i * 8u)));
}

static void tx_emit_host(tx_code_builder *builder, al_vm_host_id host) {
    tx_emit_u8(builder, AL_VM_HOST);
    tx_emit_u8(builder, (al_u8)((al_u32)host & 0xffu));
    tx_emit_u8(builder, (al_u8)((al_u32)host >> 8u));
}

static al_bytes make_builder_container(const tx_code_builder *builder,
                                       al_u8 *storage, al_size capacity) {
    al_vm_function function = {
        0u, 0u, 0u, AL_VM_DEFAULT_STACK, 0u
    };
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_vm_container_encode(
        &function, 1u, al_bytes_make(builder->data, builder->len),
        (al_bytes_mut){ storage, capacity }, &written), AL_OK);
    return al_bytes_make(storage, written);
}

static al_receipt deploy_code(al_test_state_fixture *fixture,
                              const al_keypair *keypair,
                              const al_tx_context *context, al_nonce nonce,
                              al_bytes container) {
    al_transaction deploy;
    memset(&deploy, 0, sizeof(deploy));
    deploy.version = AL_TX_VERSION;
    deploy.chain_id = context->chain_id;
    deploy.expiry_height = context->block_height + 10u;
    deploy.sender = keypair->pk;
    deploy.nonce = nonce;
    deploy.resource_limit = resources_with(100000u);
    deploy.max_base_price = resources_with(2u);
    deploy.type = AL_TX_DEPLOY;
    deploy.body.deploy.container = container;
    AL_CHECK_EQ_STATUS(al_tx_sign(&deploy, &keypair->sk), AL_OK);
    al_receipt receipt;
    AL_CHECK_EQ_STATUS(al_tx_apply(&deploy, &fixture->state, context, &receipt),
                       AL_OK);
    AL_CHECK_EQ_STATUS(receipt.status, AL_OK);
    return receipt;
}

static al_receipt call_code(al_test_state_fixture *fixture,
                            const al_keypair *keypair,
                            const al_tx_context *context, al_nonce nonce,
                            const al_address *contract, al_amount value,
                            al_bytes calldata) {
    al_transaction call;
    memset(&call, 0, sizeof(call));
    call.version = AL_TX_VERSION;
    call.chain_id = context->chain_id;
    call.expiry_height = context->block_height + 10u;
    call.sender = keypair->pk;
    call.nonce = nonce;
    call.resource_limit = resources_with(100000u);
    call.max_base_price = resources_with(2u);
    call.type = AL_TX_CALL;
    call.body.call.contract = *contract;
    call.body.call.value = value;
    call.body.call.calldata = calldata;
    AL_CHECK_EQ_STATUS(al_tx_sign(&call, &keypair->sk), AL_OK);
    al_receipt receipt;
    AL_CHECK_EQ_STATUS(al_tx_apply(&call, &fixture->state, context, &receipt),
                       AL_OK);
    return receipt;
}

AL_TEST(canonical_round_trip) {
    al_keypair keypair = keypair_with(1u);
    al_transaction tx = make_transfer(&keypair, 9u);
    memset(tx.signature.bytes, 0x5au, sizeof(tx.signature.bytes));
    al_size size = al_tx_encoded_size(&tx);
    AL_CHECK_EQ_U64(size, 231u);

    al_u8 encoded[256];
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_tx_encode(
        &tx, (al_bytes_mut){ encoded, sizeof(encoded) }, &written), AL_OK);
    AL_CHECK_EQ_U64(written, size);
    al_transaction decoded;
    AL_CHECK_EQ_STATUS(al_tx_decode(al_bytes_make(encoded, written), &decoded),
                       AL_OK);
    AL_CHECK_EQ_U64(decoded.version, AL_TX_VERSION);
    AL_CHECK_EQ_U64(decoded.expiry_height, tx.expiry_height);
    AL_CHECK_EQ_U64(decoded.resource_limit.storage,
                    tx.resource_limit.storage);
    AL_CHECK_EQ_U64(decoded.body.transfer.amount, tx.body.transfer.amount);
    AL_CHECK(memcmp(decoded.signature.bytes, tx.signature.bytes,
                    AL_SIGNATURE_SIZE) == 0);

    encoded[written] = 0u;
    AL_CHECK_EQ_STATUS(al_tx_decode(al_bytes_make(encoded, written + 1u),
                                    &decoded), AL_ERR_TRAILING_BYTES);
    tx.version = 2u;
    AL_CHECK_EQ_STATUS(al_tx_validate_shape(&tx), AL_ERR_INVALID_ARG);
}

AL_TEST(signing_domain_and_mutation) {
    al_keypair keypair = keypair_with(2u);
    al_transaction tx = make_transfer(&keypair, 0u);
    AL_CHECK_EQ_STATUS(al_tx_sign(&tx, &keypair.sk), AL_OK);
    AL_CHECK_EQ_STATUS(al_tx_verify(&tx), AL_OK);
    al_hash256 signing;
    al_hash256 identifier;
    al_tx_signing_hash(&tx, &signing);
    al_tx_hash(&tx, &identifier);
    AL_CHECK(!al_hash_eq(&signing, &identifier));
    tx.expiry_height += 1u;
    AL_CHECK_EQ_STATUS(al_tx_verify(&tx), AL_ERR_BAD_SIGNATURE);
}

AL_TEST(event_and_receipt_round_trip) {
    static const al_u8 event_data[] = { 0x10u, 0x20u, 0x30u };
    static const al_u8 return_data[] = { 0xaau, 0xbbu };
    al_event event;
    memset(&event, 0, sizeof(event));
    event.contract = address_with(0x21u);
    memset(event.topic.bytes, 0x32u, sizeof(event.topic.bytes));
    event.data = al_bytes_make(event_data, sizeof(event_data));

    al_u8 event_encoded[128];
    al_size event_written = 0u;
    AL_CHECK_EQ_STATUS(al_event_encode(
        &event, (al_bytes_mut){ event_encoded, sizeof(event_encoded) },
        &event_written), AL_OK);
    al_event decoded_event;
    AL_CHECK_EQ_STATUS(al_event_decode(
        al_bytes_make(event_encoded, event_written), &decoded_event), AL_OK);
    AL_CHECK(al_address_eq(&decoded_event.contract, &event.contract));
    AL_CHECK(al_hash_eq(&decoded_event.topic, &event.topic));
    AL_CHECK(al_bytes_eq(decoded_event.data, event.data));

    al_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    memset(receipt.transaction_hash.bytes, 0x43u,
           sizeof(receipt.transaction_hash.bytes));
    receipt.status = AL_ERR_REVERTED;
    receipt.resources = resources_with(7u);
    receipt.base_fee_burned = 28u;
    receipt.tip_paid = 9u;
    receipt.contract_address = event.contract;
    receipt.return_data = al_bytes_make(return_data, sizeof(return_data));
    receipt.events = &event;
    receipt.event_count = 1u;

    al_u8 encoded[512];
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_receipt_encode(
        &receipt, (al_bytes_mut){ encoded, sizeof(encoded) }, &written), AL_OK);
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_receipt decoded;
    AL_CHECK_EQ_STATUS(al_receipt_decode(
        al_bytes_make(encoded, written), &arena, &decoded), AL_OK);
    AL_CHECK_EQ_STATUS(decoded.status, receipt.status);
    AL_CHECK_EQ_U64(decoded.resources.storage, receipt.resources.storage);
    AL_CHECK(al_bytes_eq(decoded.return_data, receipt.return_data));
    AL_CHECK_EQ_U64(decoded.event_count, 1u);
    if (decoded.event_count == 1u)
        AL_CHECK(al_bytes_eq(decoded.events[0].data, event.data));
    al_hash256 expected_hash;
    al_hash256 decoded_hash;
    al_receipt_hash(&receipt, &expected_hash);
    al_receipt_hash(&decoded, &decoded_hash);
    AL_CHECK(al_hash_eq(&expected_hash, &decoded_hash));

    encoded[written] = 0u;
    AL_CHECK_EQ_STATUS(al_receipt_decode(
        al_bytes_make(encoded, written + 1u), &arena, &decoded),
        AL_ERR_TRAILING_BYTES);
    al_arena_destroy(&arena);
}

AL_TEST(transfer_fees_and_tip_split) {
    al_keypair keypair = keypair_with(3u);
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 1u);
    al_address sender = add_sender(&fixture.state, &keypair, 100000u, 0u);
    al_tx_context context = make_context(&fixture.arena);
    al_transaction tx = make_transfer(&keypair, 0u);
    AL_CHECK_EQ_STATUS(al_tx_sign(&tx, &keypair.sk), AL_OK);
    al_receipt receipt;
    AL_CHECK_EQ_STATUS(al_tx_apply(&tx, &fixture.state, &context, &receipt),
                       AL_OK);
    AL_CHECK_EQ_STATUS(receipt.status, AL_OK);
    AL_CHECK_EQ_U64(receipt.resources.compute, 1u);
    AL_CHECK_EQ_U64(receipt.resources.bandwidth, 231u);
    AL_CHECK_EQ_U64(receipt.base_fee_burned, 232u);
    AL_CHECK_EQ_U64(receipt.tip_paid, 100u);

    al_account account;
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &sender, &account), AL_OK);
    AL_CHECK_EQ_U64(account.balance, 100000u - 250u - 232u - 100u);
    AL_CHECK_EQ_U64(account.nonce, 1u);
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &context.tip_flat, &account),
                       AL_OK);
    AL_CHECK_EQ_U64(account.balance, 60u);
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &context.tip_weighted,
                                    &account), AL_OK);
    AL_CHECK_EQ_U64(account.balance, 25u);
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &context.tip_bonded,
                                    &account), AL_OK);
    AL_CHECK_EQ_U64(account.balance, 15u);
    al_test_state_fixture_destroy(&fixture);
}

AL_TEST(validation_order_and_expiry) {
    al_keypair keypair = keypair_with(4u);
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 1u);
    (void)add_sender(&fixture.state, &keypair, 100000u, 0u);
    al_tx_context context = make_context(&fixture.arena);
    al_transaction tx = make_transfer(&keypair, 0u);
    AL_CHECK_EQ_STATUS(al_tx_sign(&tx, &keypair.sk), AL_OK);
    tx.signature.bytes[0] ^= 1u;
    al_receipt receipt;

    tx.chain_id = 8u;
    AL_CHECK_EQ_STATUS(al_tx_apply(&tx, &fixture.state, &context, &receipt),
                       AL_ERR_CONSENSUS_VIOLATION);
    tx.chain_id = 7u;
    tx.expiry_height = 9u;
    AL_CHECK_EQ_STATUS(al_tx_apply(&tx, &fixture.state, &context, &receipt),
                       AL_ERR_EXPIRED);
    tx.expiry_height = 20u;
    tx.nonce = 1u;
    AL_CHECK_EQ_STATUS(al_tx_apply(&tx, &fixture.state, &context, &receipt),
                       AL_ERR_BAD_NONCE);
    tx.nonce = 0u;
    AL_CHECK_EQ_STATUS(al_tx_apply(&tx, &fixture.state, &context, &receipt),
                       AL_ERR_BAD_SIGNATURE);
    al_test_state_fixture_destroy(&fixture);
}

AL_TEST(deploy_and_reverted_call_charge_without_writes) {
    al_u8 container_storage[128];
    al_bytes container = make_container(AL_VM_REVERT, container_storage,
                                        sizeof(container_storage));
    al_keypair keypair = keypair_with(5u);
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 1u);
    al_address sender = add_sender(&fixture.state, &keypair, 1000000u, 0u);
    al_tx_context context = make_context(&fixture.arena);

    al_transaction deploy;
    memset(&deploy, 0, sizeof(deploy));
    deploy.version = AL_TX_VERSION;
    deploy.chain_id = 7u;
    deploy.expiry_height = 20u;
    deploy.sender = keypair.pk;
    deploy.resource_limit = resources_with(10000u);
    deploy.max_base_price = resources_with(2u);
    deploy.type = AL_TX_DEPLOY;
    deploy.body.deploy.value = 500u;
    deploy.body.deploy.container = container;
    AL_CHECK_EQ_STATUS(al_tx_sign(&deploy, &keypair.sk), AL_OK);
    al_receipt deploy_receipt;
    AL_CHECK_EQ_STATUS(al_tx_apply(&deploy, &fixture.state, &context,
                                   &deploy_receipt), AL_OK);
    AL_CHECK_EQ_STATUS(deploy_receipt.status, AL_OK);

    al_account contract_before;
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state,
        &deploy_receipt.contract_address, &contract_before), AL_OK);
    AL_CHECK_EQ_U64(contract_before.balance, 500u);

    al_transaction call;
    memset(&call, 0, sizeof(call));
    call.version = AL_TX_VERSION;
    call.chain_id = 7u;
    call.expiry_height = 20u;
    call.sender = keypair.pk;
    call.nonce = 1u;
    call.resource_limit = resources_with(10000u);
    call.max_base_price = resources_with(2u);
    call.tip = 10u;
    call.type = AL_TX_CALL;
    call.body.call.contract = deploy_receipt.contract_address;
    call.body.call.value = 100u;
    AL_CHECK_EQ_STATUS(al_tx_sign(&call, &keypair.sk), AL_OK);
    al_receipt call_receipt;
    AL_CHECK_EQ_STATUS(al_tx_apply(&call, &fixture.state, &context,
                                   &call_receipt), AL_OK);
    AL_CHECK_EQ_STATUS(call_receipt.status, AL_ERR_REVERTED);
    al_account contract_after;
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state,
        &deploy_receipt.contract_address, &contract_after), AL_OK);
    AL_CHECK_EQ_U64(contract_after.balance, contract_before.balance);
    al_account source;
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &sender, &source), AL_OK);
    AL_CHECK_EQ_U64(source.nonce, 2u);
    AL_CHECK(call_receipt.base_fee_burned > 0u);
    al_test_state_fixture_destroy(&fixture);
}

AL_TEST(nested_revert_and_reentrancy) {
    al_keypair keypair = keypair_with(7u);
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 1u);
    (void)add_sender(&fixture.state, &keypair, 10000000u, 0u);
    al_tx_context context = make_context(&fixture.arena);

    tx_code_builder child = { { 0u }, 0u };
    tx_emit_push(&child, 0x5au);
    tx_emit_push(&child, 0u);
    tx_emit_u8(&child, AL_VM_STORE8);
    tx_emit_push(&child, 0u);
    tx_emit_push(&child, 1u);
    tx_emit_u8(&child, AL_VM_REVERT);
    al_u8 child_storage[256];
    al_bytes child_container = make_builder_container(
        &child, child_storage, sizeof(child_storage));
    al_receipt child_deploy = deploy_code(
        &fixture, &keypair, &context, 0u, child_container);

    tx_code_builder parent = { { 0u }, 0u };
    tx_emit_push(&parent, 0u);
    tx_emit_push(&parent, 0u);
    tx_emit_push(&parent, AL_ADDRESS_SIZE);
    tx_emit_u8(&parent, AL_VM_CALLDATA_COPY);
    tx_emit_push(&parent, 0u);
    tx_emit_push(&parent, 5u);
    tx_emit_push(&parent, AL_ADDRESS_SIZE);
    tx_emit_push(&parent, 0u);
    tx_emit_push(&parent, 64u);
    tx_emit_push(&parent, 32u);
    tx_emit_host(&parent, AL_VM_HOST_CALL_CONTRACT);
    tx_emit_u8(&parent, AL_VM_DROP);
    tx_emit_u8(&parent, AL_VM_DROP);
    tx_emit_push(&parent, 64u);
    tx_emit_push(&parent, 1u);
    tx_emit_u8(&parent, AL_VM_RETURN);
    al_u8 parent_storage[512];
    al_bytes parent_container = make_builder_container(
        &parent, parent_storage, sizeof(parent_storage));
    al_receipt parent_deploy = deploy_code(
        &fixture, &keypair, &context, 1u, parent_container);

    al_receipt call = call_code(
        &fixture, &keypair, &context, 2u, &parent_deploy.contract_address, 100u,
        al_bytes_make(child_deploy.contract_address.bytes, AL_ADDRESS_SIZE));
    AL_CHECK_EQ_STATUS(call.status, AL_OK);
    AL_CHECK_EQ_U64(call.return_data.len, 1u);
    if (call.return_data.len == 1u) AL_CHECK_EQ_U64(call.return_data.data[0], 0x5au);
    al_account child_account;
    al_account parent_account;
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state,
        &child_deploy.contract_address, &child_account), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state,
        &parent_deploy.contract_address, &parent_account), AL_OK);
    AL_CHECK_EQ_U64(child_account.balance, 0u);
    AL_CHECK_EQ_U64(parent_account.balance, 100u);

    al_receipt reentrant = call_code(
        &fixture, &keypair, &context, 3u, &parent_deploy.contract_address, 0u,
        al_bytes_make(parent_deploy.contract_address.bytes, AL_ADDRESS_SIZE));
    AL_CHECK_EQ_STATUS(reentrant.status, AL_ERR_REENTRANCY);
    al_test_state_fixture_destroy(&fixture);
}

AL_TEST(hash_and_signature_hosts) {
    al_keypair keypair = keypair_with(8u);
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 1u);
    (void)add_sender(&fixture.state, &keypair, 10000000u, 0u);
    al_tx_context context = make_context(&fixture.arena);

    tx_code_builder hash_code = { { 0u }, 0u };
    tx_emit_push(&hash_code, 0u);
    tx_emit_push(&hash_code, 0u);
    tx_emit_push(&hash_code, 3u);
    tx_emit_u8(&hash_code, AL_VM_CALLDATA_COPY);
    tx_emit_push(&hash_code, 0u);
    tx_emit_push(&hash_code, 3u);
    tx_emit_push(&hash_code, 32u);
    tx_emit_push(&hash_code, AL_VM_HASH_CONTRACT_DATA);
    tx_emit_host(&hash_code, AL_VM_HOST_HASH_TAGGED);
    tx_emit_push(&hash_code, 32u);
    tx_emit_push(&hash_code, AL_HASH_SIZE);
    tx_emit_u8(&hash_code, AL_VM_RETURN);
    al_u8 hash_storage[512];
    al_receipt hash_deploy = deploy_code(
        &fixture, &keypair, &context, 0u,
        make_builder_container(&hash_code, hash_storage, sizeof(hash_storage)));
    static const al_u8 abc[] = { 'a', 'b', 'c' };
    al_receipt hash_call = call_code(
        &fixture, &keypair, &context, 1u, &hash_deploy.contract_address, 0u,
        al_bytes_make(abc, sizeof(abc)));
    AL_CHECK_EQ_STATUS(hash_call.status, AL_OK);
    al_hash256 expected;
    al_hash_tagged(AL_TAG_CONTRACT_DATA, abc, sizeof(abc), &expected);
    AL_CHECK(al_bytes_eq(hash_call.return_data,
                         al_bytes_make(expected.bytes, sizeof(expected.bytes))));

    tx_code_builder verify_code = { { 0u }, 0u };
    tx_emit_push(&verify_code, 0u);
    tx_emit_push(&verify_code, 0u);
    tx_emit_push(&verify_code, 128u);
    tx_emit_u8(&verify_code, AL_VM_CALLDATA_COPY);
    tx_emit_push(&verify_code, 0u);
    tx_emit_push(&verify_code, 32u);
    tx_emit_push(&verify_code, 64u);
    tx_emit_host(&verify_code, AL_VM_HOST_VERIFY_SIGNATURE);
    tx_emit_push(&verify_code, 160u);
    tx_emit_u8(&verify_code, AL_VM_STORE8);
    tx_emit_push(&verify_code, 160u);
    tx_emit_push(&verify_code, 1u);
    tx_emit_u8(&verify_code, AL_VM_RETURN);
    al_u8 verify_storage[512];
    al_receipt verify_deploy = deploy_code(
        &fixture, &keypair, &context, 2u,
        make_builder_container(&verify_code, verify_storage,
                               sizeof(verify_storage)));
    al_hash256 message;
    al_hash_tagged(AL_TAG_CONTRACT_DATA, abc, sizeof(abc), &message);
    al_sig signature;
    AL_CHECK_EQ_STATUS(al_sign_hash(&keypair.sk, &message, &signature), AL_OK);
    al_u8 input[128];
    memcpy(input, message.bytes, AL_HASH_SIZE);
    memcpy(input + 32u, keypair.pk.bytes, AL_PUBKEY_SIZE);
    memcpy(input + 64u, signature.bytes, AL_SIGNATURE_SIZE);
    al_receipt verify_call = call_code(
        &fixture, &keypair, &context, 3u, &verify_deploy.contract_address, 0u,
        al_bytes_make(input, sizeof(input)));
    AL_CHECK_EQ_STATUS(verify_call.status, AL_OK);
    AL_CHECK_EQ_U64(verify_call.return_data.len, 1u);
    if (verify_call.return_data.len == 1u)
        AL_CHECK_EQ_U64(verify_call.return_data.data[0], 1u);
    al_test_state_fixture_destroy(&fixture);
}

AL_TEST(potb_native_record_uses_system_storage) {
    static const al_u8 evidence[] = { 1u, 2u, 3u };
    al_keypair keypair = keypair_with(6u);
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 1u);
    al_address sender = add_sender(&fixture.state, &keypair, 100000u, 0u);
    al_tx_context context = make_context(&fixture.arena);
    al_transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = AL_TX_VERSION;
    tx.chain_id = 7u;
    tx.expiry_height = 20u;
    tx.sender = keypair.pk;
    tx.resource_limit = resources_with(1000u);
    tx.max_base_price = resources_with(2u);
    tx.type = AL_TX_POTB;
    tx.body.potb.operation = AL_POTB_ATTEST;
    memset(tx.body.potb.target.bytes, 0x6au,
           sizeof(tx.body.potb.target.bytes));
    tx.body.potb.amount = 77u;
    tx.body.potb.data = al_bytes_make(evidence, sizeof(evidence));
    AL_CHECK_EQ_STATUS(al_tx_sign(&tx, &keypair.sk), AL_OK);
    al_receipt receipt;
    AL_CHECK_EQ_STATUS(al_tx_apply(&tx, &fixture.state, &context, &receipt),
                       AL_OK);
    AL_CHECK_EQ_STATUS(receipt.status, AL_OK);

    al_u8 key[41];
    key[0] = AL_POTB_ATTEST;
    memcpy(key + 1u, sender.bytes, AL_ADDRESS_SIZE);
    memset(key + 33u, 0, 8u);
    al_state_txn read;
    AL_CHECK_EQ_STATUS(al_state_txn_begin(&fixture.state, &read), AL_OK);
    al_bytes stored;
    AL_CHECK_EQ_STATUS(al_state_txn_system_storage_get(
        &read, al_bytes_make(key, sizeof(key)), &fixture.arena, &stored), AL_OK);
    al_u8 expected[45];
    expected[0] = AL_POTB_ATTEST;
    memcpy(expected + 1u, tx.body.potb.target.bytes, AL_PUBKEY_SIZE);
    for (al_u32 i = 0u; i < 8u; ++i)
        expected[33u + i] = (al_u8)(tx.body.potb.amount >> (i * 8u));
    expected[41] = sizeof(evidence);
    memcpy(expected + 42u, evidence, sizeof(evidence));
    AL_CHECK(al_bytes_eq(stored, al_bytes_make(expected, sizeof(expected))));
    al_state_txn_rollback(&read);
    al_test_state_fixture_destroy(&fixture);
}

#define AL_TEST_SUITE_NAME "test_tx"
AL_TEST_MAIN {
    AL_RUN(canonical_round_trip);
    AL_RUN(signing_domain_and_mutation);
    AL_RUN(event_and_receipt_round_trip);
    AL_RUN(transfer_fees_and_tip_split);
    AL_RUN(validation_order_and_expiry);
    AL_RUN(deploy_and_reverted_call_charge_without_writes);
    AL_RUN(nested_revert_and_reentrancy);
    AL_RUN(hash_and_signature_hosts);
    AL_RUN(potb_native_record_uses_system_storage);
}
