#include "state_fixture.h"

static void fill_bytes(al_u8 *out, al_size len, al_u8 first) {
    for (al_size i = 0u; i < len; ++i) {
        out[i] = (al_u8)(first + (al_u8)i);
    }
}

static al_address make_address(al_u8 first) {
    al_address address;
    fill_bytes(address.bytes, sizeof(address.bytes), first);
    return address;
}

static al_account make_account(al_u8 first, al_amount balance,
                               al_nonce nonce) {
    al_account account;
    memset(&account, 0, sizeof(account));
    account.address = make_address(first);
    account.balance = balance;
    account.nonce = nonce;
    return account;
}

AL_TEST(initialisation_and_accounts) {
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 2u);
    AL_CHECK(!al_hash_is_zero(&fixture.state.root));
    AL_CHECK_EQ_U64(fixture.state.height, 0u);

    al_account account = make_account(0x10u, 100u, 7u);
    AL_CHECK_EQ_STATUS(al_state_upsert(&fixture.state, &account), AL_OK);
    al_account found;
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &account.address, &found),
                       AL_OK);
    AL_CHECK_EQ_U64(found.balance, 100u);
    AL_CHECK_EQ_U64(found.nonce, 7u);

    account.balance = 125u;
    AL_CHECK_EQ_STATUS(al_state_upsert(&fixture.state, &account), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &account.address, &found),
                       AL_OK);
    AL_CHECK_EQ_U64(found.balance, 125u);

    AL_CHECK_EQ_STATUS(al_state_remove(&fixture.state, &account.address),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &account.address, &found),
                       AL_ERR_NOT_FOUND);
    al_state_clear(&fixture.state);
    AL_CHECK_EQ_U64(fixture.state.height, 0u);
    al_test_state_fixture_destroy(&fixture);
}

AL_TEST(root_is_order_independent) {
    al_test_state_fixture first;
    al_test_state_fixture second;
    al_test_state_fixture_init(&first, 1u);
    al_test_state_fixture_init(&second, 1u);
    al_account a = make_account(0x10u, 10u, 1u);
    al_account b = make_account(0x80u, 20u, 2u);

    AL_CHECK_EQ_STATUS(al_state_upsert(&first.state, &a), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_upsert(&first.state, &b), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_upsert(&second.state, &b), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_upsert(&second.state, &a), AL_OK);
    AL_CHECK(al_hash_eq(&first.state.root, &second.state.root));

    a.balance = 11u;
    al_hash256 before = first.state.root;
    AL_CHECK_EQ_STATUS(al_state_upsert(&first.state, &a), AL_OK);
    AL_CHECK(!al_hash_eq(&before, &first.state.root));
    al_test_state_fixture_destroy(&first);
    al_test_state_fixture_destroy(&second);
}

AL_TEST(staged_commit_rollback_and_snapshot) {
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 1u);
    al_account source = make_account(0x10u, 100u, 0u);
    al_address destination = make_address(0x40u);
    AL_CHECK_EQ_STATUS(al_state_upsert(&fixture.state, &source), AL_OK);
    al_state_snapshot original = al_state_snapshot_take(&fixture.state);

    al_state_txn txn;
    AL_CHECK_EQ_STATUS(al_state_txn_begin(&fixture.state, &txn), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_txn_transfer(&txn, &source.address,
                                             &destination, 25u), AL_OK);
    al_state_txn_rollback(&txn);
    AL_CHECK(al_hash_eq(&fixture.state.root, &original.root));

    AL_CHECK_EQ_STATUS(al_state_txn_begin(&fixture.state, &txn), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_txn_transfer(&txn, &source.address,
                                             &destination, 25u), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_txn_commit(&txn), AL_OK);
    al_account account;
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &source.address, &account),
                       AL_OK);
    AL_CHECK_EQ_U64(account.balance, 75u);
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &destination, &account),
                       AL_OK);
    AL_CHECK_EQ_U64(account.balance, 25u);

    AL_CHECK_EQ_STATUS(al_state_snapshot_restore(&fixture.state, original),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &destination, &account),
                       AL_ERR_NOT_FOUND);
    al_test_state_fixture_destroy(&fixture);
}

AL_TEST(membership_and_absence_proofs) {
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 1u);
    al_account account = make_account(0x20u, 50u, 3u);
    AL_CHECK_EQ_STATUS(al_state_upsert(&fixture.state, &account), AL_OK);

    al_hash256 siblings[AL_STATE_TREE_DEPTH];
    al_smt_proof proof;
    memset(&proof, 0, sizeof(proof));
    proof.siblings = siblings;
    proof.sibling_capacity = AL_STATE_TREE_DEPTH;
    AL_CHECK_EQ_STATUS(al_state_prove_account(&fixture.state,
                                              &account.address, &proof), AL_OK);
    AL_CHECK(proof.exists);
    AL_CHECK(al_smt_proof_verify(&fixture.state.root, &proof));

    al_u8 encoded[32u + 1u + 32u + 32u + 2u +
                  AL_STATE_TREE_DEPTH * AL_HASH_SIZE];
    al_size written = 0u;
    al_bytes_mut output = { encoded, sizeof(encoded) };
    AL_CHECK_EQ_STATUS(al_smt_proof_encode(&proof, output, &written), AL_OK);
    al_hash256 decoded_siblings[AL_STATE_TREE_DEPTH];
    al_smt_proof decoded;
    AL_CHECK_EQ_STATUS(al_smt_proof_decode(
                           al_bytes_make(encoded, written), decoded_siblings,
                           AL_STATE_TREE_DEPTH, &decoded), AL_OK);
    AL_CHECK(al_smt_proof_verify(&fixture.state.root, &decoded));

    al_address missing = make_address(0xe0u);
    memset(&proof, 0, sizeof(proof));
    proof.siblings = siblings;
    proof.sibling_capacity = AL_STATE_TREE_DEPTH;
    AL_CHECK_EQ_STATUS(al_state_prove_account(&fixture.state, &missing, &proof),
                       AL_OK);
    AL_CHECK(!proof.exists);
    AL_CHECK(al_smt_proof_verify(&fixture.state.root, &proof));
    AL_CHECK(proof.sibling_count != 0u);
    proof.siblings[0].bytes[0] ^= 1u;
    AL_CHECK(!al_smt_proof_verify(&fixture.state.root, &proof));
    al_test_state_fixture_destroy(&fixture);
}

AL_TEST(storage_deposit_and_isolation) {
    static const al_u8 key_data[] = { 'k' };
    static const al_u8 long_value[] = { 1u, 2u, 3u };
    static const al_u8 short_value[] = { 9u };
    al_test_state_fixture fixture;
    al_test_state_fixture_init(&fixture, 2u);
    al_account contract = make_account(0x30u, 100u, 0u);
    contract.code_hash.bytes[0] = 1u;
    AL_CHECK_EQ_STATUS(al_state_upsert(&fixture.state, &contract), AL_OK);

    al_state_txn txn;
    AL_CHECK_EQ_STATUS(al_state_txn_begin(&fixture.state, &txn), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_txn_storage_set(
                           &txn, &contract.address,
                           al_bytes_make(key_data, sizeof(key_data)),
                           al_bytes_make(long_value, sizeof(long_value))),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_state_txn_commit(&txn), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &contract.address,
                                    &contract), AL_OK);
    AL_CHECK_EQ_U64(contract.balance, 94u);
    AL_CHECK_EQ_U64(contract.storage_deposit, 6u);
    AL_CHECK_EQ_U64(contract.storage_bytes, 3u);

    AL_CHECK_EQ_STATUS(al_state_txn_begin(&fixture.state, &txn), AL_OK);
    al_bytes loaded;
    AL_CHECK_EQ_STATUS(al_state_txn_storage_get(
                           &txn, &contract.address,
                           al_bytes_make(key_data, sizeof(key_data)),
                           &fixture.arena, &loaded), AL_OK);
    AL_CHECK(al_bytes_eq(loaded,
                         al_bytes_make(long_value, sizeof(long_value))));
    AL_CHECK_EQ_STATUS(al_state_txn_storage_set(
                           &txn, &contract.address,
                           al_bytes_make(key_data, sizeof(key_data)),
                           al_bytes_make(short_value, sizeof(short_value))),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_state_txn_commit(&txn), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &contract.address,
                                    &contract), AL_OK);
    AL_CHECK_EQ_U64(contract.balance, 98u);
    AL_CHECK_EQ_U64(contract.storage_deposit, 2u);

    AL_CHECK_EQ_STATUS(al_state_txn_begin(&fixture.state, &txn), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_txn_storage_delete(
                           &txn, &contract.address,
                           al_bytes_make(key_data, sizeof(key_data))), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_txn_commit(&txn), AL_OK);
    AL_CHECK_EQ_STATUS(al_state_get(&fixture.state, &contract.address,
                                    &contract), AL_OK);
    AL_CHECK_EQ_U64(contract.balance, 100u);
    AL_CHECK_EQ_U64(contract.storage_deposit, 0u);
    AL_CHECK_EQ_U64(contract.storage_bytes, 0u);
    al_test_state_fixture_destroy(&fixture);
}

#define AL_TEST_SUITE_NAME "test_state"
AL_TEST_MAIN {
    AL_RUN(initialisation_and_accounts);
    AL_RUN(root_is_order_independent);
    AL_RUN(staged_commit_rollback_and_snapshot);
    AL_RUN(membership_and_absence_proofs);
    AL_RUN(storage_deposit_and_isolation);
}
