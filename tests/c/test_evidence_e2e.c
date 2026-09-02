/*
 * End-to-end evidence/slashing test.
 *
 * Exercises the full tx execution path for AL_POTB_OFFENCE_EVIDENCE:
 * create double-signed votes, encode them into a POTB transaction, execute
 * through al_tx_apply, and verify the receipt indicates success.
 *
 * The durable persistence path is verified by the smoke test (validator
 * restart from finalized storage). Unit-level slashing logic is covered
 * by test_adversarial.c. This test fills the gap: the transaction
 * execution layer correctly handles evidence transactions.
 */

#include "altest.h"
#include "finality.h"
#include "astrolune/evidence.h"
#include "astrolune/tx.h"
#include "state_fixture.h"

#define AL_TEST_SUITE_NAME "evidence_e2e"

/* ---------- helpers -------------------------------------------------- */

static al_keypair keypair_with(al_u8 value) {
    al_u8 seed[32] = {0};
    seed[0] = value;
    al_keypair kp;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);
    return kp;
}

static al_address address_with(al_u8 value) {
    al_address addr;
    memset(addr.bytes, value, sizeof(addr.bytes));
    return addr;
}

static al_resources resources_with(al_u64 value) {
    al_resources r = {value, value, value, value};
    return r;
}

static al_tx_context make_context(al_arena *arena) {
    al_tx_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.chain_id = 7u;
    ctx.block_height = 10u;
    ctx.protocol_day = 1000u;
    ctx.base_prices = resources_with(1u);
    ctx.tip_flat = address_with(0xa1u);
    ctx.tip_weighted = address_with(0xa2u);
    ctx.tip_bonded = address_with(0xa3u);
    ctx.vm = al_vm_config_default();
    ctx.arena = arena;
    ctx.potb_params = NULL;
    return ctx;
}

static void add_sender(al_state *state, const al_pubkey *pk, al_nonce nonce) {
    al_account acct;
    memset(&acct, 0, sizeof(acct));
    al_address_from_pubkey(pk, &acct.address);
    acct.balance = 1000000u;
    acct.nonce = nonce;
    AL_CHECK_EQ_STATUS(al_state_upsert(state, &acct), AL_OK);
}

static void make_double_sign(al_keypair *kp, al_u32 chain_id,
                             al_height height, al_u32 round,
                             al_consensus_vote *out1,
                             al_consensus_vote *out2) {
    al_hash256 block_a, block_b;
    al_sha256("block-alpha", 10u, &block_a);
    al_sha256("block-beta", 9u, &block_b);

    al_hash256 committee_hash;
    al_potb_committee committee;
    committee.size = 1u;
    committee.formed_at = 9u;
    al_sha256("seed", 4u, &committee.seed);
    committee.members[0] = kp->pk;
    committee.weights[0] = AL_FIXED_ONE;
    al_consensus_committee_hash(&committee, &committee_hash);

    memset(out1, 0, sizeof(*out1));
    out1->version = AL_CONSENSUS_VERSION;
    out1->chain_id = chain_id;
    out1->height = height;
    out1->round = round;
    out1->phase = AL_CONSENSUS_PREVOTE;
    out1->block_hash = block_a;
    out1->committee_hash = committee_hash;
    out1->voter = kp->pk;
    AL_CHECK_EQ_STATUS(al_consensus_vote_sign(out1, &kp->sk), AL_OK);

    memset(out2, 0, sizeof(*out2));
    out2->version = AL_CONSENSUS_VERSION;
    out2->chain_id = chain_id;
    out2->height = height;
    out2->round = round;
    out2->phase = AL_CONSENSUS_PREVOTE;
    out2->block_hash = block_b;
    out2->committee_hash = committee_hash;
    out2->voter = kp->pk;
    AL_CHECK_EQ_STATUS(al_consensus_vote_sign(out2, &kp->sk), AL_OK);
}

/* ---------- tests ---------------------------------------------------- */

/* Test 1: Evidence tx executes and receipt is OK. */
AL_TEST(evidence_tx_executes) {
    al_test_state_fixture fx;
    al_test_state_fixture_init(&fx, 1u);

    al_keypair kp = keypair_with(1u);
    add_sender(&fx.state, &kp.pk, 0u);

    al_consensus_vote v1, v2;
    make_double_sign(&kp, 7u, 10u, 0u, &v1, &v2);
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev), AL_OK);

    al_u8 evidence_buf[AL_EVIDENCE_MAX_ENCODED_SIZE];
    al_size evidence_written = 0u;
    AL_CHECK_EQ_STATUS(al_evidence_encode(&ev,
        (al_bytes_mut){evidence_buf, sizeof(evidence_buf)}, &evidence_written),
        AL_OK);

    al_transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = AL_TX_VERSION;
    tx.chain_id = 7u;
    tx.expiry_height = 20u;
    tx.sender = kp.pk;
    tx.nonce = 0u;
    tx.resource_limit = resources_with(100000u);
    tx.max_base_price = resources_with(2u);
    tx.type = AL_TX_POTB;
    tx.body.potb.operation = AL_POTB_OFFENCE_EVIDENCE;
    tx.body.potb.data = al_bytes_make(evidence_buf, evidence_written);
    AL_CHECK_EQ_STATUS(al_tx_sign(&tx, &kp.sk), AL_OK);

    al_arena exec_arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&exec_arena, 0u), AL_OK);
    al_tx_context ctx = make_context(&exec_arena);
    al_receipt receipt;
    AL_CHECK_EQ_STATUS(al_tx_apply(&tx, &fx.state, &ctx, &receipt), AL_OK);
    AL_CHECK_EQ_STATUS(receipt.status, AL_OK);
    al_arena_destroy(&exec_arena);

    al_test_state_fixture_destroy(&fx);
}

/* Test 2: Evidence tx at different heights executes successfully. */
AL_TEST(evidence_tx_multiple_heights) {
    al_test_state_fixture fx;
    al_test_state_fixture_init(&fx, 1u);

    al_keypair kp = keypair_with(2u);
    add_sender(&fx.state, &kp.pk, 0u);

    /* First evidence at height 10. */
    al_consensus_vote v1a, v1b;
    make_double_sign(&kp, 7u, 10u, 0u, &v1a, &v1b);
    al_evidence ev1;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1a, &v1b, &ev1), AL_OK);

    al_u8 evidence_buf[AL_EVIDENCE_MAX_ENCODED_SIZE];
    al_size evidence_written = 0u;
    AL_CHECK_EQ_STATUS(al_evidence_encode(&ev1,
        (al_bytes_mut){evidence_buf, sizeof(evidence_buf)}, &evidence_written),
        AL_OK);

    al_transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = AL_TX_VERSION;
    tx.chain_id = 7u;
    tx.expiry_height = 20u;
    tx.sender = kp.pk;
    tx.nonce = 0u;
    tx.resource_limit = resources_with(100000u);
    tx.max_base_price = resources_with(2u);
    tx.type = AL_TX_POTB;
    tx.body.potb.operation = AL_POTB_OFFENCE_EVIDENCE;
    tx.body.potb.data = al_bytes_make(evidence_buf, evidence_written);
    AL_CHECK_EQ_STATUS(al_tx_sign(&tx, &kp.sk), AL_OK);

    al_arena exec_arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&exec_arena, 0u), AL_OK);
    al_tx_context ctx = make_context(&exec_arena);
    al_receipt receipt;
    AL_CHECK_EQ_STATUS(al_tx_apply(&tx, &fx.state, &ctx, &receipt), AL_OK);
    AL_CHECK_EQ_STATUS(receipt.status, AL_OK);
    al_arena_destroy(&exec_arena);

    /* Second evidence at height 11. */
    al_consensus_vote v2a, v2b;
    make_double_sign(&kp, 7u, 11u, 0u, &v2a, &v2b);
    al_evidence ev2;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v2a, &v2b, &ev2), AL_OK);

    evidence_written = 0u;
    AL_CHECK_EQ_STATUS(al_evidence_encode(&ev2,
        (al_bytes_mut){evidence_buf, sizeof(evidence_buf)}, &evidence_written),
        AL_OK);

    memset(&tx, 0, sizeof(tx));
    tx.version = AL_TX_VERSION;
    tx.chain_id = 7u;
    tx.expiry_height = 20u;
    tx.sender = kp.pk;
    tx.nonce = 1u;
    tx.resource_limit = resources_with(100000u);
    tx.max_base_price = resources_with(2u);
    tx.type = AL_TX_POTB;
    tx.body.potb.operation = AL_POTB_OFFENCE_EVIDENCE;
    tx.body.potb.data = al_bytes_make(evidence_buf, evidence_written);
    AL_CHECK_EQ_STATUS(al_tx_sign(&tx, &kp.sk), AL_OK);

    AL_CHECK_EQ_STATUS(al_arena_init(&exec_arena, 0u), AL_OK);
    ctx = make_context(&exec_arena);
    AL_CHECK_EQ_STATUS(al_tx_apply(&tx, &fx.state, &ctx, &receipt), AL_OK);
    AL_CHECK_EQ_STATUS(receipt.status, AL_OK);
    al_arena_destroy(&exec_arena);

    al_test_state_fixture_destroy(&fx);
}

/* Test 3: Evidence tx with precommit votes. */
AL_TEST(evidence_tx_precommit) {
    al_test_state_fixture fx;
    al_test_state_fixture_init(&fx, 1u);

    al_keypair kp = keypair_with(3u);
    add_sender(&fx.state, &kp.pk, 0u);

    al_hash256 block_a, block_b;
    al_sha256("block-a", 7u, &block_a);
    al_sha256("block-b", 7u, &block_b);

    al_hash256 committee_hash;
    al_potb_committee committee;
    committee.size = 1u;
    committee.formed_at = 9u;
    al_sha256("seed", 4u, &committee.seed);
    committee.members[0] = kp.pk;
    committee.weights[0] = AL_FIXED_ONE;
    al_consensus_committee_hash(&committee, &committee_hash);

    al_consensus_vote v1;
    memset(&v1, 0, sizeof(v1));
    v1.version = AL_CONSENSUS_VERSION;
    v1.chain_id = 7u;
    v1.height = 10u;
    v1.round = 0u;
    v1.phase = AL_CONSENSUS_PRECOMMIT;
    v1.block_hash = block_a;
    v1.committee_hash = committee_hash;
    v1.voter = kp.pk;
    AL_CHECK_EQ_STATUS(al_consensus_vote_sign(&v1, &kp.sk), AL_OK);

    al_consensus_vote v2;
    memset(&v2, 0, sizeof(v2));
    v2.version = AL_CONSENSUS_VERSION;
    v2.chain_id = 7u;
    v2.height = 10u;
    v2.round = 0u;
    v2.phase = AL_CONSENSUS_PRECOMMIT;
    v2.block_hash = block_b;
    v2.committee_hash = committee_hash;
    v2.voter = kp.pk;
    AL_CHECK_EQ_STATUS(al_consensus_vote_sign(&v2, &kp.sk), AL_OK);

    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev), AL_OK);

    al_u8 evidence_buf[AL_EVIDENCE_MAX_ENCODED_SIZE];
    al_size evidence_written = 0u;
    AL_CHECK_EQ_STATUS(al_evidence_encode(&ev,
        (al_bytes_mut){evidence_buf, sizeof(evidence_buf)}, &evidence_written),
        AL_OK);

    al_transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = AL_TX_VERSION;
    tx.chain_id = 7u;
    tx.expiry_height = 20u;
    tx.sender = kp.pk;
    tx.nonce = 0u;
    tx.resource_limit = resources_with(100000u);
    tx.max_base_price = resources_with(2u);
    tx.type = AL_TX_POTB;
    tx.body.potb.operation = AL_POTB_OFFENCE_EVIDENCE;
    tx.body.potb.data = al_bytes_make(evidence_buf, evidence_written);
    AL_CHECK_EQ_STATUS(al_tx_sign(&tx, &kp.sk), AL_OK);

    al_arena exec_arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&exec_arena, 0u), AL_OK);
    al_tx_context ctx = make_context(&exec_arena);
    al_receipt receipt;
    AL_CHECK_EQ_STATUS(al_tx_apply(&tx, &fx.state, &ctx, &receipt), AL_OK);
    AL_CHECK_EQ_STATUS(receipt.status, AL_OK);
    al_arena_destroy(&exec_arena);

    al_test_state_fixture_destroy(&fx);
}

AL_TEST_MAIN {
    AL_RUN(evidence_tx_executes);
    AL_RUN(evidence_tx_multiple_heights);
    AL_RUN(evidence_tx_precommit);
}
