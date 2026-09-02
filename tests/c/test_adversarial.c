/*
 * Adversarial consensus scenarios: double-sign evidence, Byzantine votes,
 * codec roundtrip, non-committee submissions, and slashing.
 */

#include "altest.h"
#include "finality.h"
#include "astrolune/evidence.h"

#define AL_TEST_SUITE_NAME "adversarial"

typedef struct adv_fixture {
    al_keypair keys[5];
    al_potb_committee committee;
    al_hash256 block_hash_a;
    al_hash256 block_hash_b;
    al_hash256 committee_hash;
} adv_fixture;

static void fixture_init(adv_fixture *f) {
    memset(f, 0, sizeof(*f));
    for (al_u8 i = 0u; i < 5u; ++i) {
        al_u8 seed[32] = {0};
        seed[0] = (al_u8)(i + 1u);
        AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &f->keys[i]), AL_OK);
    }
    f->committee.size = 4u;
    f->committee.formed_at = 9u;
    al_sha256("adv-seed", 8u, &f->committee.seed);
    for (al_u32 i = 0u; i < f->committee.size; ++i) {
        f->committee.members[i] = f->keys[i].pk;
        f->committee.weights[i] = AL_FIXED_ONE;
    }
    al_sha256("block-alpha", 10u, &f->block_hash_a);
    al_sha256("block-beta", 9u, &f->block_hash_b);
    al_consensus_committee_hash(&f->committee, &f->committee_hash);
}

static al_consensus_vote make_vote(adv_fixture *f, al_u32 voter,
                                   al_consensus_phase phase,
                                   const al_hash256 *block_hash) {
    al_consensus_vote vote;
    memset(&vote, 0, sizeof(vote));
    vote.version = AL_CONSENSUS_VERSION;
    vote.chain_id = 42u;
    vote.height = 10u;
    vote.round = 0u;
    vote.phase = phase;
    vote.block_hash = *block_hash;
    vote.committee_hash = f->committee_hash;
    vote.voter = f->keys[voter].pk;
    AL_CHECK_EQ_STATUS(
        al_consensus_vote_sign(&vote, &f->keys[voter].sk), AL_OK);
    return vote;
}

/* --------------------------------------------------------------------------
 * Double-sign evidence: create + verify
 * -------------------------------------------------------------------------- */

AL_TEST(double_sign_prevote_evidence) {
    adv_fixture f;
    fixture_init(&f);
    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_b);
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev), AL_OK);
    AL_CHECK_EQ_STATUS(al_evidence_verify(&ev, &f.committee), AL_OK);
}

AL_TEST(double_sign_precommit_evidence) {
    adv_fixture f;
    fixture_init(&f);
    al_consensus_vote v1 = make_vote(&f, 1u, AL_CONSENSUS_PRECOMMIT,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 1u, AL_CONSENSUS_PRECOMMIT,
                                     &f.block_hash_b);
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev), AL_OK);
    AL_CHECK_EQ_STATUS(al_evidence_verify(&ev, &f.committee), AL_OK);
}

/* --------------------------------------------------------------------------
 * Evidence creation rejects adversarial inputs
 * -------------------------------------------------------------------------- */

AL_TEST(evidence_create_rejects_different_voters) {
    adv_fixture f;
    fixture_init(&f);
    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 1u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_b);
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev),
                       AL_ERR_CONSENSUS_VIOLATION);
}

AL_TEST(evidence_create_rejects_same_block_hash) {
    adv_fixture f;
    fixture_init(&f);
    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = v1; /* identical vote */
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev),
                       AL_ERR_CONSENSUS_VIOLATION);
}

AL_TEST(evidence_create_rejects_different_height) {
    adv_fixture f;
    fixture_init(&f);
    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_b);
    v2.height = 11u;
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev),
                       AL_ERR_CONSENSUS_VIOLATION);
}

AL_TEST(evidence_create_rejects_different_round) {
    adv_fixture f;
    fixture_init(&f);
    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_b);
    v2.round = 1u;
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev),
                       AL_ERR_CONSENSUS_VIOLATION);
}

AL_TEST(evidence_create_rejects_different_phase) {
    adv_fixture f;
    fixture_init(&f);
    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 0u, AL_CONSENSUS_PRECOMMIT,
                                     &f.block_hash_b);
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev),
                       AL_ERR_CONSENSUS_VIOLATION);
}

AL_TEST(evidence_create_rejects_different_chain_id) {
    adv_fixture f;
    fixture_init(&f);
    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_b);
    v2.chain_id = 99u;
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev),
                       AL_ERR_CONSENSUS_VIOLATION);
}

/* --------------------------------------------------------------------------
 * Evidence verify rejects non-committee members
 * -------------------------------------------------------------------------- */

AL_TEST(evidence_verify_rejects_non_committee_member) {
    adv_fixture f;
    fixture_init(&f);
    /* Key index 4 is outside committee (size=4). We must create valid
     * evidence first (same voter), then verify against committee. */
    al_consensus_vote v1 = make_vote(&f, 4u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 4u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_b);
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev), AL_OK);
    AL_CHECK_EQ_STATUS(al_evidence_verify(&ev, &f.committee),
                       AL_ERR_CONSENSUS_VIOLATION);
}

/* --------------------------------------------------------------------------
 * Evidence codec roundtrip
 * -------------------------------------------------------------------------- */

AL_TEST(evidence_codec_roundtrip) {
    adv_fixture f;
    fixture_init(&f);
    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_b);
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev), AL_OK);

    al_u8 buf[AL_EVIDENCE_MAX_ENCODED_SIZE];
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_evidence_encode(&ev, (al_bytes_mut){buf, sizeof(buf)},
                                          &written), AL_OK);
    AL_CHECK(written > 0u);

    al_evidence decoded;
    AL_CHECK_EQ_STATUS(al_evidence_decode(al_bytes_make(buf, written), &decoded),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_evidence_verify(&decoded, &f.committee), AL_OK);

    /* Tamper: flip signature byte -> verify should now reject since
     * evidence_verify performs Ed25519 signature checks. */
    decoded.vote1.signature.bytes[0] ^= 0xffu;
    AL_CHECK_EQ_STATUS(al_evidence_verify(&decoded, &f.committee),
                       AL_ERR_BAD_SIGNATURE);
}

/* --------------------------------------------------------------------------
 * Vote set adversarial scenarios
 * -------------------------------------------------------------------------- */

AL_TEST(vote_set_rejects_duplicate_voter) {
    adv_fixture f;
    fixture_init(&f);
    al_vote_set set;
    al_vote_set_init(&set, 42u, 10u, 0u, AL_CONSENSUS_PREVOTE,
                     &f.block_hash_a, &f.committee_hash);
    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &v1, &f.committee), AL_OK);
    al_consensus_vote dup = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                      &f.block_hash_a);
    AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &dup, &f.committee),
                       AL_ERR_ALREADY_EXISTS);
}

AL_TEST(vote_set_rejects_wrong_block_hash) {
    adv_fixture f;
    fixture_init(&f);
    al_vote_set set;
    al_vote_set_init(&set, 42u, 10u, 0u, AL_CONSENSUS_PREVOTE,
                     &f.block_hash_a, &f.committee_hash);
    al_consensus_vote wrong = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                        &f.block_hash_b);
    AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &wrong, &f.committee),
                       AL_ERR_CONSENSUS_VIOLATION);
}

AL_TEST(vote_set_rejects_non_committee_voter) {
    adv_fixture f;
    fixture_init(&f);
    al_vote_set set;
    al_vote_set_init(&set, 42u, 10u, 0u, AL_CONSENSUS_PREVOTE,
                     &f.block_hash_a, &f.committee_hash);
    al_consensus_vote outsider = make_vote(&f, 4u, AL_CONSENSUS_PREVOTE,
                                           &f.block_hash_a);
    AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &outsider, &f.committee),
                       AL_ERR_CONSENSUS_VIOLATION);
}

AL_TEST(vote_set_quorum_requires_threshold) {
    adv_fixture f;
    fixture_init(&f);
    al_vote_set set;
    al_vote_set_init(&set, 42u, 10u, 0u, AL_CONSENSUS_PREVOTE,
                     &f.block_hash_a, &f.committee_hash);
    /* Committee size=4, quorum = floor(2*4/3)+1 = 3. */
    for (al_u32 i = 0u; i < 2u; ++i) {
        al_consensus_vote v = make_vote(&f, i, AL_CONSENSUS_PREVOTE,
                                        &f.block_hash_a);
        AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &v, &f.committee), AL_OK);
        AL_CHECK(!al_vote_set_has_quorum(&set, &f.committee));
    }
    al_consensus_vote v = make_vote(&f, 2u, AL_CONSENSUS_PREVOTE,
                                    &f.block_hash_a);
    AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &v, &f.committee), AL_OK);
    AL_CHECK(al_vote_set_has_quorum(&set, &f.committee));
}

/* --------------------------------------------------------------------------
 * Evidence processing: slashing
 * -------------------------------------------------------------------------- */

AL_TEST(evidence_process_applies_temporary_ban) {
    adv_fixture f;
    fixture_init(&f);
    al_potb_record record;
    memset(&record, 0, sizeof(record));
    record.identity = f.keys[0].pk;
    record.banned_until_day = 0u;
    record.penalty_multiplier = AL_FIXED_ONE;

    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_b);
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev), AL_OK);

    al_potb_params params = al_potb_params_default();
    AL_CHECK_EQ_STATUS(al_evidence_process(&params, &record, &ev, 1000u),
                       AL_OK);
    /* First offence: 14-day ban from now. */
    AL_CHECK_EQ_U64(record.banned_until_day, 1014u);
    AL_CHECK(!record.permanently_banned);
    /* Penalty multiplier reduced. */
    AL_CHECK(record.penalty_multiplier < AL_FIXED_ONE);
}

AL_TEST(evidence_process_applies_permanent_ban_on_repeat) {
    adv_fixture f;
    fixture_init(&f);
    al_potb_record record;
    memset(&record, 0, sizeof(record));
    record.identity = f.keys[0].pk;
    record.banned_until_day = 0u;
    record.penalty_multiplier = AL_FIXED_ONE;

    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_b);
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev), AL_OK);

    al_potb_params params = al_potb_params_default();
    /* First evidence processing: temporary ban. */
    AL_CHECK_EQ_STATUS(al_evidence_process(&params, &record, &ev, 1000u),
                       AL_OK);
    AL_CHECK_EQ_U64(record.banned_until_day, 1014u);
    AL_CHECK(!record.permanently_banned);

    /* Second evidence processing: permanent ban triggered. */
    AL_CHECK_EQ_STATUS(al_evidence_process(&params, &record, &ev, 2000u),
                       AL_OK);
    AL_CHECK(record.permanently_banned);
}

AL_TEST(evidence_process_rejects_wrong_identity) {
    adv_fixture f;
    fixture_init(&f);
    al_potb_record record;
    memset(&record, 0, sizeof(record));
    record.identity = f.keys[1].pk; /* key 1, not key 0 */

    al_consensus_vote v1 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_a);
    al_consensus_vote v2 = make_vote(&f, 0u, AL_CONSENSUS_PREVOTE,
                                     &f.block_hash_b);
    al_evidence ev;
    AL_CHECK_EQ_STATUS(al_evidence_create(&v1, &v2, &ev), AL_OK);

    al_potb_params params = al_potb_params_default();
    AL_CHECK_EQ_STATUS(al_evidence_process(&params, &record, &ev, 1000u),
                       AL_ERR_CONSENSUS_VIOLATION);
}

/* --------------------------------------------------------------------------
 * Evidence encoding edge cases
 * -------------------------------------------------------------------------- */

AL_TEST(evidence_encode_rejects_null_input) {
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_evidence_encode(NULL, (al_bytes_mut){NULL, 0u},
                                          &written),
                       AL_ERR_INVALID_ARG);
}

AL_TEST(evidence_encode_rejects_buffer_too_small) {
    al_u8 tiny[4];
    al_size written = 0u;
    al_evidence ev;
    memset(&ev, 0, sizeof(ev));
    AL_CHECK_EQ_STATUS(al_evidence_encode(&ev, (al_bytes_mut){tiny, sizeof(tiny)},
                                          &written),
                       AL_ERR_BUFFER_TOO_SMALL);
}

AL_TEST(evidence_decode_rejects_truncated) {
    al_u8 tiny[2] = {0x01, 0x02};
    al_evidence decoded;
    AL_CHECK_EQ_STATUS(al_evidence_decode(al_bytes_make(tiny, sizeof(tiny)),
                                          &decoded),
                       AL_ERR_TRUNCATED);
}

/* --------------------------------------------------------------------------
 * Finality certificate: tamper detection
 * -------------------------------------------------------------------------- */

AL_TEST(finality_cert_rejects_duplicate_voter) {
    adv_fixture f;
    fixture_init(&f);
    al_vote_set set;
    al_vote_set_init(&set, 42u, 10u, 0u, AL_CONSENSUS_PRECOMMIT,
                     &f.block_hash_a, &f.committee_hash);
    for (al_u32 i = 0u; i < 3u; ++i) {
        al_consensus_vote v = make_vote(&f, i, AL_CONSENSUS_PRECOMMIT,
                                        &f.block_hash_a);
        AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &v, &f.committee), AL_OK);
    }
    al_finality_certificate cert;
    AL_CHECK_EQ_STATUS(al_vote_set_certificate(&set, &f.committee, &cert),
                       AL_OK);
    /* Tamper: duplicate a vote. */
    cert.votes[2] = cert.votes[1];
    AL_CHECK_EQ_STATUS(al_finality_certificate_verify(&cert, &f.committee),
                       AL_ERR_CONSENSUS_VIOLATION);
}

AL_TEST_MAIN {
    AL_RUN(double_sign_prevote_evidence);
    AL_RUN(double_sign_precommit_evidence);
    AL_RUN(evidence_create_rejects_different_voters);
    AL_RUN(evidence_create_rejects_same_block_hash);
    AL_RUN(evidence_create_rejects_different_height);
    AL_RUN(evidence_create_rejects_different_round);
    AL_RUN(evidence_create_rejects_different_phase);
    AL_RUN(evidence_create_rejects_different_chain_id);
    AL_RUN(evidence_verify_rejects_non_committee_member);
    AL_RUN(evidence_codec_roundtrip);
    AL_RUN(vote_set_rejects_duplicate_voter);
    AL_RUN(vote_set_rejects_wrong_block_hash);
    AL_RUN(vote_set_rejects_non_committee_voter);
    AL_RUN(vote_set_quorum_requires_threshold);
    AL_RUN(evidence_process_applies_temporary_ban);
    AL_RUN(evidence_process_applies_permanent_ban_on_repeat);
    AL_RUN(evidence_process_rejects_wrong_identity);
    AL_RUN(evidence_encode_rejects_null_input);
    AL_RUN(evidence_encode_rejects_buffer_too_small);
    AL_RUN(evidence_decode_rejects_truncated);
    AL_RUN(finality_cert_rejects_duplicate_voter);
}
