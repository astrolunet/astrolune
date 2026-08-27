#include "altest.h"
#include "finality.h"

typedef struct consensus_fixture {
    al_keypair keys[5];
    al_potb_committee committee;
    al_hash256 block_hash;
    al_hash256 parent_hash;
    al_hash256 committee_hash;
} consensus_fixture;

static void fixture_init(consensus_fixture *fixture) {
    memset(fixture, 0, sizeof(*fixture));
    for (al_u8 i = 0u; i < 5u; ++i) {
        al_u8 seed[32] = {0};
        seed[0] = (al_u8)(i + 1u);
        AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &fixture->keys[i]),
                           AL_OK);
    }
    fixture->committee.size = 4u;
    fixture->committee.formed_at = 9u;
    al_sha256("committee-seed", 14u, &fixture->committee.seed);
    for (al_u32 i = 0u; i < fixture->committee.size; ++i) {
        fixture->committee.members[i] = fixture->keys[i].pk;
        fixture->committee.weights[i] = AL_FIXED_ONE;
    }
    al_sha256("block", 5u, &fixture->block_hash);
    al_sha256("parent", 6u, &fixture->parent_hash);
    al_consensus_committee_hash(&fixture->committee,
                                &fixture->committee_hash);
}

static al_consensus_proposal make_proposal(consensus_fixture *fixture,
                                           al_height height,
                                           al_u32 round) {
    al_consensus_proposal proposal;
    memset(&proposal, 0, sizeof(proposal));
    proposal.version = AL_CONSENSUS_VERSION;
    proposal.chain_id = 42u;
    proposal.height = height;
    proposal.round = round;
    proposal.block_hash = fixture->block_hash;
    proposal.parent_hash = fixture->parent_hash;
    proposal.committee_hash = fixture->committee_hash;
    const al_pubkey *proposer =
        al_consensus_proposer(&fixture->committee, height, round);
    AL_CHECK(proposer != NULL);
    if (proposer != NULL) proposal.proposer = *proposer;
    al_u32 index = (al_u32)((height + round) % fixture->committee.size);
    AL_CHECK_EQ_STATUS(al_consensus_proposal_sign(
                           &proposal, &fixture->keys[index].sk),
                       AL_OK);
    return proposal;
}

static al_consensus_vote make_vote(consensus_fixture *fixture, al_u32 voter,
                                   al_consensus_phase phase) {
    al_consensus_vote vote;
    memset(&vote, 0, sizeof(vote));
    vote.version = AL_CONSENSUS_VERSION;
    vote.chain_id = 42u;
    vote.height = 7u;
    vote.round = 0u;
    vote.phase = phase;
    vote.block_hash = fixture->block_hash;
    vote.committee_hash = fixture->committee_hash;
    vote.voter = fixture->keys[voter].pk;
    AL_CHECK_EQ_STATUS(
        al_consensus_vote_sign(&vote, &fixture->keys[voter].sk), AL_OK);
    return vote;
}

AL_TEST(committee_hash_and_proposer_are_deterministic) {
    consensus_fixture fixture;
    fixture_init(&fixture);
    al_hash256 again;
    al_consensus_committee_hash(&fixture.committee, &again);
    AL_CHECK(al_hash_eq(&again, &fixture.committee_hash));
    AL_CHECK(al_bytes_eq(
        al_bytes_make(al_consensus_proposer(&fixture.committee, 0u, 0u)->bytes,
                      AL_PUBKEY_SIZE),
        al_bytes_make(fixture.keys[0].pk.bytes, AL_PUBKEY_SIZE)));
    AL_CHECK(al_bytes_eq(
        al_bytes_make(al_consensus_proposer(&fixture.committee, 0u, 5u)->bytes,
                      AL_PUBKEY_SIZE),
        al_bytes_make(fixture.keys[1].pk.bytes, AL_PUBKEY_SIZE)));
}

AL_TEST(proposal_signature_and_codec) {
    consensus_fixture fixture;
    fixture_init(&fixture);
    al_consensus_proposal proposal = make_proposal(&fixture, 7u, 0u);
    AL_CHECK_EQ_STATUS(
        al_consensus_proposal_verify(&proposal, &fixture.committee), AL_OK);

    al_u8 encoded[AL_PROPOSAL_ENCODED_SIZE];
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_consensus_proposal_encode(
                           &proposal,
                           (al_bytes_mut){ encoded, sizeof(encoded) },
                           &written),
                       AL_OK);
    AL_CHECK_EQ_U64(written, AL_PROPOSAL_ENCODED_SIZE);
    al_consensus_proposal decoded;
    AL_CHECK_EQ_STATUS(al_consensus_proposal_decode(
                           al_bytes_make(encoded, written), &decoded),
                       AL_OK);
    AL_CHECK_EQ_STATUS(
        al_consensus_proposal_verify(&decoded, &fixture.committee), AL_OK);

    decoded.round++;
    AL_CHECK_EQ_STATUS(
        al_consensus_proposal_verify(&decoded, &fixture.committee),
        AL_ERR_CONSENSUS_VIOLATION);
    proposal.signature.bytes[0] ^= 1u;
    AL_CHECK_EQ_STATUS(
        al_consensus_proposal_verify(&proposal, &fixture.committee),
        AL_ERR_BAD_SIGNATURE);
}

AL_TEST(vote_set_requires_unique_committee_quorum) {
    consensus_fixture fixture;
    fixture_init(&fixture);
    al_vote_set set;
    al_vote_set_init(&set, 42u, 7u, 0u, AL_CONSENSUS_PRECOMMIT,
                     &fixture.block_hash, &fixture.committee_hash);
    for (al_u32 i = 0u; i < 3u; ++i) {
        al_consensus_vote vote =
            make_vote(&fixture, i, AL_CONSENSUS_PRECOMMIT);
        AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &vote, &fixture.committee),
                           AL_OK);
        if (i < 2u) AL_CHECK(!al_vote_set_has_quorum(&set, &fixture.committee));
        if (i == 2u) AL_CHECK(al_vote_set_has_quorum(&set, &fixture.committee));
    }
    al_consensus_vote duplicate =
        make_vote(&fixture, 0u, AL_CONSENSUS_PRECOMMIT);
    AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &duplicate, &fixture.committee),
                       AL_ERR_ALREADY_EXISTS);

    al_consensus_vote outsider =
        make_vote(&fixture, 4u, AL_CONSENSUS_PRECOMMIT);
    AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &outsider, &fixture.committee),
                       AL_ERR_CONSENSUS_VIOLATION);

    al_consensus_vote wrong =
        make_vote(&fixture, 3u, AL_CONSENSUS_PRECOMMIT);
    wrong.block_hash.bytes[0] ^= 1u;
    AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &wrong, &fixture.committee),
                       AL_ERR_CONSENSUS_VIOLATION);
}

AL_TEST(finality_certificate_roundtrip_and_tamper_rejection) {
    consensus_fixture fixture;
    fixture_init(&fixture);
    al_vote_set set;
    al_vote_set_init(&set, 42u, 7u, 0u, AL_CONSENSUS_PRECOMMIT,
                     &fixture.block_hash, &fixture.committee_hash);
    for (al_u32 i = 0u; i < 3u; ++i) {
        al_consensus_vote vote =
            make_vote(&fixture, i, AL_CONSENSUS_PRECOMMIT);
        AL_CHECK_EQ_STATUS(al_vote_set_add(&set, &vote, &fixture.committee),
                           AL_OK);
    }
    static al_finality_certificate certificate;
    AL_CHECK_EQ_STATUS(al_vote_set_certificate(
                           &set, &fixture.committee, &certificate),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_finality_certificate_verify(
                           &certificate, &fixture.committee),
                       AL_OK);

    al_size required = 0u;
    AL_CHECK_EQ_STATUS(al_finality_certificate_encode(
                           &certificate, (al_bytes_mut){ NULL, 0u },
                           &required),
                       AL_ERR_BUFFER_TOO_SMALL);
    al_u8 encoded[2048];
    AL_CHECK(required < sizeof(encoded));
    al_size written = 0u;
    AL_CHECK_EQ_STATUS(al_finality_certificate_encode(
                           &certificate,
                           (al_bytes_mut){ encoded, sizeof(encoded) },
                           &written),
                       AL_OK);
    static al_finality_certificate decoded;
    AL_CHECK_EQ_STATUS(al_finality_certificate_decode(
                           al_bytes_make(encoded, written), &decoded),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_finality_certificate_verify(
                           &decoded, &fixture.committee),
                       AL_OK);

    decoded.votes[2] = decoded.votes[1];
    AL_CHECK_EQ_STATUS(al_finality_certificate_verify(
                           &decoded, &fixture.committee),
                       AL_ERR_CONSENSUS_VIOLATION);
    decoded = certificate;
    decoded.votes[0].signature.bytes[0] ^= 1u;
    AL_CHECK_EQ_STATUS(al_finality_certificate_verify(
                           &decoded, &fixture.committee),
                       AL_ERR_BAD_SIGNATURE);
}

static const char *AL_TEST_SUITE_NAME = "consensus";

AL_TEST_MAIN {
    AL_RUN(committee_hash_and_proposer_are_deterministic);
    AL_RUN(proposal_signature_and_codec);
    AL_RUN(vote_set_requires_unique_committee_quorum);
    AL_RUN(finality_certificate_roundtrip_and_tamper_rejection);
}
