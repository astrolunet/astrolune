/* Signed PoTB proposal, vote and finality-certificate primitives. */

#ifndef ASTROLUNE_CONSENSUS_FINALITY_H
#define ASTROLUNE_CONSENSUS_FINALITY_H

#include "astrolune/potb.h"

AL_EXTERN_C_BEGIN

#define AL_CONSENSUS_VERSION 1u
#define AL_PROPOSAL_ENCODED_SIZE 210u
#define AL_VOTE_ENCODED_SIZE 179u
#define AL_FINALITY_CERTIFICATE_MAX_ENCODED_SIZE                         \
    (2u + 4u + 8u + 4u + AL_HASH_SIZE + AL_HASH_SIZE + 10u +           \
     AL_POTB_MAX_COMMITTEE * AL_VOTE_ENCODED_SIZE)

typedef enum al_consensus_phase {
    AL_CONSENSUS_PREVOTE = 1,
    AL_CONSENSUS_PRECOMMIT = 2,
    AL_CONSENSUS_PHASE_SENTINEL = 0x7fffffff
} al_consensus_phase;

typedef struct al_consensus_proposal {
    al_u16     version;
    al_u32     chain_id;
    al_height  height;
    al_u32     round;
    al_hash256 block_hash;
    al_hash256 parent_hash;
    al_hash256 committee_hash;
    al_pubkey  proposer;
    al_sig     signature;
} al_consensus_proposal;

typedef struct al_consensus_vote {
    al_u16             version;
    al_u32             chain_id;
    al_height          height;
    al_u32             round;
    al_consensus_phase phase;
    al_hash256         block_hash;
    al_hash256         committee_hash;
    al_pubkey          voter;
    al_sig             signature;
} al_consensus_vote;

typedef struct al_finality_certificate {
    al_u16            version;
    al_u32            chain_id;
    al_height         height;
    al_u32            round;
    al_hash256        block_hash;
    al_hash256        committee_hash;
    al_u32            vote_count;
    al_consensus_vote votes[AL_POTB_MAX_COMMITTEE];
} al_finality_certificate;

typedef struct al_vote_set {
    al_u32             chain_id;
    al_height          height;
    al_u32             round;
    al_consensus_phase phase;
    al_hash256         block_hash;
    al_hash256         committee_hash;
    al_u32             vote_count;
    al_consensus_vote  votes[AL_POTB_MAX_COMMITTEE];
} al_vote_set;

void al_consensus_committee_hash(const al_potb_committee *committee,
                                 al_hash256 *out);
const al_pubkey *al_consensus_proposer(const al_potb_committee *committee,
                                       al_height height, al_u32 round);

void al_consensus_proposal_hash(const al_consensus_proposal *proposal,
                                al_hash256 *out);
AL_NODISCARD al_status al_consensus_proposal_sign(
    al_consensus_proposal *proposal, const al_seckey *secret_key);
AL_NODISCARD al_status al_consensus_proposal_verify(
    const al_consensus_proposal *proposal,
    const al_potb_committee *committee);
AL_NODISCARD al_status al_consensus_proposal_encode(
    const al_consensus_proposal *proposal, al_bytes_mut out,
    al_size *written);
AL_NODISCARD al_status al_consensus_proposal_decode(
    al_bytes encoded, al_consensus_proposal *out);

void al_consensus_vote_hash(const al_consensus_vote *vote, al_hash256 *out);
AL_NODISCARD al_status al_consensus_vote_sign(
    al_consensus_vote *vote, const al_seckey *secret_key);
AL_NODISCARD al_status al_consensus_vote_verify(
    const al_consensus_vote *vote, const al_potb_committee *committee);
AL_NODISCARD al_status al_consensus_vote_encode(
    const al_consensus_vote *vote, al_bytes_mut out, al_size *written);
AL_NODISCARD al_status al_consensus_vote_decode(al_bytes encoded,
                                                al_consensus_vote *out);

void al_vote_set_init(al_vote_set *set, al_u32 chain_id, al_height height,
                      al_u32 round, al_consensus_phase phase,
                      const al_hash256 *block_hash,
                      const al_hash256 *committee_hash);
AL_NODISCARD al_status al_vote_set_add(
    al_vote_set *set, const al_consensus_vote *vote,
    const al_potb_committee *committee);
AL_NODISCARD al_bool al_vote_set_has_quorum(
    const al_vote_set *set, const al_potb_committee *committee);
AL_NODISCARD al_status al_vote_set_certificate(
    const al_vote_set *set, const al_potb_committee *committee,
    al_finality_certificate *out);

AL_NODISCARD al_status al_finality_certificate_verify(
    const al_finality_certificate *certificate,
    const al_potb_committee *committee);
AL_NODISCARD al_status al_finality_certificate_encode(
    const al_finality_certificate *certificate, al_bytes_mut out,
    al_size *written);
AL_NODISCARD al_status al_finality_certificate_decode(
    al_bytes encoded, al_finality_certificate *out);

AL_EXTERN_C_END

#endif
