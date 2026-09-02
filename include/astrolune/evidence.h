/*
 * astrolune/evidence.h - Double-sign evidence detection and verification.
 *
 * Evidence is proof that a validator signed two conflicting votes for the same
 * height/round/phase. Any node can submit evidence; the consensus code verifies
 * the two signatures genuinely conflict and come from a committee member.
 *
 * The evidence is stored in on-chain state and triggers automatic slashing:
 * - First offence: temporary ban from committee
 * - Second offence: permanent ban
 */

#ifndef ASTROLUNE_EVIDENCE_H
#define ASTROLUNE_EVIDENCE_H

#include "astrolune/base.h"
#include "astrolune/crypto.h"
#include "astrolune/potb.h"

AL_EXTERN_C_BEGIN

/* Forward declaration - full definition in internal consensus/finality.h */
typedef struct al_consensus_vote al_consensus_vote;

/* --------------------------------------------------------------------------
 * Evidence types
 * -------------------------------------------------------------------------- */

typedef enum al_evidence_kind {
    AL_EVIDENCE_DOUBLE_SIGN_VOTE = 0,
    AL_EVIDENCE_DOUBLE_SIGN_PROPOSAL,
    AL_EVIDENCE_KIND_SENTINEL = 0x7fffffff
} al_evidence_kind;

/* --------------------------------------------------------------------------
 * Evidence record
 * -------------------------------------------------------------------------- */

#define AL_EVIDENCE_MAX_ENCODED_SIZE (2u + 4u + 8u + 4u + 1u + \
    2u * (4u + 8u + 1u + AL_HASH_SIZE + AL_HASH_SIZE + AL_PUBKEY_SIZE + AL_SIGNATURE_SIZE))

/* Phase values matching al_consensus_phase in finality.h */
#define AL_EVIDENCE_PHASE_PREVOTE    0u
#define AL_EVIDENCE_PHASE_PRECOMMIT  1u

typedef struct al_evidence {
    al_evidence_kind kind;
    al_u32           chain_id;
    al_height        height;
    al_u32           round;
    
    /* The two conflicting signed messages. */
    struct {
        al_u8          phase;       /* AL_EVIDENCE_PHASE_PREVOTE or PRECOMMIT */
        al_hash256     block_hash;
        al_hash256     committee_hash;
        al_pubkey      voter;
        al_sig         signature;
    } vote1, vote2;
} al_evidence;

/* --------------------------------------------------------------------------
 * Evidence verification
 * -------------------------------------------------------------------------- */

/*
 * Verify that evidence is valid:
 * 1. Both votes are from the same validator
 * 2. Both votes are for the same height/round/phase
 * 3. The votes have different block hashes (conflicting)
 * 4. Both signatures are valid
 * 5. The validator is a committee member
 */
AL_PUBLIC AL_NODISCARD al_status al_evidence_verify(
    const al_evidence *evidence,
    const al_potb_committee *committee);

/*
 * Create evidence from two conflicting votes.
 */
AL_PUBLIC AL_NODISCARD al_status al_evidence_create(
    const al_consensus_vote *vote1,
    const al_consensus_vote *vote2,
    al_evidence *out);

/* --------------------------------------------------------------------------
 * Evidence encoding/decoding
 * -------------------------------------------------------------------------- */

AL_PUBLIC AL_NODISCARD al_status al_evidence_encode(
    const al_evidence *evidence,
    al_bytes_mut out,
    al_size *written);

AL_PUBLIC AL_NODISCARD al_status al_evidence_decode(
    al_bytes encoded,
    al_evidence *out);

/* --------------------------------------------------------------------------
 * Evidence processing
 * -------------------------------------------------------------------------- */

/*
 * Process evidence against a validator record.
 * Applies penalty and ban based on offence count.
 */
AL_PUBLIC AL_NODISCARD al_status al_evidence_process(
    const al_potb_params *params,
    al_potb_record *record,
    const al_evidence *evidence,
    al_u32 now_day);

/* --------------------------------------------------------------------------
 * Storage key helpers
 * -------------------------------------------------------------------------- */

/* Storage key prefix for evidence records. */
#define AL_EVIDENCE_KEY_PREFIX "evidence:"

/* Build storage key for evidence at a given height. */
AL_PUBLIC void al_evidence_key(al_height height, char *out, al_size out_cap);

AL_EXTERN_C_END

#endif /* ASTROLUNE_EVIDENCE_H */
