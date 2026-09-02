/*
 * Evidence detection and verification implementation.
 */

#include "astrolune/evidence.h"
#include "finality.h"

#include "internal/common.h"

#include <stdio.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Evidence verification
 * -------------------------------------------------------------------------- */

static al_bool pubkey_eq(const al_pubkey *a, const al_pubkey *b) {
    return al_bytes_eq(al_bytes_make(a->bytes, AL_PUBKEY_SIZE),
                       al_bytes_make(b->bytes, AL_PUBKEY_SIZE));
}

/* Reconstruct an al_consensus_vote from evidence fields and verify its
 * signature. This is the production-grade check that the audit demanded:
 * the evidence submitter must provide genuine signed votes, not just
 * plausible-looking structures. */
static al_status verify_evidence_vote(const al_evidence *evidence,
                                      al_u8 phase,
                                      const al_hash256 *block_hash,
                                      const al_hash256 *committee_hash,
                                      const al_pubkey *voter,
                                      const al_sig *signature) {
    al_consensus_vote vote;
    al_memzero(&vote, sizeof(vote));
    vote.version = AL_CONSENSUS_VERSION;
    vote.chain_id = evidence->chain_id;
    vote.height = evidence->height;
    vote.round = evidence->round;
    vote.phase = (al_consensus_phase)phase;
    vote.block_hash = *block_hash;
    vote.committee_hash = *committee_hash;
    vote.voter = *voter;
    vote.signature = *signature;

    al_hash256 hash;
    al_consensus_vote_hash(&vote, &hash);
    return al_verify_hash(voter, &hash, signature);
}

al_status al_evidence_verify(const al_evidence *evidence,
                             const al_potb_committee *committee) {
    if (evidence == NULL || committee == NULL) return AL_ERR_INVALID_ARG;
    
    /* Check both votes are from the same validator. */
    if (!pubkey_eq(&evidence->vote1.voter, &evidence->vote2.voter)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    
    /* Check both votes are for the same phase. */
    if (evidence->vote1.phase != evidence->vote2.phase) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    
    /* Check the votes have different block hashes (conflicting). */
    if (al_hash_eq(&evidence->vote1.block_hash, &evidence->vote2.block_hash)) {
        return AL_ERR_CONSENSUS_VIOLATION; /* Not conflicting */
    }
    
    /* Check the validator is a committee member. */
    if (!al_potb_committee_contains(committee, &evidence->vote1.voter)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    
    /* Verify both signatures against reconstructed vote messages. */
    AL_TRY(verify_evidence_vote(evidence, evidence->vote1.phase,
                                &evidence->vote1.block_hash,
                                &evidence->vote1.committee_hash,
                                &evidence->vote1.voter,
                                &evidence->vote1.signature));
    AL_TRY(verify_evidence_vote(evidence, evidence->vote2.phase,
                                &evidence->vote2.block_hash,
                                &evidence->vote2.committee_hash,
                                &evidence->vote2.voter,
                                &evidence->vote2.signature));
    
    return AL_OK;
}

al_status al_evidence_create(const al_consensus_vote *vote1,
                             const al_consensus_vote *vote2,
                             al_evidence *out) {
    if (vote1 == NULL || vote2 == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    
    /* Check votes are from the same validator. */
    if (!pubkey_eq(&vote1->voter, &vote2->voter)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    
    /* Check votes are for the same height/round/phase. */
    if (vote1->height != vote2->height ||
        vote1->round != vote2->round ||
        vote1->phase != vote2->phase) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }

    /* Check votes are for the same chain. */
    if (vote1->chain_id != vote2->chain_id) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    
    /* Check votes have different block hashes (conflicting). */
    if (al_hash_eq(&vote1->block_hash, &vote2->block_hash)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    
    al_memzero(out, sizeof(*out));
    out->kind = AL_EVIDENCE_DOUBLE_SIGN_VOTE;
    out->chain_id = vote1->chain_id;
    out->height = vote1->height;
    out->round = vote1->round;
    
    out->vote1.phase = (al_u8)vote1->phase;
    out->vote1.block_hash = vote1->block_hash;
    out->vote1.committee_hash = vote1->committee_hash;
    out->vote1.voter = vote1->voter;
    out->vote1.signature = vote1->signature;
    
    out->vote2.phase = (al_u8)vote2->phase;
    out->vote2.block_hash = vote2->block_hash;
    out->vote2.committee_hash = vote2->committee_hash;
    out->vote2.voter = vote2->voter;
    out->vote2.signature = vote2->signature;
    
    return AL_OK;
}

/* --------------------------------------------------------------------------
 * Evidence encoding/decoding
 * -------------------------------------------------------------------------- */

al_status al_evidence_encode(const al_evidence *evidence,
                             al_bytes_mut out,
                             al_size *written) {
    if (written == NULL) return AL_ERR_INVALID_ARG;
    *written = 0u;
    
    if (evidence == NULL || (out.data == NULL && out.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    
    al_size required = AL_EVIDENCE_MAX_ENCODED_SIZE;
    *written = required;
    if (out.data == NULL || out.len < required) return AL_ERR_BUFFER_TOO_SMALL;
    
    al_writer writer;
    al_writer_init(&writer, out.data, out.len);
    
    al_writer_u16(&writer, (al_u16)evidence->kind);
    al_writer_u32(&writer, evidence->chain_id);
    al_writer_u64(&writer, evidence->height);
    al_writer_u32(&writer, evidence->round);
    
    /* Vote 1 */
    al_writer_u8(&writer, evidence->vote1.phase);
    al_writer_hash(&writer, &evidence->vote1.block_hash);
    al_writer_hash(&writer, &evidence->vote1.committee_hash);
    al_writer_raw(&writer, evidence->vote1.voter.bytes, AL_PUBKEY_SIZE);
    al_writer_raw(&writer, evidence->vote1.signature.bytes, AL_SIGNATURE_SIZE);
    
    /* Vote 2 */
    al_writer_u8(&writer, evidence->vote2.phase);
    al_writer_hash(&writer, &evidence->vote2.block_hash);
    al_writer_hash(&writer, &evidence->vote2.committee_hash);
    al_writer_raw(&writer, evidence->vote2.voter.bytes, AL_PUBKEY_SIZE);
    al_writer_raw(&writer, evidence->vote2.signature.bytes, AL_SIGNATURE_SIZE);
    
    AL_TRY(al_writer_finish(&writer));
    *written = al_writer_len(&writer);
    return AL_OK;
}

al_status al_evidence_decode(al_bytes encoded, al_evidence *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    
    al_reader reader;
    al_reader_init(&reader, encoded);
    al_memzero(out, sizeof(*out));
    
    out->kind = (al_evidence_kind)al_reader_u16(&reader);
    out->chain_id = al_reader_u32(&reader);
    out->height = al_reader_u64(&reader);
    out->round = al_reader_u32(&reader);
    
    /* Vote 1 */
    out->vote1.phase = al_reader_u8(&reader);
    al_reader_hash(&reader, &out->vote1.block_hash);
    al_reader_hash(&reader, &out->vote1.committee_hash);
    al_reader_bytes(&reader, out->vote1.voter.bytes, AL_PUBKEY_SIZE);
    al_reader_bytes(&reader, out->vote1.signature.bytes, AL_SIGNATURE_SIZE);
    
    /* Vote 2 */
    out->vote2.phase = al_reader_u8(&reader);
    al_reader_hash(&reader, &out->vote2.block_hash);
    al_reader_hash(&reader, &out->vote2.committee_hash);
    al_reader_bytes(&reader, out->vote2.voter.bytes, AL_PUBKEY_SIZE);
    al_reader_bytes(&reader, out->vote2.signature.bytes, AL_SIGNATURE_SIZE);
    
    return al_reader_finish(&reader);
}

/* --------------------------------------------------------------------------
 * Evidence processing
 * -------------------------------------------------------------------------- */

al_status al_evidence_process(const al_potb_params *params,
                              al_potb_record *record,
                              const al_evidence *evidence,
                              al_u32 now_day) {
    if (params == NULL || record == NULL || evidence == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    
    /* Check the evidence is against this record's identity. */
    if (!pubkey_eq(&record->identity, &evidence->vote1.voter)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    
    /* If already banned from a previous double-sign, this is a repeat. */
    al_bool was_banned = (record->banned_until_day > 0u);
    
    /* Apply double-sign penalty. */
    AL_TRY(al_potb_slash(params, record, NULL,
                         AL_POTB_OFFENCE_DOUBLE_SIGN, now_day));
    
    /* Repeat offence → permanent ban. */
    if (was_banned) {
        record->permanently_banned = AL_TRUE;
        record->penalty_multiplier = 0;
    }
    
    return AL_OK;
}

/* --------------------------------------------------------------------------
 * Storage key helpers
 * -------------------------------------------------------------------------- */

void al_evidence_key(al_height height, char *out, al_size out_cap) {
    if (out == NULL || out_cap == 0u) return;
    snprintf(out, out_cap, "%s%llu", AL_EVIDENCE_KEY_PREFIX,
             (unsigned long long)height);
}
