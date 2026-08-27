#include "finality.h"
#include "internal/common.h"

#include <string.h>

#define AL_PROPOSAL_SIGNING_SIZE (AL_PROPOSAL_ENCODED_SIZE - AL_SIGNATURE_SIZE)
#define AL_VOTE_SIGNING_SIZE (AL_VOTE_ENCODED_SIZE - AL_SIGNATURE_SIZE)
#define AL_COMMITTEE_HASH_MAX_SIZE                                           \
    (4u + 8u + AL_HASH_SIZE +                                               \
     AL_POTB_MAX_COMMITTEE * (AL_PUBKEY_SIZE + 8u))

static al_bool pubkey_eq(const al_pubkey *a, const al_pubkey *b) {
    return al_bytes_eq(al_bytes_make(a->bytes, AL_PUBKEY_SIZE),
                       al_bytes_make(b->bytes, AL_PUBKEY_SIZE));
}

static al_bool phase_valid(al_consensus_phase phase) {
    return phase == AL_CONSENSUS_PREVOTE ||
                   phase == AL_CONSENSUS_PRECOMMIT
               ? AL_TRUE
               : AL_FALSE;
}

static void proposal_write_signing(al_writer *writer,
                                   const al_consensus_proposal *proposal) {
    al_writer_u16(writer, proposal->version);
    al_writer_u32(writer, proposal->chain_id);
    al_writer_u64(writer, proposal->height);
    al_writer_u32(writer, proposal->round);
    al_writer_hash(writer, &proposal->block_hash);
    al_writer_hash(writer, &proposal->parent_hash);
    al_writer_hash(writer, &proposal->committee_hash);
    al_writer_raw(writer, proposal->proposer.bytes, AL_PUBKEY_SIZE);
}

static void vote_write_signing(al_writer *writer,
                               const al_consensus_vote *vote) {
    al_writer_u16(writer, vote->version);
    al_writer_u32(writer, vote->chain_id);
    al_writer_u64(writer, vote->height);
    al_writer_u32(writer, vote->round);
    al_writer_u8(writer, (al_u8)vote->phase);
    al_writer_hash(writer, &vote->block_hash);
    al_writer_hash(writer, &vote->committee_hash);
    al_writer_raw(writer, vote->voter.bytes, AL_PUBKEY_SIZE);
}

void al_consensus_committee_hash(const al_potb_committee *committee,
                                 al_hash256 *out) {
    if (out == NULL) return;
    if (committee == NULL || committee->size > AL_POTB_MAX_COMMITTEE) {
        *out = al_hash_zero();
        return;
    }
    al_u8 encoded[AL_COMMITTEE_HASH_MAX_SIZE];
    al_writer writer;
    al_writer_init(&writer, encoded, sizeof(encoded));
    al_writer_u32(&writer, committee->size);
    al_writer_u64(&writer, committee->formed_at);
    al_writer_hash(&writer, &committee->seed);
    for (al_u32 i = 0u; i < committee->size; ++i) {
        al_writer_raw(&writer, committee->members[i].bytes, AL_PUBKEY_SIZE);
        al_writer_u64(&writer, (al_u64)committee->weights[i]);
    }
    if (al_writer_finish(&writer) != AL_OK) {
        *out = al_hash_zero();
        return;
    }
    al_hash_tagged(AL_TAG_COMMITTEE, encoded, al_writer_len(&writer), out);
}

const al_pubkey *al_consensus_proposer(const al_potb_committee *committee,
                                       al_height height, al_u32 round) {
    if (committee == NULL || committee->size == 0u ||
        committee->size > AL_POTB_MAX_COMMITTEE) {
        return NULL;
    }
    al_u64 size = committee->size;
    al_u64 index = ((height % size) + ((al_u64)round % size)) % size;
    return &committee->members[(al_u32)index];
}

void al_consensus_proposal_hash(const al_consensus_proposal *proposal,
                                al_hash256 *out) {
    if (out == NULL) return;
    if (proposal == NULL) {
        *out = al_hash_zero();
        return;
    }
    al_u8 encoded[AL_PROPOSAL_SIGNING_SIZE];
    al_writer writer;
    al_writer_init(&writer, encoded, sizeof(encoded));
    proposal_write_signing(&writer, proposal);
    if (al_writer_finish(&writer) != AL_OK) {
        *out = al_hash_zero();
        return;
    }
    al_hash_tagged(AL_TAG_PROPOSAL, encoded, sizeof(encoded), out);
}

al_status al_consensus_proposal_sign(al_consensus_proposal *proposal,
                                     const al_seckey *secret_key) {
    if (proposal == NULL || secret_key == NULL) return AL_ERR_INVALID_ARG;
    al_pubkey signer;
    AL_TRY(al_pubkey_from_seckey(secret_key, &signer));
    if (!pubkey_eq(&signer, &proposal->proposer)) return AL_ERR_INVALID_ARG;
    al_hash256 hash;
    al_consensus_proposal_hash(proposal, &hash);
    return al_sign_hash(secret_key, &hash, &proposal->signature);
}

al_status al_consensus_proposal_verify(
    const al_consensus_proposal *proposal,
    const al_potb_committee *committee) {
    if (proposal == NULL || committee == NULL) return AL_ERR_INVALID_ARG;
    if (proposal->version != AL_CONSENSUS_VERSION || committee->size == 0u ||
        committee->size > AL_POTB_MAX_COMMITTEE ||
        al_hash_is_zero(&proposal->block_hash)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    al_hash256 committee_hash;
    al_consensus_committee_hash(committee, &committee_hash);
    const al_pubkey *expected =
        al_consensus_proposer(committee, proposal->height, proposal->round);
    if (!al_hash_eq(&committee_hash, &proposal->committee_hash) ||
        expected == NULL || !pubkey_eq(expected, &proposal->proposer)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    al_hash256 hash;
    al_consensus_proposal_hash(proposal, &hash);
    return al_verify_hash(&proposal->proposer, &hash, &proposal->signature);
}

al_status al_consensus_proposal_encode(const al_consensus_proposal *proposal,
                                       al_bytes_mut out, al_size *written) {
    if (written == NULL) return AL_ERR_INVALID_ARG;
    *written = AL_PROPOSAL_ENCODED_SIZE;
    if (proposal == NULL || (out.data == NULL && out.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    if (out.data == NULL || out.len < AL_PROPOSAL_ENCODED_SIZE) {
        return AL_ERR_BUFFER_TOO_SMALL;
    }
    al_writer writer;
    al_writer_init(&writer, out.data, out.len);
    proposal_write_signing(&writer, proposal);
    al_writer_raw(&writer, proposal->signature.bytes, AL_SIGNATURE_SIZE);
    AL_TRY(al_writer_finish(&writer));
    *written = al_writer_len(&writer);
    return AL_OK;
}

al_status al_consensus_proposal_decode(al_bytes encoded,
                                       al_consensus_proposal *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    if (encoded.len != AL_PROPOSAL_ENCODED_SIZE) return AL_ERR_MALFORMED;
    al_reader reader;
    al_reader_init(&reader, encoded);
    al_memzero(out, sizeof(*out));
    out->version = al_reader_u16(&reader);
    out->chain_id = al_reader_u32(&reader);
    out->height = al_reader_u64(&reader);
    out->round = al_reader_u32(&reader);
    al_reader_hash(&reader, &out->block_hash);
    al_reader_hash(&reader, &out->parent_hash);
    al_reader_hash(&reader, &out->committee_hash);
    al_reader_bytes(&reader, out->proposer.bytes, AL_PUBKEY_SIZE);
    al_reader_bytes(&reader, out->signature.bytes, AL_SIGNATURE_SIZE);
    return al_reader_finish(&reader);
}

void al_consensus_vote_hash(const al_consensus_vote *vote, al_hash256 *out) {
    if (out == NULL) return;
    if (vote == NULL) {
        *out = al_hash_zero();
        return;
    }
    al_u8 encoded[AL_VOTE_SIGNING_SIZE];
    al_writer writer;
    al_writer_init(&writer, encoded, sizeof(encoded));
    vote_write_signing(&writer, vote);
    if (al_writer_finish(&writer) != AL_OK) {
        *out = al_hash_zero();
        return;
    }
    al_hash_tagged(AL_TAG_VOTE, encoded, sizeof(encoded), out);
}

al_status al_consensus_vote_sign(al_consensus_vote *vote,
                                 const al_seckey *secret_key) {
    if (vote == NULL || secret_key == NULL || !phase_valid(vote->phase)) {
        return AL_ERR_INVALID_ARG;
    }
    al_pubkey signer;
    AL_TRY(al_pubkey_from_seckey(secret_key, &signer));
    if (!pubkey_eq(&signer, &vote->voter)) return AL_ERR_INVALID_ARG;
    al_hash256 hash;
    al_consensus_vote_hash(vote, &hash);
    return al_sign_hash(secret_key, &hash, &vote->signature);
}

al_status al_consensus_vote_verify(const al_consensus_vote *vote,
                                   const al_potb_committee *committee) {
    if (vote == NULL || committee == NULL) return AL_ERR_INVALID_ARG;
    if (vote->version != AL_CONSENSUS_VERSION || !phase_valid(vote->phase) ||
        al_hash_is_zero(&vote->block_hash) ||
        !al_potb_committee_contains(committee, &vote->voter)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    al_hash256 committee_hash;
    al_consensus_committee_hash(committee, &committee_hash);
    if (!al_hash_eq(&committee_hash, &vote->committee_hash)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    al_hash256 hash;
    al_consensus_vote_hash(vote, &hash);
    return al_verify_hash(&vote->voter, &hash, &vote->signature);
}

al_status al_consensus_vote_encode(const al_consensus_vote *vote,
                                   al_bytes_mut out, al_size *written) {
    if (written == NULL) return AL_ERR_INVALID_ARG;
    *written = AL_VOTE_ENCODED_SIZE;
    if (vote == NULL || (out.data == NULL && out.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    if (out.data == NULL || out.len < AL_VOTE_ENCODED_SIZE) {
        return AL_ERR_BUFFER_TOO_SMALL;
    }
    al_writer writer;
    al_writer_init(&writer, out.data, out.len);
    vote_write_signing(&writer, vote);
    al_writer_raw(&writer, vote->signature.bytes, AL_SIGNATURE_SIZE);
    AL_TRY(al_writer_finish(&writer));
    *written = al_writer_len(&writer);
    return AL_OK;
}

al_status al_consensus_vote_decode(al_bytes encoded, al_consensus_vote *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    if (encoded.len != AL_VOTE_ENCODED_SIZE) return AL_ERR_MALFORMED;
    al_reader reader;
    al_reader_init(&reader, encoded);
    al_memzero(out, sizeof(*out));
    out->version = al_reader_u16(&reader);
    out->chain_id = al_reader_u32(&reader);
    out->height = al_reader_u64(&reader);
    out->round = al_reader_u32(&reader);
    al_u8 phase = al_reader_u8(&reader);
    out->phase = (al_consensus_phase)phase;
    al_reader_hash(&reader, &out->block_hash);
    al_reader_hash(&reader, &out->committee_hash);
    al_reader_bytes(&reader, out->voter.bytes, AL_PUBKEY_SIZE);
    al_reader_bytes(&reader, out->signature.bytes, AL_SIGNATURE_SIZE);
    AL_TRY(al_reader_finish(&reader));
    return phase_valid(out->phase) ? AL_OK : AL_ERR_OUT_OF_RANGE;
}

void al_vote_set_init(al_vote_set *set, al_u32 chain_id, al_height height,
                      al_u32 round, al_consensus_phase phase,
                      const al_hash256 *block_hash,
                      const al_hash256 *committee_hash) {
    if (set == NULL) return;
    al_memzero(set, sizeof(*set));
    set->chain_id = chain_id;
    set->height = height;
    set->round = round;
    set->phase = phase;
    if (block_hash != NULL) set->block_hash = *block_hash;
    if (committee_hash != NULL) set->committee_hash = *committee_hash;
}

al_status al_vote_set_add(al_vote_set *set, const al_consensus_vote *vote,
                          const al_potb_committee *committee) {
    if (set == NULL || vote == NULL || committee == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    if (vote->chain_id != set->chain_id || vote->height != set->height ||
        vote->round != set->round || vote->phase != set->phase ||
        !al_hash_eq(&vote->block_hash, &set->block_hash) ||
        !al_hash_eq(&vote->committee_hash, &set->committee_hash)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    AL_TRY(al_consensus_vote_verify(vote, committee));
    for (al_u32 i = 0u; i < set->vote_count; ++i) {
        if (pubkey_eq(&set->votes[i].voter, &vote->voter)) {
            return AL_ERR_ALREADY_EXISTS;
        }
    }
    if (set->vote_count >= AL_POTB_MAX_COMMITTEE) {
        return AL_ERR_RESOURCE_LIMIT;
    }
    set->votes[set->vote_count++] = *vote;
    return AL_OK;
}

al_bool al_vote_set_has_quorum(const al_vote_set *set,
                               const al_potb_committee *committee) {
    if (set == NULL || committee == NULL || committee->size == 0u ||
        set->vote_count > committee->size) {
        return AL_FALSE;
    }
    return set->vote_count >= al_potb_quorum_threshold(committee->size)
               ? AL_TRUE
               : AL_FALSE;
}

al_status al_vote_set_certificate(const al_vote_set *set,
                                  const al_potb_committee *committee,
                                  al_finality_certificate *out) {
    if (set == NULL || committee == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    if (set->phase != AL_CONSENSUS_PRECOMMIT ||
        !al_vote_set_has_quorum(set, committee)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    al_memzero(out, sizeof(*out));
    out->version = AL_CONSENSUS_VERSION;
    out->chain_id = set->chain_id;
    out->height = set->height;
    out->round = set->round;
    out->block_hash = set->block_hash;
    out->committee_hash = set->committee_hash;
    out->vote_count = set->vote_count;
    memcpy(out->votes, set->votes,
           (size_t)set->vote_count * sizeof(set->votes[0]));
    return al_finality_certificate_verify(out, committee);
}

al_status al_finality_certificate_verify(
    const al_finality_certificate *certificate,
    const al_potb_committee *committee) {
    if (certificate == NULL || committee == NULL) return AL_ERR_INVALID_ARG;
    if (certificate->version != AL_CONSENSUS_VERSION ||
        certificate->vote_count > committee->size ||
        certificate->vote_count > AL_POTB_MAX_COMMITTEE ||
        certificate->vote_count < al_potb_quorum_threshold(committee->size)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    al_hash256 committee_hash;
    al_consensus_committee_hash(committee, &committee_hash);
    if (!al_hash_eq(&certificate->committee_hash, &committee_hash)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    for (al_u32 i = 0u; i < certificate->vote_count; ++i) {
        const al_consensus_vote *vote = &certificate->votes[i];
        if (vote->chain_id != certificate->chain_id ||
            vote->height != certificate->height ||
            vote->round != certificate->round ||
            vote->phase != AL_CONSENSUS_PRECOMMIT ||
            !al_hash_eq(&vote->block_hash, &certificate->block_hash) ||
            !al_hash_eq(&vote->committee_hash,
                        &certificate->committee_hash)) {
            return AL_ERR_CONSENSUS_VIOLATION;
        }
        AL_TRY(al_consensus_vote_verify(vote, committee));
        for (al_u32 j = 0u; j < i; ++j) {
            if (pubkey_eq(&vote->voter, &certificate->votes[j].voter)) {
                return AL_ERR_CONSENSUS_VIOLATION;
            }
        }
    }
    return AL_OK;
}

al_status al_finality_certificate_encode(
    const al_finality_certificate *certificate, al_bytes_mut out,
    al_size *written) {
    if (written == NULL) return AL_ERR_INVALID_ARG;
    *written = 0u;
    if (certificate == NULL || certificate->vote_count > AL_POTB_MAX_COMMITTEE ||
        (out.data == NULL && out.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    al_size required = 2u + 4u + 8u + 4u + AL_HASH_SIZE + AL_HASH_SIZE +
                       al_varint_size(certificate->vote_count) +
                       (al_size)certificate->vote_count * AL_VOTE_ENCODED_SIZE;
    *written = required;
    if (out.data == NULL || out.len < required) return AL_ERR_BUFFER_TOO_SMALL;
    al_writer writer;
    al_writer_init(&writer, out.data, out.len);
    al_writer_u16(&writer, certificate->version);
    al_writer_u32(&writer, certificate->chain_id);
    al_writer_u64(&writer, certificate->height);
    al_writer_u32(&writer, certificate->round);
    al_writer_hash(&writer, &certificate->block_hash);
    al_writer_hash(&writer, &certificate->committee_hash);
    al_writer_varint(&writer, certificate->vote_count);
    for (al_u32 i = 0u; i < certificate->vote_count; ++i) {
        al_size vote_written = 0u;
        AL_TRY(al_consensus_vote_encode(
            &certificate->votes[i],
            (al_bytes_mut){ writer.data + writer.pos,
                            writer.cap - writer.pos },
            &vote_written));
        writer.pos += vote_written;
    }
    AL_TRY(al_writer_finish(&writer));
    *written = al_writer_len(&writer);
    return AL_OK;
}

al_status al_finality_certificate_decode(al_bytes encoded,
                                         al_finality_certificate *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    al_reader reader;
    al_reader_init(&reader, encoded);
    al_memzero(out, sizeof(*out));
    out->version = al_reader_u16(&reader);
    out->chain_id = al_reader_u32(&reader);
    out->height = al_reader_u64(&reader);
    out->round = al_reader_u32(&reader);
    al_reader_hash(&reader, &out->block_hash);
    al_reader_hash(&reader, &out->committee_hash);
    al_u64 count = al_reader_varint(&reader);
    if (count > AL_POTB_MAX_COMMITTEE) return AL_ERR_OUT_OF_RANGE;
    out->vote_count = (al_u32)count;
    for (al_u32 i = 0u; i < out->vote_count; ++i) {
        al_bytes vote = al_reader_take(&reader, AL_VOTE_ENCODED_SIZE);
        if (al_reader_status(&reader) != AL_OK) return AL_ERR_TRUNCATED;
        AL_TRY(al_consensus_vote_decode(vote, &out->votes[i]));
    }
    return al_reader_finish(&reader);
}
