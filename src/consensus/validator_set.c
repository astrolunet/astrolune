/*
 * On-chain validator set management.
 *
 * Validators are stored in the reserved PoTB system account's storage.
 * The committee is derived state: computed from the set of registered
 * validators minus those who are banned or have not yet passed the
 * activation delay.
 */

#include "astrolune/validator_set.h"

#include "internal/common.h"

#include <stdio.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Storage keys
 * -------------------------------------------------------------------------- */

al_size al_validator_storage_key(const al_pubkey *pk, char *buf, al_size cap) {
    char pk_hex[AL_PUBKEY_SIZE * 2u + 1u];
    if (al_hex_encode(al_bytes_make(pk->bytes, AL_PUBKEY_SIZE), pk_hex,
                      sizeof(pk_hex)) != AL_OK) {
        return 0u;
    }
    return (al_size)snprintf(buf, cap, "validators:%s", pk_hex);
}

al_size al_validator_registration_height_key(const al_pubkey *pk, char *buf,
                                             al_size cap) {
    char pk_hex[AL_PUBKEY_SIZE * 2u + 1u];
    if (al_hex_encode(al_bytes_make(pk->bytes, AL_PUBKEY_SIZE), pk_hex,
                      sizeof(pk_hex)) != AL_OK) {
        return 0u;
    }
    return (al_size)snprintf(buf, cap, "registration_height:%s", pk_hex);
}

/* --------------------------------------------------------------------------
 * Record encoding/decoding
 * -------------------------------------------------------------------------- */

/* Encoded format (all little-endian):
 *   [0:32]   identity (pubkey)
 *   [32:36]  uptime_days (u32)
 *   [36:40]  last_active_day (u32)
 *   [40:44]  first_seen_day (u32)
 *   [44:52]  responses_total (u64)
 *   [52:60]  responses_correct (u64)
 *   [60:68]  votes_expected (u64)
 *   [68:76]  votes_cast (u64)
 *   [76:80]  penalty_multiplier (fixed Q32.32)
 *   [80:84]  banned_until_day (u32)
 *   [84]     permanently_banned (u8)
 *   [85:89]  inbound_attestations (u32)
 *   [89:93]  inbound_from_cluster (u32)
 *   [93:97]  cluster_size (u32)
 *   [97:101] tdi (fixed Q32.32)
 *   [101:105] challenges_issued (u32)
 *   [105:109] challenges_passed (u32)
 *   [109:113] asn (u32)
 *   [113:117] asn_peer_count (u32)
 *   [117:121] correlation_score (fixed Q32.32)
 *   [121:129] operational_bond (u64 amount)
 * Total: 129 bytes
 */
#define AL_RECORD_ENCODED_SIZE 129u

static al_status encode_record(const al_potb_record *r, al_bytes_mut out) {
    if (out.len < AL_RECORD_ENCODED_SIZE) return AL_ERR_OUT_OF_MEMORY;

    al_u8 *p = out.data;
    al_memcpy(p, r->identity.bytes, AL_PUBKEY_SIZE);
    p += AL_PUBKEY_SIZE;
    al_store_le32(p, r->uptime_days); p += 4u;
    al_store_le32(p, r->last_active_day); p += 4u;
    al_store_le32(p, r->first_seen_day); p += 4u;
    al_store_le64(p, r->responses_total); p += 8u;
    al_store_le64(p, r->responses_correct); p += 8u;
    al_store_le64(p, r->votes_expected); p += 8u;
    al_store_le64(p, r->votes_cast); p += 8u;
    al_store_le32(p, (al_u32)r->penalty_multiplier); p += 4u;
    al_store_le32(p, r->banned_until_day); p += 4u;
    *p++ = r->permanently_banned ? 1u : 0u;
    al_store_le32(p, r->inbound_attestations); p += 4u;
    al_store_le32(p, r->inbound_from_cluster); p += 4u;
    al_store_le32(p, r->cluster_size); p += 4u;
    al_store_le32(p, (al_u32)r->tdi); p += 4u;
    al_store_le32(p, r->challenges_issued); p += 4u;
    al_store_le32(p, r->challenges_passed); p += 4u;
    al_store_le32(p, r->asn); p += 4u;
    al_store_le32(p, r->asn_peer_count); p += 4u;
    al_store_le32(p, (al_u32)r->correlation_score); p += 4u;
    al_store_le64(p, r->operational_bond);

    return AL_OK;
}

static al_status decode_record(al_bytes encoded, al_potb_record *r) {
    if (encoded.len < AL_RECORD_ENCODED_SIZE) return AL_ERR_MALFORMED;

    const al_u8 *p = encoded.data;
    al_memcpy(r->identity.bytes, p, AL_PUBKEY_SIZE);
    p += AL_PUBKEY_SIZE;
    r->uptime_days = al_load_le32(p); p += 4u;
    r->last_active_day = al_load_le32(p); p += 4u;
    r->first_seen_day = al_load_le32(p); p += 4u;
    r->responses_total = al_load_le64(p); p += 8u;
    r->responses_correct = al_load_le64(p); p += 8u;
    r->votes_expected = al_load_le64(p); p += 8u;
    r->votes_cast = al_load_le64(p); p += 8u;
    r->penalty_multiplier = (al_fixed)al_load_le32(p); p += 4u;
    r->banned_until_day = al_load_le32(p); p += 4u;
    r->permanently_banned = (*p++ != 0u) ? AL_TRUE : AL_FALSE;
    r->inbound_attestations = al_load_le32(p); p += 4u;
    r->inbound_from_cluster = al_load_le32(p); p += 4u;
    r->cluster_size = al_load_le32(p); p += 4u;
    r->tdi = (al_fixed)al_load_le32(p); p += 4u;
    r->challenges_issued = al_load_le32(p); p += 4u;
    r->challenges_passed = al_load_le32(p); p += 4u;
    r->asn = al_load_le32(p); p += 4u;
    r->asn_peer_count = al_load_le32(p); p += 4u;
    r->correlation_score = (al_fixed)al_load_le32(p); p += 4u;
    r->operational_bond = al_load_le64(p);

    return AL_OK;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

al_status al_validator_set_load(const al_state_txn *txn,
                                const al_potb_params *p,
                                al_potb_record *records,
                                al_size record_capacity,
                                const al_potb_record **candidates,
                                al_size *candidate_count,
                                al_u32 protocol_day) {
    if (txn == NULL || p == NULL || records == NULL || candidates == NULL ||
        candidate_count == NULL) {
        return AL_ERR_INVALID_ARG;
    }

    *candidate_count = 0u;

    /* Read validator count from storage. */
    al_bytes count_key = al_bytes_make((const al_u8 *)"validator_count", 15u);
    al_bytes count_value;
    al_status status = al_state_txn_system_storage_get(
        txn, count_key, NULL, &count_value);
    if (status == AL_ERR_NOT_FOUND) {
        /* No validators registered yet - this is valid at genesis. */
        return AL_OK;
    }
    if (status != AL_OK) return status;
    if (count_value.len != 4u) return AL_ERR_MALFORMED;

    al_u32 count = al_load_le32(count_value.data);
    if (count > (al_u32)record_capacity) return AL_ERR_OUT_OF_MEMORY;
    if (count > AL_POTB_MAX_COMMITTEE) return AL_ERR_OUT_OF_RANGE;

    /* Load each validator record. */
    for (al_u32 i = 0u; i < count; ++i) {
        /* Read the pubkey from the validator list. */
        char list_key_buf[32];
        (void)snprintf(list_key_buf, sizeof(list_key_buf), "validator_list:%u",
                       (unsigned)i);
        al_bytes list_key = al_bytes_make((const al_u8 *)list_key_buf,
                                          strlen(list_key_buf));
        al_bytes pk_value;
        status = al_state_txn_system_storage_get(txn, list_key, NULL,
                                                  &pk_value);
        if (status != AL_OK) return status;
        if (pk_value.len != AL_PUBKEY_SIZE) return AL_ERR_MALFORMED;

        al_pubkey pk;
        al_memcpy(pk.bytes, pk_value.data, AL_PUBKEY_SIZE);

        /* Read the full record. */
        char record_key_buf[AL_VALIDATOR_KEY_MAX];
        al_size record_key_len = al_validator_storage_key(
            &pk, record_key_buf, sizeof(record_key_buf));
        al_bytes record_key = al_bytes_make((const al_u8 *)record_key_buf,
                                            record_key_len);
        al_bytes record_value;
        status = al_state_txn_system_storage_get(txn, record_key, NULL,
                                                  &record_value);
        if (status != AL_OK) return status;

        al_potb_record *rec = &records[*candidate_count];
        al_memzero(rec, sizeof(*rec));
        rec->penalty_multiplier = AL_FIXED_ONE;
        status = decode_record(record_value, rec);
        if (status != AL_OK) return status;

        /* Check activation delay. */
        char height_key_buf[AL_VALIDATOR_KEY_MAX];
        al_size height_key_len = al_validator_registration_height_key(
            &pk, height_key_buf, sizeof(height_key_buf));
        al_bytes height_key = al_bytes_make((const al_u8 *)height_key_buf,
                                            height_key_len);
        al_bytes height_value;
        status = al_state_txn_system_storage_get(txn, height_key, NULL,
                                                  &height_value);
        if (status == AL_OK && height_value.len == 8u) {
            al_height reg_height = al_load_le64(height_value.data);
            if (reg_height + AL_VALIDATOR_ACTIVATION_DELAY > 
                (al_height)protocol_day) {
                /* Not yet active - skip this validator. */
                continue;
            }
        }

        candidates[*candidate_count] = rec;
        ++(*candidate_count);
    }

    return AL_OK;
}

al_status al_validator_set_store(al_state_txn *txn,
                                 const al_potb_record *record) {
    if (txn == NULL || record == NULL) return AL_ERR_INVALID_ARG;

    /* Encode the record. */
    al_u8 encoded[AL_RECORD_ENCODED_SIZE];
    al_bytes_mut encoded_view = { encoded, sizeof(encoded) };
    al_status status = encode_record(record, encoded_view);
    if (status != AL_OK) return status;

    /* Store the record. */
    char key_buf[AL_VALIDATOR_KEY_MAX];
    al_size key_len = al_validator_storage_key(&record->identity, key_buf,
                                               sizeof(key_buf));
    al_bytes key = al_bytes_make((const al_u8 *)key_buf, key_len);
    return al_state_txn_system_storage_set(txn, key,
                                           al_bytes_make(encoded,
                                                         AL_RECORD_ENCODED_SIZE));
}

al_status al_validator_set_remove(al_state_txn *txn, const al_pubkey *pk) {
    if (txn == NULL || pk == NULL) return AL_ERR_INVALID_ARG;

    char key_buf[AL_VALIDATOR_KEY_MAX];
    al_size key_len = al_validator_storage_key(pk, key_buf, sizeof(key_buf));
    al_bytes key = al_bytes_make((const al_u8 *)key_buf, key_len);
    return al_state_txn_system_storage_delete(txn, key);
}

al_status al_validator_set_contains(const al_state_txn *txn,
                                    const al_pubkey *pk, al_bool *out) {
    if (txn == NULL || pk == NULL || out == NULL) return AL_ERR_INVALID_ARG;

    char key_buf[AL_VALIDATOR_KEY_MAX];
    al_size key_len = al_validator_storage_key(pk, key_buf, sizeof(key_buf));
    al_bytes key = al_bytes_make((const al_u8 *)key_buf, key_len);
    al_bytes value;
    al_status status = al_state_txn_system_storage_get(txn, key, NULL, &value);
    if (status == AL_ERR_NOT_FOUND) {
        *out = AL_FALSE;
        return AL_OK;
    }
    if (status != AL_OK) return status;
    *out = AL_TRUE;
    return AL_OK;
}

al_status al_validator_set_record_registration(al_state_txn *txn,
                                               const al_pubkey *pk,
                                               al_height height) {
    if (txn == NULL || pk == NULL) return AL_ERR_INVALID_ARG;

    char key_buf[AL_VALIDATOR_KEY_MAX];
    al_size key_len = al_validator_registration_height_key(pk, key_buf,
                                                           sizeof(key_buf));
    al_bytes key = al_bytes_make((const al_u8 *)key_buf, key_len);
    al_u8 height_bytes[8];
    al_store_le64(height_bytes, height);
    return al_state_txn_system_storage_set(txn, key,
                                           al_bytes_make(height_bytes, 8u));
}

al_status al_validator_set_is_active(const al_state_txn *txn,
                                     const al_pubkey *pk,
                                     al_height current_height,
                                     al_bool *out) {
    if (txn == NULL || pk == NULL || out == NULL) return AL_ERR_INVALID_ARG;

    /* Check if validator is registered. */
    al_bool registered;
    al_status status = al_validator_set_contains(txn, pk, &registered);
    if (status != AL_OK) return status;
    if (!registered) {
        *out = AL_FALSE;
        return AL_OK;
    }

    /* Check activation delay. */
    char key_buf[AL_VALIDATOR_KEY_MAX];
    al_size key_len = al_validator_registration_height_key(pk, key_buf,
                                                           sizeof(key_buf));
    al_bytes key = al_bytes_make((const al_u8 *)key_buf, key_len);
    al_bytes height_value;
    status = al_state_txn_system_storage_get(txn, key, NULL, &height_value);
    if (status == AL_ERR_NOT_FOUND) {
        /* No height recorded - treat as active (legacy validator). */
        *out = AL_TRUE;
        return AL_OK;
    }
    if (status != AL_OK) return status;
    if (height_value.len != 8u) return AL_ERR_MALFORMED;

    al_height reg_height = al_load_le64(height_value.data);
    *out = (current_height >= reg_height + AL_VALIDATOR_ACTIVATION_DELAY)
               ? AL_TRUE : AL_FALSE;
    return AL_OK;
}

al_status al_validator_set_register(al_state_txn *txn,
                                    const al_potb_record *record,
                                    al_height height) {
    if (txn == NULL || record == NULL) return AL_ERR_INVALID_ARG;

    /* Store the record. */
    al_status status = al_validator_set_store(txn, record);
    if (status != AL_OK) return status;

    /* Record the registration height. */
    return al_validator_set_record_registration(txn, &record->identity, height);
}

al_status al_validator_set_load_single(const al_state_txn *txn,
                                       const al_pubkey *pk,
                                       al_potb_record *out) {
    if (txn == NULL || pk == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }

    char key_buf[AL_VALIDATOR_KEY_MAX];
    al_size key_len = al_validator_storage_key(pk, key_buf, sizeof(key_buf));
    al_bytes key = al_bytes_make((const al_u8 *)key_buf, key_len);
    al_bytes value;
    al_status status = al_state_txn_system_storage_get(txn, key, NULL, &value);
    if (status != AL_OK) return status;

    al_memzero(out, sizeof(*out));
    out->penalty_multiplier = AL_FIXED_ONE;
    return decode_record(value, out);
}
