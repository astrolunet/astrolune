/*
 * astrolune/validator_set.h - on-chain validator set management.
 *
 * Validators register via AL_POTB_REGISTER transactions. The validator set
 * is derived state: at any height, the active committee is computed from the
 * set of registered validators minus those who are banned or have not yet
 * passed the activation delay.
 *
 * Storage layout under the reserved PoTB system account:
 *   Key: "validators:<pubkey>"  ->  Value: encoded al_potb_record
 *   Key: "validator_count"      ->  Value: LE u32 count
 *   Key: "validator_list:<idx>" ->  Value: 32-byte pubkey
 *   Key: "registration_height:<pubkey>" -> Value: LE u64 height
 */

#ifndef ASTROLUNE_VALIDATOR_SET_H
#define ASTROLUNE_VALIDATOR_SET_H

#include "astrolune/base.h"
#include "astrolune/crypto.h"
#include "astrolune/potb.h"
#include "astrolune/state.h"

AL_EXTERN_C_BEGIN

/* Number of blocks before a registration takes effect. This prevents same-height
 * signer ambiguity: a validator cannot join the committee at the same height it
 * registered. */
#define AL_VALIDATOR_ACTIVATION_DELAY 1u

/* --------------------------------------------------------------------------
 * Storage keys
 * -------------------------------------------------------------------------- */

/* Maximum encoded size of a validator record key. */
#define AL_VALIDATOR_KEY_MAX 96u

/* Write "validators:<pubkey-hex>" into buf. Returns bytes written. */
al_size al_validator_storage_key(const al_pubkey *pk, char *buf, al_size cap);

/* Write "registration_height:<pubkey-hex>" into buf. Returns bytes written. */
al_size al_validator_registration_height_key(const al_pubkey *pk, char *buf,
                                             al_size cap);

/* --------------------------------------------------------------------------
 * On-chain validator set operations
 * -------------------------------------------------------------------------- */

/* Load all validators from on-chain state into the candidate array.
 * Returns AL_OK on success, AL_ERR_NOT_FOUND if no validators are registered. */
AL_PUBLIC AL_NODISCARD al_status al_validator_set_load(
    const al_state_txn *txn, const al_potb_params *p,
    al_potb_record *records, al_size record_capacity,
    const al_potb_record **candidates, al_size *candidate_count,
    al_u32 protocol_day);

/* Store a validator record in on-chain state. */
AL_PUBLIC AL_NODISCARD al_status al_validator_set_store(
    al_state_txn *txn, const al_potb_record *record);

/* Remove a validator from on-chain state. */
AL_PUBLIC AL_NODISCARD al_status al_validator_set_remove(
    al_state_txn *txn, const al_pubkey *pk);

/* Check if a validator is registered. */
AL_PUBLIC AL_NODISCARD al_status al_validator_set_contains(
    const al_state_txn *txn, const al_pubkey *pk, al_bool *out);

/* Record the registration height for activation delay. */
AL_PUBLIC AL_NODISCARD al_status al_validator_set_record_registration(
    al_state_txn *txn, const al_pubkey *pk, al_height height);

/* Check if a validator's activation delay has elapsed. */
AL_PUBLIC AL_NODISCARD al_status al_validator_set_is_active(
    const al_state_txn *txn, const al_pubkey *pk, al_height current_height,
    al_bool *out);

/* Process a registration transaction: store the record and record the height. */
AL_PUBLIC AL_NODISCARD al_status al_validator_set_register(
    al_state_txn *txn, const al_potb_record *record, al_height height);

/* Load a single validator record by identity. */
AL_PUBLIC AL_NODISCARD al_status al_validator_set_load_single(
    const al_state_txn *txn, const al_pubkey *pk, al_potb_record *out);

AL_EXTERN_C_END

#endif /* ASTROLUNE_VALIDATOR_SET_H */
