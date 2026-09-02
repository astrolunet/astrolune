/*
 * The C linkage check: take the address of every public function from C++.
 *
 * This is the half of the boundary that compiling cannot verify.
 *
 * Boundary rule 1.1 says every public header wraps its declarations in
 * AL_EXTERN_C_BEGIN / AL_EXTERN_C_END. Forget that on a header and it still
 * compiles as C++ - cleanly, with no diagnostic - because C++ is perfectly happy
 * to declare a function with C++ linkage. The declaration simply names a
 * different symbol than the one the C archive defines: al_potb_tbs becomes
 * ?al_potb_tbs@@YA… under MSVC or _Z12al_potb_tbs… under the Itanium ABI, and
 * the mistake surfaces as an unresolved external at link time, in whichever
 * tool first tried to call it.
 *
 * So the check has to link, not just compile, and it has to reference every
 * symbol it means to cover. Taking the address of a function emits a relocation
 * against it, which the linker must resolve against al_base, al_crypto or
 * al_potb - so an entry in this table is a claim that the corresponding C
 * function is reachable from C++ under the name the header promises.
 *
 * It catches a second class of mistake for free: a function declared in a public
 * header and never implemented. That also appears as an unresolved external, and
 * would otherwise wait for the first caller to find it.
 *
 * All public functions declared in the eleven public headers are listed,
 * grouped by header in declaration order. The dependency-free manifest checker
 * compares this table with every AL_PUBLIC declaration during every build, so
 * additions, omissions and duplicate entries fail before linking consumers.
 */

#include "boundary.hpp"

#include "astrolune/arena.h"
#include "astrolune/base.h"
#include "astrolune/block.h"
#include "astrolune/bytes.h"
#include "astrolune/crypto.h"
#include "astrolune/evidence.h"
#include "astrolune/fixed.h"
#include "astrolune/hash.h"
#include "astrolune/potb.h"
#include "astrolune/signer.h"
#include "astrolune/state.h"
#include "astrolune/tx.h"
#include "astrolune/validator_set.h"
#include "astrolune/vm.h"

/* reinterpret_cast rather than a C cast: the tooling builds with
 * -Wold-style-cast, and under the ci and asan presets warnings are errors. */
#define AL_ABI_SYM(f) reinterpret_cast<al_abi_fn>(&f)

/* `extern` is load bearing. A const array at namespace scope has internal
 * linkage in C++, and an unreferenced internal-linkage array may be discarded
 * before it ever produces a relocation - which would quietly turn this file into
 * a no-op that always passes. */
extern const al_abi_fn al_abi_symbols[] = {
    /* base.h - 8 */
    AL_ABI_SYM(al_status_str),
    AL_ABI_SYM(al_ok),
    AL_ABI_SYM(al_resources_zero),
    AL_ABI_SYM(al_resources_add),
    AL_ABI_SYM(al_resources_within),
    AL_ABI_SYM(al_resources_fee),
    AL_ABI_SYM(al_fee_next_base_prices),
    AL_ABI_SYM(al_version_string),

    /* bytes.h - 37 */
    AL_ABI_SYM(al_bytes_make),
    AL_ABI_SYM(al_bytes_from_cstr),
    AL_ABI_SYM(al_bytes_empty),
    AL_ABI_SYM(al_bytes_slice),
    AL_ABI_SYM(al_bytes_eq),
    AL_ABI_SYM(al_bytes_eq_ct),
    AL_ABI_SYM(al_reader_init),
    AL_ABI_SYM(al_reader_remaining),
    AL_ABI_SYM(al_reader_status),
    AL_ABI_SYM(al_reader_fail),
    AL_ABI_SYM(al_reader_take),
    AL_ABI_SYM(al_reader_bytes),
    AL_ABI_SYM(al_reader_u8),
    AL_ABI_SYM(al_reader_u16),
    AL_ABI_SYM(al_reader_u32),
    AL_ABI_SYM(al_reader_u64),
    AL_ABI_SYM(al_reader_varint),
    AL_ABI_SYM(al_reader_hash),
    AL_ABI_SYM(al_reader_address),
    AL_ABI_SYM(al_reader_finish),
    AL_ABI_SYM(al_writer_init),
    AL_ABI_SYM(al_writer_len),
    AL_ABI_SYM(al_writer_raw),
    AL_ABI_SYM(al_writer_bytes),
    AL_ABI_SYM(al_writer_u8),
    AL_ABI_SYM(al_writer_u16),
    AL_ABI_SYM(al_writer_u32),
    AL_ABI_SYM(al_writer_u64),
    AL_ABI_SYM(al_writer_varint),
    AL_ABI_SYM(al_writer_hash),
    AL_ABI_SYM(al_writer_address),
    AL_ABI_SYM(al_writer_finish),
    AL_ABI_SYM(al_varint_size),
    AL_ABI_SYM(al_hex_encode),
    AL_ABI_SYM(al_hex_decode),
    AL_ABI_SYM(al_hash_to_hex),
    AL_ABI_SYM(al_address_to_hex),

    /* arena.h - 12 */
    AL_ABI_SYM(al_arena_init),
    AL_ABI_SYM(al_arena_destroy),
    AL_ABI_SYM(al_arena_reset),
    AL_ABI_SYM(al_arena_alloc),
    AL_ABI_SYM(al_arena_alloc_aligned),
    AL_ABI_SYM(al_arena_calloc),
    AL_ABI_SYM(al_arena_dup),
    AL_ABI_SYM(al_arena_strdup),
    AL_ABI_SYM(al_arena_save),
    AL_ABI_SYM(al_arena_restore),
    AL_ABI_SYM(al_arena_used),
    AL_ABI_SYM(al_arena_peak),

    /* fixed.h - 20 */
    AL_ABI_SYM(al_fixed_from_int),
    AL_ABI_SYM(al_fixed_from_ratio),
    AL_ABI_SYM(al_fixed_to_int_trunc),
    AL_ABI_SYM(al_fixed_to_int_round),
    AL_ABI_SYM(al_fixed_floor_int),
    AL_ABI_SYM(al_fixed_add),
    AL_ABI_SYM(al_fixed_sub),
    AL_ABI_SYM(al_fixed_mul),
    AL_ABI_SYM(al_fixed_div),
    AL_ABI_SYM(al_fixed_abs),
    AL_ABI_SYM(al_fixed_min),
    AL_ABI_SYM(al_fixed_max),
    AL_ABI_SYM(al_fixed_clamp),
    AL_ABI_SYM(al_fixed_sqrt),
    AL_ABI_SYM(al_fixed_log2),
    AL_ABI_SYM(al_fixed_ln),
    AL_ABI_SYM(al_fixed_ln1p),
    AL_ABI_SYM(al_fixed_exp2),
    AL_ABI_SYM(al_fixed_half_pow),
    AL_ABI_SYM(al_fixed_to_str),

    /* hash.h - 25 */
    AL_ABI_SYM(al_sha256_init),
    AL_ABI_SYM(al_sha256_update),
    AL_ABI_SYM(al_sha256_final),
    AL_ABI_SYM(al_sha256),
    AL_ABI_SYM(al_sha256_bytes),
    AL_ABI_SYM(al_sha256d),
    AL_ABI_SYM(al_hash_tagged),
    AL_ABI_SYM(al_hash_tagged_bytes),
    AL_ABI_SYM(al_hash_tagged_pair),
    AL_ABI_SYM(al_hmac_init),
    AL_ABI_SYM(al_hmac_update),
    AL_ABI_SYM(al_hmac_final),
    AL_ABI_SYM(al_hmac_sha256),
    AL_ABI_SYM(al_hkdf_extract),
    AL_ABI_SYM(al_hkdf_expand),
    AL_ABI_SYM(al_merkle_leaf),
    AL_ABI_SYM(al_merkle_root),
    AL_ABI_SYM(al_merkle_proof_max_len),
    AL_ABI_SYM(al_merkle_prove),
    AL_ABI_SYM(al_merkle_verify),
    AL_ABI_SYM(al_hash_eq),
    AL_ABI_SYM(al_hash_cmp),
    AL_ABI_SYM(al_hash_is_zero),
    AL_ABI_SYM(al_hash_zero),
    AL_ABI_SYM(al_hash_bit),

    /* crypto.h - 32 */
    AL_ABI_SYM(al_crypto_backend),
    AL_ABI_SYM(al_crypto_backend_name),
    AL_ABI_SYM(al_crypto_is_secure),
    AL_ABI_SYM(al_keypair_from_seed),
    AL_ABI_SYM(al_pubkey_from_seckey),
    AL_ABI_SYM(al_sign),
    AL_ABI_SYM(al_verify),
    AL_ABI_SYM(al_sign_hash),
    AL_ABI_SYM(al_verify_hash),
    AL_ABI_SYM(al_address_from_pubkey),
    AL_ABI_SYM(al_address_for_contract),
    AL_ABI_SYM(al_address_eq),
    AL_ABI_SYM(al_address_cmp),
    AL_ABI_SYM(al_address_to_bech32),
    AL_ABI_SYM(al_address_from_bech32),
    AL_ABI_SYM(al_address_is_zero),
    AL_ABI_SYM(al_address_zero),
    AL_ABI_SYM(al_secure_zero),
    AL_ABI_SYM(al_kx_keygen),
    AL_ABI_SYM(al_kx_shared),
    AL_ABI_SYM(al_aead_encrypt),
    AL_ABI_SYM(al_aead_decrypt),

    /* potb.h - 38 */
    AL_ABI_SYM(al_potb_params_default),
    AL_ABI_SYM(al_potb_params_validate),
    AL_ABI_SYM(al_potb_record_init),
    AL_ABI_SYM(al_potb_correctness_rate),
    AL_ABI_SYM(al_potb_miss_rate),
    AL_ABI_SYM(al_potb_loyalty_bonus),
    AL_ABI_SYM(al_potb_decay_multiplier),
    AL_ABI_SYM(al_potb_tbs),
    AL_ABI_SYM(al_potb_tgw),
    AL_ABI_SYM(al_potb_ndm),
    AL_ABI_SYM(al_potb_cod),
    AL_ABI_SYM(al_potb_weight_compute),
    AL_ABI_SYM(al_potb_weight_total),
    AL_ABI_SYM(al_potb_level_of),
    AL_ABI_SYM(al_potb_level_str),
    AL_ABI_SYM(al_potb_is_suspicious_cluster),
    AL_ABI_SYM(al_potb_correlation_pair),
    AL_ABI_SYM(al_potb_correlation_score),
    AL_ABI_SYM(al_potb_offence_str),
    AL_ABI_SYM(al_potb_penalty_for),
    AL_ABI_SYM(al_potb_slash),
    AL_ABI_SYM(al_potb_quorum_threshold),
    AL_ABI_SYM(al_potb_committee_select),
    AL_ABI_SYM(al_potb_committee_contains),
    AL_ABI_SYM(al_potb_committee_rotate),
    AL_ABI_SYM(al_potb_epoch_seed_commit),
    AL_ABI_SYM(al_potb_epoch_seed_check),
    AL_ABI_SYM(al_potb_epoch_seed_mix),
    AL_ABI_SYM(al_potb_epoch_seed_finalise),
    AL_ABI_SYM(al_potb_reward_for),
    AL_ABI_SYM(al_potb_gini),
    AL_ABI_SYM(al_potb_hhi),
    AL_ABI_SYM(al_potb_independence_check),
    AL_ABI_SYM(al_potb_entropy_observe),
    AL_ABI_SYM(al_potb_entropy_value),
    AL_ABI_SYM(al_potb_profile_change_score),
    AL_ABI_SYM(al_potb_profile_snapshot),
    AL_ABI_SYM(al_potb_appeal_resolve),

    /* evidence.h - 6 */
    AL_ABI_SYM(al_evidence_create),
    AL_ABI_SYM(al_evidence_encode),
    AL_ABI_SYM(al_evidence_decode),
    AL_ABI_SYM(al_evidence_verify),
    AL_ABI_SYM(al_evidence_process),
    AL_ABI_SYM(al_evidence_key),

    /* signer.h - 7 */
    AL_ABI_SYM(al_signer_new_from_keypair),
    AL_ABI_SYM(al_signer_new_from_hex),
    AL_ABI_SYM(al_signer_destroy),
    AL_ABI_SYM(al_signer_pubkey),
    AL_ABI_SYM(al_signer_sign),
    AL_ABI_SYM(al_signer_encrypt_seed),
    AL_ABI_SYM(al_signer_decrypt_seed),

    /* validator_set.h - 8 */
    AL_ABI_SYM(al_validator_set_load),
    AL_ABI_SYM(al_validator_set_load_single),
    AL_ABI_SYM(al_validator_set_store),
    AL_ABI_SYM(al_validator_set_register),
    AL_ABI_SYM(al_validator_set_remove),
    AL_ABI_SYM(al_validator_set_record_registration),
    AL_ABI_SYM(al_validator_set_contains),
    AL_ABI_SYM(al_validator_set_is_active),

    /* block.h - 13 */
    AL_ABI_SYM(al_genesis_validate),
    AL_ABI_SYM(al_genesis_encode),
    AL_ABI_SYM(al_genesis_decode),
    AL_ABI_SYM(al_genesis_hash),
    AL_ABI_SYM(al_block_header_hash),
    AL_ABI_SYM(al_block_header_encode),
    AL_ABI_SYM(al_block_header_decode),
    AL_ABI_SYM(al_block_encode),
    AL_ABI_SYM(al_block_decode),
    AL_ABI_SYM(al_block_transaction_root),
    AL_ABI_SYM(al_block_receipt_root),
    AL_ABI_SYM(al_block_produce),
    AL_ABI_SYM(al_block_execute),

    /* state.h - 32 */
    AL_ABI_SYM(al_state_memory_store_init),
    AL_ABI_SYM(al_state_memory_store_interface),
    AL_ABI_SYM(al_state_init),
    AL_ABI_SYM(al_state_open),
    AL_ABI_SYM(al_state_clear),
    AL_ABI_SYM(al_state_get),
    AL_ABI_SYM(al_state_upsert),
    AL_ABI_SYM(al_state_remove),
    AL_ABI_SYM(al_state_transfer),
    AL_ABI_SYM(al_state_root),
    AL_ABI_SYM(al_state_snapshot_take),
    AL_ABI_SYM(al_state_snapshot_restore),
    AL_ABI_SYM(al_state_txn_begin),
    AL_ABI_SYM(al_state_txn_get),
    AL_ABI_SYM(al_state_txn_upsert),
    AL_ABI_SYM(al_state_txn_remove),
    AL_ABI_SYM(al_state_txn_transfer),
    AL_ABI_SYM(al_state_txn_deploy),
    AL_ABI_SYM(al_state_txn_code_get),
    AL_ABI_SYM(al_state_txn_storage_get),
    AL_ABI_SYM(al_state_txn_storage_set),
    AL_ABI_SYM(al_state_txn_storage_delete),
    AL_ABI_SYM(al_state_txn_system_storage_get),
    AL_ABI_SYM(al_state_txn_system_storage_set),
    AL_ABI_SYM(al_state_txn_system_storage_delete),
    AL_ABI_SYM(al_state_txn_commit),
    AL_ABI_SYM(al_state_txn_rollback),
    AL_ABI_SYM(al_state_prove_account),
    AL_ABI_SYM(al_smt_proof_verify),
    AL_ABI_SYM(al_smt_proof_encode),
    AL_ABI_SYM(al_smt_proof_decode),
    AL_ABI_SYM(al_state_potb_system_address),

    /* tx.h - 15 */
    AL_ABI_SYM(al_tx_validate_shape),
    AL_ABI_SYM(al_tx_encoded_size),
    AL_ABI_SYM(al_tx_encode),
    AL_ABI_SYM(al_tx_decode),
    AL_ABI_SYM(al_tx_hash),
    AL_ABI_SYM(al_tx_signing_hash),
    AL_ABI_SYM(al_tx_sign),
    AL_ABI_SYM(al_tx_verify),
    AL_ABI_SYM(al_event_encode),
    AL_ABI_SYM(al_event_decode),
    AL_ABI_SYM(al_event_hash),
    AL_ABI_SYM(al_receipt_encode),
    AL_ABI_SYM(al_receipt_decode),
    AL_ABI_SYM(al_receipt_hash),
    AL_ABI_SYM(al_tx_apply),

    /* vm.h - 8 */
    AL_ABI_SYM(al_vm_config_default),
    AL_ABI_SYM(al_vm_resource_schedule_default),
    AL_ABI_SYM(al_vm_compute_cost),
    AL_ABI_SYM(al_vm_host_compute_cost),
    AL_ABI_SYM(al_vm_container_encode),
    AL_ABI_SYM(al_vm_program_load),
    AL_ABI_SYM(al_vm_validate),
    AL_ABI_SYM(al_vm_execute),
};

extern const std::size_t al_abi_symbol_count =
    sizeof(al_abi_symbols) / sizeof(al_abi_symbols[0]);

/* 8 + 37 + 12 + 20 + 25 + 28 + 38 + 6 + 7 + 8 + 13 + 32 + 15 + 8. Catches an entry lost to a
 * bad merge; does not catch a function added to a header and never listed. */
static_assert(sizeof(al_abi_symbols) / sizeof(al_abi_symbols[0]) == 251u,
              "ABI: the public surface is 251 functions (5 removed: VRF/VDF) - "
              "update the table and this count together, or say why the surface changed");
