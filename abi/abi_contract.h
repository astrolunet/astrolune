/*
 * The C/C++ ABI contract for include/astrolune/.
 *
 * This header contains no declarations - only compile-time assertions about
 * the layout and the constants of the public types. It is compiled twice, by
 * contract_c.c as C and by contract_cxx.cpp as C++, which is the whole point:
 * a layout assertion inside one language proves only that the language agrees
 * with itself. Two translation units checking the same literals is what turns
 * "the C core and the C++ tooling see the same struct" into a build failure
 * rather than a review finding.
 *
 * Layout divergence is the failure mode docs/02-architecture/c-cpp-boundary.md
 * calls the worse of the two, because it is silent: both sides compile, both
 * link, and each writes fields where the other does not read them.
 *
 * PROVENANCE. Every number below was measured, not computed by hand. A scratch
 * probe printing sizeof/alignof/offsetof for each public type was compiled from
 * identical source as C (/TC /std:clatest) and as C++ (/TP /std:c++latest)
 * under MSVC 19.51 x64, and the two outputs were diffed - they agreed on every
 * line. Where a hand computation was done first it served only as a cross-check.
 * The toolchain is the authority.
 *
 * SCOPE. These numbers describe a 64-bit target with 8-byte pointers. No public
 * struct contains `long`, `wchar_t`, a bit-field, or a pointer to a function, so
 * the layouts should hold identically across Win64, LP64 and ARM64 - but that is
 * a prediction, not a measurement. Only MSVC x64 has actually been run. A
 * toolchain that disagrees fails here, loudly, with the offending field named.
 * That is the intended behaviour: this file is a tripwire, not a portability
 * shim, and a 32-bit port must revisit it rather than relax it.
 *
 * PADDING. al_potb_params and al_potb_record contain interior padding, because
 * 4- and 8-byte fields alternate in declaration order. That is harmless -
 * neither struct is ever hashed or copied to the wire as a blob; serialisation
 * goes field by field through al_writer. The offsets are pinned regardless: a
 * change that reshuffles them changes the ABI whether or not it changes
 * consensus, and the tooling links these archives directly.
 *
 * WHAT THIS FILE DOES NOT CHECK. That the headers are self-sufficient (see the
 * per-header translation units next to it) and that their functions carry C
 * linkage (see boundary_symbols.cpp - a missing AL_EXTERN_C_BEGIN is invisible
 * to the compiler and only surfaces as an unresolved symbol at link time).
 */

#ifndef ASTROLUNE_ABI_CONTRACT_H
#define ASTROLUNE_ABI_CONTRACT_H

#include <limits.h>
#include <stddef.h>

#include "astrolune/arena.h"
#include "astrolune/base.h"
#include "astrolune/block.h"
#include "astrolune/bytes.h"
#include "astrolune/crypto.h"
#include "astrolune/fixed.h"
#include "astrolune/hash.h"
#include "astrolune/potb.h"
#include "astrolune/state.h"
#include "astrolune/tx.h"
#include "astrolune/vm.h"

/* `alignof` is both the C++ spelling and the C23 spelling, but MSVC in C mode
 * only reliably accepts _Alignof. Same routing idea as AL_STATIC_ASSERT. */
#if defined(__cplusplus)
#  define AL_ABI_ALIGNOF(T) alignof(T)
#else
#  define AL_ABI_ALIGNOF(T) _Alignof(T)
#endif

/*
 * Each macro expands to exactly one assertion and does not swallow the caller's
 * semicolon. Two assertions in one macro would leave a stray semicolon at file
 * scope - a constraint violation in C, reported as an unrelated error long
 * before anyone reached the layout numbers.
 *
 * The expected value is cast to al_size so both sides of the comparison are
 * unsigned; sizeof against a bare signed literal is the shape -Wsign-compare
 * exists to flag.
 */
#define AL_ABI_SIZE(T, n) \
    AL_STATIC_ASSERT(sizeof(T) == AL_CAST(al_size, n), \
                     "ABI: sizeof(" #T ") is not " #n)

#define AL_ABI_ALIGN(T, n) \
    AL_STATIC_ASSERT(AL_ABI_ALIGNOF(T) == AL_CAST(al_size, n), \
                     "ABI: alignof(" #T ") is not " #n)

#define AL_ABI_OFFSET(T, f, n) \
    AL_STATIC_ASSERT(offsetof(T, f) == AL_CAST(al_size, n), \
                     "ABI: offsetof(" #T ", " #f ") is not " #n)

/* For enumerators and macro constants, which cross the boundary as values
 * rather than as layout. */
#define AL_ABI_VALUE(expr, n) \
    AL_STATIC_ASSERT((expr) == (n), "ABI: " #expr " is not " #n)

/* --------------------------------------------------------------------------
 * 1. Preconditions
 *
 * If any of these fails, nothing below it is meaningful. Read this section
 * first and stop.
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(void *, 8);
AL_ABI_SIZE(al_size, 8);
AL_ABI_VALUE(CHAR_BIT, 8);

/* --------------------------------------------------------------------------
 * 2. Scalar widths (base.h, fixed.h)
 *
 * These are typedefs of the stdint names, so a failure here means the platform
 * disagrees with its own stdint.h - not that a header was edited.
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_u8,  1);  AL_ABI_ALIGN(al_u8,  1);
AL_ABI_SIZE(al_u16, 2);  AL_ABI_ALIGN(al_u16, 2);
AL_ABI_SIZE(al_u32, 4);  AL_ABI_ALIGN(al_u32, 4);
AL_ABI_SIZE(al_u64, 8);  AL_ABI_ALIGN(al_u64, 8);
AL_ABI_SIZE(al_i8,  1);  AL_ABI_ALIGN(al_i8,  1);
AL_ABI_SIZE(al_i16, 2);  AL_ABI_ALIGN(al_i16, 2);
AL_ABI_SIZE(al_i32, 4);  AL_ABI_ALIGN(al_i32, 4);
AL_ABI_SIZE(al_i64, 8);  AL_ABI_ALIGN(al_i64, 8);

/* The semantic aliases. Widening any of these is a consensus change, because
 * each names a quantity that goes into a hash. */
AL_ABI_SIZE(al_amount, 8);
AL_ABI_SIZE(al_height, 8);
AL_ABI_SIZE(al_gas,    8);
AL_ABI_SIZE(al_nonce,  8);

AL_ABI_SIZE(al_resources, 32);
AL_ABI_ALIGN(al_resources, 8);
AL_ABI_OFFSET(al_resources, compute,    0);
AL_ABI_OFFSET(al_resources, memory,     8);
AL_ABI_OFFSET(al_resources, storage,   16);
AL_ABI_OFFSET(al_resources, bandwidth, 24);

AL_ABI_SIZE(al_fee_params, 104);
AL_ABI_ALIGN(al_fee_params, 8);
AL_ABI_OFFSET(al_fee_params, block_limit,               0);
AL_ABI_OFFSET(al_fee_params, target,                   32);
AL_ABI_OFFSET(al_fee_params, initial_base_price,       64);
AL_ABI_OFFSET(al_fee_params, storage_deposit_per_byte, 96);

/* Q32.32 in an int64_t. If this is ever 4 bytes, every score silently loses its
 * fractional half; if it is ever unsigned, every decay curve loses its sign. */
AL_ABI_SIZE(al_fixed, 8);
AL_ABI_ALIGN(al_fixed, 8);
AL_STATIC_ASSERT(AL_CAST(al_fixed, -1) < 0, "ABI: al_fixed must be signed");
AL_ABI_VALUE(AL_FIXED_FRAC_BITS, 32);
AL_ABI_VALUE(AL_FIXED_ONE,  INT64_C(4294967296));
AL_ABI_VALUE(AL_FIXED_HALF, INT64_C(2147483648));

/* --------------------------------------------------------------------------
 * 3. al_bool is not C++'s bool (boundary rule 1.7)
 *
 * The rule exists because `bool` is a distinct type in C++ with an
 * implementation-defined size, and because a bool holds only 0 or 1 - so a
 * struct field round-tripped through one would quietly normalise every nonzero
 * byte to 1. The check below is the language-neutral way to tell the two apart:
 * converting 2 to a one-byte integer keeps 2, converting it to a bool yields 1.
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_bool, 1);
AL_ABI_ALIGN(al_bool, 1);
AL_STATIC_ASSERT(AL_CAST(al_bool, 2) == 2,
                 "ABI: al_bool collapses 2 to 1 - it is a bool, not a byte");
AL_ABI_VALUE(AL_TRUE,  1);
AL_ABI_VALUE(AL_FALSE, 0);

/* --------------------------------------------------------------------------
 * 4. Enum widths and values (boundary rules 1.5, 1.6)
 *
 * MSVC has no `enum : type` despite reporting C23, so each public enum pins its
 * own width with an explicit …_SENTINEL = 0x7fffffff. Without that, an enum
 * whose largest enumerator fits in a byte may be given a byte, and the two
 * languages need not choose the same underlying type.
 *
 * The values matter too, not just the widths: an al_status crosses the ABI as a
 * number, and an al_potb_level or al_potb_offence is a consensus-visible code.
 * Renumbering one is not a refactor. Only the enumerators whose values are
 * written explicitly in the header, plus the two encoding codes named as
 * consensus rules in CLAUDE.md, are pinned here - the rest follow by succession
 * and pinning them would be transcription, not verification.
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_status, 4);
AL_ABI_ALIGN(al_status, 4);
AL_ABI_VALUE(AL_OK, 0);
AL_ABI_VALUE(AL_ERR_INVALID_ARG, 1);
AL_ABI_VALUE(AL_ERR_OUT_OF_MEMORY, 32);
AL_ABI_VALUE(AL_ERR_MALFORMED, 64);
AL_ABI_VALUE(AL_ERR_NOT_CANONICAL, 65);   /* non-minimal varint  */
AL_ABI_VALUE(AL_ERR_TRAILING_BYTES, 67);  /* unconsumed input    */
AL_ABI_VALUE(AL_ERR_BAD_SIGNATURE, 96);
AL_ABI_VALUE(AL_ERR_OUT_OF_GAS, 128);
AL_ABI_VALUE(AL_ERR_INSUFFICIENT_FUNDS, 160);
AL_ABI_VALUE(AL_STATUS_SENTINEL, 0x7fffffff);

AL_ABI_SIZE(al_crypto_backend_kind, 4);
AL_ABI_ALIGN(al_crypto_backend_kind, 4);
AL_ABI_VALUE(AL_CRYPTO_BACKEND_DEV, 0);
AL_ABI_VALUE(AL_CRYPTO_BACKEND_ED25519, 1);
AL_ABI_VALUE(AL_CRYPTO_BACKEND_SENTINEL, 0x7fffffff);

AL_ABI_SIZE(al_potb_level, 4);
AL_ABI_ALIGN(al_potb_level, 4);
AL_ABI_VALUE(AL_POTB_LEVEL_RELAY, 0);
AL_ABI_VALUE(AL_POTB_LEVEL_CANDIDATE, 1);
AL_ABI_VALUE(AL_POTB_LEVEL_VALIDATOR, 2);
AL_ABI_VALUE(AL_POTB_LEVEL_BANNED, 3);
AL_ABI_VALUE(AL_POTB_LEVEL_SENTINEL, 0x7fffffff);

AL_ABI_SIZE(al_potb_offence, 4);
AL_ABI_ALIGN(al_potb_offence, 4);
AL_ABI_VALUE(AL_POTB_OFFENCE_VOTE_MISS, 0);
AL_ABI_VALUE(AL_POTB_OFFENCE_SENTINEL, 0x7fffffff);

/* --------------------------------------------------------------------------
 * 5. The byte-array wrappers (boundary rule 1.9)
 *
 * Each of these is a struct around an array, not a bare array, so an address
 * cannot be passed where a public key is expected. Two properties are load
 * bearing. The size must equal the corresponding AL_*_SIZE, and the alignment
 * must be 1 - together they say the struct is exactly its bytes with no
 * padding, which is what makes hashing sizeof(al_hash256) bytes the same as
 * hashing 32 content bytes. Padding here would feed uninitialised memory into
 * a hash and make the digest depend on the allocator.
 *
 * base.h already asserts the al_hash256 and al_address sizes at the point of
 * declaration. The duplication is intentional: those two fire even for a C-only
 * consumer, and these fire in both languages side by side.
 *
 * The sizes are stated against the AL_*_SIZE constants rather than against bare
 * literals, because the relation "the struct is exactly its declared constant"
 * is the invariant worth holding. Section 6 pins the constants themselves, so
 * the two together still nail the numbers down.
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_hash256, AL_HASH_SIZE);        AL_ABI_ALIGN(al_hash256, 1);
AL_ABI_SIZE(al_address, AL_ADDRESS_SIZE);     AL_ABI_ALIGN(al_address, 1);
AL_ABI_SIZE(al_pubkey,  AL_PUBKEY_SIZE);      AL_ABI_ALIGN(al_pubkey,  1);
AL_ABI_SIZE(al_seckey,  AL_SECKEY_SIZE);      AL_ABI_ALIGN(al_seckey,  1);
AL_ABI_SIZE(al_sig,     AL_SIGNATURE_SIZE);   AL_ABI_ALIGN(al_sig,     1);
AL_ABI_SIZE(al_vrf_proof, AL_VRF_PROOF_SIZE); AL_ABI_ALIGN(al_vrf_proof, 1);

/* --------------------------------------------------------------------------
 * 6. Public constants
 *
 * These reach the tooling as literals, so they are ABI in the same sense a
 * struct offset is: a C archive compiled against one value and a C++ tool
 * compiled against another disagree with no diagnostic anywhere.
 * -------------------------------------------------------------------------- */

AL_ABI_VALUE(AL_HASH_SIZE, 32);
AL_ABI_VALUE(AL_ADDRESS_SIZE, 32);
AL_ABI_VALUE(AL_PUBKEY_SIZE, 32);
AL_ABI_VALUE(AL_SECKEY_SIZE, 64);
AL_ABI_VALUE(AL_SIGNATURE_SIZE, 64);
AL_ABI_VALUE(AL_VRF_PROOF_SIZE, 80);

/* Hex forms are 2n+1 to leave room for the NUL. Off by one here is a buffer
 * overrun in every caller that sizes an array with it. */
AL_ABI_VALUE(AL_HASH_HEX_SIZE, 65);
AL_ABI_VALUE(AL_ADDRESS_HEX_SIZE, 65);

/* Nine decimal places. Changing this redenominates every balance in existence. */
AL_ABI_VALUE(AL_UNITS_PER_COIN, UINT64_C(1000000000));

/* The committee arrays are fixed-size, which is why al_potb_committee is large
 * enough that test_potb declares it static. */
AL_ABI_VALUE(AL_POTB_MAX_COMMITTEE, 512);

/* --------------------------------------------------------------------------
 * 7. Layout: bytes.h
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_bytes, 16);
AL_ABI_ALIGN(al_bytes, 8);
AL_ABI_OFFSET(al_bytes, data, 0);
AL_ABI_OFFSET(al_bytes, len,  8);

AL_ABI_SIZE(al_bytes_mut, 16);
AL_ABI_ALIGN(al_bytes_mut, 8);
AL_ABI_OFFSET(al_bytes_mut, data, 0);
AL_ABI_OFFSET(al_bytes_mut, len,  8);

AL_ABI_SIZE(al_reader, 32);
AL_ABI_ALIGN(al_reader, 8);
AL_ABI_OFFSET(al_reader, data,   0);
AL_ABI_OFFSET(al_reader, len,    8);
AL_ABI_OFFSET(al_reader, pos,   16);
AL_ABI_OFFSET(al_reader, status, 24);

AL_ABI_SIZE(al_writer, 32);
AL_ABI_ALIGN(al_writer, 8);
AL_ABI_OFFSET(al_writer, data,   0);
AL_ABI_OFFSET(al_writer, cap,    8);
AL_ABI_OFFSET(al_writer, pos,   16);
AL_ABI_OFFSET(al_writer, status, 24);

/* --------------------------------------------------------------------------
 * 8. Layout: arena.h
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_arena, 40);
AL_ABI_ALIGN(al_arena, 8);
AL_ABI_OFFSET(al_arena, head,        0);
AL_ABI_OFFSET(al_arena, block_size,  8);
AL_ABI_OFFSET(al_arena, total_bytes, 16);
AL_ABI_OFFSET(al_arena, used_bytes,  24);
AL_ABI_OFFSET(al_arena, peak_bytes,  32);

AL_ABI_SIZE(al_arena_mark, 16);
AL_ABI_ALIGN(al_arena_mark, 8);
AL_ABI_OFFSET(al_arena_mark, block,  0);
AL_ABI_OFFSET(al_arena_mark, offset, 8);

/* --------------------------------------------------------------------------
 * 9. Layout: hash.h
 *
 * These are the only public structs a caller is expected to allocate on the
 * stack and hand to a C function repeatedly across calls, so their size is
 * part of the calling contract rather than an implementation detail.
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_sha256_ctx, 112);
AL_ABI_ALIGN(al_sha256_ctx, 8);
AL_ABI_OFFSET(al_sha256_ctx, state,       0);
AL_ABI_OFFSET(al_sha256_ctx, bit_len,     32);
AL_ABI_OFFSET(al_sha256_ctx, buffer,      40);
AL_ABI_OFFSET(al_sha256_ctx, buffer_len, 104);

AL_ABI_SIZE(al_hmac_ctx, 224);
AL_ABI_ALIGN(al_hmac_ctx, 8);
AL_ABI_OFFSET(al_hmac_ctx, inner,   0);
AL_ABI_OFFSET(al_hmac_ctx, outer, 112);

/* --------------------------------------------------------------------------
 * 10. Layout: crypto.h
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_keypair, 96);
AL_ABI_ALIGN(al_keypair, 1);
AL_ABI_OFFSET(al_keypair, pk,  0);
AL_ABI_OFFSET(al_keypair, sk, 32);

AL_ABI_SIZE(al_vdf_output, 40);
AL_ABI_ALIGN(al_vdf_output, 8);
AL_ABI_OFFSET(al_vdf_output, value,       0);
AL_ABI_OFFSET(al_vdf_output, iterations, 32);

/* --------------------------------------------------------------------------
 * 11. Layout: potb.h
 *
 * The largest public surface. Offsets are listed in declaration order, so a
 * field inserted rather than appended shifts every line below it and the
 * failure names the first field that moved.
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_potb_params, 168);
AL_ABI_ALIGN(al_potb_params, 8);
AL_ABI_OFFSET(al_potb_params, loyalty_threshold_days,     0);
AL_ABI_OFFSET(al_potb_params, loyalty_rate_per_day,       8);
AL_ABI_OFFSET(al_potb_params, cap_loyalty,               16);
AL_ABI_OFFSET(al_potb_params, grace_period_days,         24);
AL_ABI_OFFSET(al_potb_params, decay_half_life_days,      28);
AL_ABI_OFFSET(al_potb_params, cap_tbs,                   32);
AL_ABI_OFFSET(al_potb_params, cap_tgw,                   40);
AL_ABI_OFFSET(al_potb_params, sybil_cluster_threshold,   48);
AL_ABI_OFFSET(al_potb_params, sybil_cluster_max_size,    56);
AL_ABI_OFFSET(al_potb_params, tdi_suspicious_below,      64);
AL_ABI_OFFSET(al_potb_params, committee_size,            72);
AL_ABI_OFFSET(al_potb_params, committee_lifetime_blocks, 76);
AL_ABI_OFFSET(al_potb_params, rotation_fraction,         80);
AL_ABI_OFFSET(al_potb_params, min_tbs_candidate,         88);
AL_ABI_OFFSET(al_potb_params, min_tbs_validator,         96);
AL_ABI_OFFSET(al_potb_params, min_tgw_validator,        104);
AL_ABI_OFFSET(al_potb_params, candidate_weight_factor,  112);
AL_ABI_OFFSET(al_potb_params, epoch_days,               120);
AL_ABI_OFFSET(al_potb_params, reward_flat_bp,           124);
AL_ABI_OFFSET(al_potb_params, reward_weighted_bp,       126);
AL_ABI_OFFSET(al_potb_params, reward_bonded_bp,         128);
AL_ABI_OFFSET(al_potb_params, reward_max_multiple,      136);
AL_ABI_OFFSET(al_potb_params, gini_max,                 144);
AL_ABI_OFFSET(al_potb_params, hhi_max,                  152);
AL_ABI_OFFSET(al_potb_params, committee_size_min,       160);
AL_ABI_OFFSET(al_potb_params, committee_size_max,       164);

AL_ABI_SIZE(al_potb_record, 192);
AL_ABI_ALIGN(al_potb_record, 8);
AL_ABI_OFFSET(al_potb_record, identity,               0);
AL_ABI_OFFSET(al_potb_record, uptime_days,           32);
AL_ABI_OFFSET(al_potb_record, last_active_day,       36);
AL_ABI_OFFSET(al_potb_record, first_seen_day,        40);
AL_ABI_OFFSET(al_potb_record, responses_total,       48);
AL_ABI_OFFSET(al_potb_record, responses_correct,     56);
AL_ABI_OFFSET(al_potb_record, votes_expected,        64);
AL_ABI_OFFSET(al_potb_record, votes_cast,            72);
AL_ABI_OFFSET(al_potb_record, penalty_multiplier,    80);
AL_ABI_OFFSET(al_potb_record, banned_until_day,      88);
AL_ABI_OFFSET(al_potb_record, permanently_banned,    92);
AL_ABI_OFFSET(al_potb_record, inbound_attestations,  96);
AL_ABI_OFFSET(al_potb_record, inbound_from_cluster, 100);
AL_ABI_OFFSET(al_potb_record, cluster_size,         104);
AL_ABI_OFFSET(al_potb_record, tdi,                  112);
AL_ABI_OFFSET(al_potb_record, challenges_issued,    120);
AL_ABI_OFFSET(al_potb_record, challenges_passed,    124);
AL_ABI_OFFSET(al_potb_record, challenges_missed,    128);
AL_ABI_OFFSET(al_potb_record, asn,                  132);
AL_ABI_OFFSET(al_potb_record, asn_peer_count,       136);
AL_ABI_OFFSET(al_potb_record, correlation_score,    144);
AL_ABI_OFFSET(al_potb_record, prev_asn,             152);
AL_ABI_OFFSET(al_potb_record, prev_inbound_attestations, 156);
AL_ABI_OFFSET(al_potb_record, prev_challenges_passed,    160);
AL_ABI_OFFSET(al_potb_record, prev_uptime_days,          164);
AL_ABI_OFFSET(al_potb_record, profile_snapshot_day,      168);
AL_ABI_OFFSET(al_potb_record, behavioral_entropy,        176);
AL_ABI_OFFSET(al_potb_record, operational_bond,          184);

AL_ABI_SIZE(al_potb_network_stats, 32);
AL_ABI_ALIGN(al_potb_network_stats, 8);
AL_ABI_OFFSET(al_potb_network_stats, node_count,         0);
AL_ABI_OFFSET(al_potb_network_stats, median_miss_rate,   8);
AL_ABI_OFFSET(al_potb_network_stats, median_error_rate, 16);
AL_ABI_OFFSET(al_potb_network_stats, total_weight,      24);

AL_ABI_SIZE(al_potb_weight, 56);
AL_ABI_ALIGN(al_potb_weight, 8);
AL_ABI_OFFSET(al_potb_weight, tbs,         0);
AL_ABI_OFFSET(al_potb_weight, tgw,         8);
AL_ABI_OFFSET(al_potb_weight, ndm,        16);
AL_ABI_OFFSET(al_potb_weight, cod,        24);
AL_ABI_OFFSET(al_potb_weight, tbs_capped, 32);
AL_ABI_OFFSET(al_potb_weight, tgw_capped, 40);
AL_ABI_OFFSET(al_potb_weight, total,      48);

/* 20528 bytes. The two AL_POTB_MAX_COMMITTEE arrays account for 512*32 + 512*8
 * = 20480 of it; the rest is size, formed_at, seed and four bytes of padding
 * after `size` to align `members`… which needs none, being align-1. MSVC still
 * places members at 4, so the padding is inside the array's leading offset
 * rather than before it. Pinned because a size this large is a stack hazard the
 * suites already work around. */
AL_ABI_SIZE(al_potb_committee, 20528);
AL_ABI_ALIGN(al_potb_committee, 8);
AL_ABI_OFFSET(al_potb_committee, size,          0);
AL_ABI_OFFSET(al_potb_committee, members,       4);
AL_ABI_OFFSET(al_potb_committee, weights,   16392);
AL_ABI_OFFSET(al_potb_committee, formed_at, 20488);
AL_ABI_OFFSET(al_potb_committee, seed,      20496);

AL_ABI_SIZE(al_potb_reward_split, 32);
AL_ABI_ALIGN(al_potb_reward_split, 8);
AL_ABI_OFFSET(al_potb_reward_split, flat,      0);
AL_ABI_OFFSET(al_potb_reward_split, weighted,  8);
AL_ABI_OFFSET(al_potb_reward_split, bonded,   16);
AL_ABI_OFFSET(al_potb_reward_split, total,    24);

/* --------------------------------------------------------------------------
 * 12. Layout: block.h
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_genesis_allocation, 40);
AL_ABI_ALIGN(al_genesis_allocation, 8);
AL_ABI_OFFSET(al_genesis_allocation, address,  0);
AL_ABI_OFFSET(al_genesis_allocation, balance, 32);

AL_ABI_SIZE(al_genesis, 832);
AL_ABI_ALIGN(al_genesis, 8);
AL_ABI_OFFSET(al_genesis, version,                   0);
AL_ABI_OFFSET(al_genesis, chain_id,                  4);
AL_ABI_OFFSET(al_genesis, initial_state_root,        8);
AL_ABI_OFFSET(al_genesis, fees,                     40);
AL_ABI_OFFSET(al_genesis, schedule,                144);
AL_ABI_OFFSET(al_genesis, vm_stack_limit,          624);
AL_ABI_OFFSET(al_genesis, vm_memory_limit,         632);
AL_ABI_OFFSET(al_genesis, vm_call_depth_limit,     640);
AL_ABI_OFFSET(al_genesis, potb,                    648);
AL_ABI_OFFSET(al_genesis, allocations,             816);
AL_ABI_OFFSET(al_genesis, allocation_count,        824);

AL_ABI_SIZE(al_block_header, 344);
AL_ABI_ALIGN(al_block_header, 8);
AL_ABI_OFFSET(al_block_header, version,        0);
AL_ABI_OFFSET(al_block_header, chain_id,       4);
AL_ABI_OFFSET(al_block_header, height,         8);
AL_ABI_OFFSET(al_block_header, protocol_day,  16);
AL_ABI_OFFSET(al_block_header, parent_hash,   20);
AL_ABI_OFFSET(al_block_header, state_root,    52);
AL_ABI_OFFSET(al_block_header, tx_root,       84);
AL_ABI_OFFSET(al_block_header, receipt_root, 116);
AL_ABI_OFFSET(al_block_header, resources,   152);
AL_ABI_OFFSET(al_block_header, base_prices, 184);
AL_ABI_OFFSET(al_block_header, proposer,    216);
AL_ABI_OFFSET(al_block_header, tip_flat,    248);
AL_ABI_OFFSET(al_block_header, tip_weighted,280);
AL_ABI_OFFSET(al_block_header, tip_bonded,  312);

AL_ABI_SIZE(al_block, 360);
AL_ABI_ALIGN(al_block, 8);
AL_ABI_OFFSET(al_block, header,              0);
AL_ABI_OFFSET(al_block, transactions,      344);
AL_ABI_OFFSET(al_block, transaction_count, 352);

/* --------------------------------------------------------------------------
 * 13. Layout: state.h
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_account, 128);
AL_ABI_ALIGN(al_account, 8);
AL_ABI_OFFSET(al_account, address,       0);
AL_ABI_OFFSET(al_account, balance,      32);
AL_ABI_OFFSET(al_account, nonce,        40);
AL_ABI_OFFSET(al_account, code_hash,    48);
AL_ABI_OFFSET(al_account, storage_root, 80);
AL_ABI_OFFSET(al_account, storage_bytes, 112);
AL_ABI_OFFSET(al_account, storage_deposit, 120);

AL_ABI_SIZE(al_state_node, 68);
AL_ABI_ALIGN(al_state_node, 4);
AL_ABI_OFFSET(al_state_node, kind,   0);
AL_ABI_OFFSET(al_state_node, first,  4);
AL_ABI_OFFSET(al_state_node, second, 36);

AL_ABI_SIZE(al_state_store, 40);
AL_ABI_ALIGN(al_state_store, 8);
AL_ABI_OFFSET(al_state_store, context,    0);
AL_ABI_OFFSET(al_state_store, node_get,   8);
AL_ABI_OFFSET(al_state_store, node_put,  16);
AL_ABI_OFFSET(al_state_store, value_get, 24);
AL_ABI_OFFSET(al_state_store, value_put, 32);

AL_ABI_SIZE(al_state, 48);
AL_ABI_ALIGN(al_state, 8);
AL_ABI_OFFSET(al_state, impl,    0);
AL_ABI_OFFSET(al_state, height,  8);
AL_ABI_OFFSET(al_state, root,   16);

AL_ABI_SIZE(al_state_txn, 80);
AL_ABI_ALIGN(al_state_txn, 8);
AL_ABI_OFFSET(al_state_txn, state,      0);
AL_ABI_OFFSET(al_state_txn, root,       8);
AL_ABI_OFFSET(al_state_txn, resources, 40);
AL_ABI_OFFSET(al_state_txn, active,    72);

AL_ABI_SIZE(al_state_snapshot, 40);
AL_ABI_ALIGN(al_state_snapshot, 8);
AL_ABI_OFFSET(al_state_snapshot, height, 0);
AL_ABI_OFFSET(al_state_snapshot, root,   8);

AL_ABI_SIZE(al_smt_proof, 128);
AL_ABI_ALIGN(al_smt_proof, 8);
AL_ABI_OFFSET(al_smt_proof, key,               0);
AL_ABI_OFFSET(al_smt_proof, value_hash,       32);
AL_ABI_OFFSET(al_smt_proof, sibling_bitmap,   64);
AL_ABI_OFFSET(al_smt_proof, siblings,         96);
AL_ABI_OFFSET(al_smt_proof, sibling_count,   104);
AL_ABI_OFFSET(al_smt_proof, sibling_capacity,112);
AL_ABI_OFFSET(al_smt_proof, exists,          120);

/* --------------------------------------------------------------------------
 * 14. Layout and codes: tx.h
 *
 * The type tag goes on the wire, so its values are as consensus-visible
 * as an opcode. Renumbering one reinterprets every encoded transaction.
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_tx_type, 4);
AL_ABI_ALIGN(al_tx_type, 4);
AL_ABI_VALUE(AL_TX_TRANSFER, 0);
AL_ABI_VALUE(AL_TX_DEPLOY, 1);
AL_ABI_VALUE(AL_TX_CALL, 2);
AL_ABI_VALUE(AL_TX_POTB, 3);
AL_ABI_VALUE(AL_TX_TYPE_SENTINEL, 0x7fffffff);

/* One mebibyte. A limit that differs between two nodes is a fork: one accepts
 * a transaction the other rejects. */
AL_ABI_VALUE(AL_TX_MAX_PAYLOAD, 1048320u);

AL_ABI_SIZE(al_potb_operation, 4);
AL_ABI_ALIGN(al_potb_operation, 4);
AL_ABI_VALUE(AL_POTB_REGISTER, 0);
AL_ABI_VALUE(AL_POTB_COMMITTEE_VOTE, 9);
AL_ABI_VALUE(AL_POTB_OPERATION_SENTINEL, 0x7fffffff);

AL_ABI_SIZE(al_tx_transfer_body, 40);
AL_ABI_SIZE(al_tx_deploy_body, 24);
AL_ABI_SIZE(al_tx_call_body, 64);
AL_ABI_SIZE(al_tx_potb_body, 64);
AL_ABI_SIZE(al_tx_body, 64);

AL_ABI_SIZE(al_transaction, 264);
AL_ABI_ALIGN(al_transaction, 8);
AL_ABI_OFFSET(al_transaction, version,          0);
AL_ABI_OFFSET(al_transaction, chain_id,         4);
AL_ABI_OFFSET(al_transaction, expiry_height,    8);
AL_ABI_OFFSET(al_transaction, sender,          16);
AL_ABI_OFFSET(al_transaction, nonce,           48);
AL_ABI_OFFSET(al_transaction, resource_limit,  56);
AL_ABI_OFFSET(al_transaction, max_base_price,  88);
AL_ABI_OFFSET(al_transaction, tip,            120);
AL_ABI_OFFSET(al_transaction, type,           128);
AL_ABI_OFFSET(al_transaction, body,           136);
AL_ABI_OFFSET(al_transaction, signature,      200);

AL_ABI_SIZE(al_event, 80);
AL_ABI_ALIGN(al_event, 8);
AL_ABI_OFFSET(al_event, contract, 0);
AL_ABI_OFFSET(al_event, topic,   32);
AL_ABI_OFFSET(al_event, data,    64);

AL_ABI_SIZE(al_receipt, 152);
AL_ABI_ALIGN(al_receipt, 8);
AL_ABI_OFFSET(al_receipt, transaction_hash,  0);
AL_ABI_OFFSET(al_receipt, status,            32);
AL_ABI_OFFSET(al_receipt, resources,         40);
AL_ABI_OFFSET(al_receipt, base_fee_burned,   72);
AL_ABI_OFFSET(al_receipt, tip_paid,          80);
AL_ABI_OFFSET(al_receipt, contract_address,  88);
AL_ABI_OFFSET(al_receipt, return_data,      120);
AL_ABI_OFFSET(al_receipt, events,           136);
AL_ABI_OFFSET(al_receipt, event_count,      144);

AL_ABI_SIZE(al_tx_context, 232);
AL_ABI_ALIGN(al_tx_context, 8);
AL_ABI_OFFSET(al_tx_context, chain_id,       0);
AL_ABI_OFFSET(al_tx_context, block_height,   8);
AL_ABI_OFFSET(al_tx_context, protocol_day,  16);
AL_ABI_OFFSET(al_tx_context, base_prices,   24);
AL_ABI_OFFSET(al_tx_context, tip_flat,      56);
AL_ABI_OFFSET(al_tx_context, tip_weighted,  88);
AL_ABI_OFFSET(al_tx_context, tip_bonded,   120);
AL_ABI_OFFSET(al_tx_context, vm,           152);
AL_ABI_OFFSET(al_tx_context, arena,        216);
AL_ABI_OFFSET(al_tx_context, potb_params,  224);

/* --------------------------------------------------------------------------
 * 15. Layout and opcodes: vm.h
 *
 * The opcode numbers are the most consensus-visible constants in the tree.
 * They are the bytecode. Renumbering one silently changes the meaning of every
 * contract already deployed, and no signature, hash or state root would notice
 * - the code bytes are unchanged, only their interpretation. Pinned exhaustively
 * for that reason, unlike the enums where only the explicitly-assigned members
 * are checked.
 * -------------------------------------------------------------------------- */

AL_ABI_SIZE(al_vm_opcode, 4);
AL_ABI_ALIGN(al_vm_opcode, 4);
AL_ABI_VALUE(AL_VM_STOP,   0x00);
AL_ABI_VALUE(AL_VM_PUSH64, 0x01);
AL_ABI_VALUE(AL_VM_ADD,    0x02);
AL_ABI_VALUE(AL_VM_SUB,    0x03);
AL_ABI_VALUE(AL_VM_MUL,    0x04);
AL_ABI_VALUE(AL_VM_DIV,    0x05);
AL_ABI_VALUE(AL_VM_EQ,     0x06);
AL_ABI_VALUE(AL_VM_LT,     0x07);
AL_ABI_VALUE(AL_VM_DUP,    0x08);
AL_ABI_VALUE(AL_VM_DROP,   0x09);
AL_ABI_VALUE(AL_VM_JUMP,   0x0a);
AL_ABI_VALUE(AL_VM_JUMPI,  0x0b);
AL_ABI_VALUE(AL_VM_LOAD8,  0x0c);
AL_ABI_VALUE(AL_VM_STORE8, 0x0d);
AL_ABI_VALUE(AL_VM_RETURN, 0x0e);
AL_ABI_VALUE(AL_VM_REVERT, 0x0f);
AL_ABI_VALUE(AL_VM_MOD,           0x10);
AL_ABI_VALUE(AL_VM_AND,           0x11);
AL_ABI_VALUE(AL_VM_OR,            0x12);
AL_ABI_VALUE(AL_VM_XOR,           0x13);
AL_ABI_VALUE(AL_VM_NOT,           0x14);
AL_ABI_VALUE(AL_VM_SHL,           0x15);
AL_ABI_VALUE(AL_VM_SHR,           0x16);
AL_ABI_VALUE(AL_VM_GT,            0x17);
AL_ABI_VALUE(AL_VM_LE,            0x18);
AL_ABI_VALUE(AL_VM_GE,            0x19);
AL_ABI_VALUE(AL_VM_SWAP,          0x1a);
AL_ABI_VALUE(AL_VM_LOAD64,        0x1b);
AL_ABI_VALUE(AL_VM_STORE64,       0x1c);
AL_ABI_VALUE(AL_VM_CALLDATA_SIZE, 0x1d);
AL_ABI_VALUE(AL_VM_CALLDATA_COPY, 0x1e);
AL_ABI_VALUE(AL_VM_CALL,          0x1f);
AL_ABI_VALUE(AL_VM_RET,           0x20);
AL_ABI_VALUE(AL_VM_HOST,          0x21);
AL_ABI_VALUE(AL_VM_OPCODE_SENTINEL, 0x7fffffff);

AL_ABI_SIZE(al_vm_host_id, 4);
AL_ABI_ALIGN(al_vm_host_id, 4);
AL_ABI_VALUE(AL_VM_HOST_SENDER, 0);
AL_ABI_VALUE(AL_VM_HOST_CURRENT_ADDRESS, 1);
AL_ABI_VALUE(AL_VM_HOST_BLOCK_HEIGHT, 2);
AL_ABI_VALUE(AL_VM_HOST_PROTOCOL_DAY, 3);
AL_ABI_VALUE(AL_VM_HOST_BALANCE, 4);
AL_ABI_VALUE(AL_VM_HOST_TRANSFER, 5);
AL_ABI_VALUE(AL_VM_HOST_STORAGE_GET, 6);
AL_ABI_VALUE(AL_VM_HOST_STORAGE_SET, 7);
AL_ABI_VALUE(AL_VM_HOST_STORAGE_DELETE, 8);
AL_ABI_VALUE(AL_VM_HOST_EMIT_EVENT, 9);
AL_ABI_VALUE(AL_VM_HOST_HASH_TAGGED, 10);
AL_ABI_VALUE(AL_VM_HOST_VERIFY_SIGNATURE, 11);
AL_ABI_VALUE(AL_VM_HOST_CALL_CONTRACT, 12);
AL_ABI_VALUE(AL_VM_HOST_ID_SENTINEL, 0x7fffffff);

AL_ABI_SIZE(al_vm_hash_domain, 4);
AL_ABI_ALIGN(al_vm_hash_domain, 4);
AL_ABI_VALUE(AL_VM_HASH_CONTRACT_DATA, 0);
AL_ABI_VALUE(AL_VM_HASH_ADDRESS, 1);
AL_ABI_VALUE(AL_VM_HASH_STORAGE_KEY, 2);
AL_ABI_VALUE(AL_VM_HASH_STORAGE_VALUE, 3);
AL_ABI_VALUE(AL_VM_HASH_EVENT, 4);
AL_ABI_VALUE(AL_VM_HASH_POTB_RECORD, 5);
AL_ABI_VALUE(AL_VM_HASH_TRANSACTION, 6);
AL_ABI_VALUE(AL_VM_HASH_BLOCK, 7);
AL_ABI_VALUE(AL_VM_HASH_DOMAIN_SENTINEL, 0x7fffffff);

/* Resource limits. Two nodes disagreeing on any of these disagree about which
 * programs halt, which is a fork rather than a performance difference. */
AL_ABI_VALUE(AL_VM_MAX_CODE_SIZE, 1048576u);
AL_ABI_VALUE(AL_VM_DEFAULT_STACK, 1024u);
AL_ABI_VALUE(AL_VM_DEFAULT_MEMORY, 65536u);
AL_ABI_VALUE(AL_VM_DEFAULT_CALL_DEPTH, 64u);

AL_ABI_SIZE(al_vm_function, 12);
AL_ABI_ALIGN(al_vm_function, 4);
AL_ABI_OFFSET(al_vm_function, offset,           0);
AL_ABI_OFFSET(al_vm_function, parameter_count,  4);
AL_ABI_OFFSET(al_vm_function, result_count,     6);
AL_ABI_OFFSET(al_vm_function, max_stack,        8);
AL_ABI_OFFSET(al_vm_function, reserved,        10);

AL_ABI_SIZE(al_vm_program, 56);
AL_ABI_ALIGN(al_vm_program, 8);
AL_ABI_OFFSET(al_vm_program, container,          0);
AL_ABI_OFFSET(al_vm_program, code,              16);
AL_ABI_OFFSET(al_vm_program, functions,         32);
AL_ABI_OFFSET(al_vm_program, function_count,    40);
AL_ABI_OFFSET(al_vm_program, container_version, 48);
AL_ABI_OFFSET(al_vm_program, isa_version,       50);
AL_ABI_OFFSET(al_vm_program, flags,             52);

AL_ABI_SIZE(al_vm_resource_schedule, 480);
AL_ABI_ALIGN(al_vm_resource_schedule, 8);
AL_ABI_OFFSET(al_vm_resource_schedule, opcode, 0);
AL_ABI_OFFSET(al_vm_resource_schedule, host, 376);

AL_ABI_SIZE(al_vm_config, 64);
AL_ABI_ALIGN(al_vm_config, 8);
AL_ABI_OFFSET(al_vm_config, stack_limit,       0);
AL_ABI_OFFSET(al_vm_config, memory_limit,      8);
AL_ABI_OFFSET(al_vm_config, call_depth_limit, 16);
AL_ABI_OFFSET(al_vm_config, resource_limit,   24);
AL_ABI_OFFSET(al_vm_config, schedule,         56);

AL_ABI_SIZE(al_vm_execution_context, 128);
AL_ABI_ALIGN(al_vm_execution_context, 8);
AL_ABI_OFFSET(al_vm_execution_context, sender,                 0);
AL_ABI_OFFSET(al_vm_execution_context, current_contract,      32);
AL_ABI_OFFSET(al_vm_execution_context, block_height,          64);
AL_ABI_OFFSET(al_vm_execution_context, protocol_day,          72);
AL_ABI_OFFSET(al_vm_execution_context, entrypoint,            76);
AL_ABI_OFFSET(al_vm_execution_context, value,                 80);
AL_ABI_OFFSET(al_vm_execution_context, code,                  88);
AL_ABI_OFFSET(al_vm_execution_context, state_txn,            104);
AL_ABI_OFFSET(al_vm_execution_context, active_contracts,     112);
AL_ABI_OFFSET(al_vm_execution_context, active_contract_count,120);

AL_ABI_SIZE(al_vm_host, 16);
AL_ABI_ALIGN(al_vm_host, 8);
AL_ABI_OFFSET(al_vm_host, context, 0);
AL_ABI_OFFSET(al_vm_host, invoke,  8);

AL_ABI_SIZE(al_vm_result, 56);
AL_ABI_ALIGN(al_vm_result, 8);
AL_ABI_OFFSET(al_vm_result, status,         0);
AL_ABI_OFFSET(al_vm_result, resources,      8);
AL_ABI_OFFSET(al_vm_result, return_data,   40);

#endif /* ASTROLUNE_ABI_CONTRACT_H */
