/*
 * The C++ half of the layout contract, plus the assertions that only C++ can
 * make.
 *
 * The first half is the point of the pairing: this file compiles exactly the
 * same v1 abi_contract.h that contract_c.c compiles, so every size, alignment and
 * offset in it is checked twice, once per language, against one set of literals.
 *
 * The second half asserts properties that have no C spelling. They are not
 * decoration - `standard_layout` is precisely the C++ property that makes the C
 * layout rules apply to a type, and without it offsetof is only conditionally
 * supported, which would mean the contract's own offset checks rest on nothing.
 */

#include <type_traits>

#include "abi_contract.h"

namespace {

/* One macro, two assertions, no trailing semicolon of its own - the caller's
 * terminates the second, so nothing stray is left at namespace scope. */
#define AL_ABI_LAYOUT(T) \
    static_assert(std::is_standard_layout<T>::value, \
                  "ABI: " #T " is not standard-layout as C++"); \
    static_assert(std::is_trivially_copyable<T>::value, \
                  "ABI: " #T " is not trivially copyable as C++")

/* Standard-layout is what licenses offsetof and what makes the C and C++ views
 * of a struct the same object. Trivially-copyable is what licenses memcpy and
 * hashing the bytes - which the core does to every one of these. If a future
 * tooling header ever gave one of them a constructor, a base class or a private
 * member, both properties would go and the failure would name the type. */
AL_ABI_LAYOUT(al_hash256);
AL_ABI_LAYOUT(al_address);
AL_ABI_LAYOUT(al_pubkey);
AL_ABI_LAYOUT(al_seckey);
AL_ABI_LAYOUT(al_sig);
AL_ABI_LAYOUT(al_bytes);
AL_ABI_LAYOUT(al_bytes_mut);
AL_ABI_LAYOUT(al_reader);
AL_ABI_LAYOUT(al_writer);
AL_ABI_LAYOUT(al_arena);
AL_ABI_LAYOUT(al_arena_mark);
AL_ABI_LAYOUT(al_sha256_ctx);
AL_ABI_LAYOUT(al_hmac_ctx);
AL_ABI_LAYOUT(al_keypair);
AL_ABI_LAYOUT(al_vrf_proof);
AL_ABI_LAYOUT(al_vdf_output);
AL_ABI_LAYOUT(al_potb_params);
AL_ABI_LAYOUT(al_potb_record);
AL_ABI_LAYOUT(al_potb_network_stats);
AL_ABI_LAYOUT(al_potb_weight);
AL_ABI_LAYOUT(al_potb_committee);
AL_ABI_LAYOUT(al_potb_reward_split);
AL_ABI_LAYOUT(al_block_header);
AL_ABI_LAYOUT(al_account);
AL_ABI_LAYOUT(al_state);
AL_ABI_LAYOUT(al_transaction);
AL_ABI_LAYOUT(al_vm_config);
AL_ABI_LAYOUT(al_vm_result);

/* Boundary rule 1.7, stated the way C++ can state it. The contract's
 * AL_CAST(al_bool, 2) == 2 check catches the same mistake from either language;
 * this one names it. */
static_assert(!std::is_same<al_bool, bool>::value,
              "ABI: al_bool must not be C++'s bool");
static_assert(std::is_unsigned<al_bool>::value,
              "ABI: al_bool must be an unsigned byte");

/*
 * Boundary rule 1.9. In both languages two structs with identical members are
 * still distinct types, so these hold automatically today - which is the point:
 * they will keep holding only as long as nobody replaces one of the wrappers
 * with a typedef of another, and that is exactly the edit that would let an
 * address be passed where a public key is expected. Same size, same alignment,
 * same field: the compiler's type system is the only thing separating them.
 */
static_assert(!std::is_same<al_hash256, al_address>::value,
              "ABI: al_hash256 and al_address must be distinct types");
static_assert(!std::is_same<al_address, al_pubkey>::value,
              "ABI: al_address and al_pubkey must be distinct types");
static_assert(!std::is_same<al_pubkey, al_hash256>::value,
              "ABI: al_pubkey and al_hash256 must be distinct types");
static_assert(!std::is_same<al_seckey, al_sig>::value,
              "ABI: al_seckey and al_sig must be distinct types");

/*
 * Boundary rules 1.5 and 1.6. MSVC has no `enum : type` in C, so the public
 * enums pin their width with an explicit …_SENTINEL = 0x7fffffff instead. This
 * asserts the trick actually worked: each enum's underlying type is four bytes
 * wide in C++ too, which is what makes it safe to pass one across the boundary
 * by value.
 */
#define AL_ABI_ENUM_WIDTH(E) \
    static_assert(std::is_enum<E>::value, "ABI: " #E " is not an enum"); \
    static_assert(sizeof(std::underlying_type<E>::type) == 4u, \
                  "ABI: " #E " does not have a 4-byte underlying type")

AL_ABI_ENUM_WIDTH(al_status);
AL_ABI_ENUM_WIDTH(al_crypto_backend_kind);
AL_ABI_ENUM_WIDTH(al_potb_level);
AL_ABI_ENUM_WIDTH(al_potb_offence);
AL_ABI_ENUM_WIDTH(al_tx_type);
AL_ABI_ENUM_WIDTH(al_potb_operation);
AL_ABI_ENUM_WIDTH(al_vm_opcode);
AL_ABI_ENUM_WIDTH(al_vm_host_id);
AL_ABI_ENUM_WIDTH(al_vm_hash_domain);

/* Q32.32 must stay a signed 64-bit integer, not a class and not a float. */
static_assert(std::is_integral<al_fixed>::value,
              "ABI: al_fixed must be an integral type");
static_assert(std::is_signed<al_fixed>::value,
              "ABI: al_fixed must be signed");

/* Boundary rule 1.8, as far as a type check can reach: no public struct may
 * contain a floating-point member. There is no trait for "contains no float",
 * but every public struct is trivially copyable and of a pinned size, and the
 * two named non-integer quantities are al_fixed. This asserts the one that can
 * be asserted - that al_fixed itself has not quietly become a double. */
static_assert(!std::is_floating_point<al_fixed>::value,
              "ABI: al_fixed must not be floating point");

}  /* namespace */
