/*
 * astrolune/crypto.h - keys, signatures, VRF and VDF.
 *
 * =========================================================================
 *  SECURITY STATUS - READ BEFORE USING THIS FOR ANYTHING REAL
 * =========================================================================
 *
 * The hash layer (astrolune/hash.h) is real: SHA-256, HMAC and HKDF are
 * complete implementations checked against the published NIST and RFC test
 * vectors, and they are what the rest of the core relies on.
 *
 * The *signature/VRF/VDF* layer below has two build configurations. The default
 * dependency-free configuration uses development signatures. An explicit
 * ASTROLUNE_CRYPTO_BACKEND=sodium build uses libsodium's audited Ed25519 while
 * retaining the development VRF and VDF:
 *
 *   - It is deterministic and self-consistent, so the node, the VM, the state
 *     machine and the whole test suite exercise the real code paths.
 *   - The default is NOT cryptographically secure. It does not implement
 *     Ed25519. The
 *     verified half of a "signature" is a hash of the public key and the
 *     message, so anyone can produce one for any key. Signing still genuinely
 *     requires the secret key - the signature carries a second, unverified half
 *     that only the key holder can compute - which keeps the layers above honest
 *     about key ownership, but forgery is trivial for anyone who reads
 *     core/crypto/dev_backend.c.
 *
 *   - The sodium configuration implements RFC 8032 signatures, rejects
 *     non-canonical S encodings and is checked against published vectors. It
 *     still reports the complete stack as insecure until VRF and VDF are
 *     replaced or deliberately removed by protocol decision.
 *
 * Backend identity is observable through al_crypto_backend(); callers must use
 * al_crypto_is_secure() as the final deployment gate. See
 * docs/02-architecture/cryptography.md for the remaining migration checklist.
 * =========================================================================
 */

#ifndef ASTROLUNE_CRYPTO_H
#define ASTROLUNE_CRYPTO_H

#include "astrolune/base.h"
#include "astrolune/bytes.h"
#include "astrolune/hash.h"

AL_EXTERN_C_BEGIN

/* --------------------------------------------------------------------------
 * Backend identification
 * -------------------------------------------------------------------------- */

typedef enum al_crypto_backend_kind {
    /* Deterministic, insecure, for development and tests only. */
    AL_CRYPTO_BACKEND_DEV = 0,
    /* Real Ed25519 signatures; other primitives may still be development-only. */
    AL_CRYPTO_BACKEND_ED25519 = 1,
    AL_CRYPTO_BACKEND_SENTINEL = 0x7fffffff
} al_crypto_backend_kind;

AL_PUBLIC al_crypto_backend_kind al_crypto_backend(void);

/* Human-readable backend name, e.g. "dev-insecure". */
AL_PUBLIC const char *al_crypto_backend_name(void);

/* AL_FALSE for any complete stack not fit for a real network. A real signature
 * backend alone is insufficient while VRF/VDF remain development primitives. */
AL_PUBLIC AL_NODISCARD al_bool al_crypto_is_secure(void);

/* --------------------------------------------------------------------------
 * Keys
 * -------------------------------------------------------------------------- */

typedef struct al_keypair {
    al_pubkey pk;
    al_seckey sk;
} al_keypair;

/*
 * Derive a keypair from 32 bytes of seed material.
 *
 * Deterministic by design: tests, genesis fixtures and reproducible simulation
 * runs all need to regenerate the same identities. Production key generation
 * must feed this a seed from a real CSPRNG.
 *
 * AL_CRYPTO_INSECURE with the dev backend.
 */
AL_PUBLIC AL_NODISCARD al_status al_keypair_from_seed(const al_u8 seed[32],
                                           al_keypair *out);

/* Public key of a secret key. */
AL_PUBLIC AL_NODISCARD al_status al_pubkey_from_seckey(const al_seckey *sk,
                                            al_pubkey *out);

/*
 * Address of a public key: tagged SHA-256 of the key bytes.
 *
 * The full 32-byte digest is used rather than a truncation. A 20-byte address
 * offers 80-bit collision resistance, which is uncomfortably close to feasible
 * for a chain expected to be long-lived, and the 12 saved bytes per account do
 * not justify designing in that ceiling.
 */
AL_PUBLIC void al_address_from_pubkey(const al_pubkey *pk, al_address *out);

/* The all-zero address. Rejected as a transfer destination. */
AL_PUBLIC al_address al_address_zero(void);
AL_PUBLIC AL_NODISCARD al_bool al_address_eq(const al_address *a, const al_address *b);
AL_PUBLIC AL_NODISCARD al_bool al_address_is_zero(const al_address *a);
AL_PUBLIC int al_address_cmp(const al_address *a, const al_address *b);

/* --------------------------------------------------------------------------
 * Human-readable address text
 * -------------------------------------------------------------------------- */

/*
 * Bech32 text form of an address, "al1…". Checksummed and unambiguous; this
 * is the format users see and type. Raw 32 bytes remain the wire/storage
 * form everywhere else.
 *
 * `cap` should be AL_ADDRESS_TEXT_SIZE. Decoding rejects uppercase input
 * outright (a mixed-case string is a typo, not a format) and verifies the
 * Bech32 checksum before returning the address.
 */
#define AL_ADDRESS_TEXT_SIZE (AL_ADDRESS_SIZE * 8u / 5u + 16u)

#define AL_ERR_CHECKSUM ((al_status)(-3)) /* transport-local: bad bech32 */

AL_PUBLIC AL_NODISCARD al_status al_address_to_bech32(
    const al_address *address, char *out, al_size cap);
AL_PUBLIC AL_NODISCARD al_status al_address_from_bech32(const char *text,
                                                        al_address *out);

/*
 * Contract address: tagged hash of the deployer's address, their nonce and the
 * code hash. Deterministic, so a deployer can compute the address before the
 * transaction lands, and collision-free across deployers.
 */
AL_PUBLIC void al_address_for_contract(const al_address *deployer, al_nonce nonce,
                             const al_hash256 *code_hash, al_address *out);

/* --------------------------------------------------------------------------
 * Signatures
 * -------------------------------------------------------------------------- */

/* AL_CRYPTO_INSECURE with the dev backend. */
AL_PUBLIC AL_NODISCARD al_status al_sign(const al_seckey *sk, al_bytes message,
                              al_sig *out);

/* AL_CRYPTO_INSECURE with the dev backend.
 * Returns AL_OK when valid, AL_ERR_BAD_SIGNATURE when not. */
AL_PUBLIC AL_NODISCARD al_status al_verify(const al_pubkey *pk, al_bytes message,
                                const al_sig *sig);

/* Sign a digest that has already been domain-separated. The transaction path
 * uses this so the message is hashed exactly once. */
AL_PUBLIC AL_NODISCARD al_status al_sign_hash(const al_seckey *sk, const al_hash256 *h,
                                    al_sig *out);
AL_PUBLIC AL_NODISCARD al_status al_verify_hash(const al_pubkey *pk, const al_hash256 *h,
                                      const al_sig *sig);

/* --------------------------------------------------------------------------
 * Verifiable Random Function
 *
 * PoTB selects each block's committee with a VRF: every candidate evaluates it
 * on the epoch seed and their own key, and the output decides membership. The
 * properties the consensus depends on are that the output is unpredictable
 * before evaluation, unique per (key, input), and publicly verifiable
 * afterwards - so nobody can grind their way into a committee, and nobody can
 * deny the result once produced.
 *
 * AL_CRYPTO_INSECURE with the dev backend: the stub is deterministic and
 * verifiable but not unpredictable to a holder of the secret key.
 * -------------------------------------------------------------------------- */

#define AL_VRF_PROOF_SIZE 80

typedef struct al_vrf_proof { al_u8 bytes[AL_VRF_PROOF_SIZE]; } al_vrf_proof;

/* Evaluate the VRF, producing both the output digest and its proof. */
AL_PUBLIC AL_NODISCARD al_status al_vrf_prove(const al_seckey *sk, al_bytes input,
                                   al_vrf_proof *proof_out,
                                   al_hash256 *output_out);

/* Verify a proof and recover the output it commits to. */
AL_PUBLIC AL_NODISCARD al_status al_vrf_verify(const al_pubkey *pk, al_bytes input,
                                    const al_vrf_proof *proof,
                                    al_hash256 *output_out);

/*
 * Map a VRF output to the unit interval as a Q32.32 fixed-point value in
 * [0, 1), for threshold comparisons.
 *
 * Fixed point rather than a float because the comparison against a node's
 * weight is a consensus decision, and it must resolve identically on every
 * machine. See astrolune/fixed.h.
 */
AL_PUBLIC al_i64 al_vrf_output_to_unit(const al_hash256 *output);

/* --------------------------------------------------------------------------
 * Verifiable Delay Function
 *
 * The seed for committee selection is agreed by commit-reveal. Commit-reveal
 * alone lets the last revealer see everyone else's contribution and choose
 * whether to reveal, biasing the result. A VDF closes that: the seed is passed
 * through a function that provably takes wall-clock time to evaluate but is
 * fast to verify, so by the time anyone could compute the outcome, the window
 * to act on it has closed.
 *
 * Status: the interface is defined and a deliberately weak iterated-hash stand-in
 * is compiled in. A real deployment needs a proper construction (Wesolowski or
 * Pietrzak over a class group of unknown order); that choice, and whether the
 * VDF branch is taken at all, is the open question tracked in
 * docs/01-consensus/potb.md section 5 and docs/07-roadmap/open-questions.md.
 * The iterated hash here is sequential but has no succinct proof, so
 * verification costs the same as evaluation - which is exactly the property a
 * real VDF must provide and this one does not.
 * -------------------------------------------------------------------------- */

typedef struct al_vdf_output {
    al_hash256 value;
    al_u64     iterations;
} al_vdf_output;

/* Evaluate the delay function. Cost is linear in `iterations`. */
AL_PUBLIC void al_vdf_eval(const al_hash256 *input, al_u64 iterations,
                 al_vdf_output *out);

/* AL_CRYPTO_INSECURE: recomputes the whole chain, so it is as slow as
 * evaluation. A real VDF verifies in polylog time. */
AL_PUBLIC AL_NODISCARD al_status al_vdf_verify(const al_hash256 *input,
                                     const al_vdf_output *output);

/* --------------------------------------------------------------------------
 * Utilities
 * -------------------------------------------------------------------------- */

/* Overwrite a buffer, resistant to being optimised away. Use for key material
 * before it goes out of scope. */
AL_PUBLIC void al_secure_zero(void *p, al_size len);

AL_EXTERN_C_END

#endif /* ASTROLUNE_CRYPTO_H */
