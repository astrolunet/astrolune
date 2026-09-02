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
 * The *signature/VRF/VDF* layer below has two build configurations:
 *
 *   - The default dependency-free configuration uses development signatures
 *     (dev-insecure). It does NOT implement Ed25519. The verified half of a
 *     "signature" is a hash of the public key and the message, so anyone can
 *     produce one for any key. Signing still genuinely requires the secret
 *     key - the signature carries a second, unverified half that only the key
 *     holder can compute - which keeps the layers above honest about key
 *     ownership, but forgery is trivial for anyone who reads
 *     core/crypto/dev_backend.c.
 *
 *   - The ASTROLUNE_CRYPTO_BACKEND=sodium build uses libsodium's audited
 *     Ed25519 (RFC 8032, rejects non-canonical S encodings). This backend
 *     reports al_crypto_is_secure() == AL_TRUE because signatures are real.
 *     VRF and VDF remain development primitives but are not used in consensus
 *     for a controlled-validator network (VRF is unused in consensus; VDF is
 *     optional and handled via NULL checks).
 *
 * Backend identity is observable through al_crypto_backend(); callers must use
 * al_crypto_is_secure() as the final deployment gate. The daemon refuses to
 * start with an insecure backend unless --allow-insecure-crypto is passed.
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
 * Verifiable Random Function — REMOVED
 *
 * VRF was a development primitive for committee selection. It has been removed
 * from the deployment path because the dev backend's VRF is deterministic and
 * predictable to key holders, providing no real unpredictability. The sodium
 * backend does not provide a production VRF either. Committee selection uses a
 * hash-chain seed instead.
 * -------------------------------------------------------------------------- */

#define AL_VRF_PROOF_SIZE 80
typedef struct al_vrf_proof { al_u8 bytes[AL_VRF_PROOF_SIZE]; } al_vrf_proof;

/* --------------------------------------------------------------------------
 * Verifiable Delay Function — REMOVED
 *
 * VDF was a development primitive for epoch seed hardening. It has been removed
 * because no production VDF construction (Wesolowski/Pietrzak over class
 * groups) is implemented. The epoch seed function accepts an optional VDF
 * output but gracefully handles NULL.
 * -------------------------------------------------------------------------- */

typedef struct al_vdf_output {
    al_hash256 value;
    al_u64     iterations;
} al_vdf_output;

/* --------------------------------------------------------------------------
 * Key Exchange (for P2P transport encryption)
 *
 * X25519 key exchange: both sides generate an ephemeral keypair, exchange
 * public keys, and compute a shared secret. The shared secret is then used
 * as input to AEAD encryption for all subsequent P2P frames.
 * -------------------------------------------------------------------------- */

#define AL_KX_PUBLIC_KEY_SIZE  32u
#define AL_KX_SECRET_KEY_SIZE  32u
#define AL_KX_SHARED_KEY_SIZE  32u

typedef struct al_kx_keypair {
    al_u8 pk[AL_KX_PUBLIC_KEY_SIZE];
    al_u8 sk[AL_KX_SECRET_KEY_SIZE];
} al_kx_keypair;

/* Generate an ephemeral keypair for key exchange. */
AL_PUBLIC AL_NODISCARD al_status al_kx_keygen(al_kx_keypair *out);

/* Compute a shared secret from our secret key and their public key.
 * The shared key is deterministic: same inputs always produce the same output.
 * AL_CRYPTO_INSECURE with the dev backend (uses a toy exchange). */
AL_PUBLIC AL_NODISCARD al_status al_kx_shared(
    const al_kx_keypair *local,
    const al_u8 remote_pk[AL_KX_PUBLIC_KEY_SIZE],
    al_u8 shared_out[AL_KX_SHARED_KEY_SIZE]);

/* --------------------------------------------------------------------------
 * Authenticated Encryption with Associated Data (for P2P frames)
 *
 * AEAD using XChaCha20-Poly1305 (libsodium). Provides confidentiality and
 * integrity for P2P frame payloads. The 24-byte nonce must be unique per
 * (key, message) pair; we use a per-peer counter to guarantee uniqueness.
 * -------------------------------------------------------------------------- */

#define AL_AEAD_NONCE_SIZE    24u
#define AL_AEAD_KEY_SIZE      32u
#define AL_AEAD_TAG_SIZE      16u

/* Encrypt a frame payload in place. `nonce` must be unique for this key.
 * `ad` is additional authenticated data (the frame header, not encrypted).
 * Returns the ciphertext length = plaintext_len + AL_AEAD_TAG_SIZE. */
AL_PUBLIC AL_NODISCARD al_status al_aead_encrypt(
    const al_u8 key[AL_AEAD_KEY_SIZE],
    const al_u8 nonce[AL_AEAD_NONCE_SIZE],
    const al_u8 *ad, al_size ad_len,
    const al_u8 *plaintext, al_size plaintext_len,
    al_u8 *ciphertext_out, al_size *ciphertext_len);

/* Decrypt a frame payload. `nonce` and `ad` must match the encryption call.
 * Returns the plaintext length = ciphertext_len - AL_AEAD_TAG_SIZE. */
AL_PUBLIC AL_NODISCARD al_status al_aead_decrypt(
    const al_u8 key[AL_AEAD_KEY_SIZE],
    const al_u8 nonce[AL_AEAD_NONCE_SIZE],
    const al_u8 *ad, al_size ad_len,
    const al_u8 *ciphertext, al_size ciphertext_len,
    al_u8 *plaintext_out, al_size *plaintext_len);

/* --------------------------------------------------------------------------
 * Utilities
 * -------------------------------------------------------------------------- */

/* Overwrite a buffer, resistant to being optimised away. Use for key material
 * before it goes out of scope. */
AL_PUBLIC void al_secure_zero(void *p, al_size len);

AL_EXTERN_C_END

#endif /* ASTROLUNE_CRYPTO_H */
