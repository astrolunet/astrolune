/*
 * Ed25519 signatures backed by libsodium.
 *
 * libsodium owns the curve arithmetic, constant-time scalar operations and
 * point validation. This file owns Astrolune's API rules: the stable 64-byte
 * secret-key layout, corruption checks, status mapping and the explicit
 * canonical-S consensus rule.
 *
 * VRF and VDF are still development primitives in dev_vrf_vdf.c. Consequently
 * this backend reports real Ed25519 support but does not claim that the complete
 * cryptographic stack is ready for a public network.
 */

#include "astrolune/crypto.h"

#include "internal/common.h"

#include <sodium.h>

#define AL_SK_SEED_OFFSET 0

AL_STATIC_ASSERT(crypto_sign_ed25519_PUBLICKEYBYTES == AL_PUBKEY_SIZE,
                 "libsodium public-key size must match the Astrolune ABI");
AL_STATIC_ASSERT(crypto_sign_ed25519_SECRETKEYBYTES == AL_SECKEY_SIZE,
                 "libsodium secret-key size must match the Astrolune ABI");
AL_STATIC_ASSERT(crypto_sign_ed25519_BYTES == AL_SIGNATURE_SIZE,
                 "libsodium signature size must match the Astrolune ABI");
AL_STATIC_ASSERT(crypto_sign_ed25519_SEEDBYTES == 32,
                 "Astrolune key derivation requires a 32-byte Ed25519 seed");

static al_status al_sodium_ready(void) {
    /* sodium_init is thread-safe and explicitly permits repeated calls. This
     * keeps initialization local to the library instead of adding global node
     * startup ordering to a C ABI that previously needed none. */
    return sodium_init() < 0 ? AL_ERR_UNSUPPORTED : AL_OK;
}

static const unsigned char *al_sodium_message(al_bytes message) {
    /* Some C libraries still apply nonnull annotations to zero-length buffers.
     * Supplying a stable address keeps the empty-message path warning-free. */
    static const unsigned char empty = 0u;
    return message.len == 0u ? &empty : message.data;
}

static al_bool al_message_is_valid(al_bytes message) {
    return (message.len == 0u || message.data != NULL) ? AL_TRUE : AL_FALSE;
}

static al_bool al_ed25519_scalar_is_canonical(const al_u8 scalar[32]) {
    /* Group order L in little-endian form. RFC 8032 requires S < L; accepting
     * S + L would create a second wire encoding for the same signature. */
    static const al_u8 order[32] = {
        0xedu, 0xd3u, 0xf5u, 0x5cu, 0x1au, 0x63u, 0x12u, 0x58u,
        0xd6u, 0x9cu, 0xf7u, 0xa2u, 0xdeu, 0xf9u, 0xdeu, 0x14u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x10u
    };

    for (al_size i = 32u; i-- != 0u;) {
        if (scalar[i] < order[i]) {
            return AL_TRUE;
        }
        if (scalar[i] > order[i]) {
            return AL_FALSE;
        }
    }
    return AL_FALSE;
}

al_crypto_backend_kind al_crypto_backend(void) {
    return AL_CRYPTO_BACKEND_ED25519;
}

const char *al_crypto_backend_name(void) {
    return "libsodium-ed25519+dev-vrf-vdf";
}

al_bool al_crypto_is_secure(void) {
    return AL_FALSE;
}

al_status al_keypair_from_seed(const al_u8 seed[32], al_keypair *out) {
    if (seed == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    AL_TRY(al_sodium_ready());

    if (crypto_sign_ed25519_seed_keypair(out->pk.bytes, out->sk.bytes, seed) !=
        0) {
        al_wipe(out, sizeof(*out));
        return AL_ERR_UNSUPPORTED;
    }
    return AL_OK;
}

al_status al_pubkey_from_seckey(const al_seckey *sk, al_pubkey *out) {
    if (sk == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    AL_TRY(al_sodium_ready());

    al_pubkey derived;
    al_seckey canonical;
    if (crypto_sign_ed25519_seed_keypair(
            derived.bytes, canonical.bytes, sk->bytes + AL_SK_SEED_OFFSET) != 0) {
        return AL_ERR_UNSUPPORTED;
    }

    int mismatch = sodium_memcmp(canonical.bytes, sk->bytes, AL_SECKEY_SIZE);
    al_wipe(&canonical, sizeof(canonical));
    if (mismatch != 0) {
        al_wipe(&derived, sizeof(derived));
        return AL_ERR_INVALID_ARG;
    }

    *out = derived;
    return AL_OK;
}

static al_status al_sodium_sign(const al_seckey *sk, al_bytes message,
                                al_sig *out) {
    if (sk == NULL || out == NULL || !al_message_is_valid(message)) {
        return AL_ERR_INVALID_ARG;
    }
    AL_TRY(al_sodium_ready());

    /* Validate both halves before signing. libsodium's secret key caches the
     * public key, so accepting a corrupted cache could emit an unusable or
     * identity-confused signature. */
    al_pubkey ignored;
    AL_TRY(al_pubkey_from_seckey(sk, &ignored));

    if (crypto_sign_ed25519_detached(out->bytes, NULL,
                                    al_sodium_message(message),
                                    (unsigned long long)message.len,
                                    sk->bytes) != 0) {
        al_wipe(out, sizeof(*out));
        return AL_ERR_UNSUPPORTED;
    }
    return AL_OK;
}

static al_status al_sodium_verify(const al_pubkey *pk, al_bytes message,
                                  const al_sig *sig) {
    if (pk == NULL || sig == NULL || !al_message_is_valid(message)) {
        return AL_ERR_INVALID_ARG;
    }
    AL_TRY(al_sodium_ready());

    if (!al_ed25519_scalar_is_canonical(sig->bytes + 32u)) {
        return AL_ERR_BAD_SIGNATURE;
    }

    return crypto_sign_ed25519_verify_detached(
               sig->bytes, al_sodium_message(message),
               (unsigned long long)message.len, pk->bytes) == 0
               ? AL_OK
               : AL_ERR_BAD_SIGNATURE;
}

al_status al_sign(const al_seckey *sk, al_bytes message, al_sig *out) {
    return al_sodium_sign(sk, message, out);
}

al_status al_verify(const al_pubkey *pk, al_bytes message, const al_sig *sig) {
    return al_sodium_verify(pk, message, sig);
}

al_status al_sign_hash(const al_seckey *sk, const al_hash256 *h, al_sig *out) {
    if (h == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    return al_sodium_sign(sk, al_bytes_make(h->bytes, AL_HASH_SIZE), out);
}

al_status al_verify_hash(const al_pubkey *pk, const al_hash256 *h,
                         const al_sig *sig) {
    if (h == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    return al_sodium_verify(pk, al_bytes_make(h->bytes, AL_HASH_SIZE), sig);
}
