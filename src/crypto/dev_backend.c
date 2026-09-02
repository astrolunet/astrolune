/*
 * Development Ed25519-shaped signature backend - NOT CRYPTOGRAPHICALLY SECURE.
 *
 * Read the SECURITY STATUS block at the top of astrolune/crypto.h before
 * touching this file. In short: it implements the signature, VRF and VDF
 * signature interface with hash constructions so that every code path above it
 * runs against real logic, while the primitive remains deliberately trivial
 * and trivially forgeable. VRF/VDF have been removed from the deployment
 * path (see crypto.h).
 * they remain in use while the signature backend is migrated independently.
 *
 * What it actually does
 * ------------------------------------------------------------------------
 * A "signature" is two halves:
 *
 *   sig[0:32]   H(tag_sig || pk || message)      - checked by al_verify
 *   sig[32:64]  H(tag_bind || sk_scalar || msg)  - not checked, see below
 *
 * The first half is computable from public data, which is precisely why this is
 * insecure: anyone can forge it. The second half is computable only by the key
 * holder, and it is carried but never verified.
 *
 * That looks pointless and is not. The signing path must genuinely require the
 * secret key, or the layers above would compile and pass their tests while
 * silently never using a key at all - and the day a real Ed25519 backend is
 * dropped in, every one of those call sites would break at once. Carrying the
 * binding half keeps the API honest about who can sign, keeps the 64-byte wire
 * format identical to Ed25519's, and makes the swap a change confined to this
 * file.
 *
 * This translation unit is selected only for ASTROLUNE_CRYPTO_BACKEND=dev.
 * Nothing outside core/crypto/ depends on the construction.
 */

#include "astrolune/crypto.h"

#include <stdlib.h>

#include "internal/common.h"

/*
 * Backend-internal domain tags.
 *
 * Deliberately not in astrolune/hash.h's AL_TAG_* list: that list enumerates the
 * protocol's hashed *structures*, and these are an implementation detail of a
 * component that is going to be deleted. The "dev" segment also guarantees they
 * can never collide with a protocol tag.
 */
#define AL_TAG_DEV_SECKEY "astrolune.dev.seckey.v1"
#define AL_TAG_DEV_PUBKEY "astrolune.dev.pubkey.v1"
#define AL_TAG_DEV_SIG    "astrolune.dev.sig.v1"
#define AL_TAG_DEV_BIND   "astrolune.dev.bind.v1"

/*
 * Secret key layout, matching Ed25519's so that the wire format and the storage
 * format do not change when the backend does:
 *
 *   sk[0:32]   the secret scalar derived from the seed
 *   sk[32:64]  the corresponding public key, cached
 */
#define AL_SK_SCALAR_OFFSET 0
#define AL_SK_PUBKEY_OFFSET 32

/* --------------------------------------------------------------------------
 * Backend identification
 * -------------------------------------------------------------------------- */

al_crypto_backend_kind al_crypto_backend(void) {
    return AL_CRYPTO_BACKEND_DEV;
}

const char *al_crypto_backend_name(void) {
    return "dev-insecure";
}

al_bool al_crypto_is_secure(void) {
    return AL_FALSE;
}

/* --------------------------------------------------------------------------
 * Keys
 * -------------------------------------------------------------------------- */

/* Public key for a secret scalar. The only place the mapping is defined. */
static void al_dev_pubkey_of_scalar(const al_u8 scalar[32], al_pubkey *out) {
    al_hash256 h;
    al_hash_tagged(AL_TAG_DEV_PUBKEY, scalar, 32u, &h);
    al_memcpy(out->bytes, h.bytes, AL_PUBKEY_SIZE);
}

al_status al_keypair_from_seed(const al_u8 seed[32], al_keypair *out) {
    if (seed == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }

    /* The seed is stretched through the tagged hash rather than used directly,
     * so that a caller who supplies a low-entropy or structured seed does not
     * end up with a secret key that has the same structure. */
    al_hash256 scalar;
    al_hash_tagged(AL_TAG_DEV_SECKEY, seed, 32u, &scalar);

    al_memzero(out->sk.bytes, AL_SECKEY_SIZE);
    al_memcpy(out->sk.bytes + AL_SK_SCALAR_OFFSET, scalar.bytes, 32u);

    al_dev_pubkey_of_scalar(out->sk.bytes + AL_SK_SCALAR_OFFSET, &out->pk);
    al_memcpy(out->sk.bytes + AL_SK_PUBKEY_OFFSET, out->pk.bytes,
              AL_PUBKEY_SIZE);

    al_wipe(&scalar, sizeof(scalar));
    return AL_OK;
}

al_status al_pubkey_from_seckey(const al_seckey *sk, al_pubkey *out) {
    if (sk == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }

    /* Recompute rather than trust the cached copy, and reject a mismatch. A
     * secret key whose two halves disagree is either corrupt storage or an
     * attempt to make one signature verify under two identities. */
    al_pubkey derived;
    al_dev_pubkey_of_scalar(sk->bytes + AL_SK_SCALAR_OFFSET, &derived);

    if (memcmp(derived.bytes, sk->bytes + AL_SK_PUBKEY_OFFSET,
               AL_PUBKEY_SIZE) != 0) {
        return AL_ERR_INVALID_ARG;
    }
    *out = derived;
    return AL_OK;
}

/* --------------------------------------------------------------------------
 * Signatures
 * -------------------------------------------------------------------------- */

/* The publicly recomputable half. */
static void al_dev_sig_public(const al_pubkey *pk, const void *msg,
                              al_size msg_len, al_u8 out[32]) {
    al_hash256 tag_hash, h;
    al_sha256(AL_TAG_DEV_SIG, strlen(AL_TAG_DEV_SIG), &tag_hash);

    al_sha256_ctx ctx;
    al_sha256_init(&ctx);
    al_sha256_update(&ctx, tag_hash.bytes, AL_HASH_SIZE);
    al_sha256_update(&ctx, pk->bytes, AL_PUBKEY_SIZE);
    al_sha256_update(&ctx, msg, msg_len);
    al_sha256_final(&ctx, &h);

    al_memcpy(out, h.bytes, 32u);
}

/* The half that requires the secret scalar. Carried, never checked. */
static void al_dev_sig_binding(const al_u8 scalar[32], const void *msg,
                               al_size msg_len, al_u8 out[32]) {
    al_hash256 h;
    al_hmac_ctx ctx;
    al_hmac_init(&ctx, scalar, 32u);
    al_hmac_update(&ctx, AL_TAG_DEV_BIND, strlen(AL_TAG_DEV_BIND));
    al_hmac_update(&ctx, msg, msg_len);
    al_hmac_final(&ctx, &h);
    al_memcpy(out, h.bytes, 32u);
    al_wipe(&h, sizeof(h));
}

static al_status al_dev_sign(const al_seckey *sk, const void *msg,
                             al_size msg_len, al_sig *out) {
    if (sk == NULL || out == NULL || (msg_len != 0u && msg == NULL)) {
        return AL_ERR_INVALID_ARG;
    }

    al_pubkey pk;
    AL_TRY(al_pubkey_from_seckey(sk, &pk));

    al_dev_sig_public(&pk, msg, msg_len, out->bytes);
    al_dev_sig_binding(sk->bytes + AL_SK_SCALAR_OFFSET, msg, msg_len,
                       out->bytes + 32);
    return AL_OK;
}

static al_status al_dev_verify(const al_pubkey *pk, const void *msg,
                               al_size msg_len, const al_sig *sig) {
    if (pk == NULL || sig == NULL || (msg_len != 0u && msg == NULL)) {
        return AL_ERR_INVALID_ARG;
    }

    al_u8 expected[32];
    al_dev_sig_public(pk, msg, msg_len, expected);

    /* Constant-time compare. The value is public here, so this buys nothing
     * today - but a real backend's verifier compares secret-adjacent data, and
     * the call sites should not have to change when it lands. */
    al_bool eq = al_bytes_eq_ct(al_bytes_make(expected, 32u),
                                al_bytes_make(sig->bytes, 32u));
    return eq ? AL_OK : AL_ERR_BAD_SIGNATURE;
}

al_status al_sign(const al_seckey *sk, al_bytes message, al_sig *out) {
    return al_dev_sign(sk, message.data, message.len, out);
}

al_status al_verify(const al_pubkey *pk, al_bytes message, const al_sig *sig) {
    return al_dev_verify(pk, message.data, message.len, sig);
}

al_status al_sign_hash(const al_seckey *sk, const al_hash256 *h, al_sig *out) {
    if (h == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    return al_dev_sign(sk, h->bytes, AL_HASH_SIZE, out);
}

al_status al_verify_hash(const al_pubkey *pk, const al_hash256 *h,
                         const al_sig *sig) {
    if (h == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    return al_dev_verify(pk, h->bytes, AL_HASH_SIZE, sig);
}

/* --------------------------------------------------------------------------
 * Key Exchange (toy: hash-based, NOT secure)
 * -------------------------------------------------------------------------- */

/* Forward declaration - dev backend only, not in public headers. */
static al_status dev_random_bytes(al_u8 *buf, al_size len) {
    if (buf == NULL || len == 0u) return AL_ERR_INVALID_ARG;
    for (al_size i = 0u; i < len; ++i) {
        buf[i] = (al_u8)(rand() & 0xFF);
    }
    return AL_OK;
}

al_status al_kx_keygen(al_kx_keypair *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    dev_random_bytes(out->sk, AL_KX_SECRET_KEY_SIZE);
    al_hash256 h;
    al_hash_tagged("astrolune.dev.kx.pk", out->sk, AL_KX_SECRET_KEY_SIZE, &h);
    al_memcpy(out->pk, h.bytes, AL_KX_PUBLIC_KEY_SIZE);
    al_wipe(&h, sizeof(h));
    return AL_OK;
}

al_status al_kx_shared(const al_kx_keypair *local,
                        const al_u8 remote_pk[AL_KX_PUBLIC_KEY_SIZE],
                        al_u8 shared_out[AL_KX_SHARED_KEY_SIZE]) {
    if (local == NULL || remote_pk == NULL || shared_out == NULL)
        return AL_ERR_INVALID_ARG;
    al_hmac_ctx ctx;
    al_hmac_init(&ctx, local->sk, AL_KX_SECRET_KEY_SIZE);
    al_hmac_update(&ctx, "astrolune.dev.kx.shared", 24u);
    al_hmac_update(&ctx, local->pk, AL_KX_PUBLIC_KEY_SIZE);
    al_hmac_update(&ctx, remote_pk, AL_KX_PUBLIC_KEY_SIZE);
    al_hash256 h;
    al_hmac_final(&ctx, &h);
    al_memcpy(shared_out, h.bytes, AL_KX_SHARED_KEY_SIZE);
    al_wipe(&h, sizeof(h));
    return AL_OK;
}

/* --------------------------------------------------------------------------
 * AEAD (toy: HMAC-based, NOT secure — encrypt-then-MAC with truncated tag)
 * -------------------------------------------------------------------------- */

al_status al_aead_encrypt(const al_u8 key[AL_AEAD_KEY_SIZE],
                           const al_u8 nonce[AL_AEAD_NONCE_SIZE],
                           const al_u8 *ad, al_size ad_len,
                           const al_u8 *plaintext, al_size plaintext_len,
                           al_u8 *ciphertext_out, al_size *ciphertext_len) {
    if (key == NULL || nonce == NULL || ciphertext_out == NULL ||
        ciphertext_len == NULL)
        return AL_ERR_INVALID_ARG;
    /* XOR plaintext with keystream derived from HMAC(key, nonce). */
    al_hmac_ctx ctx;
    al_hmac_init(&ctx, key, AL_AEAD_KEY_SIZE);
    al_hmac_update(&ctx, nonce, AL_AEAD_NONCE_SIZE);
    al_hash256 stream_seed;
    al_hmac_final(&ctx, &stream_seed);
    for (al_size i = 0u; i < plaintext_len; ++i) {
        ciphertext_out[i] = plaintext[i] ^ stream_seed.bytes[i % AL_HASH_SIZE];
    }
    /* MAC over AD + ciphertext. */
    al_hmac_init(&ctx, key, AL_AEAD_KEY_SIZE);
    if (ad != NULL && ad_len > 0u)
        al_hmac_update(&ctx, ad, ad_len);
    al_hmac_update(&ctx, ciphertext_out, plaintext_len);
    al_hash256 mac;
    al_hmac_final(&ctx, &mac);
    al_memcpy(ciphertext_out + plaintext_len, mac.bytes, AL_AEAD_TAG_SIZE);
    *ciphertext_len = plaintext_len + AL_AEAD_TAG_SIZE;
    al_wipe(&stream_seed, sizeof(stream_seed));
    al_wipe(&mac, sizeof(mac));
    return AL_OK;
}

al_status al_aead_decrypt(const al_u8 key[AL_AEAD_KEY_SIZE],
                           const al_u8 nonce[AL_AEAD_NONCE_SIZE],
                           const al_u8 *ad, al_size ad_len,
                           const al_u8 *ciphertext, al_size ciphertext_len,
                           al_u8 *plaintext_out, al_size *plaintext_len) {
    if (key == NULL || nonce == NULL || plaintext_out == NULL ||
        plaintext_len == NULL)
        return AL_ERR_INVALID_ARG;
    if (ciphertext_len < AL_AEAD_TAG_SIZE)
        return AL_ERR_TRUNCATED;
    al_size msg_len = ciphertext_len - AL_AEAD_TAG_SIZE;
    /* Verify MAC first. */
    al_hmac_ctx ctx;
    al_hmac_init(&ctx, key, AL_AEAD_KEY_SIZE);
    if (ad != NULL && ad_len > 0u)
        al_hmac_update(&ctx, ad, ad_len);
    al_hmac_update(&ctx, ciphertext, msg_len);
    al_hash256 mac;
    al_hmac_final(&ctx, &mac);
    if (memcmp(mac.bytes, ciphertext + msg_len, AL_AEAD_TAG_SIZE) != 0) {
        al_wipe(&mac, sizeof(mac));
        return AL_ERR_BAD_SIGNATURE;
    }
    /* Decrypt with keystream. */
    al_hmac_init(&ctx, key, AL_AEAD_KEY_SIZE);
    al_hmac_update(&ctx, nonce, AL_AEAD_NONCE_SIZE);
    al_hash256 stream_seed;
    al_hmac_final(&ctx, &stream_seed);
    for (al_size i = 0u; i < msg_len; ++i) {
        plaintext_out[i] = ciphertext[i] ^ stream_seed.bytes[i % AL_HASH_SIZE];
    }
    *plaintext_len = msg_len;
    al_wipe(&stream_seed, sizeof(stream_seed));
    al_wipe(&mac, sizeof(mac));
    return AL_OK;
}
