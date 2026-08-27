/*
 * Development Ed25519-shaped signature backend - NOT CRYPTOGRAPHICALLY SECURE.
 *
 * Read the SECURITY STATUS block at the top of astrolune/crypto.h before
 * touching this file. In short: it implements the signature, VRF and VDF
 * signature interface with hash constructions so that every code path above it
 * runs against real logic, while the primitive remains deliberately trivial
 * and trivially forgeable. The temporary VRF/VDF live in dev_vrf_vdf.c because
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
