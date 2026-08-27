/*
 * HMAC-SHA256 (RFC 2104) and HKDF (RFC 5869).
 *
 * HKDF is what turns a single seed into the several independent keys a node
 * needs. Deriving them by hashing the seed with different suffixes would work
 * but is exactly the kind of ad-hoc construction that gets subtly reused across
 * domains; HKDF has an explicit info parameter for the purpose and a published
 * analysis behind it.
 */

#include "astrolune/hash.h"

#include "internal/common.h"

#define AL_HMAC_IPAD 0x36u
#define AL_HMAC_OPAD 0x5cu

void al_hmac_init(al_hmac_ctx *ctx, const void *key, al_size key_len) {
    al_u8 block[AL_SHA256_BLOCK_SIZE];
    al_memzero(block, sizeof(block));

    if (key_len > AL_SHA256_BLOCK_SIZE) {
        /* RFC 2104: a key longer than the block size is replaced by its own
         * digest. Note this makes long keys collide with their digests, which is
         * inherent to HMAC and not a defect here. */
        al_hash256 key_hash;
        al_sha256(key, key_len, &key_hash);
        al_memcpy(block, key_hash.bytes, AL_HASH_SIZE);
        al_wipe(&key_hash, sizeof(key_hash));
    } else {
        al_memcpy(block, key, key_len);
    }

    al_u8 pad[AL_SHA256_BLOCK_SIZE];

    for (al_size i = 0u; i < AL_SHA256_BLOCK_SIZE; ++i) {
        pad[i] = (al_u8)(block[i] ^ AL_HMAC_IPAD);
    }
    al_sha256_init(&ctx->inner);
    al_sha256_update(&ctx->inner, pad, sizeof(pad));

    for (al_size i = 0u; i < AL_SHA256_BLOCK_SIZE; ++i) {
        pad[i] = (al_u8)(block[i] ^ AL_HMAC_OPAD);
    }
    al_sha256_init(&ctx->outer);
    al_sha256_update(&ctx->outer, pad, sizeof(pad));

    al_wipe(pad, sizeof(pad));
    al_wipe(block, sizeof(block));
}

void al_hmac_update(al_hmac_ctx *ctx, const void *data, al_size len) {
    al_sha256_update(&ctx->inner, data, len);
}

void al_hmac_final(al_hmac_ctx *ctx, al_hash256 *out) {
    al_hash256 inner_digest;
    al_sha256_final(&ctx->inner, &inner_digest);
    al_sha256_update(&ctx->outer, inner_digest.bytes, AL_HASH_SIZE);
    al_sha256_final(&ctx->outer, out);
    al_wipe(&inner_digest, sizeof(inner_digest));
}

void al_hmac_sha256(const void *key, al_size key_len,
                    const void *data, al_size len, al_hash256 *out) {
    al_hmac_ctx ctx;
    al_hmac_init(&ctx, key, key_len);
    al_hmac_update(&ctx, data, len);
    al_hmac_final(&ctx, out);
}

/* --------------------------------------------------------------------------
 * HKDF
 * -------------------------------------------------------------------------- */

void al_hkdf_extract(const void *salt, al_size salt_len,
                     const void *ikm, al_size ikm_len, al_hash256 *prk_out) {
    static const al_u8 zero_salt[AL_HASH_SIZE] = {0};
    if (salt == NULL || salt_len == 0u) {
        /* RFC 5869 section 2.2: absent salt is a string of HashLen zeros. */
        salt     = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    al_hmac_sha256(salt, salt_len, ikm, ikm_len, prk_out);
}

al_status al_hkdf_expand(const al_hash256 *prk, const void *info,
                         al_size info_len, void *out, al_size out_len) {
    if (prk == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    /* The counter is a single byte, so 255 blocks is the hard ceiling. */
    if (out_len > 255u * AL_HASH_SIZE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (out_len == 0u) {
        return AL_OK;
    }

    al_u8     *dst       = (al_u8 *)out;
    al_size    produced  = 0u;
    al_hash256 t         = al_hash_zero();
    al_bool    have_prev = AL_FALSE;
    al_u8      counter   = 1u;

    while (produced < out_len) {
        al_hmac_ctx ctx;
        al_hmac_init(&ctx, prk->bytes, AL_HASH_SIZE);
        if (have_prev) {
            al_hmac_update(&ctx, t.bytes, AL_HASH_SIZE);
        }
        al_hmac_update(&ctx, info, info_len);
        al_hmac_update(&ctx, &counter, 1u);
        al_hmac_final(&ctx, &t);
        have_prev = AL_TRUE;

        al_size chunk = out_len - produced;
        if (chunk > AL_HASH_SIZE) {
            chunk = AL_HASH_SIZE;
        }
        al_memcpy(dst + produced, t.bytes, chunk);
        produced += chunk;
        ++counter;
    }

    al_wipe(&t, sizeof(t));
    return AL_OK;
}
