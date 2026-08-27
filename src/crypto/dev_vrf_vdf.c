/*
 * Temporary VRF and VDF primitives - NOT CRYPTOGRAPHICALLY SECURE.
 *
 * Signature migration is intentionally independent from these primitives:
 * production Ed25519 can be exercised and checked against RFC 8032 without
 * pretending that committee selection or delayed randomness is production
 * ready. al_crypto_is_secure() therefore remains false for every current build.
 */

#include "astrolune/crypto.h"

#include "internal/common.h"

#define AL_TAG_DEV_VRF    "astrolune.dev.vrf.v1"
#define AL_TAG_DEV_VRF_PK "astrolune.dev.vrf.bind.v1"
#define AL_TAG_DEV_VDF    "astrolune.dev.vdf.v1"

#define AL_SK_SECRET_OFFSET   0
#define AL_VRF_PK_OFFSET      0
#define AL_VRF_OUTPUT_OFFSET 32
#define AL_VRF_BIND_OFFSET   64
#define AL_VRF_BIND_SIZE     16

AL_STATIC_ASSERT(AL_VRF_BIND_OFFSET + AL_VRF_BIND_SIZE == AL_VRF_PROOF_SIZE,
                 "VRF proof layout must fill exactly AL_VRF_PROOF_SIZE bytes");

static void al_dev_vrf_output(const al_pubkey *pk, al_bytes input,
                              al_hash256 *out) {
    al_hash256 tag_hash;
    al_sha256(AL_TAG_DEV_VRF, strlen(AL_TAG_DEV_VRF), &tag_hash);

    al_sha256_ctx ctx;
    al_sha256_init(&ctx);
    al_sha256_update(&ctx, tag_hash.bytes, AL_HASH_SIZE);
    al_sha256_update(&ctx, pk->bytes, AL_PUBKEY_SIZE);
    al_sha256_update(&ctx, input.data, input.len);
    al_sha256_final(&ctx, out);
}

al_status al_vrf_prove(const al_seckey *sk, al_bytes input,
                       al_vrf_proof *proof_out, al_hash256 *output_out) {
    if (sk == NULL || proof_out == NULL || output_out == NULL ||
        (input.len != 0u && input.data == NULL)) {
        return AL_ERR_INVALID_ARG;
    }

    al_pubkey pk;
    AL_TRY(al_pubkey_from_seckey(sk, &pk));

    al_hash256 output;
    al_dev_vrf_output(&pk, input, &output);

    al_hash256 bind;
    al_hmac_ctx ctx;
    al_hmac_init(&ctx, sk->bytes + AL_SK_SECRET_OFFSET, 32u);
    al_hmac_update(&ctx, AL_TAG_DEV_VRF_PK, strlen(AL_TAG_DEV_VRF_PK));
    al_hmac_update(&ctx, input.data, input.len);
    al_hmac_final(&ctx, &bind);

    al_memcpy(proof_out->bytes + AL_VRF_PK_OFFSET, pk.bytes, AL_PUBKEY_SIZE);
    al_memcpy(proof_out->bytes + AL_VRF_OUTPUT_OFFSET, output.bytes,
              AL_HASH_SIZE);
    al_memcpy(proof_out->bytes + AL_VRF_BIND_OFFSET, bind.bytes,
              AL_VRF_BIND_SIZE);

    *output_out = output;
    al_wipe(&bind, sizeof(bind));
    return AL_OK;
}

al_status al_vrf_verify(const al_pubkey *pk, al_bytes input,
                        const al_vrf_proof *proof, al_hash256 *output_out) {
    if (pk == NULL || proof == NULL || output_out == NULL ||
        (input.len != 0u && input.data == NULL)) {
        return AL_ERR_INVALID_ARG;
    }

    /* A mismatched embedded key belongs to another identity and is rejected
     * before the claimed output is recomputed. */
    if (!al_bytes_eq_ct(al_bytes_make(pk->bytes, AL_PUBKEY_SIZE),
                        al_bytes_make(proof->bytes + AL_VRF_PK_OFFSET,
                                      AL_PUBKEY_SIZE))) {
        return AL_ERR_BAD_PROOF;
    }

    al_hash256 expected;
    al_dev_vrf_output(pk, input, &expected);
    if (!al_bytes_eq_ct(al_bytes_make(expected.bytes, AL_HASH_SIZE),
                        al_bytes_make(proof->bytes + AL_VRF_OUTPUT_OFFSET,
                                      AL_HASH_SIZE))) {
        return AL_ERR_BAD_PROOF;
    }

    *output_out = expected;
    return AL_OK;
}

al_i64 al_vrf_output_to_unit(const al_hash256 *output) {
    /* The top 32 digest bits are exactly the fractional part of a Q32.32 value.
     * This avoids division and is deterministic on every architecture. */
    return (al_i64)(al_u64)al_load_be32(output->bytes);
}

void al_vdf_eval(const al_hash256 *input, al_u64 iterations,
                 al_vdf_output *out) {
    /* The tag digest is invariant across iterations; computing it outside the
     * loop halves the hashing setup cost of this deliberately slow primitive. */
    al_hash256 tag_hash;
    al_sha256(AL_TAG_DEV_VDF, strlen(AL_TAG_DEV_VDF), &tag_hash);

    al_hash256 h = *input;
    for (al_u64 i = 0u; i < iterations; ++i) {
        al_u8 counter[8];
        al_store_le64(counter, i);

        al_sha256_ctx ctx;
        al_sha256_init(&ctx);
        al_sha256_update(&ctx, tag_hash.bytes, AL_HASH_SIZE);
        al_sha256_update(&ctx, h.bytes, AL_HASH_SIZE);
        al_sha256_update(&ctx, counter, sizeof(counter));
        al_sha256_final(&ctx, &h);
    }
    out->value      = h;
    out->iterations = iterations;
}

al_status al_vdf_verify(const al_hash256 *input, const al_vdf_output *output) {
    if (input == NULL || output == NULL) {
        return AL_ERR_INVALID_ARG;
    }

    al_vdf_output recomputed;
    al_vdf_eval(input, output->iterations, &recomputed);
    return al_hash_eq(&recomputed.value, &output->value) ? AL_OK
                                                         : AL_ERR_BAD_PROOF;
}
