/*
 * Addresses and the backend-independent parts of the key API.
 *
 * An address is the tagged SHA-256 of a public key, used at full 32-byte width.
 * See astrolune/crypto.h for why it is not truncated to 20 bytes.
 */

#include "astrolune/crypto.h"

#include "internal/common.h"

void al_address_from_pubkey(const al_pubkey *pk, al_address *out) {
    al_hash256 h;
    al_hash_tagged(AL_TAG_ADDRESS, pk->bytes, AL_PUBKEY_SIZE, &h);
    al_memcpy(out->bytes, h.bytes, AL_ADDRESS_SIZE);
}

al_address al_address_zero(void) {
    al_address a;
    al_memzero(a.bytes, AL_ADDRESS_SIZE);
    return a;
}

al_bool al_address_eq(const al_address *a, const al_address *b) {
    return (memcmp(a->bytes, b->bytes, AL_ADDRESS_SIZE) == 0) ? AL_TRUE
                                                              : AL_FALSE;
}

al_bool al_address_is_zero(const al_address *a) {
    al_u8 acc = 0u;
    for (al_size i = 0u; i < AL_ADDRESS_SIZE; ++i) {
        acc |= a->bytes[i];
    }
    return (acc == 0u) ? AL_TRUE : AL_FALSE;
}

int al_address_cmp(const al_address *a, const al_address *b) {
    /* Normalised sign, like al_hash_cmp: address ordering is consensus-visible
     * wherever a set of accounts has to be serialised. */
    int c = memcmp(a->bytes, b->bytes, AL_ADDRESS_SIZE);
    return (c < 0) ? -1 : ((c > 0) ? 1 : 0);
}

void al_address_for_contract(const al_address *deployer, al_nonce nonce,
                             const al_hash256 *code_hash, al_address *out) {
    /*
     * Committing to the deployer, their nonce and the code hash makes the
     * address predictable before the deploy transaction is mined, and unique
     * without a global counter that would serialise deployments.
     *
     * The nonce is encoded little-endian and fixed-width, not as a varint: a
     * variable-length field inside a hash preimage is a place where two distinct
     * (deployer, nonce) pairs could produce the same bytes.
     */
    al_u8 nonce_le[8];
    al_store_le64(nonce_le, nonce);

    al_sha256_ctx ctx;
    al_hash256 tag_hash;
    al_sha256(AL_TAG_CONTRACT, strlen(AL_TAG_CONTRACT), &tag_hash);
    al_sha256_init(&ctx);
    al_sha256_update(&ctx, tag_hash.bytes, AL_HASH_SIZE);
    al_sha256_update(&ctx, deployer->bytes, AL_ADDRESS_SIZE);
    al_sha256_update(&ctx, nonce_le, sizeof(nonce_le));
    al_sha256_update(&ctx, code_hash->bytes, AL_HASH_SIZE);

    al_hash256 h;
    al_sha256_final(&ctx, &h);
    al_memcpy(out->bytes, h.bytes, AL_ADDRESS_SIZE);
}

void al_secure_zero(void *p, al_size len) {
    al_wipe(p, len);
}
