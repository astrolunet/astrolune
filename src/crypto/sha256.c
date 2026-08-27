/*
 * SHA-256 (FIPS 180-4) and the domain-separated hashing built on top of it.
 *
 * A straightforward, constant-time-by-construction implementation: no data-
 * dependent branches and no table lookups indexed by secret data, because this
 * is also the primitive under HMAC and the key derivation.
 *
 * Verified against the NIST published vectors in tests/c/test_hash.c.
 */

#include "astrolune/hash.h"

#include "internal/common.h"

/* --------------------------------------------------------------------------
 * SHA-256 core
 * -------------------------------------------------------------------------- */

/* First 32 bits of the fractional parts of the cube roots of the first 64
 * primes (FIPS 180-4 section 4.2.2). */
static const al_u32 al_sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define AL_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define AL_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define AL_BSIG0(x)     (al_rotr32(x, 2) ^ al_rotr32(x, 13) ^ al_rotr32(x, 22))
#define AL_BSIG1(x)     (al_rotr32(x, 6) ^ al_rotr32(x, 11) ^ al_rotr32(x, 25))
#define AL_SSIG0(x)     (al_rotr32(x, 7) ^ al_rotr32(x, 18) ^ ((x) >> 3))
#define AL_SSIG1(x)     (al_rotr32(x, 17) ^ al_rotr32(x, 19) ^ ((x) >> 10))

static void al_sha256_compress(al_u32 state[8], const al_u8 block[64]) {
    al_u32 w[64];

    /* SHA-256 is specified big-endian; al_load_be32 makes that explicit rather
     * than depending on the host's byte order. */
    for (unsigned i = 0u; i < 16u; ++i) {
        w[i] = al_load_be32(block + i * 4u);
    }
    for (unsigned i = 16u; i < 64u; ++i) {
        w[i] = AL_SSIG1(w[i - 2]) + w[i - 7] + AL_SSIG0(w[i - 15]) + w[i - 16];
    }

    al_u32 a = state[0], b = state[1], c = state[2], d = state[3];
    al_u32 e = state[4], f = state[5], g = state[6], h = state[7];

    for (unsigned i = 0u; i < 64u; ++i) {
        al_u32 t1 = h + AL_BSIG1(e) + AL_CH(e, f, g) + al_sha256_k[i] + w[i];
        al_u32 t2 = AL_BSIG0(a) + AL_MAJ(a, b, c);
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    /* w holds message-derived data; for HMAC over key material that is worth
     * clearing, and the compiler cannot elide a call through a volatile-backed
     * helper. */
    al_memzero(w, sizeof(w));
}

void al_sha256_init(al_sha256_ctx *ctx) {
    /* First 32 bits of the fractional parts of the square roots of the first
     * eight primes. */
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bit_len    = 0u;
    ctx->buffer_len = 0u;
    al_memzero(ctx->buffer, sizeof(ctx->buffer));
}

void al_sha256_update(al_sha256_ctx *ctx, const void *data, al_size len) {
    if (len == 0u || data == NULL) {
        return;
    }
    const al_u8 *p = (const al_u8 *)data;

    ctx->bit_len += (al_u64)len * 8u;

    /* Top off a partially filled buffer first. */
    if (ctx->buffer_len != 0u) {
        al_size want = AL_SHA256_BLOCK_SIZE - ctx->buffer_len;
        al_size take = (len < want) ? len : want;
        al_memcpy(ctx->buffer + ctx->buffer_len, p, take);
        ctx->buffer_len += take;
        p   += take;
        len -= take;
        if (ctx->buffer_len < AL_SHA256_BLOCK_SIZE) {
            return;
        }
        al_sha256_compress(ctx->state, ctx->buffer);
        ctx->buffer_len = 0u;
    }

    /* Then whole blocks straight from the input, no copy. */
    while (len >= AL_SHA256_BLOCK_SIZE) {
        al_sha256_compress(ctx->state, p);
        p   += AL_SHA256_BLOCK_SIZE;
        len -= AL_SHA256_BLOCK_SIZE;
    }

    if (len != 0u) {
        al_memcpy(ctx->buffer, p, len);
        ctx->buffer_len = len;
    }
}

void al_sha256_final(al_sha256_ctx *ctx, al_hash256 *out) {
    al_u64 bit_len = ctx->bit_len;

    /* Padding: 0x80, then zeros, then the 64-bit big-endian bit length. */
    ctx->buffer[ctx->buffer_len++] = 0x80u;

    if (ctx->buffer_len > AL_SHA256_BLOCK_SIZE - 8u) {
        al_memzero(ctx->buffer + ctx->buffer_len,
                   AL_SHA256_BLOCK_SIZE - ctx->buffer_len);
        al_sha256_compress(ctx->state, ctx->buffer);
        ctx->buffer_len = 0u;
    }
    al_memzero(ctx->buffer + ctx->buffer_len,
               AL_SHA256_BLOCK_SIZE - 8u - ctx->buffer_len);
    al_store_be64(ctx->buffer + AL_SHA256_BLOCK_SIZE - 8u, bit_len);
    al_sha256_compress(ctx->state, ctx->buffer);

    for (unsigned i = 0u; i < 8u; ++i) {
        al_store_be32(out->bytes + i * 4u, ctx->state[i]);
    }

    /* The context may hold the tail of a secret; leaving it on the stack for a
     * later frame to observe is avoidable, so avoid it. */
    al_memzero(ctx, sizeof(*ctx));
}

void al_sha256(const void *data, al_size len, al_hash256 *out) {
    al_sha256_ctx ctx;
    al_sha256_init(&ctx);
    al_sha256_update(&ctx, data, len);
    al_sha256_final(&ctx, out);
}

void al_sha256_bytes(al_bytes data, al_hash256 *out) {
    al_sha256(data.data, data.len, out);
}

void al_sha256d(const void *data, al_size len, al_hash256 *out) {
    al_hash256 first;
    al_sha256(data, len, &first);
    al_sha256(first.bytes, AL_HASH_SIZE, out);
}

/* --------------------------------------------------------------------------
 * Domain-separated hashing
 * -------------------------------------------------------------------------- */

/*
 * The tag is absorbed as its 32-byte digest, not as raw text.
 *
 * A raw variable-length prefix would let two different (tag, data) pairs
 * concatenate to the same byte string - "astrolune.tx" || "ab" and
 * "astrolune.txa" || "b" - so the domain separation would not actually
 * separate. A fixed-width prefix cannot shift the boundary.
 */
static void al_hash_tag_prefix(al_sha256_ctx *ctx, const char *tag) {
    al_hash256 tag_hash;
    al_sha256(tag, (tag != NULL) ? strlen(tag) : 0u, &tag_hash);
    al_sha256_init(ctx);
    al_sha256_update(ctx, tag_hash.bytes, AL_HASH_SIZE);
}

void al_hash_tagged(const char *tag, const void *data, al_size len,
                    al_hash256 *out) {
    al_sha256_ctx ctx;
    al_hash_tag_prefix(&ctx, tag);
    al_sha256_update(&ctx, data, len);
    al_sha256_final(&ctx, out);
}

void al_hash_tagged_bytes(const char *tag, al_bytes data, al_hash256 *out) {
    al_hash_tagged(tag, data.data, data.len, out);
}

void al_hash_tagged_pair(const char *tag, const al_hash256 *left,
                         const al_hash256 *right, al_hash256 *out) {
    al_sha256_ctx ctx;
    al_hash_tag_prefix(&ctx, tag);
    al_sha256_update(&ctx, left->bytes, AL_HASH_SIZE);
    al_sha256_update(&ctx, right->bytes, AL_HASH_SIZE);
    al_sha256_final(&ctx, out);
}

/* --------------------------------------------------------------------------
 * Hash utilities
 * -------------------------------------------------------------------------- */

al_hash256 al_hash_zero(void) {
    al_hash256 h;
    al_memzero(h.bytes, AL_HASH_SIZE);
    return h;
}

al_bool al_hash_eq(const al_hash256 *a, const al_hash256 *b) {
    /* Digests are public values, so a plain compare is fine here; the
     * constant-time comparison in bytes.h is for secrets and MACs. */
    return (memcmp(a->bytes, b->bytes, AL_HASH_SIZE) == 0) ? AL_TRUE : AL_FALSE;
}

al_bool al_hash_is_zero(const al_hash256 *h) {
    al_u8 acc = 0u;
    for (al_size i = 0u; i < AL_HASH_SIZE; ++i) {
        acc |= h->bytes[i];
    }
    return (acc == 0u) ? AL_TRUE : AL_FALSE;
}

int al_hash_cmp(const al_hash256 *a, const al_hash256 *b) {
    /* memcmp's sign is unspecified beyond being consistent; normalise it so the
     * ordering is identical on every platform. Sets sorted by this comparator
     * are consensus-visible. */
    int c = memcmp(a->bytes, b->bytes, AL_HASH_SIZE);
    return (c < 0) ? -1 : ((c > 0) ? 1 : 0);
}

al_bool al_hash_bit(const al_hash256 *h, al_size i) {
    if (i >= AL_HASH_SIZE * 8u) {
        return AL_FALSE;
    }
    al_u8 byte = h->bytes[i / 8u];
    /* Bit 0 is the most significant bit of byte 0, so that descending a tree by
     * increasing bit index walks the digest left to right. */
    unsigned shift = 7u - (unsigned)(i % 8u);
    return ((byte >> shift) & 1u) ? AL_TRUE : AL_FALSE;
}
