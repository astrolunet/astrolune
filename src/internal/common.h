/*
 * Internal helpers shared across the core. Not installed, not part of the ABI.
 *
 * Anything that would be unsafe or unstable to expose to the C++ tooling lives
 * here: compiler intrinsics, atomics, and the debug assertion macro.
 */

#ifndef ASTROLUNE_INTERNAL_COMMON_H
#define ASTROLUNE_INTERNAL_COMMON_H

#include "astrolune/base.h"

#include <string.h>

#if defined(AL_COMPILER_MSVC)
/* _BitScanReverse64 and _umul128 are used below and must be declared first. */
#  include <intrin.h>
#endif

/* --------------------------------------------------------------------------
 * Assertions
 *
 * AL_ASSERT documents an invariant the code relies on and is compiled out of
 * release builds. It is never used to validate untrusted input - a malformed
 * block from the network must produce a status code, not a crash, so those
 * checks are plain `if` statements that stay in every build.
 * -------------------------------------------------------------------------- */

#if defined(NDEBUG)
#  define AL_ASSERT(cond) ((void)0)
#else
#  include <assert.h>
#  define AL_ASSERT(cond) assert(cond)
#endif

/* --------------------------------------------------------------------------
 * Byte order
 *
 * Astrolune serialises little-endian everywhere. These helpers make the
 * conversion explicit at every boundary instead of relying on the host's
 * layout, so the encoding is identical on a big-endian machine.
 * -------------------------------------------------------------------------- */

static AL_FORCEINLINE al_u16 al_load_le16(const al_u8 *p) {
    return (al_u16)((al_u16)p[0] | ((al_u16)p[1] << 8));
}

static AL_FORCEINLINE al_u32 al_load_le32(const al_u8 *p) {
    return (al_u32)p[0] | ((al_u32)p[1] << 8) | ((al_u32)p[2] << 16) |
           ((al_u32)p[3] << 24);
}

static AL_FORCEINLINE al_u64 al_load_le64(const al_u8 *p) {
    return (al_u64)al_load_le32(p) | ((al_u64)al_load_le32(p + 4) << 32);
}

static AL_FORCEINLINE al_u32 al_load_be32(const al_u8 *p) {
    return ((al_u32)p[0] << 24) | ((al_u32)p[1] << 16) | ((al_u32)p[2] << 8) |
           (al_u32)p[3];
}

static AL_FORCEINLINE void al_store_le16(al_u8 *p, al_u16 v) {
    p[0] = (al_u8)(v & 0xffu);
    p[1] = (al_u8)((v >> 8) & 0xffu);
}

static AL_FORCEINLINE void al_store_le32(al_u8 *p, al_u32 v) {
    p[0] = (al_u8)(v & 0xffu);
    p[1] = (al_u8)((v >> 8) & 0xffu);
    p[2] = (al_u8)((v >> 16) & 0xffu);
    p[3] = (al_u8)((v >> 24) & 0xffu);
}

static AL_FORCEINLINE void al_store_le64(al_u8 *p, al_u64 v) {
    al_store_le32(p, (al_u32)(v & 0xffffffffu));
    al_store_le32(p + 4, (al_u32)(v >> 32));
}

static AL_FORCEINLINE void al_store_be32(al_u8 *p, al_u32 v) {
    p[0] = (al_u8)((v >> 24) & 0xffu);
    p[1] = (al_u8)((v >> 16) & 0xffu);
    p[2] = (al_u8)((v >> 8) & 0xffu);
    p[3] = (al_u8)(v & 0xffu);
}

static AL_FORCEINLINE void al_store_be64(al_u8 *p, al_u64 v) {
    al_store_be32(p, (al_u32)(v >> 32));
    al_store_be32(p + 4, (al_u32)(v & 0xffffffffu));
}

/* --------------------------------------------------------------------------
 * Bit operations
 *
 * Wrapped rather than used directly because the intrinsics differ per compiler
 * and the fallbacks must produce identical results - these feed the fixed-point
 * logarithm, which is consensus-visible.
 * -------------------------------------------------------------------------- */

/* Rotate right, 32-bit. The compiler recognises this idiom and emits ROR. */
static AL_FORCEINLINE al_u32 al_rotr32(al_u32 v, unsigned n) {
    return (v >> n) | (v << (32u - n));
}

/* Index of the highest set bit, 0-based. Undefined for v == 0, so callers
 * check first. */
static AL_FORCEINLINE unsigned al_bit_width64(al_u64 v) {
#if defined(AL_COMPILER_MSVC)
    unsigned long idx = 0;
    /* _BitScanReverse64 is available on x64 and ARM64, the only 64-bit targets
     * MSVC supports. */
    if (_BitScanReverse64(&idx, v)) {
        return (unsigned)idx + 1u;
    }
    return 0u;
#else
    if (v == 0u) {
        return 0u;
    }
    return 64u - (unsigned)__builtin_clzll(v);
#endif
}

/* --------------------------------------------------------------------------
 * Checked arithmetic
 *
 * The VM's arithmetic opcodes trap on overflow rather than wrapping, so these
 * return a flag instead of a value. Written against the compiler builtins where
 * available because the portable form is easy to get wrong.
 * -------------------------------------------------------------------------- */

static AL_FORCEINLINE al_bool al_add_overflow_u64(al_u64 a, al_u64 b,
                                                  al_u64 *out) {
#if defined(AL_COMPILER_MSVC)
    *out = a + b;
    return (*out < a) ? AL_TRUE : AL_FALSE;
#else
    return __builtin_add_overflow(a, b, out) ? AL_TRUE : AL_FALSE;
#endif
}

static AL_FORCEINLINE al_bool al_sub_overflow_u64(al_u64 a, al_u64 b,
                                                  al_u64 *out) {
#if defined(AL_COMPILER_MSVC)
    *out = a - b;
    return (a < b) ? AL_TRUE : AL_FALSE;
#else
    return __builtin_sub_overflow(a, b, out) ? AL_TRUE : AL_FALSE;
#endif
}

static AL_FORCEINLINE al_bool al_mul_overflow_u64(al_u64 a, al_u64 b,
                                                  al_u64 *out) {
#if defined(AL_COMPILER_MSVC)
    al_u64 hi = 0;
    al_u64 lo = _umul128(a, b, &hi);
    *out = lo;
    return (hi != 0u) ? AL_TRUE : AL_FALSE;
#else
    return __builtin_mul_overflow(a, b, out) ? AL_TRUE : AL_FALSE;
#endif
}

/* --------------------------------------------------------------------------
 * Small utilities
 * -------------------------------------------------------------------------- */

#define AL_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define AL_MAX(a, b) (((a) > (b)) ? (a) : (b))

/* memcpy that tolerates a zero length with a NULL source. Passing NULL to
 * memcpy is undefined even when len is 0, and UBSan reports it. */
static AL_FORCEINLINE void al_memcpy(void *dst, const void *src, al_size len) {
    if (len != 0u) {
        memcpy(dst, src, len);
    }
}

static AL_FORCEINLINE void al_memzero(void *dst, al_size len) {
    if (len != 0u) {
        memset(dst, 0, len);
    }
}

/*
 * Overwrite a buffer so the compiler may not remove the write.
 *
 * memset on a local that is never read again is dead code, and optimisers do
 * delete it - which is how key material survives in stack frames. The volatile
 * pointer makes each store observable, so it cannot be elided. This is the
 * internal spelling; the public al_secure_zero forwards to it.
 */
static AL_FORCEINLINE void al_wipe(void *p, al_size len) {
    if (p == NULL || len == 0u) {
        return;
    }
    volatile al_u8 *q = (volatile al_u8 *)p;
    while (len-- != 0u) {
        *q++ = 0u;
    }
}

#endif /* ASTROLUNE_INTERNAL_COMMON_H */
