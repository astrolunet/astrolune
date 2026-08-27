/*
 * Q32.32 fixed-point arithmetic. See astrolune/fixed.h for why consensus math
 * may not use floating point.
 *
 * Everything here is integer arithmetic, so every result is bit-identical on
 * every platform and compiler. The transcendental functions use classic
 * bit-by-bit algorithms rather than polynomial approximations, because a
 * polynomial's accuracy depends on the evaluation order the optimiser picks,
 * while shift-and-compare does not.
 */

#include "astrolune/fixed.h"

#include "internal/common.h"

#include <stdio.h>

/* --------------------------------------------------------------------------
 * 128-bit intermediates
 *
 * Q32.32 multiplication needs a 128-bit product before shifting back down, and
 * division needs a 128-bit dividend. GCC and Clang have __int128; MSVC does not,
 * so a portable limb-based implementation is provided. Both paths are exercised
 * by tests/c/test_fixed.c.
 * -------------------------------------------------------------------------- */

#if defined(__SIZEOF_INT128__)

static void al_umul(al_u64 a, al_u64 b, al_u64 *hi, al_u64 *lo) {
    unsigned __int128 p = (unsigned __int128)a * (unsigned __int128)b;
    *lo = (al_u64)p;
    *hi = (al_u64)(p >> 64);
}

/* (hi:lo) / d, requires hi < d so the quotient fits in 64 bits. */
static al_u64 al_udiv(al_u64 hi, al_u64 lo, al_u64 d) {
    unsigned __int128 n = ((unsigned __int128)hi << 64) | (unsigned __int128)lo;
    return (al_u64)(n / (unsigned __int128)d);
}

#else /* MSVC and any other toolchain without __int128 */

static void al_umul(al_u64 a, al_u64 b, al_u64 *hi, al_u64 *lo) {
#  if defined(AL_COMPILER_MSVC) && defined(AL_ARCH_X86_64)
    *lo = _umul128(a, b, hi);
#  else
    /* Schoolbook multiplication on 32-bit limbs. */
    al_u64 a_lo = a & 0xffffffffu, a_hi = a >> 32;
    al_u64 b_lo = b & 0xffffffffu, b_hi = b >> 32;

    al_u64 p0 = a_lo * b_lo;
    al_u64 p1 = a_lo * b_hi;
    al_u64 p2 = a_hi * b_lo;
    al_u64 p3 = a_hi * b_hi;

    al_u64 mid = (p0 >> 32) + (p1 & 0xffffffffu) + (p2 & 0xffffffffu);
    *lo = (p0 & 0xffffffffu) | (mid << 32);
    *hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
#  endif
}

static al_u64 al_udiv(al_u64 hi, al_u64 lo, al_u64 d) {
    /* Restoring shift-subtract division, 64 iterations. Slower than a hardware
     * 128/64 divide but available everywhere and exactly as accurate. Fixed-point
     * division is not on the VM's inner loop, so the cost is acceptable. */
    if (hi >= d) {
        return UINT64_MAX;   /* saturate; callers pre-scale to avoid this */
    }
    al_u64 quotient  = 0u;
    al_u64 remainder = hi;
    for (int i = 63; i >= 0; --i) {
        al_u64 bit = (lo >> (unsigned)i) & 1u;
        /* remainder < d here, so the shift cannot lose the top bit. */
        remainder = (remainder << 1) | bit;
        quotient <<= 1;
        if (remainder >= d) {
            remainder -= d;
            quotient |= 1u;
        }
    }
    return quotient;
}

#endif

/* Unsigned Q32.32 multiply: (a * b) >> 32. */
static al_u64 al_umul_q32(al_u64 a, al_u64 b) {
    al_u64 hi = 0u, lo = 0u;
    al_umul(a, b, &hi, &lo);
    return (lo >> 32) | (hi << 32);
}

/* --------------------------------------------------------------------------
 * Construction and conversion
 * -------------------------------------------------------------------------- */

/* Magnitude of an i64 as a u64, correct for INT64_MIN. */
static al_u64 al_abs_u64(al_i64 v) {
    return (v < 0) ? (~(al_u64)v + 1u) : (al_u64)v;
}

static al_fixed al_apply_sign(al_u64 magnitude, al_bool negative) {
    if (negative) {
        if (magnitude >= (al_u64)INT64_MAX + 1u) {
            return AL_FIXED_MIN;
        }
        return -(al_fixed)magnitude;
    }
    if (magnitude > (al_u64)INT64_MAX) {
        return AL_FIXED_MAX;
    }
    return (al_fixed)magnitude;
}

al_fixed al_fixed_from_int(al_i64 v) {
    /* Saturate rather than wrap: the integer range of Q32.32 is +/-2^31. */
    if (v > (al_i64)INT32_MAX) {
        return AL_FIXED_MAX;
    }
    if (v < (al_i64)INT32_MIN) {
        return AL_FIXED_MIN;
    }
    return (al_fixed)v << AL_FIXED_FRAC_BITS;
}

al_fixed al_fixed_from_ratio(al_i64 n, al_i64 d) {
    if (d == 0) {
        /* No exception mechanism in the core, and no sensible value: the
         * callers treat 0 as "no data available". */
        return 0;
    }
    al_bool negative = ((n < 0) != (d < 0)) ? AL_TRUE : AL_FALSE;
    al_u64  un = al_abs_u64(n);
    al_u64  ud = al_abs_u64(d);

    /* (un << 32) / ud with the shift held in the high word, then rounded to
     * nearest by adding half the divisor to the dividend. */
    al_u64 hi = un >> 32;
    al_u64 lo = un << 32;

    /* Round half away from zero: add ud/2 to the 128-bit dividend. */
    al_u64 half = ud >> 1;
    al_u64 new_lo = lo + half;
    if (new_lo < lo) {
        ++hi;
    }
    lo = new_lo;

    if (hi >= ud) {
        return negative ? AL_FIXED_MIN : AL_FIXED_MAX;
    }
    return al_apply_sign(al_udiv(hi, lo, ud), negative);
}

al_i64 al_fixed_to_int_trunc(al_fixed v) {
    /* Arithmetic shift on a negative value rounds toward -inf, so negatives are
     * negated around the shift to get truncation toward zero. */
    if (v < 0) {
        return -(al_i64)(al_abs_u64(v) >> AL_FIXED_FRAC_BITS);
    }
    return (al_i64)((al_u64)v >> AL_FIXED_FRAC_BITS);
}

al_i64 al_fixed_to_int_round(al_fixed v) {
    if (v < 0) {
        al_u64 m = al_abs_u64(v) + (al_u64)AL_FIXED_HALF;
        return -(al_i64)(m >> AL_FIXED_FRAC_BITS);
    }
    return (al_i64)(((al_u64)v + (al_u64)AL_FIXED_HALF) >> AL_FIXED_FRAC_BITS);
}

al_i64 al_fixed_floor_int(al_fixed v) {
    return v >> AL_FIXED_FRAC_BITS;   /* arithmetic shift: floor by definition */
}

/* --------------------------------------------------------------------------
 * Arithmetic - saturating
 * -------------------------------------------------------------------------- */

al_fixed al_fixed_add(al_fixed a, al_fixed b) {
    /* Unsigned arithmetic to compute the sum, then detect overflow from the
     * signs. Signed overflow itself is undefined behaviour and cannot be used
     * as the detection mechanism. */
    al_u64 sum = (al_u64)a + (al_u64)b;
    al_fixed r = (al_fixed)sum;
    if (((a > 0) && (b > 0) && (r < 0))) {
        return AL_FIXED_MAX;
    }
    if (((a < 0) && (b < 0) && (r >= 0))) {
        return AL_FIXED_MIN;
    }
    return r;
}

al_fixed al_fixed_sub(al_fixed a, al_fixed b) {
    al_u64 diff = (al_u64)a - (al_u64)b;
    al_fixed r = (al_fixed)diff;
    if ((a >= 0) && (b < 0) && (r < 0)) {
        return AL_FIXED_MAX;
    }
    if ((a < 0) && (b > 0) && (r > 0)) {
        return AL_FIXED_MIN;
    }
    return r;
}

al_fixed al_fixed_mul(al_fixed a, al_fixed b) {
    al_bool negative = ((a < 0) != (b < 0)) ? AL_TRUE : AL_FALSE;
    al_u64  hi = 0u, lo = 0u;
    al_umul(al_abs_u64(a), al_abs_u64(b), &hi, &lo);

    /* The Q32.32 result is bits [32, 96) of the 128-bit product. Anything at or
     * above bit 95 does not fit in the signed 64-bit result. */
    if ((hi >> 31) != 0u) {
        return negative ? AL_FIXED_MIN : AL_FIXED_MAX;
    }
    al_u64 magnitude = (lo >> 32) | (hi << 32);
    return al_apply_sign(magnitude, negative);
}

al_fixed al_fixed_div(al_fixed a, al_fixed b) {
    if (b == 0) {
        return 0;
    }
    al_bool negative = ((a < 0) != (b < 0)) ? AL_TRUE : AL_FALSE;
    al_u64  ua = al_abs_u64(a);
    al_u64  ub = al_abs_u64(b);

    al_u64 hi = ua >> 32;
    al_u64 lo = ua << 32;
    if (hi >= ub) {
        return negative ? AL_FIXED_MIN : AL_FIXED_MAX;
    }
    return al_apply_sign(al_udiv(hi, lo, ub), negative);
}

al_fixed al_fixed_min(al_fixed a, al_fixed b) { return (a < b) ? a : b; }
al_fixed al_fixed_max(al_fixed a, al_fixed b) { return (a > b) ? a : b; }

al_fixed al_fixed_clamp(al_fixed v, al_fixed lo, al_fixed hi) {
    if (v < lo) { return lo; }
    if (v > hi) { return hi; }
    return v;
}

al_fixed al_fixed_abs(al_fixed v) {
    if (v == AL_FIXED_MIN) {
        return AL_FIXED_MAX;   /* no positive counterpart; saturate */
    }
    return (v < 0) ? -v : v;
}

/* --------------------------------------------------------------------------
 * Transcendental functions
 * -------------------------------------------------------------------------- */

/* ln(2) in Q32.32. */
#define AL_LN2_Q32 UINT64_C(0xB17217F8)

/*
 * 2^(2^-(i+1)) for i in 0..31, in Q32.32.
 *
 * Generated with Python's `decimal` module at 80 significant digits by repeated
 * square root of 2, rounded half-even:
 *
 *   from decimal import Decimal, getcontext
 *   getcontext().prec = 80
 *   x = Decimal(2)
 *   for i in range(32):
 *       x = x.sqrt()
 *       print(hex(int((x * Decimal(2)**32).to_integral_value())))
 *
 * The tail converges to 1 + 1 ulp, which is why the last entries repeat.
 */
static const al_u64 al_exp2_frac_table[32] = {
    UINT64_C(0x0016A09E668), UINT64_C(0x001306FE0A3),
    UINT64_C(0x001172B83C8), UINT64_C(0x0010B5586D0),
    UINT64_C(0x001059B0D31), UINT64_C(0x00102C9A3E7),
    UINT64_C(0x0010163DAA0), UINT64_C(0x00100B1AFA6),
    UINT64_C(0x0010058C86E), UINT64_C(0x001002C605E),
    UINT64_C(0x00100162F39), UINT64_C(0x001000B175F),
    UINT64_C(0x00100058BA0), UINT64_C(0x0010002C5CC),
    UINT64_C(0x001000162E5), UINT64_C(0x0010000B172),
    UINT64_C(0x001000058B9), UINT64_C(0x00100002C5D),
    UINT64_C(0x0010000162E), UINT64_C(0x00100000B17),
    UINT64_C(0x0010000058C), UINT64_C(0x001000002C6),
    UINT64_C(0x00100000163), UINT64_C(0x001000000B1),
    UINT64_C(0x00100000059), UINT64_C(0x0010000002C),
    UINT64_C(0x00100000016), UINT64_C(0x0010000000B),
    UINT64_C(0x00100000006), UINT64_C(0x00100000003),
    UINT64_C(0x00100000001), UINT64_C(0x00100000001),
};

al_fixed al_fixed_log2(al_fixed v) {
    if (v <= 0) {
        /* log2 is undefined at and below zero. Saturating to the minimum makes
         * the callers' clamps do the right thing without a separate error path. */
        return AL_FIXED_MIN;
    }

    al_u64   uv    = (al_u64)v;
    unsigned width = al_bit_width64(uv);          /* index of MSB, plus one */

    /* v = m * 2^exponent with m in [1, 2). In Q32.32 the MSB of a value in
     * [1, 2) sits at bit 32, so the exponent is (width - 1) - 32. */
    al_i64 exponent = (al_i64)width - 1 - AL_FIXED_FRAC_BITS;

    al_u64 m;
    if (exponent > 0) {
        m = uv >> (unsigned)exponent;
    } else if (exponent < 0) {
        m = uv << (unsigned)(-exponent);
    } else {
        m = uv;
    }

    al_fixed result = (al_fixed)exponent << AL_FIXED_FRAC_BITS;

    /*
     * Bit-by-bit refinement. At each step m is in [1, 2); squaring puts it in
     * [1, 4). If the square is at or above 2 the next fraction bit is set and m
     * is halved back into [1, 2).
     */
    for (unsigned i = 1u; i <= AL_FIXED_FRAC_BITS; ++i) {
        m = al_umul_q32(m, m);
        if (m >= ((al_u64)AL_FIXED_ONE << 1)) {
            m >>= 1;
            result += (al_fixed)((al_u64)AL_FIXED_ONE >> i);
        }
    }
    return result;
}

al_fixed al_fixed_ln(al_fixed v) {
    if (v <= 0) {
        return AL_FIXED_MIN;
    }
    return al_fixed_mul(al_fixed_log2(v), (al_fixed)AL_LN2_Q32);
}

al_fixed al_fixed_ln1p(al_fixed v) {
    /* Computed as ln(1 + v) directly rather than through a series expansion: the
     * TBS formula feeds this values in the thousands, where a small-argument
     * series would be badly wrong, and the +1 is exact in fixed point. */
    al_fixed arg = al_fixed_add(AL_FIXED_ONE, v);
    if (arg <= 0) {
        return AL_FIXED_MIN;
    }
    return al_fixed_ln(arg);
}

al_fixed al_fixed_exp2(al_fixed v) {
    al_i64 int_part = al_fixed_floor_int(v);

    /* 2^31 overflows the integer range of Q32.32; 2^-33 underflows to zero. */
    if (int_part >= 31) {
        return AL_FIXED_MAX;
    }
    if (int_part < -33) {
        return 0;
    }

    /* Fractional part in [0, 1), exact because floor was used. */
    al_u64 frac = (al_u64)(v - (int_part << AL_FIXED_FRAC_BITS));

    /* 2^frac = product of 2^(2^-(i+1)) over the set bits of frac, MSB first. */
    al_u64 result = (al_u64)AL_FIXED_ONE;
    for (unsigned i = 0u; i < 32u; ++i) {
        if ((frac >> (31u - i)) & 1u) {
            result = al_umul_q32(result, al_exp2_frac_table[i]);
        }
    }

    if (int_part > 0) {
        /* Check for overflow before shifting rather than after. */
        if (al_bit_width64(result) + (unsigned)int_part > 63u) {
            return AL_FIXED_MAX;
        }
        result <<= (unsigned)int_part;
    } else if (int_part < 0) {
        result >>= (unsigned)(-int_part);
    }
    return (al_fixed)result;
}

al_fixed al_fixed_sqrt(al_fixed v) {
    if (v <= 0) {
        return 0;
    }

    /*
     * sqrt of a Q32.32 value x is sqrt(x * 2^32) in the same representation,
     * so the radicand is up to 2^95 and needs a 128-bit integer square root.
     * Computed bit by bit, most significant first: the classic restoring
     * algorithm, with the candidate held as a 128-bit pair.
     */
    al_u64 rad_hi = (al_u64)v >> 32;
    al_u64 rad_lo = (al_u64)v << 32;

    al_u64 result    = 0u;
    al_u64 rem_hi    = 0u;
    al_u64 rem_lo    = 0u;

    /* 96 significant bits, processed two at a time. */
    for (int shift = 94; shift >= 0; shift -= 2) {
        /* Bring down the next two bits of the radicand. */
        al_u64 two_bits;
        if (shift >= 64) {
            two_bits = (rad_hi >> (unsigned)(shift - 64)) & 3u;
        } else {
            two_bits = (rad_lo >> (unsigned)shift) & 3u;
        }

        /* remainder = remainder * 4 + two_bits */
        rem_hi = (rem_hi << 2) | (rem_lo >> 62);
        rem_lo = (rem_lo << 2) | two_bits;

        /* trial = result * 4 + 1 */
        al_u64 trial_lo = (result << 2) | 1u;
        al_u64 trial_hi = result >> 62;

        result <<= 1;
        if (rem_hi > trial_hi || (rem_hi == trial_hi && rem_lo >= trial_lo)) {
            /* remainder -= trial */
            al_u64 new_lo = rem_lo - trial_lo;
            rem_hi -= trial_hi + ((rem_lo < trial_lo) ? 1u : 0u);
            rem_lo = new_lo;
            result |= 1u;
        }
    }
    /* The loop produced sqrt(v * 2^32) scaled by 2^0; shift into Q32.32. */
    return (al_fixed)result;
}

al_fixed al_fixed_half_pow(al_i64 n, al_i64 d) {
    if (d == 0) {
        return AL_FIXED_ONE;
    }
    if (n <= 0) {
        return AL_FIXED_ONE;   /* no elapsed time means no decay */
    }
    /* 0.5^(n/d) == 2^(-(n/d)). Forming the exponent as an exact ratio first
     * keeps the result reproducible; see the header for why this is its own
     * function rather than a call to exp2. */
    al_fixed exponent = al_fixed_from_ratio(-n, d);
    return al_fixed_exp2(exponent);
}

/* --------------------------------------------------------------------------
 * Formatting
 * -------------------------------------------------------------------------- */

void al_fixed_to_str(al_fixed v, int decimals, char out[AL_FIXED_STR_SIZE]) {
    if (decimals < 0) { decimals = 0; }
    if (decimals > 9) { decimals = 9; }

    static const al_u64 pow10[10] = {
        1u, 10u, 100u, 1000u, 10000u,
        100000u, 1000000u, 10000000u, 100000000u, 1000000000u
    };

    al_bool negative = (v < 0) ? AL_TRUE : AL_FALSE;
    al_u64  magnitude = al_abs_u64(v);

    al_u64 whole = magnitude >> AL_FIXED_FRAC_BITS;
    al_u64 frac  = magnitude & 0xffffffffu;

    /* Scale the fraction to `decimals` digits, rounding to nearest. */
    al_u64 scale = pow10[decimals];
    al_u64 hi = 0u, lo = 0u;
    al_umul(frac, scale, &hi, &lo);
    al_u64 frac_digits = (lo >> 32) | (hi << 32);
    /* Round half up on the discarded remainder. */
    if ((lo & 0xffffffffu) >= 0x80000000u) {
        ++frac_digits;
        if (frac_digits >= scale) {
            frac_digits = 0u;
            ++whole;
        }
    }

    if (decimals == 0) {
        (void)snprintf(out, AL_FIXED_STR_SIZE, "%s%llu",
                       negative ? "-" : "", (unsigned long long)whole);
    } else {
        (void)snprintf(out, AL_FIXED_STR_SIZE, "%s%llu.%0*llu",
                       negative ? "-" : "", (unsigned long long)whole,
                       decimals, (unsigned long long)frac_digits);
    }
}
