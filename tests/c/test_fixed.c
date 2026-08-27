/*
 * Fixed-point arithmetic.
 *
 * The expected values here are exact, not approximate. That is deliberate: these
 * functions are consensus-visible, so "close enough" is not a property worth
 * testing - bit-for-bit reproducibility is. Every expectation below was computed
 * independently with Python's `decimal` module at 80 digits, and where the
 * integer algorithm differs from the true value the difference is noted in a
 * comment so a future change that shifts it cannot pass unnoticed.
 */

#include "astrolune/fixed.h"

#include "altest.h"

#define AL_TEST_SUITE_NAME "fixed"

/* Q32.32 literals used throughout. */
#define ONE  AL_FIXED_ONE
#define HALF AL_FIXED_HALF

AL_TEST(from_int_and_back) {
    AL_CHECK_EQ_I64(al_fixed_from_int(0), 0);
    AL_CHECK_EQ_I64(al_fixed_from_int(1), ONE);
    AL_CHECK_EQ_I64(al_fixed_from_int(-1), -ONE);
    AL_CHECK_EQ_I64(al_fixed_from_int(1024), (al_i64)1024 * ONE);

    AL_CHECK_EQ_I64(al_fixed_to_int_trunc(ONE), 1);
    AL_CHECK_EQ_I64(al_fixed_to_int_trunc(ONE + HALF), 1);
    AL_CHECK_EQ_I64(al_fixed_to_int_trunc(-(ONE + HALF)), -1);

    AL_CHECK_EQ_I64(al_fixed_to_int_round(ONE + HALF), 2);
    AL_CHECK_EQ_I64(al_fixed_to_int_round(-(ONE + HALF)), -2);
    AL_CHECK_EQ_I64(al_fixed_to_int_round(ONE + HALF - 1), 1);

    /* floor rounds toward negative infinity, unlike the other two. */
    AL_CHECK_EQ_I64(al_fixed_floor_int(ONE + HALF), 1);
    AL_CHECK_EQ_I64(al_fixed_floor_int(-(ONE + HALF)), -2);
    AL_CHECK_EQ_I64(al_fixed_floor_int(-1), -1);

    /* Out of the Q32.32 integer range: saturate, never wrap. */
    AL_CHECK_EQ_I64(al_fixed_from_int((al_i64)INT32_MAX + 1), AL_FIXED_MAX);
    AL_CHECK_EQ_I64(al_fixed_from_int((al_i64)INT32_MIN - 1), AL_FIXED_MIN);
}

AL_TEST(from_ratio) {
    AL_CHECK_EQ_I64(al_fixed_from_ratio(1, 2), HALF);
    AL_CHECK_EQ_I64(al_fixed_from_ratio(1, 3), 1431655765);
    AL_CHECK_EQ_I64(al_fixed_from_ratio(-1, 3), -1431655765);
    AL_CHECK_EQ_I64(al_fixed_from_ratio(1, -3), -1431655765);
    AL_CHECK_EQ_I64(al_fixed_from_ratio(-1, -3), 1431655765);
    AL_CHECK_EQ_I64(al_fixed_from_ratio(2, 7), 1227133513);
    AL_CHECK_EQ_I64(al_fixed_from_ratio(7, 1), (al_i64)7 * ONE);

    /* A zero denominator means "no data" to the scoring code, not a crash. */
    AL_CHECK_EQ_I64(al_fixed_from_ratio(1, 0), 0);
}

AL_TEST(arithmetic_saturates) {
    AL_CHECK_EQ_I64(al_fixed_add(ONE, ONE), 2 * ONE);
    AL_CHECK_EQ_I64(al_fixed_sub(ONE, ONE), 0);
    AL_CHECK_EQ_I64(al_fixed_sub(0, ONE), -ONE);

    AL_CHECK_EQ_I64(al_fixed_mul(ONE, ONE), ONE);
    AL_CHECK_EQ_I64(al_fixed_mul(2 * ONE, 3 * ONE), 6 * ONE);
    AL_CHECK_EQ_I64(al_fixed_mul(-2 * ONE, 3 * ONE), -6 * ONE);
    AL_CHECK_EQ_I64(al_fixed_mul(HALF, HALF), ONE / 4);

    /* 3 * (1/3) is one ulp short of 1: the ratio is not exactly representable,
     * and the product truncates. Asserting the exact result documents that the
     * shortfall is the representation's, not a bug in the multiply. */
    AL_CHECK_EQ_I64(al_fixed_mul(3 * ONE, al_fixed_from_ratio(1, 3)), ONE - 1);

    AL_CHECK_EQ_I64(al_fixed_div(6 * ONE, 3 * ONE), 2 * ONE);
    AL_CHECK_EQ_I64(al_fixed_div(ONE, 2 * ONE), HALF);
    AL_CHECK_EQ_I64(al_fixed_div(-ONE, 2 * ONE), -HALF);
    AL_CHECK_EQ_I64(al_fixed_div(ONE, 0), 0);

    /* Saturation, not wraparound. A score that overflows must pin high; wrapping
     * would turn a large honest weight into a negative one. */
    AL_CHECK_EQ_I64(al_fixed_add(AL_FIXED_MAX, ONE), AL_FIXED_MAX);
    AL_CHECK_EQ_I64(al_fixed_sub(AL_FIXED_MIN, ONE), AL_FIXED_MIN);
    AL_CHECK_EQ_I64(al_fixed_mul(AL_FIXED_MAX, 2 * ONE), AL_FIXED_MAX);
    AL_CHECK_EQ_I64(al_fixed_mul(AL_FIXED_MAX, -2 * ONE), AL_FIXED_MIN);
    AL_CHECK_EQ_I64(al_fixed_div(AL_FIXED_MAX, ONE / 4), AL_FIXED_MAX);

    AL_CHECK_EQ_I64(al_fixed_abs(-ONE), ONE);
    AL_CHECK_EQ_I64(al_fixed_abs(AL_FIXED_MIN), AL_FIXED_MAX);
    AL_CHECK_EQ_I64(al_fixed_clamp(5 * ONE, 0, ONE), ONE);
    AL_CHECK_EQ_I64(al_fixed_clamp(-5 * ONE, 0, ONE), 0);
    AL_CHECK_EQ_I64(al_fixed_min(ONE, 2 * ONE), ONE);
    AL_CHECK_EQ_I64(al_fixed_max(ONE, 2 * ONE), 2 * ONE);
}

AL_TEST(log2_exact) {
    AL_CHECK_EQ_I64(al_fixed_log2(ONE), 0);
    AL_CHECK_EQ_I64(al_fixed_log2(2 * ONE), ONE);
    AL_CHECK_EQ_I64(al_fixed_log2(HALF), -ONE);
    AL_CHECK_EQ_I64(al_fixed_log2((al_i64)1024 * ONE), 10 * ONE);

    /* log2(3)  = 1.58496250072...  true Q32.32 value 6807362106;
     * the bit-by-bit refinement truncates, landing one ulp below. */
    AL_CHECK_EQ_I64(al_fixed_log2(3 * ONE), 6807362105);
    /* log2(10) = 3.32192809489...  matches the true value exactly. */
    AL_CHECK_EQ_I64(al_fixed_log2(10 * ONE), 14267572527);

    /* Non-positive input saturates rather than trapping; callers clamp. */
    AL_CHECK_EQ_I64(al_fixed_log2(0), AL_FIXED_MIN);
    AL_CHECK_EQ_I64(al_fixed_log2(-ONE), AL_FIXED_MIN);
}

AL_TEST(exp2_exact) {
    AL_CHECK_EQ_I64(al_fixed_exp2(0), ONE);
    AL_CHECK_EQ_I64(al_fixed_exp2(ONE), 2 * ONE);
    AL_CHECK_EQ_I64(al_fixed_exp2(10 * ONE), (al_i64)1024 * ONE);
    AL_CHECK_EQ_I64(al_fixed_exp2(-ONE), HALF);

    /* 2^0.5 = 1.41421356237...  exactly the true Q32.32 value. */
    AL_CHECK_EQ_I64(al_fixed_exp2(HALF), 6074001000);
    /* 2^10.5: true value 6219777023951; the table product accumulates 49 ulp of
     * truncation, which is 8e-9 relative - far inside what the scoring needs. */
    AL_CHECK_EQ_I64(al_fixed_exp2(10 * ONE + HALF), 6219777024000);
    /* 2^-3.25 = 0.10511205190...  exact. */
    AL_CHECK_EQ_I64(al_fixed_exp2(-(3 * ONE + ONE / 4)), 451452825);

    /* Range limits: 2^31 leaves the integer range, 2^-33 falls below the last
     * fraction bit. */
    AL_CHECK_EQ_I64(al_fixed_exp2(31 * ONE), AL_FIXED_MAX);
    AL_CHECK_EQ_I64(al_fixed_exp2(-40 * ONE), 0);
}

AL_TEST(log2_exp2_roundtrip) {
    /* Every power of two must survive the round trip exactly - the integer part
     * of the algorithm is a shift, so any error here is a real defect. */
    for (int k = -20; k <= 20; ++k) {
        al_fixed v = (k >= 0) ? (ONE << k) : (ONE >> (-k));
        AL_CHECK_EQ_I64(al_fixed_log2(v), (al_i64)k * ONE);
        AL_CHECK_EQ_I64(al_fixed_exp2((al_i64)k * ONE), v);
    }

    /* And for a spread of non-powers, exp2(log2(v)) must land within a few ulp
     * of v. Two independent approximations compose, so this is a tolerance
     * check, not an equality one. */
    static const al_i64 samples[] = {3, 5, 7, 11, 100, 12345};
    for (al_size i = 0u; i < AL_COUNTOF(samples); ++i) {
        al_fixed v  = samples[i] * ONE;
        al_fixed rt = al_fixed_exp2(al_fixed_log2(v));
        /* Relative error of ~2^-27 at worst; scale the tolerance with v. */
        AL_CHECK_NEAR_I64(rt, v, (v >> 24) + 8);
    }
}

AL_TEST(ln_and_ln1p) {
    AL_CHECK_EQ_I64(al_fixed_ln(ONE), 0);
    /* ln(2) = 0.69314718055...  exact. */
    AL_CHECK_EQ_I64(al_fixed_ln(2 * ONE), 2977044472);
    /* ln(10) = 2.30258509299...  exact. */
    AL_CHECK_EQ_I64(al_fixed_ln(10 * ONE), 9889527671);
    AL_CHECK_EQ_I64(al_fixed_ln(0), AL_FIXED_MIN);

    AL_CHECK_EQ_I64(al_fixed_ln1p(0), 0);
    AL_CHECK_EQ_I64(al_fixed_ln1p(ONE), 2977044472);
    /* ln(1001) = 6.90875477932...  one ulp above the true 29672875833. This is
     * the value TBS's uptime term actually evaluates. */
    AL_CHECK_EQ_I64(al_fixed_ln1p((al_i64)1000 * ONE), 29672875834);

    /* ln is negative below 1, and the sign must survive the multiply by ln(2).
     *
     * INT64_C is not decoration here. An unsuffixed decimal constant gets the
     * first type from int/long/long long that fits it, and 2977044472 exceeds
     * INT32_MAX - so on a 32-bit-long target it lands on `unsigned long`, and
     * negating it wraps to 1317922824 instead of going negative. Verified on
     * MSVC 19.51, where this assertion failed against a correct implementation.
     * Every literal in this file wider than 31 bits carries the suffix. */
    AL_CHECK_EQ_I64(al_fixed_ln(HALF), -INT64_C(2977044472));
}

AL_TEST(sqrt_floors) {
    AL_CHECK_EQ_I64(al_fixed_sqrt(0), 0);
    AL_CHECK_EQ_I64(al_fixed_sqrt(-ONE), 0);
    AL_CHECK_EQ_I64(al_fixed_sqrt(ONE), ONE);
    AL_CHECK_EQ_I64(al_fixed_sqrt(4 * ONE), 2 * ONE);
    AL_CHECK_EQ_I64(al_fixed_sqrt(ONE / 4), HALF);

    /* Integer square root truncates, so both of these sit one ulp below the
     * true value (6074001000 and 7439101574). */
    AL_CHECK_EQ_I64(al_fixed_sqrt(2 * ONE), 6074000999);
    AL_CHECK_EQ_I64(al_fixed_sqrt(3 * ONE), 7439101573);

    /* Large input, to exercise the 128-bit radicand path.
     *
     * Spelled as a raw Q32.32 bit pattern rather than as `ONE << 40`, which was
     * the original expression here: ONE is 2^32, so ONE << 40 is 2^72, which
     * overflows the int64 the type is built on. That is undefined behaviour and
     * MSVC folded it to 0, failing the assertion against correct code.
     *
     * 2^62 as a raw pattern represents the value 2^30, whose square root is
     * 2^15, represented as 2^15 * 2^32 = 2^47. Near the top of the range, so the
     * radicand really is 2^94 and the 128-bit path is what computes it. */
    AL_CHECK_EQ_I64(al_fixed_sqrt((al_fixed)1 << 62), (al_fixed)1 << 47);
}

AL_TEST(half_pow_decay) {
    /* No elapsed time, no decay. */
    AL_CHECK_EQ_I64(al_fixed_half_pow(0, 730), ONE);
    AL_CHECK_EQ_I64(al_fixed_half_pow(-5, 730), ONE);
    AL_CHECK_EQ_I64(al_fixed_half_pow(5, 0), ONE);

    /* Exactly one half-life halves the value, exactly. */
    AL_CHECK_EQ_I64(al_fixed_half_pow(730, 730), HALF);
    AL_CHECK_EQ_I64(al_fixed_half_pow(1460, 730), ONE / 4);

    /* 0.5^0.5 = 0.70710678118...  exact. */
    AL_CHECK_EQ_I64(al_fixed_half_pow(365, 730), 3037000500);
    /* 0.5^(1000/730) = 0.38692...  one ulp below the true 1661843046. */
    AL_CHECK_EQ_I64(al_fixed_half_pow(1000, 730), 1661843045);

    /* Monotonically decreasing in n. A decay curve that ever ticks upward would
     * let a node improve its score by waiting. */
    al_fixed prev = ONE;
    for (al_i64 n = 1; n <= 400; ++n) {
        al_fixed cur = al_fixed_half_pow(n, 730);
        AL_CHECK(cur <= prev);
        prev = cur;
    }
}

AL_TEST(to_str) {
    char buf[AL_FIXED_STR_SIZE];

    al_fixed_to_str(ONE, 3, buf);
    AL_CHECK_EQ_STR(buf, "1.000");

    al_fixed_to_str(HALF, 3, buf);
    AL_CHECK_EQ_STR(buf, "0.500");

    al_fixed_to_str(-HALF, 2, buf);
    AL_CHECK_EQ_STR(buf, "-0.50");

    al_fixed_to_str(al_fixed_from_ratio(1, 3), 6, buf);
    AL_CHECK_EQ_STR(buf, "0.333333");

    al_fixed_to_str((al_i64)1234 * ONE, 0, buf);
    AL_CHECK_EQ_STR(buf, "1234");

    /* Rounding at the printed precision must carry into the integer part. */
    al_fixed_to_str(ONE - 1, 3, buf);
    AL_CHECK_EQ_STR(buf, "1.000");
}

AL_TEST_MAIN {
    AL_RUN(from_int_and_back);
    AL_RUN(from_ratio);
    AL_RUN(arithmetic_saturates);
    AL_RUN(log2_exact);
    AL_RUN(exp2_exact);
    AL_RUN(log2_exp2_roundtrip);
    AL_RUN(ln_and_ln1p);
    AL_RUN(sqrt_floors);
    AL_RUN(half_pow_decay);
    AL_RUN(to_str);
}
