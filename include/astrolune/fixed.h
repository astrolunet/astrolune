/*
 * astrolune/fixed.h - deterministic fixed-point arithmetic.
 *
 * The problem this solves
 * ------------------------------------------------------------------------
 * PoTB scores nodes with logarithms, ratios and a decay curve. Expressed in
 * floating point, those computations are not reproducible: the result depends on
 * x87 versus SSE code generation, on whether the compiler contracted a multiply
 * and an add into an FMA, on the rounding mode the process happens to be in,
 * and on the libm implementation the platform ships. Two honest validators on
 * different machines would compute two different weights from identical inputs.
 *
 * For a consensus rule that is not a rounding error - it is a chain split.
 *
 * So every consensus-visible number is an integer. This header provides the
 * fixed-point type the scoring math uses, along with integer implementations of
 * the transcendental functions PoTB needs. Every operation here is exact and
 * bit-identical on every platform, because it is all integer arithmetic.
 *
 * Representation: Q32.32 in an int64_t. 32 integer bits, 32 fraction bits,
 * range about +/-2.1e9 with a resolution of 2.3e-10. That is far more headroom
 * and precision than node scores require.
 */

#ifndef ASTROLUNE_FIXED_H
#define ASTROLUNE_FIXED_H

#include "astrolune/base.h"

AL_EXTERN_C_BEGIN

typedef al_i64 al_fixed;

#define AL_FIXED_FRAC_BITS 32
#define AL_FIXED_ONE       (AL_CAST(al_fixed, 1) << AL_FIXED_FRAC_BITS)
#define AL_FIXED_HALF      (AL_FIXED_ONE / 2)
#define AL_FIXED_MAX       INT64_MAX
#define AL_FIXED_MIN       INT64_MIN

/* --------------------------------------------------------------------------
 * Construction and conversion
 * -------------------------------------------------------------------------- */

AL_PUBLIC al_fixed al_fixed_from_int(al_i64 v);

/* Exact ratio n/d, rounded to nearest, ties away from zero. d must be non-zero;
 * returns 0 if it is, which the callers treat as "no data". */
AL_PUBLIC al_fixed al_fixed_from_ratio(al_i64 n, al_i64 d);

AL_PUBLIC al_i64 al_fixed_to_int_trunc(al_fixed v);   /* toward zero        */
AL_PUBLIC al_i64 al_fixed_to_int_round(al_fixed v);   /* nearest, ties away */
AL_PUBLIC al_i64 al_fixed_floor_int(al_fixed v);      /* toward -inf        */

/* --------------------------------------------------------------------------
 * Arithmetic
 *
 * Saturating rather than wrapping. A score that overflows should pin at the
 * maximum, not wrap to a negative weight and hand an attacker a way to turn a
 * large honest score into a small one.
 * -------------------------------------------------------------------------- */

AL_PUBLIC al_fixed al_fixed_add(al_fixed a, al_fixed b);
AL_PUBLIC al_fixed al_fixed_sub(al_fixed a, al_fixed b);
AL_PUBLIC al_fixed al_fixed_mul(al_fixed a, al_fixed b);
AL_PUBLIC al_fixed al_fixed_div(al_fixed a, al_fixed b);   /* b == 0 yields 0 */

AL_PUBLIC al_fixed al_fixed_min(al_fixed a, al_fixed b);
AL_PUBLIC al_fixed al_fixed_max(al_fixed a, al_fixed b);
AL_PUBLIC al_fixed al_fixed_clamp(al_fixed v, al_fixed lo, al_fixed hi);
AL_PUBLIC al_fixed al_fixed_abs(al_fixed v);

/* --------------------------------------------------------------------------
 * Transcendental functions
 *
 * Integer implementations, accurate to within a few units in the last place of
 * the Q32.32 representation and - crucially - identical everywhere. Accuracy
 * is verified against reference values in tests/c/test_fixed.c.
 * -------------------------------------------------------------------------- */

/* Base-2 logarithm. v <= 0 returns AL_FIXED_MIN as a saturated sentinel.
 * Implemented as an integer log2 of the leading bit plus a fractional
 * refinement by repeated squaring. */
AL_PUBLIC al_fixed al_fixed_log2(al_fixed v);

/* Natural logarithm, via log2(v) * ln(2). */
AL_PUBLIC al_fixed al_fixed_ln(al_fixed v);

/* ln(1 + v). Used directly by the TBS formula. Computed as ln of (1+v) rather
 * than as a series so that it stays exact for large v as well as small. */
AL_PUBLIC al_fixed al_fixed_ln1p(al_fixed v);

/* 2^v, saturating on overflow. */
AL_PUBLIC al_fixed al_fixed_exp2(al_fixed v);

/* Integer square root of a fixed-point value. */
AL_PUBLIC al_fixed al_fixed_sqrt(al_fixed v);

/*
 * 0.5^(n/d) - the shape every decay curve in the protocol uses.
 *
 * Exposed as its own function because expressing it as exp2(-n/d) would round
 * the exponent first and the result second, so two nodes computing the same
 * decay from the same integers could disagree in the last bit. Taking the
 * integer ratio directly keeps it exact.
 */
AL_PUBLIC al_fixed al_fixed_half_pow(al_i64 n, al_i64 d);

/* --------------------------------------------------------------------------
 * Formatting
 * -------------------------------------------------------------------------- */

/* Decimal representation with `decimals` fractional digits (max 9).
 * For logs and diagnostics; never used in a consensus-visible encoding. */
#define AL_FIXED_STR_SIZE 32
AL_PUBLIC void al_fixed_to_str(al_fixed v, int decimals, char out[AL_FIXED_STR_SIZE]);

AL_EXTERN_C_END

#endif /* ASTROLUNE_FIXED_H */
