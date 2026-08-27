/*
 * A test harness, deliberately tiny.
 *
 * The core has no dependencies, and the test suite that guards it should not
 * introduce one: pulling in a framework to check that SHA-256 matches its NIST
 * vector would mean the smallest useful build of this project is no longer
 * self-contained. What a unit test needs is a way to record a failure with a
 * file and line, and a non-zero exit status - both of which fit in one header.
 *
 * Usage:
 *
 *     #include "altest.h"
 *
 *     AL_TEST(sums) {
 *         AL_CHECK_EQ_U64(2u + 2u, 4u);
 *     }
 *
 *     AL_TEST_MAIN {
 *         AL_RUN(sums);
 *     }
 *
 * Every check keeps going after a failure rather than aborting, so one run
 * reports every broken assertion instead of only the first.
 */

#ifndef ASTROLUNE_TESTS_ALTEST_H
#define ASTROLUNE_TESTS_ALTEST_H

#include "astrolune/base.h"
#include "astrolune/bytes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int al_test_failures = 0;
static int al_test_checks   = 0;
static int al_test_cases    = 0;

#define AL_TEST(name) static void name(void)

#if defined(__cplusplus)
#  define AL_TEST_CAST(type, value) static_cast<type>(value)
#else
#  define AL_TEST_CAST(type, value) ((type)(value))
#endif

/* Report a failure and carry on. */
#define AL_FAIL_AT(fmt, ...)                                            \
    do {                                                                \
        ++al_test_failures;                                             \
        (void)fprintf(stderr, "    FAIL %s:%d: " fmt "\n",              \
                      __FILE__, __LINE__, __VA_ARGS__);                 \
    } while (0)

#define AL_CHECK(cond)                                                  \
    do {                                                                \
        ++al_test_checks;                                               \
        if (!(cond)) {                                                  \
            AL_FAIL_AT("%s", #cond);                                     \
        }                                                               \
    } while (0)

#define AL_CHECK_MSG(cond, msg)                                         \
    do {                                                                \
        ++al_test_checks;                                               \
        if (!(cond)) {                                                  \
            AL_FAIL_AT("%s (%s)", #cond, (msg));                         \
        }                                                               \
    } while (0)

#define AL_CHECK_EQ_U64(actual, expected)                               \
    do {                                                                \
        ++al_test_checks;                                               \
        al_u64 al_a_ = AL_TEST_CAST(al_u64, actual);                    \
        al_u64 al_e_ = AL_TEST_CAST(al_u64, expected);                  \
        if (al_a_ != al_e_) {                                           \
            AL_FAIL_AT("%s: got %llu (0x%llx), want %llu (0x%llx)",      \
                       #actual, AL_TEST_CAST(unsigned long long, al_a_), \
                       AL_TEST_CAST(unsigned long long, al_a_),          \
                       AL_TEST_CAST(unsigned long long, al_e_),          \
                       AL_TEST_CAST(unsigned long long, al_e_));         \
        }                                                               \
    } while (0)

#define AL_CHECK_EQ_I64(actual, expected)                               \
    do {                                                                \
        ++al_test_checks;                                               \
        al_i64 al_a_ = AL_TEST_CAST(al_i64, actual);                    \
        al_i64 al_e_ = AL_TEST_CAST(al_i64, expected);                  \
        if (al_a_ != al_e_) {                                           \
            AL_FAIL_AT("%s: got %lld, want %lld", #actual,               \
                       AL_TEST_CAST(long long, al_a_),                   \
                       AL_TEST_CAST(long long, al_e_));                  \
        }                                                               \
    } while (0)

/* For approximate fixed-point results: |actual - expected| <= tol. */
#define AL_CHECK_NEAR_I64(actual, expected, tol)                        \
    do {                                                                \
        ++al_test_checks;                                               \
        al_i64 al_a_ = AL_TEST_CAST(al_i64, actual);                    \
        al_i64 al_e_ = AL_TEST_CAST(al_i64, expected);                  \
        al_i64 al_d_ = (al_a_ > al_e_) ? (al_a_ - al_e_) : (al_e_ - al_a_); \
        if (al_d_ > AL_TEST_CAST(al_i64, tol)) {                         \
            AL_FAIL_AT("%s: got %lld, want %lld +/- %lld (off by %lld)",  \
                       #actual, AL_TEST_CAST(long long, al_a_),          \
                       AL_TEST_CAST(long long, al_e_),                   \
                       AL_TEST_CAST(long long, tol),                     \
                       AL_TEST_CAST(long long, al_d_));                  \
        }                                                               \
    } while (0)

#define AL_CHECK_EQ_STATUS(actual, expected)                            \
    do {                                                                \
        ++al_test_checks;                                               \
        al_status al_a_ = (actual);                                     \
        al_status al_e_ = (expected);                                   \
        if (al_a_ != al_e_) {                                           \
            AL_FAIL_AT("%s: got %s, want %s", #actual,                   \
                       al_status_str(al_a_), al_status_str(al_e_));       \
        }                                                               \
    } while (0)

#define AL_CHECK_EQ_STR(actual, expected)                               \
    do {                                                                \
        ++al_test_checks;                                               \
        const char *al_a_ = (actual);                                   \
        const char *al_e_ = (expected);                                 \
        if (strcmp(al_a_, al_e_) != 0) {                                \
            AL_FAIL_AT("%s: got \"%s\", want \"%s\"", #actual, al_a_, al_e_); \
        }                                                               \
    } while (0)

/* Compare a byte range against a lowercase hex string.
 * AL_MAYBE_UNUSED because not every suite hashes anything, and an unused static
 * function in a header is a warning the suites should not have to suppress. */
AL_MAYBE_UNUSED static void al_test_check_hex(const char *what, const char *file,
                                              int line, const void *data,
                                              al_size len,
                                              const char *expected_hex) {
    ++al_test_checks;

    char got[257];
    if (len > 128u) {
        ++al_test_failures;
        (void)fprintf(stderr, "    FAIL %s:%d: %s: range too long to print\n",
                      file, line, what);
        return;
    }
    if (al_hex_encode(al_bytes_make(data, len), got, sizeof(got)) != AL_OK) {
        ++al_test_failures;
        (void)fprintf(stderr, "    FAIL %s:%d: %s: hex encode failed\n",
                      file, line, what);
        return;
    }
    if (strcmp(got, expected_hex) != 0) {
        ++al_test_failures;
        (void)fprintf(stderr, "    FAIL %s:%d: %s:\n      got  %s\n      want %s\n",
                      file, line, what, got, expected_hex);
    }
}

#define AL_CHECK_HEX(data, len, expected)                                \
    al_test_check_hex(#data, __FILE__, __LINE__, (data), (len), (expected))

#define AL_CHECK_HASH_HEX(hash, expected)                                \
    al_test_check_hex(#hash, __FILE__, __LINE__, (hash).bytes,            \
                      AL_HASH_SIZE, (expected))

/* Decode a hex literal into a fixed buffer. Test input only: it aborts the
 * process on malformed input, because a bad literal in a test is a typo, not a
 * condition to handle. */
AL_MAYBE_UNUSED static al_size al_test_unhex(const char *hex, void *out,
                                             al_size out_cap) {
    al_size len = 0u;
    if (al_hex_decode(hex, out, out_cap, &len) != AL_OK) {
        (void)fprintf(stderr, "altest: bad hex literal: %s\n", hex);
        exit(2);
    }
    return len;
}

/* --------------------------------------------------------------------------
 * Runner
 * -------------------------------------------------------------------------- */

#define AL_RUN(fn)                                                       \
    do {                                                                 \
        ++al_test_cases;                                                 \
        int al_before_ = al_test_failures;                               \
        fn();                                                            \
        (void)printf("  %-4s %s\n",                                      \
                     (al_test_failures == al_before_) ? "ok" : "FAIL",    \
                     #fn);                                               \
    } while (0)

#define AL_TEST_MAIN                                                     \
    static void al_test_body(void);                                      \
    int main(void) {                                                     \
        (void)printf("%s\n", AL_TEST_SUITE_NAME);                        \
        al_test_body();                                                  \
        (void)printf("%d checks in %d cases, %d failed\n",                \
                     al_test_checks, al_test_cases, al_test_failures);    \
        return (al_test_failures == 0) ? 0 : 1;                          \
    }                                                                    \
    static void al_test_body(void)

#endif /* ASTROLUNE_TESTS_ALTEST_H */
