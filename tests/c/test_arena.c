/*
 * Arena allocator.
 *
 * The properties that matter are alignment, that a restore actually reclaims,
 * and that nothing overflows on absurd sizes. Alignment gets the most attention:
 * the block header is 24 bytes on a 64-bit target, so the payload is not
 * 16-byte aligned, and an implementation that computes padding from the offset
 * within the block instead of the absolute address hands out misaligned pointers
 * that happen to work on x86 and fault on stricter targets.
 */

#include "astrolune/arena.h"

#include "altest.h"

#define AL_TEST_SUITE_NAME "arena"

static al_bool al_is_aligned(const void *p, al_size align) {
    return (((uintptr_t)p & (uintptr_t)(align - 1u)) == 0u) ? AL_TRUE : AL_FALSE;
}

AL_TEST(init_and_destroy) {
    al_arena a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 0u), AL_OK);

    /* An unused arena reserves nothing. Nodes hold several of these per
     * subsystem, and an idle one must not cost a page. */
    AL_CHECK_EQ_U64(al_arena_used(&a), 0u);
    AL_CHECK_EQ_U64(al_arena_peak(&a), 0u);
    AL_CHECK(a.head == NULL);
    AL_CHECK_EQ_U64(a.total_bytes, 0u);

    al_arena_destroy(&a);

    /* Destroying twice, and destroying a null arena, must be safe: cleanup runs
     * on error paths that may not have initialised anything. */
    al_arena_destroy(&a);
    al_arena_destroy(NULL);

    AL_CHECK_EQ_STATUS(al_arena_init(NULL, 0u), AL_ERR_INVALID_ARG);
}

AL_TEST(alignment) {
    al_arena a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 256u), AL_OK);

    /* Interleave odd sizes so the cursor lands on every residue class. */
    for (al_size i = 0u; i < 200u; ++i) {
        void *p = al_arena_alloc(&a, (i % 37u) + 1u);
        AL_CHECK(p != NULL);
        AL_CHECK_MSG(al_is_aligned(p, AL_ARENA_ALIGN), "default alignment");
    }

    /* Every power-of-two alignment up to a cache line. */
    static const al_size aligns[] = {1u, 2u, 4u, 8u, 16u, 32u, 64u};
    for (al_size i = 0u; i < AL_COUNTOF(aligns); ++i) {
        for (al_size size = 1u; size <= 40u; size += 7u) {
            void *p = al_arena_alloc_aligned(&a, size, aligns[i]);
            AL_CHECK(p != NULL);
            AL_CHECK_MSG(al_is_aligned(p, aligns[i]), "explicit alignment");
        }
    }

    /* A non-power-of-two alignment is a programming error, not something to
     * round up silently. */
    AL_CHECK(al_arena_alloc_aligned(&a, 8u, 0u) == NULL);
    AL_CHECK(al_arena_alloc_aligned(&a, 8u, 3u) == NULL);
    AL_CHECK(al_arena_alloc_aligned(&a, 8u, 24u) == NULL);
    AL_CHECK(al_arena_alloc_aligned(NULL, 8u, 16u) == NULL);

    al_arena_destroy(&a);
}

AL_TEST(zero_size_allocation_is_unique) {
    al_arena a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 4096u), AL_OK);

    /* A zero-length collection is common (a block with no transactions), and its
     * backing pointer must be usable as an identity without special-casing. */
    void *p = al_arena_alloc(&a, 0u);
    void *q = al_arena_alloc(&a, 0u);
    AL_CHECK(p != NULL);
    AL_CHECK(q != NULL);
    AL_CHECK(p != q);

    al_arena_destroy(&a);
}

AL_TEST(allocations_do_not_overlap) {
    al_arena a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 128u), AL_OK);

    /* Fill each allocation with a distinct byte, then re-read them all. This is
     * the check that catches a padding miscalculation that hands out overlapping
     * ranges - a bug the alignment test alone would not see. */
    enum { N = 64 };
    al_u8  *ptrs[N];
    al_size sizes[N];

    for (al_size i = 0u; i < (al_size)N; ++i) {
        sizes[i] = (i % 23u) + 1u;
        ptrs[i]  = (al_u8 *)al_arena_alloc(&a, sizes[i]);
        AL_CHECK(ptrs[i] != NULL);
        memset(ptrs[i], (int)(i + 1u), sizes[i]);
    }

    for (al_size i = 0u; i < (al_size)N; ++i) {
        for (al_size j = 0u; j < sizes[i]; ++j) {
            AL_CHECK_EQ_U64(ptrs[i][j], (al_u8)(i + 1u));
        }
    }

    al_arena_destroy(&a);
}

AL_TEST(calloc_zeroes_and_checks_overflow) {
    al_arena a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 4096u), AL_OK);

    /* Dirty the block first, so zeroing is actually being observed rather than
     * fresh pages happening to be zero. */
    al_u8 *dirty = (al_u8 *)al_arena_alloc(&a, 512u);
    AL_CHECK(dirty != NULL);
    memset(dirty, 0xab, 512u);
    al_arena_reset(&a);

    al_u64 *v = AL_ARENA_NEW_ARRAY(&a, al_u64, 32u);
    AL_CHECK(v != NULL);
    for (al_size i = 0u; i < 32u; ++i) {
        AL_CHECK_EQ_U64(v[i], 0u);
    }

    al_u32 *one = AL_ARENA_NEW(&a, al_u32);
    AL_CHECK(one != NULL);
    AL_CHECK_EQ_U64(*one, 0u);

    /*
     * count * size must not wrap. An attacker-influenced element count reaching
     * an unchecked multiply is the classic path to a heap overflow, and the arena
     * is on the block-decoding path.
     */
    AL_CHECK(al_arena_calloc(&a, SIZE_MAX, 2u) == NULL);
    AL_CHECK(al_arena_calloc(&a, SIZE_MAX / 4u + 1u, 4u) == NULL);

    /* A single allocation larger than the address space cannot succeed either. */
    AL_CHECK(al_arena_alloc(&a, SIZE_MAX) == NULL);
    AL_CHECK(al_arena_alloc(&a, SIZE_MAX - 64u) == NULL);

    /* count of zero is legal and must not be reported as overflow. */
    AL_CHECK(al_arena_calloc(&a, 0u, 8u) != NULL);

    al_arena_destroy(&a);
}

AL_TEST(dup_and_strdup) {
    al_arena a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 4096u), AL_OK);

    static const al_u8 src[] = {1u, 2u, 3u, 4u, 5u};
    al_u8 *copy = (al_u8 *)al_arena_dup(&a, src, sizeof(src));
    AL_CHECK(copy != NULL);
    AL_CHECK((const al_u8 *)copy != src);
    AL_CHECK(memcmp(copy, src, sizeof(src)) == 0);

    char *s = al_arena_strdup(&a, "trocto");
    AL_CHECK(s != NULL);
    AL_CHECK_EQ_STR(s, "trocto");

    char *empty = al_arena_strdup(&a, "");
    AL_CHECK(empty != NULL);
    AL_CHECK_EQ_STR(empty, "");

    AL_CHECK(al_arena_strdup(&a, NULL) == NULL);

    al_arena_destroy(&a);
}

AL_TEST(save_and_restore) {
    al_arena a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 4096u), AL_OK);

    al_u8 *before = (al_u8 *)al_arena_alloc(&a, 64u);
    AL_CHECK(before != NULL);
    al_size used_before = al_arena_used(&a);

    al_arena_mark m = al_arena_save(&a);

    al_u8 *inner = (al_u8 *)al_arena_alloc(&a, 128u);
    AL_CHECK(inner != NULL);
    AL_CHECK(al_arena_used(&a) > used_before);

    al_arena_restore(&a, m);
    AL_CHECK_EQ_U64(al_arena_used(&a), used_before);

    /* The reclaimed range is handed out again - that is the whole point of a
     * scoped reset in a per-transaction loop. */
    al_u8 *again = (al_u8 *)al_arena_alloc(&a, 128u);
    AL_CHECK(again == inner);

    /* Allocations from before the mark are untouched. */
    memset(before, 0x5a, 64u);
    al_arena_restore(&a, m);
    for (al_size i = 0u; i < 64u; ++i) {
        AL_CHECK_EQ_U64(before[i], 0x5au);
    }

    /* Restoring twice to the same mark is idempotent, and restoring a null arena
     * is a no-op rather than a crash. */
    al_arena_restore(&a, m);
    AL_CHECK_EQ_U64(al_arena_used(&a), used_before);
    al_arena_restore(NULL, m);

    al_arena_destroy(&a);
}

AL_TEST(restore_across_blocks) {
    /* A tiny first block forces several blocks to be chained, so the restore has
     * to unwind the chain and not just rewind a cursor. */
    al_arena a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 64u), AL_OK);

    void *first = al_arena_alloc(&a, 32u);
    AL_CHECK(first != NULL);

    al_arena_mark m         = al_arena_save(&a);
    al_size       used_mark = al_arena_used(&a);
    al_size       total_mark = a.total_bytes;

    /* Enough to spill into new blocks. */
    for (al_size i = 0u; i < 64u; ++i) {
        AL_CHECK(al_arena_alloc(&a, 200u) != NULL);
    }
    AL_CHECK(a.total_bytes > total_mark);

    al_arena_restore(&a, m);
    AL_CHECK_EQ_U64(al_arena_used(&a), used_mark);
    AL_CHECK_EQ_U64(a.total_bytes, total_mark);

    /* A mark taken on an empty arena rewinds it completely. */
    al_arena b;
    AL_CHECK_EQ_STATUS(al_arena_init(&b, 64u), AL_OK);
    al_arena_mark zero_mark = al_arena_save(&b);
    AL_CHECK(zero_mark.block == NULL);
    for (al_size i = 0u; i < 16u; ++i) {
        AL_CHECK(al_arena_alloc(&b, 100u) != NULL);
    }
    al_arena_restore(&b, zero_mark);
    AL_CHECK_EQ_U64(al_arena_used(&b), 0u);
    AL_CHECK(b.head == NULL);
    AL_CHECK_EQ_U64(b.total_bytes, 0u);

    al_arena_destroy(&b);
    al_arena_destroy(&a);
}

AL_TEST(reset_keeps_capacity) {
    al_arena a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 64u), AL_OK);

    for (al_size i = 0u; i < 64u; ++i) {
        AL_CHECK(al_arena_alloc(&a, 300u) != NULL);
    }
    al_size peak = al_arena_peak(&a);
    AL_CHECK(peak > 0u);

    al_arena_reset(&a);
    AL_CHECK_EQ_U64(al_arena_used(&a), 0u);

    /*
     * Reset keeps the largest block, so the arena still holds capacity and the
     * next burst allocates nothing from the OS. That is observable without
     * reaching into the block header - which is an incomplete type outside
     * core/base/arena.c, on purpose - by checking that a fresh allocation the
     * kept block can serve does not change the reserved total.
     */
    AL_CHECK(a.head != NULL);
    AL_CHECK(a.total_bytes > 0u);

    al_size reserved = a.total_bytes;
    AL_CHECK(al_arena_alloc(&a, 300u) != NULL);
    AL_CHECK_EQ_U64(a.total_bytes, reserved);

    /* The peak survives a reset: it describes the arena's whole life, which is
     * what a node operator sizes a machine against. */
    AL_CHECK(al_arena_peak(&a) >= peak);

    al_arena_reset(NULL);

    /* Reset on a never-used arena is also fine. */
    al_arena fresh;
    AL_CHECK_EQ_STATUS(al_arena_init(&fresh, 0u), AL_OK);
    al_arena_reset(&fresh);
    AL_CHECK(fresh.head == NULL);
    AL_CHECK_EQ_U64(fresh.total_bytes, 0u);
    al_arena_destroy(&fresh);

    al_arena_destroy(&a);
}

AL_TEST(used_and_peak_are_consistent) {
    al_arena a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 1024u), AL_OK);

    /*
     * `used` is recomputed from the block chain on restore and accumulated
     * incrementally on allocate. Those two must agree, or the figure jumps at
     * every scope exit and capacity planning off `peak` becomes meaningless.
     */
    for (al_size i = 0u; i < 100u; ++i) {
        AL_CHECK(al_arena_alloc(&a, 1u) != NULL);
    }
    al_size incremental = al_arena_used(&a);

    al_arena_mark m = al_arena_save(&a);
    al_arena_restore(&a, m);
    AL_CHECK_EQ_U64(al_arena_used(&a), incremental);

    /* Peak never decreases and always bounds `used`. */
    AL_CHECK(al_arena_peak(&a) >= al_arena_used(&a));

    al_size peak = al_arena_peak(&a);
    al_arena_mark m2 = al_arena_save(&a);
    AL_CHECK(al_arena_alloc(&a, 4096u) != NULL);
    AL_CHECK(al_arena_peak(&a) > peak);
    al_size higher = al_arena_peak(&a);
    al_arena_restore(&a, m2);
    AL_CHECK_EQ_U64(al_arena_peak(&a), higher);

    /* And `used` never exceeds what was reserved. */
    AL_CHECK(al_arena_used(&a) <= a.total_bytes);

    AL_CHECK_EQ_U64(al_arena_used(NULL), 0u);
    AL_CHECK_EQ_U64(al_arena_peak(NULL), 0u);

    al_arena_destroy(&a);
}

AL_TEST(large_allocation_gets_its_own_block) {
    al_arena a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 1024u), AL_OK);

    /* A request far larger than the block size must be served rather than
     * failing, and must not force the arena to step its geometric size up to
     * match. Contract bytecode arrives in sizes the arena cannot predict. */
    al_u8 *big = (al_u8 *)al_arena_alloc(&a, 1u << 20);
    AL_CHECK(big != NULL);
    AL_CHECK(al_is_aligned(big, AL_ARENA_ALIGN));

    /* Writeable over its whole length - a short block would fault or corrupt. */
    memset(big, 0x33, 1u << 20);
    AL_CHECK_EQ_U64(big[0], 0x33u);
    AL_CHECK_EQ_U64(big[(1u << 20) - 1u], 0x33u);

    /* Small allocations still work afterwards. */
    AL_CHECK(al_arena_alloc(&a, 8u) != NULL);

    al_arena_destroy(&a);
}

AL_TEST_MAIN {
    AL_RUN(init_and_destroy);
    AL_RUN(alignment);
    AL_RUN(zero_size_allocation_is_unique);
    AL_RUN(allocations_do_not_overlap);
    AL_RUN(calloc_zeroes_and_checks_overflow);
    AL_RUN(dup_and_strdup);
    AL_RUN(save_and_restore);
    AL_RUN(restore_across_blocks);
    AL_RUN(reset_keeps_capacity);
    AL_RUN(used_and_peak_are_consistent);
    AL_RUN(large_allocation_gets_its_own_block);
}
