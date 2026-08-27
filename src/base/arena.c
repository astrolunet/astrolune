/*
 * Bump allocator. See astrolune/arena.h for the rationale.
 *
 * Blocks are chained newest-first and grow geometrically, so an arena that ends
 * up needing a lot of memory converges on few large blocks instead of many
 * small ones. A request larger than the current block size gets its own
 * right-sized block, which keeps one big allocation from wasting a whole
 * geometric step.
 */

#include "astrolune/arena.h"

#include "internal/common.h"

#include <stdlib.h>

#define AL_ARENA_DEFAULT_BLOCK (64u * 1024u)
#define AL_ARENA_MAX_BLOCK     (8u * 1024u * 1024u)

struct al_arena_block {
    al_arena_block *next;
    al_size         capacity;
    al_size         used;
    /* Payload follows the header in the same allocation, so there is exactly one
     * malloc per block.
     *
     * Note the header is 24 bytes on a 64-bit target, so `data` is *not*
     * 16-byte aligned. Alignment is therefore computed from the absolute
     * address of the cursor rather than from its offset within the block - see
     * al_arena_alloc_aligned. Getting this wrong would hand out misaligned
     * pointers that happen to work on x86 and fault on stricter targets. */
    al_u8 data[];
};

static al_bool al_is_pow2(al_size v) {
    return (v != 0u && (v & (v - 1u)) == 0u) ? AL_TRUE : AL_FALSE;
}

/* Bytes of padding needed at `p` to reach `align`. */
static al_size al_align_padding(const al_u8 *p, al_size align) {
    al_size misaligned = (al_size)((uintptr_t)p & (uintptr_t)(align - 1u));
    return (misaligned == 0u) ? 0u : (align - misaligned);
}

al_status al_arena_init(al_arena *a, al_size first_block_size) {
    if (a == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    a->head        = NULL;
    a->block_size  = (first_block_size != 0u) ? first_block_size
                                              : AL_ARENA_DEFAULT_BLOCK;
    a->total_bytes = 0u;
    a->used_bytes  = 0u;
    a->peak_bytes  = 0u;
    return AL_OK;
}

void al_arena_destroy(al_arena *a) {
    if (a == NULL) {
        return;
    }
    al_arena_block *b = a->head;
    while (b != NULL) {
        al_arena_block *next = b->next;
        free(b);
        b = next;
    }
    a->head        = NULL;
    a->total_bytes = 0u;
    a->used_bytes  = 0u;
    /* peak_bytes is deliberately preserved: it is a diagnostic about this
     * arena's whole life, and destroy is where it usually gets read. */
}

/* Chain on a new block big enough for `need` bytes at `align`. */
static al_bool al_arena_grow(al_arena *a, al_size need, al_size align) {
    /* Reserve worst-case padding so the caller's alignment is satisfiable from an
     * arbitrary block start. Check the addition first: `need` can come from a
     * length field in a decoded block, so a request near SIZE_MAX must fail here
     * rather than wrap into a small allocation that the caller then overruns. */
    if (need > SIZE_MAX - align) {
        return AL_FALSE;
    }
    al_size want = need + align;

    if (want < a->block_size) {
        want = a->block_size;
    }

    al_size header = offsetof(al_arena_block, data);
    if (want > SIZE_MAX - header) {
        return AL_FALSE;
    }

    al_arena_block *b = (al_arena_block *)malloc(header + want);
    if (b == NULL) {
        return AL_FALSE;
    }
    b->next     = a->head;
    b->capacity = want;
    b->used     = 0u;
    a->head     = b;

    a->total_bytes += want;

    /* Geometric growth, capped so a long-lived arena does not request
     * increasingly enormous contiguous blocks. */
    if (a->block_size < AL_ARENA_MAX_BLOCK) {
        a->block_size *= 2u;
        if (a->block_size > AL_ARENA_MAX_BLOCK) {
            a->block_size = AL_ARENA_MAX_BLOCK;
        }
    }
    return AL_TRUE;
}

void *al_arena_alloc_aligned(al_arena *a, al_size size, al_size align) {
    if (a == NULL || !al_is_pow2(align)) {
        return NULL;
    }
    if (size == 0u) {
        /* Zero-size allocations return a valid, non-NULL, uniquely-owned
         * pointer so that callers need not special-case empty collections. */
        size = 1u;
    }

    al_arena_block *b = a->head;
    if (b != NULL) {
        al_size pad = al_align_padding(b->data + b->used, align);
        if (pad <= b->capacity - b->used &&
            size <= b->capacity - b->used - pad) {
            void *p = b->data + b->used + pad;
            b->used += pad + size;
            /* Alignment padding counts as consumed. It is bytes the arena can no
             * longer hand out, so excluding it would understate what a node
             * actually needs - and al_arena_restore recomputes this figure from
             * the block chain, where the padding is unavoidably included. The two
             * paths have to agree or `used` jumps at every scope exit. */
            a->used_bytes += pad + size;
            if (a->used_bytes > a->peak_bytes) {
                a->peak_bytes = a->used_bytes;
            }
            return p;
        }
    }

    if (!al_arena_grow(a, size, align)) {
        return NULL;
    }

    b = a->head;
    al_size pad = al_align_padding(b->data + b->used, align);
    /* grow() reserved size + align bytes, so padding plus size always fits. */
    AL_ASSERT(pad + size <= b->capacity - b->used);
    void *p = b->data + b->used + pad;
    b->used += pad + size;
    a->used_bytes += pad + size;
    if (a->used_bytes > a->peak_bytes) {
        a->peak_bytes = a->used_bytes;
    }
    return p;
}

void *al_arena_alloc(al_arena *a, al_size size) {
    return al_arena_alloc_aligned(a, size, AL_ARENA_ALIGN);
}

void *al_arena_calloc(al_arena *a, al_size count, al_size size) {
    if (count != 0u && size > SIZE_MAX / count) {
        return NULL;   /* multiplication would wrap */
    }
    al_size total = count * size;
    void   *p     = al_arena_alloc_aligned(a, total, AL_ARENA_ALIGN);
    if (p != NULL) {
        al_memzero(p, total);
    }
    return p;
}

void *al_arena_dup(al_arena *a, const void *src, al_size len) {
    void *p = al_arena_alloc(a, len);
    if (p != NULL) {
        al_memcpy(p, src, len);
    }
    return p;
}

char *al_arena_strdup(al_arena *a, const char *s) {
    if (s == NULL) {
        return NULL;
    }
    al_size len = strlen(s);
    char   *p   = (char *)al_arena_alloc(a, len + 1u);
    if (p != NULL) {
        al_memcpy(p, s, len);
        p[len] = '\0';
    }
    return p;
}

al_arena_mark al_arena_save(const al_arena *a) {
    al_arena_mark m;
    m.block  = (a != NULL) ? a->head : NULL;
    m.offset = (a != NULL && a->head != NULL) ? a->head->used : 0u;
    return m;
}

void al_arena_restore(al_arena *a, al_arena_mark mark) {
    if (a == NULL) {
        return;
    }

    /* Free the blocks added since the mark. They cannot be reused in place
     * because the mark's block must become the head again. */
    while (a->head != NULL && a->head != mark.block) {
        al_arena_block *next = a->head->next;
        a->total_bytes -= a->head->capacity;
        free(a->head);
        a->head = next;
    }

    if (a->head != NULL) {
        AL_ASSERT(mark.offset <= a->head->used);
        a->head->used = mark.offset;
    }

    /* Recompute used_bytes from the surviving chain rather than tracking a
     * delta: restoring across several blocks makes a delta easy to get wrong,
     * and this runs once per scope exit, not per allocation. */
    al_size used = 0u;
    for (const al_arena_block *b = a->head; b != NULL; b = b->next) {
        used += b->used;
    }
    a->used_bytes = used;
}

void al_arena_reset(al_arena *a) {
    if (a == NULL) {
        return;
    }
    /* Keep only the largest block and reuse it. Dropping the rest stops a
     * long-lived arena from holding every block it ever needed, while keeping
     * one means the common case allocates nothing at all. */
    al_arena_block *largest = a->head;
    for (al_arena_block *b = a->head; b != NULL; b = b->next) {
        if (b->capacity > largest->capacity) {
            largest = b;
        }
    }

    al_arena_block *b = a->head;
    while (b != NULL) {
        al_arena_block *next = b->next;
        if (b != largest) {
            free(b);
        }
        b = next;
    }

    a->head = largest;
    if (largest != NULL) {
        largest->next = NULL;
        largest->used = 0u;
        a->total_bytes = largest->capacity;
    } else {
        a->total_bytes = 0u;
    }
    a->used_bytes = 0u;
}

al_size al_arena_used(const al_arena *a) {
    return (a != NULL) ? a->used_bytes : 0u;
}

al_size al_arena_peak(const al_arena *a) {
    return (a != NULL) ? a->peak_bytes : 0u;
}
