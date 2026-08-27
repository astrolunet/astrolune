/*
 * astrolune/arena.h - bump allocator with scoped reset.
 *
 * Why the core allocates this way
 * ------------------------------------------------------------------------
 * Executing a block is a burst of short-lived allocations - decoded
 * transactions, VM frames, Merkle proof nodes - that all die together when the
 * block is done. A general-purpose malloc/free pair is the wrong tool for that
 * shape: it costs a lock, it fragments over the lifetime of a long-running
 * validator, and freeing thousands of small nodes individually is pure overhead.
 *
 * An arena turns the whole burst into a pointer bump and the whole cleanup into
 * a single store. It also removes an entire bug class, because nothing in the
 * block-execution path calls free() at all, so there is nothing to
 * double-free, leak or use after freeing.
 *
 * Lifetime rule: memory from an arena is valid until the next reset of that
 * arena at or below the mark it was allocated after. Nothing in the core stores
 * an arena pointer across block boundaries.
 */

#ifndef ASTROLUNE_ARENA_H
#define ASTROLUNE_ARENA_H

#include "astrolune/base.h"

AL_EXTERN_C_BEGIN

/* Default alignment: 16 bytes, enough for every type the core allocates and for
 * SIMD loads on both x86-64 and ARM64. */
#define AL_ARENA_ALIGN 16

typedef struct al_arena_block al_arena_block;

typedef struct al_arena {
    al_arena_block *head;        /* newest block; allocation happens here    */
    al_size         block_size;  /* size of the next block to request        */
    al_size         total_bytes; /* reserved across all blocks               */
    al_size         used_bytes;  /* handed out, for diagnostics              */
    al_size         peak_bytes;  /* high-water mark, for capacity planning   */
} al_arena;

/* Position marker for scoped reuse. Opaque by convention. */
typedef struct al_arena_mark {
    al_arena_block *block;
    al_size         offset;
} al_arena_mark;

/*
 * Initialise an arena. `first_block_size` is a hint; 0 selects a 64 KiB default.
 * No memory is reserved until the first allocation, so an unused arena is free.
 */
AL_PUBLIC AL_NODISCARD al_status al_arena_init(al_arena *a, al_size first_block_size);

/* Release every block. The arena is reusable after this via al_arena_init. */
AL_PUBLIC void al_arena_destroy(al_arena *a);

/*
 * Allocate `size` bytes aligned to `align` (must be a power of two).
 * Returns NULL on overflow or allocation failure - callers must check.
 */
AL_PUBLIC AL_NODISCARD void *al_arena_alloc_aligned(al_arena *a, al_size size, al_size align);

/* Allocate with the default alignment. */
AL_PUBLIC AL_NODISCARD void *al_arena_alloc(al_arena *a, al_size size);

/* Allocate and zero. Use for anything whose uninitialised state would be
 * consensus-visible. */
AL_PUBLIC AL_NODISCARD void *al_arena_calloc(al_arena *a, al_size count, al_size size);

/* Copy `len` bytes into the arena and return the copy. */
AL_PUBLIC AL_NODISCARD void *al_arena_dup(al_arena *a, const void *src, al_size len);

/* Copy a NUL-terminated string into the arena. */
AL_PUBLIC AL_NODISCARD char *al_arena_strdup(al_arena *a, const char *s);

/* Typed allocation helpers. These read better at the call site and remove the
 * chance of a sizeof/type mismatch. */
#define AL_ARENA_NEW(arena, T) \
    AL_CAST(T *, al_arena_calloc((arena), 1, sizeof(T)))
#define AL_ARENA_NEW_ARRAY(arena, T, n) \
    AL_CAST(T *, al_arena_calloc((arena), (n), sizeof(T)))

/*
 * Scoped reuse.
 *
 *   al_arena_mark m = al_arena_save(a);
 *   ... allocate freely ...
 *   al_arena_restore(a, m);       // everything since the mark is reclaimed
 *
 * Restoring keeps the underlying blocks, so a repeated inner loop reuses the
 * same pages instead of asking the OS for more.
 */
AL_PUBLIC al_arena_mark al_arena_save(const al_arena *a);
AL_PUBLIC void          al_arena_restore(al_arena *a, al_arena_mark mark);

/* Reclaim everything, keeping the blocks for reuse. */
AL_PUBLIC void al_arena_reset(al_arena *a);

/* Bytes currently handed out, and the high-water mark over the arena's life.
 * Both include alignment padding, because padding is capacity the arena can no
 * longer hand out. The peak is what a node operator needs in order to size a
 * machine. */
AL_PUBLIC al_size al_arena_used(const al_arena *a);
AL_PUBLIC al_size al_arena_peak(const al_arena *a);

AL_EXTERN_C_END

#endif /* ASTROLUNE_ARENA_H */
