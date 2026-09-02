/*
 * Internal score declarations shared across score*.c translation units.
 * NOT part of the public API.
 */

#ifndef ASTROLUNE_SCORE_INTERNAL_H
#define ASTROLUNE_SCORE_INTERNAL_H

#include "astrolune/potb.h"
#include "internal/common.h"

#include <stdlib.h>

/* Q32.32 helper for a literal fraction. */
#define AL_FX(num, den) al_fixed_from_ratio((al_i64)(num), (al_i64)(den))

/* score.c — shared static helpers */
al_fixed al_potb_error_rate(const al_potb_record *r);
int      al_fixed_cmp_asc(const void *a, const void *b);
al_fixed al_u32_diff_fx(al_u32 a, al_u32 b);

/* score_anti_domination.c — shared */
al_fixed al_potb_entropy_from_hist(const al_u32 *hist, al_u32 slots);

/* score_slash.c — shared */
al_bool  al_potb_exceeds_median(al_fixed rate, al_fixed median);

#endif /* ASTROLUNE_SCORE_INTERNAL_H */
