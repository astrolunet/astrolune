/*
 * PoTB committee selection, epoch seed and reward splitting.
 *
 * Everything here has to produce byte-identical results on every node, so the
 * randomness is a hash chain rather than a PRNG, every draw is integer
 * arithmetic, and the rejection loop below is bounded deterministically instead
 * of "until it works".
 */

#include "astrolune/potb.h"

#include "internal/common.h"

/* --------------------------------------------------------------------------
 * Deterministic draw
 *
 * A hash chain, not a random number generator. The distinction matters: every
 * node must produce the same sequence from the same seed, so there is no state
 * that could differ between machines - the chain is a pure function of (seed,
 * height, counter).
 * -------------------------------------------------------------------------- */

typedef struct al_potb_chain {
    al_hash256 seed;
    al_height  height;
    al_u64     counter;
    /* 32 bytes of chain output, consumed 8 at a time. Refilled by advancing the
     * counter, which costs one SHA-256 per four draws rather than one per draw. */
    al_hash256 block;
    al_size    used;
} al_potb_chain;

static void al_potb_chain_init(al_potb_chain *c, const al_hash256 *seed,
                              al_height height, al_u64 domain) {
    al_memzero(c, sizeof(*c));
    if (seed != NULL) {
        c->seed = *seed;
    }
    c->height  = height;
    /* The domain separates independent draws from one seed. Selection and
     * rotation at the same height must not walk the same sequence, or the nodes
     * rotation evicts would be exactly the ones selection picked first. */
    c->counter = domain;
    c->used    = AL_HASH_SIZE;   /* forces a refill on the first draw */
}

static void al_potb_chain_refill(al_potb_chain *c) {
    al_u8 buf[AL_HASH_SIZE + 8 + 8];
    al_memcpy(buf, c->seed.bytes, AL_HASH_SIZE);
    al_store_le64(buf + AL_HASH_SIZE, c->height);
    al_store_le64(buf + AL_HASH_SIZE + 8, c->counter);
    al_hash_tagged(AL_TAG_COMMITTEE, buf, sizeof(buf), &c->block);
    ++c->counter;
    c->used = 0u;
}

static al_u64 al_potb_chain_u64(al_potb_chain *c) {
    if (c->used + 8u > AL_HASH_SIZE) {
        al_potb_chain_refill(c);
    }
    al_u64 v = al_load_le64(c->block.bytes + c->used);
    c->used += 8u;
    return v;
}

/*
 * Uniform value in [0, bound).
 *
 * Rejection sampling rather than a plain modulo. With bound near 2^63 the modulo
 * of a u64 is biased by up to a factor of two toward the low half of the range,
 * and the bound here is a sum of weights that can genuinely reach that size - so
 * the bias would land on whichever nodes happen to sit early in the candidate
 * list. The retry count is capped so the function always terminates in bounded
 * time; falling through to the modulo after 64 rejections is a bias of order
 * 2^-64, which is not reachable.
 */
static al_u64 al_potb_chain_below(al_potb_chain *c, al_u64 bound) {
    if (bound == 0u) {
        return 0u;
    }
    al_u64 limit = UINT64_MAX - (UINT64_MAX % bound);
    for (int attempt = 0; attempt < 64; ++attempt) {
        al_u64 v = al_potb_chain_u64(c);
        if (v < limit) {
            return v % bound;
        }
    }
    return al_potb_chain_u64(c) % bound;
}

/* Draw domains. Distinct constants so two draws from one seed never coincide. */
#define AL_POTB_DOMAIN_SELECT 0u
#define AL_POTB_DOMAIN_EVICT  0x5000000000000000ull
#define AL_POTB_DOMAIN_REFILL 0xa000000000000000ull

/* --------------------------------------------------------------------------
 * Eligibility
 * -------------------------------------------------------------------------- */

/*
 * The weight a candidate is drawn with, or 0 if it may not be drawn at all.
 *
 * Level gates entry and also scales it: a validator is drawn at full weight, a
 * candidate at the discounted factor, and anything below is not drawn.
 */
static al_fixed al_potb_draw_weight(const al_potb_params *p,
                                   const al_potb_record *r,
                                   const al_potb_network_stats *net,
                                   al_u32 now_day) {
    if (r == NULL) {
        return 0;
    }
    al_potb_level level = al_potb_level_of(p, r, now_day);
    if (level == AL_POTB_LEVEL_BANNED || level == AL_POTB_LEVEL_RELAY) {
        return 0;
    }
    al_fixed w = al_potb_weight_total(p, r, net, now_day);
    if (w <= 0) {
        return 0;
    }
    if (level == AL_POTB_LEVEL_CANDIDATE) {
        w = al_fixed_mul(w, p->candidate_weight_factor);
    }
    /* A weight that rounds to zero cannot be drawn by the walk below, and
     * treating it as eligible would let it be counted in the total without ever
     * being selectable. One ulp is the smallest weight that is really drawable. */
    return (w > 0) ? w : 0;
}

/* --------------------------------------------------------------------------
 * Weighted sampling without replacement
 * -------------------------------------------------------------------------- */

/* One eligible candidate, as the sampler sees it. */
typedef struct al_potb_slot {
    const al_potb_record *record;
    al_fixed              weight;
} al_potb_slot;

/*
 * Draw one slot, remove it from the pool and return it.
 *
 * Linear walk over the remaining pool, then swap-remove. O(n) per draw, so O(kn)
 * for a committee of k - and with k at most 512 that is the term that matters,
 * not the constant. The alternative, a prefix-sum tree, would be O(k log n) but
 * needs the tree rebuilt after every removal, which is where the simple version
 * wins for these sizes.
 *
 * `*total` is kept in step so it does not have to be re-summed per draw. It is
 * recomputed rather than decremented when the running value would go negative,
 * which can only happen if a caller mutated a record mid-call.
 */
static al_bool al_potb_draw_one(al_potb_chain *chain, al_potb_slot *pool,
                               al_size *pool_len, al_fixed *total,
                               al_potb_slot *out) {
    if (*pool_len == 0u || *total <= 0) {
        return AL_FALSE;
    }

    al_u64 target = al_potb_chain_below(chain, (al_u64)*total);

    al_u64  acc   = 0u;
    al_size chosen = *pool_len - 1u;   /* the walk cannot fall off the end, but
                                        * a rounding shortfall must land on a
                                        * real index rather than one past it */
    for (al_size i = 0u; i < *pool_len; ++i) {
        acc += (al_u64)pool[i].weight;
        if (target < acc) {
            chosen = i;
            break;
        }
    }

    *out = pool[chosen];
    *total = al_fixed_sub(*total, pool[chosen].weight);
    if (*total < 0) {
        *total = 0;
    }

    /* Swap-remove. Order in the pool is not consensus-visible - the draw is
     * driven by the chain, and every node builds the pool from the same
     * candidate list in the same order, so every node performs the same swaps. */
    pool[chosen] = pool[*pool_len - 1u];
    --(*pool_len);
    return AL_TRUE;
}

/* Build the eligible pool into arena memory. Returns the pool or NULL if the
 * allocation failed; writes the length and the summed weight. */
static al_potb_slot *al_potb_build_pool(const al_potb_params *p,
                                       const al_potb_record *const *candidates,
                                       al_size candidate_count,
                                       const al_potb_network_stats *net,
                                       al_u32 now_day, al_arena *scratch,
                                       al_size *out_len, al_fixed *out_total) {
    *out_len   = 0u;
    *out_total = 0;

    al_potb_slot *pool = AL_ARENA_NEW_ARRAY(scratch, al_potb_slot,
                                            candidate_count);
    if (pool == NULL) {
        return NULL;
    }

    al_size  n     = 0u;
    al_fixed total = 0;
    for (al_size i = 0u; i < candidate_count; ++i) {
        al_fixed w = al_potb_draw_weight(p, candidates[i], net, now_day);
        if (w <= 0) {
            continue;
        }
        pool[n].record = candidates[i];
        pool[n].weight = w;
        ++n;
        total = al_fixed_add(total, w);
    }

    *out_len   = n;
    *out_total = total;
    return pool;
}

/* Drop the members of `exclude` from a pool. Used by rotation so a node cannot
 * be drawn into a seat it already holds. */
static void al_potb_pool_exclude(al_potb_slot *pool, al_size *pool_len,
                                al_fixed *total,
                                const al_potb_committee *exclude) {
    if (exclude == NULL) {
        return;
    }
    al_size n = *pool_len;
    for (al_size i = 0u; i < n;) {
        if (al_potb_committee_contains(exclude, &pool[i].record->identity)) {
            *total = al_fixed_sub(*total, pool[i].weight);
            pool[i] = pool[n - 1u];
            --n;
            /* No ++i: the swapped-in element has not been examined yet. */
        } else {
            ++i;
        }
    }
    if (*total < 0) {
        *total = 0;
    }
    *pool_len = n;
}

/* --------------------------------------------------------------------------
 * Selection
 * -------------------------------------------------------------------------- */

al_status al_potb_committee_select(const al_potb_params *p,
                                  const al_potb_record *const *candidates,
                                  al_size candidate_count,
                                  const al_potb_network_stats *net,
                                  const al_hash256 *seed, al_height height,
                                  al_u32 now_day, al_arena *scratch,
                                  al_potb_committee *out) {
    if (p == NULL || out == NULL || scratch == NULL || seed == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    if (candidates == NULL && candidate_count != 0u) {
        return AL_ERR_INVALID_ARG;
    }
    /* B3: committee size is randomized in [min, max] per epoch. */
    al_u32 size_min = p->committee_size_min;
    al_u32 size_max = p->committee_size_max;
    if (size_min == 0u || size_min > size_max) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (size_max > AL_POTB_MAX_COMMITTEE) {
        return AL_ERR_OUT_OF_RANGE;
    }

    al_memzero(out, sizeof(*out));
    out->formed_at = height;
    out->seed      = *seed;

    if (candidate_count == 0u) {
        return AL_ERR_NOT_FOUND;
    }

    al_arena_mark mark = al_arena_save(scratch);

    al_size  pool_len = 0u;
    al_fixed total    = 0;
    al_potb_slot *pool = al_potb_build_pool(p, candidates, candidate_count, net,
                                            now_day, scratch, &pool_len, &total);
    if (pool == NULL) {
        al_arena_restore(scratch, mark);
        return AL_ERR_OUT_OF_MEMORY;
    }
    if (pool_len == 0u) {
        al_arena_restore(scratch, mark);
        return AL_ERR_NOT_FOUND;
    }

    al_potb_chain chain;
    al_potb_chain_init(&chain, seed, height, AL_POTB_DOMAIN_SELECT);

    /* B3: Derive a randomized committee size from the hash chain.
     * size = size_min + (chain_u64 % (size_max - size_min + 1)). */
    al_u64 range = (al_u64)size_max - (al_u64)size_min + 1u;
    al_u32 want = size_min + (al_u32)(al_potb_chain_u64(&chain) % range);

    /* Fewer eligible nodes than the target committee is not a failure. A network
     * on its first week has a handful of qualifying nodes, and a chain that
     * refused to form a committee until it had a hundred would never start. */
    if ((al_u64)want > (al_u64)pool_len) {
        want = (al_u32)pool_len;
    }

    for (al_u32 i = 0u; i < want; ++i) {
        al_potb_slot slot;
        if (!al_potb_draw_one(&chain, pool, &pool_len, &total, &slot)) {
            break;
        }
        out->members[out->size] = slot.record->identity;
        out->weights[out->size] = slot.weight;
        ++out->size;
    }

    al_arena_restore(scratch, mark);
    return (out->size > 0u) ? AL_OK : AL_ERR_NOT_FOUND;
}

/* --------------------------------------------------------------------------
 * Rotation
 * -------------------------------------------------------------------------- */

/* Find a candidate record by identity. Linear, and called at most once per
 * rotated seat, so at most ~10% of 512 per block. */
static const al_potb_record *al_potb_find(const al_potb_record *const *candidates,
                                         al_size count, const al_pubkey *pk) {
    for (al_size i = 0u; i < count; ++i) {
        if (candidates[i] == NULL) {
            continue;
        }
        if (al_bytes_eq(al_bytes_make(candidates[i]->identity.bytes,
                                      AL_PUBKEY_SIZE),
                        al_bytes_make(pk->bytes, AL_PUBKEY_SIZE))) {
            return candidates[i];
        }
    }
    return NULL;
}

/* Remove seat `idx`, preserving nothing about order. */
static void al_potb_committee_remove(al_potb_committee *c, al_u32 idx) {
    if (idx >= c->size) {
        return;
    }
    c->members[idx] = c->members[c->size - 1u];
    c->weights[idx] = c->weights[c->size - 1u];
    --c->size;
}

al_status al_potb_committee_rotate(const al_potb_params *p,
                                  al_potb_committee *committee,
                                  const al_potb_record *const *candidates,
                                  al_size candidate_count,
                                  const al_potb_network_stats *net,
                                  const al_hash256 *seed, al_height height,
                                  al_u32 now_day, al_arena *scratch) {
    if (p == NULL || committee == NULL || seed == NULL || scratch == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    if (candidates == NULL && candidate_count != 0u) {
        return AL_ERR_INVALID_ARG;
    }
    /* B3: committee size range check. */
    al_u32 size_min = p->committee_size_min;
    al_u32 size_max = p->committee_size_max;
    if (size_min == 0u || size_min > size_max) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (size_max > AL_POTB_MAX_COMMITTEE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (committee->size > AL_POTB_MAX_COMMITTEE) {
        return AL_ERR_OUT_OF_RANGE;
    }

    /*
     * Evict anyone who has stopped being eligible, before counting rotations.
     *
     * A member proven to have double-signed since the committee formed must leave
     * now, not when its slot happens to come up. Waiting would leave a node the
     * chain has already condemned voting on finality for up to ten more blocks,
     * which no amount of rotation-budget tidiness justifies.
     */
    for (al_u32 i = 0u; i < committee->size;) {
        const al_potb_record *rec = al_potb_find(candidates, candidate_count,
                                                &committee->members[i]);
        /* A member that has vanished from the candidate set is also gone: the set
         * is the chain's view of who exists, and a seat held by a record nobody
         * has is unauditable. */
        if (rec == NULL ||
            al_potb_draw_weight(p, rec, net, now_day) <= 0) {
            al_potb_committee_remove(committee, i);
            continue;   /* the swapped-in member has not been checked yet */
        }
        ++i;
    }

    /*
     * How many seats to turn over. round(fraction * size), floored at one so that
     * rotation always makes progress: with a size of 5 and a fraction of 0.1 the
     * exact answer is 0.5, and rounding that to zero would freeze the committee
     * for the rest of its life - the exact predictability partial rotation exists
     * to prevent.
     */
    al_u32 rotate = 0u;
    if (committee->size > 0u) {
        al_fixed n = al_fixed_mul(al_fixed_from_int((al_i64)committee->size),
                                  p->rotation_fraction);
        al_i64 rounded = al_fixed_to_int_round(n);
        if (rounded < 1) {
            rounded = 1;
        }
        if ((al_u64)rounded > (al_u64)committee->size) {
            rounded = (al_i64)committee->size;
        }
        rotate = (al_u32)rounded;
    }

    /* Evict the rotating seats, chosen by the chain so no member can predict
     * which of its peers will be replaced. */
    al_potb_chain evict;
    al_potb_chain_init(&evict, seed, height, AL_POTB_DOMAIN_EVICT);
    for (al_u32 i = 0u; i < rotate && committee->size > 0u; ++i) {
        al_u64 idx = al_potb_chain_below(&evict, (al_u64)committee->size);
        al_potb_committee_remove(committee, (al_u32)idx);
    }

    /* Refill from the eligible pool, excluding sitting members. */
    al_arena_mark mark = al_arena_save(scratch);

    al_size  pool_len = 0u;
    al_fixed total    = 0;
    al_potb_slot *pool = al_potb_build_pool(p, candidates, candidate_count, net,
                                            now_day, scratch, &pool_len, &total);
    if (pool == NULL) {
        al_arena_restore(scratch, mark);
        return AL_ERR_OUT_OF_MEMORY;
    }
    al_potb_pool_exclude(pool, &pool_len, &total, committee);

    al_potb_chain refill;
    al_potb_chain_init(&refill, seed, height, AL_POTB_DOMAIN_REFILL);

    /* B3: refill to the randomized target size (derived from the chain). */
    al_u64 range_r = (al_u64)size_max - (al_u64)size_min + 1u;
    al_u32 target = size_min + (al_u32)(al_potb_chain_u64(&refill) % range_r);

    while (committee->size < target && pool_len > 0u) {
        al_potb_slot slot;
        if (!al_potb_draw_one(&refill, pool, &pool_len, &total, &slot)) {
            break;
        }
        committee->members[committee->size] = slot.record->identity;
        committee->weights[committee->size] = slot.weight;
        ++committee->size;
    }

    al_arena_restore(scratch, mark);

    /* The seed is recorded so the rotation is auditable, but formed_at is not
     * touched: it dates the committee's formation, and rotation extends a
     * committee rather than creating one. Overwriting it would break the
     * lifetime accounting the caller does against
     * committee_lifetime_blocks. */
    committee->seed = *seed;

    /* An empty committee means no node in the candidate set is eligible, which is
     * a halted chain and must not be reported as success. */
    return (committee->size > 0u) ? AL_OK : AL_ERR_NOT_FOUND;
}

al_bool al_potb_committee_contains(const al_potb_committee *c,
                                  const al_pubkey *pk) {
    if (c == NULL || pk == NULL) {
        return AL_FALSE;
    }
    al_u32 size = (c->size <= AL_POTB_MAX_COMMITTEE) ? c->size
                                                     : AL_POTB_MAX_COMMITTEE;
    for (al_u32 i = 0u; i < size; ++i) {
        /* Plain comparison, not constant-time: committee membership is public
         * information, published in every block. */
        if (al_bytes_eq(al_bytes_make(c->members[i].bytes, AL_PUBKEY_SIZE),
                        al_bytes_make(pk->bytes, AL_PUBKEY_SIZE))) {
            return AL_TRUE;
        }
    }
    return AL_FALSE;
}

/* --------------------------------------------------------------------------
 * Epoch seed
 * -------------------------------------------------------------------------- */

void al_potb_epoch_seed_commit(const al_pubkey *contributor,
                              const al_hash256 *reveal, al_hash256 *out) {
    if (out == NULL) {
        return;
    }
    if (contributor == NULL || reveal == NULL) {
        *out = al_hash_zero();
        return;
    }
    al_u8 buf[AL_PUBKEY_SIZE + AL_HASH_SIZE];
    al_memcpy(buf, contributor->bytes, AL_PUBKEY_SIZE);
    al_memcpy(buf + AL_PUBKEY_SIZE, reveal->bytes, AL_HASH_SIZE);
    /* Bound to the contributor's key so a commitment cannot be copied from
     * another participant and claimed - which would otherwise let a node commit
     * to a value it does not know and reveal nothing. */
    al_hash_tagged(AL_TAG_EPOCH_COMMIT, buf, sizeof(buf), out);
}

al_bool al_potb_epoch_seed_check(const al_pubkey *contributor,
                                const al_hash256 *reveal,
                                const al_hash256 *commitment) {
    if (contributor == NULL || reveal == NULL || commitment == NULL) {
        return AL_FALSE;
    }
    al_hash256 expected;
    al_potb_epoch_seed_commit(contributor, reveal, &expected);
    return al_bytes_eq_ct(al_bytes_make(expected.bytes, AL_HASH_SIZE),
                          al_bytes_make(commitment->bytes, AL_HASH_SIZE));
}

void al_potb_epoch_seed_mix(al_hash256 *seed, const al_pubkey *contributor,
                           const al_hash256 *reveal) {
    if (seed == NULL || contributor == NULL || reveal == NULL) {
        return;
    }
    al_u8 buf[AL_PUBKEY_SIZE + AL_HASH_SIZE];
    al_memcpy(buf, contributor->bytes, AL_PUBKEY_SIZE);
    al_memcpy(buf + AL_PUBKEY_SIZE, reveal->bytes, AL_HASH_SIZE);

    al_hash256 contribution;
    /* AL_TAG_EPOCH_SEED, not AL_TAG_EPOCH_COMMIT. See the note in potb.h: if
     * these shared a tag the commit round would publish the seed. */
    al_hash_tagged(AL_TAG_EPOCH_SEED, buf, sizeof(buf), &contribution);

    /* XOR, so the fold is commutative and the order reveals arrive in cannot
     * change the result. A hash chain over the reveals would be order-dependent,
     * and the order is whatever the network delivers - which is to say,
     * something a well-placed adversary can influence. */
    for (al_size i = 0u; i < AL_HASH_SIZE; ++i) {
        seed->bytes[i] ^= contribution.bytes[i];
    }
}

void al_potb_epoch_seed_finalise(const al_hash256 *mixed, al_u64 epoch,
                                const al_vdf_output *vdf, al_hash256 *out) {
    if (out == NULL) {
        return;
    }
    if (mixed == NULL) {
        *out = al_hash_zero();
        return;
    }

    /* The epoch number is bound in so the same set of reveals cannot be replayed
     * into a later epoch to reproduce a known committee. */
    al_u8   buf[AL_HASH_SIZE + 8 + AL_HASH_SIZE + 8];
    al_size len = 0u;

    al_memcpy(buf, mixed->bytes, AL_HASH_SIZE);
    len += AL_HASH_SIZE;
    al_store_le64(buf + len, epoch);
    len += 8u;

    if (vdf != NULL) {
        al_memcpy(buf + len, vdf->value.bytes, AL_HASH_SIZE);
        len += AL_HASH_SIZE;
        /* Iteration count is bound in as well: without it, two VDF outputs at
         * different difficulties would be interchangeable and a participant
         * could pick the cheaper one. */
        al_store_le64(buf + len, vdf->iterations);
        len += 8u;
    }

    al_hash_tagged(AL_TAG_EPOCH_SEED, buf, len, out);
}

/* --------------------------------------------------------------------------
 * Rewards
 * -------------------------------------------------------------------------- */

/*
 * floor(amount * bp / 10000) with no overflow and no 128-bit type.
 *
 * The direct form overflows for any amount above 1.8e15, which is well inside the
 * representable supply. Splitting into quotient and remainder is exact: the
 * remainder is below 10000 and bp is at most 10000, so the product is at most
 * 1e8. MSVC has no __int128, so this is the portable form rather than a
 * preference.
 */
static al_amount al_bp_of(al_amount amount, al_u16 bp) {
    al_amount q = amount / 10000u;
    al_amount r = amount % 10000u;
    return q * (al_amount)bp + (r * (al_amount)bp) / 10000u;
}

/*
 * floor(amount * frac) where frac is Q32.32 in [0, 1].
 *
 * Same split, for the same reason: amount * frac would need 96 bits. The high and
 * low halves of amount are scaled separately, which is exact because the shift is
 * by exactly the fraction width.
 */
static al_amount al_scale_by_fixed(al_amount amount, al_fixed frac) {
    if (frac <= 0) {
        return 0u;
    }
    if (frac > AL_FIXED_ONE) {
        frac = AL_FIXED_ONE;   /* a share above 1 is a caller bug, not a payout */
    }
    al_u64 f  = (al_u64)frac;
    al_u64 hi = amount >> AL_FIXED_FRAC_BITS;
    al_u64 lo = amount & 0xffffffffull;
    return hi * f + ((lo * f) >> AL_FIXED_FRAC_BITS);
}

/*
 * floor(amount * mult) where mult is Q32.32 and may exceed 1, saturating rather
 * than wrapping.
 *
 * al_scale_by_fixed clamps its fraction to 1 because both of its callers
 * distribute a share *of* a bucket, where a factor above 1 really would be a
 * caller bug. The reward cap is the one place that scales *up*, and passing 3.0
 * to the share version silently yielded 1.0 - which turned "no more than
 * reward_max_multiple times the flat share" into "exactly the flat share", so
 * out->total exceeded the cap on every call and the trim below zeroed the
 * weighted and bonded buckets every time. Forty percent of every block reward.
 *
 * Split into integer and fraction parts so neither half can overflow: the
 * integer half is range-checked before multiplying, and the fraction half is
 * below 1 by construction so it cannot exceed `amount`. No __int128, because
 * MSVC has none.
 */
static al_amount al_mul_amount_sat(al_amount amount, al_fixed mult) {
    if (mult <= 0) {
        return 0u;
    }
    al_u64 f  = (al_u64)mult;
    al_u64 ip = f >> AL_FIXED_FRAC_BITS;
    al_u64 fp = f & 0xffffffffull;

    al_u64 whole = 0u;
    if (ip != 0u) {
        if (amount > UINT64_MAX / ip) {
            return UINT64_MAX;
        }
        whole = amount * ip;
    }
    al_u64 frac = (amount >> AL_FIXED_FRAC_BITS) * fp +
                  (((amount & 0xffffffffull) * fp) >> AL_FIXED_FRAC_BITS);
    if (whole > UINT64_MAX - frac) {
        return UINT64_MAX;
    }
    return whole + frac;
}

/*
 * Q32.32 ratio of two unsigned amounts.
 *
 * al_fixed_from_ratio takes signed arguments, and al_amount is unsigned with a
 * representable range that reaches past INT64_MAX. Casting a bond above that
 * straight to al_i64 would make it negative and produce a negative share, so both
 * operands are shifted down together until they fit. Shifting both preserves the
 * ratio; the precision lost is in bits far below the Q32.32 resolution.
 */
static al_fixed al_ratio_u64(al_u64 n, al_u64 d) {
    if (d == 0u) {
        return 0;
    }
    while (n > (al_u64)INT64_MAX || d > (al_u64)INT64_MAX) {
        n >>= 1;
        d >>= 1;
        if (d == 0u) {
            return 0;
        }
    }
    return al_fixed_from_ratio((al_i64)n, (al_i64)d);
}

void al_potb_reward_for(const al_potb_params *p, al_amount block_reward,
                       const al_potb_committee *committee, al_u32 member_index,
                       al_amount member_bond, al_amount total_bond,
                       al_potb_reward_split *out) {
    if (out == NULL) {
        return;
    }
    al_memzero(out, sizeof(*out));
    if (p == NULL || committee == NULL || committee->size == 0u ||
        member_index >= committee->size) {
        return;
    }

    /* --- flat: an equal share of the flat bucket ------------------------- */
    al_amount flat_bucket = al_bp_of(block_reward, p->reward_flat_bp);
    /* Integer division, so the remainder is not paid out. That is deliberate:
     * the leftover is at most (committee_size - 1) base units per block, and
     * distributing it would need a tie-break rule that every node computes
     * identically - a consensus rule for a few billionths of a token. It is
     * burned instead, and the supply schedule accounts for it. */
    out->flat = flat_bucket / (al_amount)committee->size;

    /* --- weighted: share of the weighted bucket, by selection weight ----- */
    al_fixed total_weight = 0;
    for (al_u32 i = 0u; i < committee->size; ++i) {
        total_weight = al_fixed_add(total_weight, committee->weights[i]);
    }
    if (total_weight > 0) {
        al_fixed share = al_fixed_div(committee->weights[member_index],
                                      total_weight);
        out->weighted = al_scale_by_fixed(
            al_bp_of(block_reward, p->reward_weighted_bp), share);
    }

    /* --- bonded: share of the bonded bucket, by bond -------------------- */
    /*
     * The bond buys a share of this bucket and nothing else. It is not in the
     * weight formula, it is not in the selection draw, and it is not in the
     * quorum count. A bond that bought any of those would make PoTB
     * stake-weighted consensus with a different name on it, which is the one
     * thing the design is trying not to be.
     *
     * Unbonded members receive nothing here, and that is the whole extent of the
     * disadvantage: they keep their full flat and weighted shares, so running
     * without a bond is a smaller reward, never a smaller vote.
     */
    if (total_bond > 0u && member_bond > 0u) {
        al_amount bond = (member_bond <= total_bond) ? member_bond : total_bond;
        al_fixed  share = al_ratio_u64(bond, total_bond);
        out->bonded = al_scale_by_fixed(
            al_bp_of(block_reward, p->reward_bonded_bp), share);
    }

    out->total = out->flat + out->weighted + out->bonded;

    /* --- cap ------------------------------------------------------------- */
    /* No node may take more than reward_max_multiple times the flat share. This
     * is the last line of defence on reward concentration: even if the weight
     * calculation is wrong, or a cluster slips past every heuristic, the payout
     * per identity is bounded. */
    al_amount cap = al_mul_amount_sat(out->flat, p->reward_max_multiple);
    if (p->reward_max_multiple > AL_FIXED_ONE && cap < out->flat) {
        cap = out->flat;   /* the scale saturated; never cap below the flat share */
    }
    if (out->total > cap) {
        al_amount excess = out->total - cap;
        /* Trim the discretionary buckets first, in reverse order of how much
         * they are meant to be earned: bonded, then weighted. The flat share is
         * never trimmed - it is the payment for having done the work. */
        al_amount take = (excess < out->bonded) ? excess : out->bonded;
        out->bonded -= take;
        excess      -= take;
        take = (excess < out->weighted) ? excess : out->weighted;
        out->weighted -= take;
        out->total = out->flat + out->weighted + out->bonded;
    }
}
