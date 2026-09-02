/*
 * Anti-domination metrics (A1), behavioral entropy (A3), profile change (B2).
 */

#include "score_internal.h"

/* --------------------------------------------------------------------------
 * Anti-domination metrics (A1)
 * -------------------------------------------------------------------------- */

al_fixed al_potb_gini(const al_fixed *weights, al_size count) {
    if (weights == NULL || count == 0u) {
        return 0;
    }
    al_fixed buf[AL_POTB_MAX_COMMITTEE];
    al_size n = count < AL_POTB_MAX_COMMITTEE ? count : AL_POTB_MAX_COMMITTEE;
    al_memcpy(buf, weights, n * sizeof(al_fixed));
    qsort(buf, n, sizeof(al_fixed), al_fixed_cmp_asc);

    al_fixed sum = 0;
    for (al_size i = 0u; i < n; ++i) {
        sum = al_fixed_add(sum, buf[i]);
    }
    if (sum <= 0) {
        return 0;
    }

    al_fixed weighted = 0;
    for (al_size i = 0u; i < n; ++i) {
        al_fixed rank = al_fixed_from_int((al_i64)(i + 1u));
        weighted = al_fixed_add(weighted,
                                al_fixed_mul(rank, buf[i]));
    }
    al_fixed n_fx = al_fixed_from_int((al_i64)n);
    al_fixed gini = al_fixed_mul(
        al_fixed_from_int(2),
        al_fixed_div(weighted, al_fixed_mul(n_fx, sum)));
    gini = al_fixed_sub(gini, al_fixed_div(
        al_fixed_add(n_fx, AL_FIXED_ONE), n_fx));
    return al_fixed_clamp(gini, 0, AL_FIXED_ONE);
}

al_fixed al_potb_hhi(const al_fixed *weights, al_size count) {
    if (weights == NULL || count == 0u) {
        return 0;
    }
    al_fixed sum = 0;
    for (al_size i = 0u; i < count; ++i) {
        sum = al_fixed_add(sum, weights[i]);
    }
    if (sum <= 0) {
        return 0;
    }
    al_fixed hhi = 0;
    for (al_size i = 0u; i < count; ++i) {
        al_fixed share = al_fixed_div(weights[i], sum);
        hhi = al_fixed_add(hhi, al_fixed_mul(share, share));
    }
    return hhi;
}

void al_potb_independence_check(
    const al_potb_params *p,
    const al_potb_record *const *records, al_size record_count,
    const al_potb_network_stats *net, al_u32 now_day,
    al_potb_independence_stats *out) {
    if (out == NULL) {
        return;
    }
    al_memzero(out, sizeof(*out));
    if (p == NULL || records == NULL || record_count == 0u) {
        return;
    }

    al_fixed weights[AL_POTB_MAX_COMMITTEE];
    al_size  eligible = 0u;
    al_size  independent = 0u;

    for (al_size i = 0u; i < record_count && eligible < AL_POTB_MAX_COMMITTEE; ++i) {
        const al_potb_record *r = records[i];
        if (r == NULL) {
            continue;
        }
        al_potb_level level = al_potb_level_of(p, r, now_day);
        if (level < AL_POTB_LEVEL_CANDIDATE) {
            continue;
        }
        al_fixed w = al_potb_weight_total(p, r, net, now_day);
        if (w <= 0) {
            continue;
        }
        weights[eligible++] = w;

        if (al_potb_cod(r) < AL_FX(5, 10) && r->correlation_score < AL_FX(15, 100)) {
            ++independent;
        }
    }

    out->total_eligible  = (al_u32)eligible;
    out->independent_count = (al_u32)independent;

    if (eligible == 0u) {
        return;
    }

    out->gini = al_potb_gini(weights, eligible);

    al_fixed top20_buf[AL_POTB_MAX_COMMITTEE];
    al_memcpy(top20_buf, weights, eligible * sizeof(al_fixed));
    qsort(top20_buf, eligible, sizeof(al_fixed), al_fixed_cmp_asc);
    al_size top20 = eligible < 20u ? eligible : 20u;
    al_fixed top20_weights[20];
    for (al_size i = 0u; i < top20; ++i) {
        top20_weights[i] = top20_buf[eligible - top20 + i];
    }
    out->hhi = al_potb_hhi(top20_weights, top20);

    out->alert_triggered = (out->gini > p->gini_max || out->hhi > p->hhi_max);
}

/* --------------------------------------------------------------------------
 * Behavioral entropy (A3)
 * -------------------------------------------------------------------------- */

al_fixed al_potb_entropy_from_hist(const al_u32 *hist, al_u32 slots) {
    if (slots == 0u) {
        return 0;
    }
    al_u64 total = 0;
    for (al_u32 i = 0u; i < slots; ++i) {
        total += (al_u64)hist[i];
    }
    if (total == 0u) {
        return 0;
    }
    al_fixed entropy = 0;
    for (al_u32 i = 0u; i < slots; ++i) {
        if (hist[i] == 0u) {
            continue;
        }
        al_i64 p_times_1e9 = ((al_i64)hist[i] * 1000000000ll) / (al_i64)total;
        if (p_times_1e9 <= 0 || p_times_1e9 >= 1000000000ll) {
            continue;
        }
        al_fixed p_fx = al_fixed_from_ratio(p_times_1e9, 1000000000ll);
        al_fixed one_minus_p = al_fixed_sub(AL_FIXED_ONE, p_fx);
        al_fixed contrib = al_fixed_mul(p_fx, one_minus_p);
        contrib = al_fixed_mul(contrib, al_fixed_from_int(2));
        entropy = al_fixed_add(entropy, contrib);
    }
    al_fixed max_norm = al_fixed_from_int((al_i64)slots);
    max_norm = al_fixed_div(al_fixed_from_int((al_i64)(slots - 1u)), max_norm);
    max_norm = al_fixed_mul(max_norm, al_fixed_from_int(2));
    if (max_norm > 0) {
        entropy = al_fixed_div(entropy, max_norm);
    }
    return al_fixed_clamp(entropy, 0, AL_FIXED_ONE);
}

void al_potb_entropy_observe(al_potb_record *r, al_u32 activity_slot,
                             al_u32 total_slots) {
    if (r == NULL || total_slots == 0u || activity_slot >= total_slots) {
        return;
    }
    al_fixed unique_ratio = al_fixed_div(
        al_fixed_from_int((al_i64)r->uptime_days),
        al_fixed_from_int((al_i64)total_slots));
    r->behavioral_entropy = al_fixed_clamp(unique_ratio, 0, AL_FIXED_ONE);
}

al_fixed al_potb_entropy_value(const al_potb_record *r) {
    if (r == NULL) {
        return 0;
    }
    return r->behavioral_entropy;
}

/* --------------------------------------------------------------------------
 * Profile change detection (B2)
 * -------------------------------------------------------------------------- */

al_fixed al_potb_profile_change_score(const al_potb_record *r) {
    if (r == NULL || r->profile_snapshot_day == 0u) {
        return 0;
    }

    al_fixed score = 0;
    al_fixed segments = al_fixed_from_int(4);

    if (r->prev_asn != 0u && r->asn != 0u && r->prev_asn != r->asn) {
        score = al_fixed_add(score, AL_FIXED_ONE);
    }

    if (r->prev_inbound_attestations != 0u) {
        al_u32 diff = (r->inbound_attestations > r->prev_inbound_attestations)
            ? (r->inbound_attestations - r->prev_inbound_attestations)
            : (r->prev_inbound_attestations - r->inbound_attestations);
        al_u32 avg = (r->inbound_attestations + r->prev_inbound_attestations + 1u) / 2u;
        if (avg > 0u) {
            al_fixed change = al_fixed_div(
                al_fixed_from_int((al_i64)diff),
                al_fixed_from_int((al_i64)avg));
            if (change > AL_FX(5, 10)) {
                score = al_fixed_add(score, AL_FIXED_ONE);
            } else {
                score = al_fixed_add(score, al_fixed_mul(change, al_fixed_from_int(2)));
            }
        }
    }

    if (r->challenges_issued > 0u && r->prev_challenges_passed != 0u) {
        al_u32 curr_rate = (r->challenges_passed * 100u) / r->challenges_issued;
        al_u32 prev_rate = (r->prev_challenges_passed * 100u) /
            (r->challenges_issued + 1u);
        al_u32 rate_diff = (curr_rate > prev_rate) ? (curr_rate - prev_rate) : (prev_rate - curr_rate);
        if (rate_diff > 30u) {
            score = al_fixed_add(score, AL_FIXED_ONE);
        }
    }

    if (r->prev_uptime_days != 0u) {
        al_u32 up_diff = (r->uptime_days > r->prev_uptime_days)
            ? (r->uptime_days - r->prev_uptime_days)
            : (r->prev_uptime_days - r->uptime_days);
        if (up_diff > 14u) {
            score = al_fixed_add(score, AL_FIXED_ONE);
        }
    }

    return al_fixed_div(score, segments);
}

void al_potb_profile_snapshot(al_potb_record *r, al_u32 now_day) {
    if (r == NULL) {
        return;
    }
    r->prev_asn = r->asn;
    r->prev_inbound_attestations = r->inbound_attestations;
    r->prev_challenges_passed = r->challenges_passed;
    r->prev_uptime_days = r->uptime_days;
    r->profile_snapshot_day = now_day;
}
