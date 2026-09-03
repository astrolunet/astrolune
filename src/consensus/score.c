/*
 * PoTB parameters, node records and the weight formula.
 *
 * All fixed-point, no floating point, no clock reads - see astrolune/potb.h for
 * why each of those is a hard rule rather than a preference.
 */

#include "astrolune/potb.h"

#include "internal/common.h"
#include "score_internal.h"

/* --------------------------------------------------------------------------
 * Parameters
 * -------------------------------------------------------------------------- */

/* Q32.32 helper for a literal fraction. Written as a ratio rather than a decimal
 * so the value in the source is the exact value the code uses. */
#define AL_FX(num, den) al_fixed_from_ratio((al_i64)(num), (al_i64)(den))

al_potb_params al_potb_params_default(void) {
    al_potb_params p;
    al_memzero(&p, sizeof(p));

    /* --- TBS -------------------------------------------------------------- */
    p.loyalty_threshold_days = 365u;
    /* 0.001 per day: a decade past the threshold accrues ~3.3, comparable to the
     * logarithmic term for a multi-year node, so seniority is visible without
     * overwhelming behaviour. */
    p.loyalty_rate_per_day = AL_FX(1, 1000);
    p.cap_loyalty          = al_fixed_from_int(4);

    p.grace_period_days    = 60u;
    p.decay_half_life_days = 21u;

    /* --- Caps ------------------------------------------------------------- */
    /* ln(1 + 3650 * 1.0) is about 8.2, so a ten-year flawless node reaches the
     * cap and no further. The cap is what bounds a single identity; the share
     * limit in the specification is enforced above this module, at the point
     * weights are normalised across the set. */
    p.cap_tbs = al_fixed_from_int(10);
    p.cap_tgw = al_fixed_from_int(1);

    /* --- Trust graph ------------------------------------------------------ */
    p.sybil_cluster_threshold = AL_FX(8, 10);
    p.sybil_cluster_max_size  = 50u;
    p.tdi_suspicious_below    = AL_FX(2, 10);

    /* --- Committee -------------------------------------------------------- */
    p.committee_size            = 100u;
    p.committee_lifetime_blocks = 10u;
    p.committee_size_min       = 75u;
    p.committee_size_max       = 125u;
    p.rotation_fraction         = AL_FX(1, 10);

    p.min_tbs_candidate = AL_FX(3, 1);   /* ~2 weeks of correct operation */
    p.min_tbs_validator = AL_FX(4, 1);
    p.min_tgw_validator = AL_FX(3, 10);
    /* A candidate is drawn at half weight. Enough that a young node can be seated
     * and start building a record, little enough that the cheapest way into a
     * committee is still to have behaved correctly for a while. */
    p.candidate_weight_factor = AL_FIXED_HALF;

    /* --- Anti-domination (A1) --- */
    p.gini_max              = AL_FX(9, 20);  /* 0.45 */
    p.hhi_max              = AL_FX(1, 50);   /* 0.02 */

    /* --- Committee size randomization (B3) --- */

    /* --- Epoch ------------------------------------------------------------ */
    p.epoch_days = 1u;

    /* --- Rewards ---------------------------------------------------------- */
    p.reward_flat_bp     = 6000u;
    p.reward_weighted_bp = 2500u;
    p.reward_bonded_bp   = 1500u;
    p.reward_max_multiple = al_fixed_from_int(3);

    return p;
}

al_status al_potb_params_validate(const al_potb_params *p) {
    if (p == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_u32 bp = (al_u32)p->reward_flat_bp + (al_u32)p->reward_weighted_bp +
                (al_u32)p->reward_bonded_bp;
    if (bp != 10000u) {
        return AL_ERR_INVALID_ARG;
    }
    if (p->committee_size == 0u || p->committee_size > AL_POTB_MAX_COMMITTEE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (p->committee_size_min == 0u ||
        p->committee_size_min > p->committee_size_max ||
        p->committee_size_max > AL_POTB_MAX_COMMITTEE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (p->committee_lifetime_blocks == 0u) {
        return AL_ERR_INVALID_ARG;
    }
    if (p->rotation_fraction <= 0 || p->rotation_fraction > AL_FIXED_ONE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (p->decay_half_life_days == 0u) {
        return AL_ERR_INVALID_ARG;
    }
    if (p->cap_tbs <= 0 || p->cap_tgw <= 0) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (p->sybil_cluster_threshold < 0 || p->sybil_cluster_threshold > AL_FIXED_ONE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (p->tdi_suspicious_below < 0 || p->tdi_suspicious_below > AL_FIXED_ONE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (p->reward_max_multiple < AL_FIXED_ONE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (p->candidate_weight_factor <= 0 ||
        p->candidate_weight_factor > AL_FIXED_ONE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (p->min_tbs_validator < p->min_tbs_candidate) {
        return AL_ERR_INVALID_ARG;
    }
    if (p->gini_max < 0 || p->gini_max > AL_FIXED_ONE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (p->hhi_max < 0 || p->hhi_max > AL_FIXED_ONE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    return AL_OK;
}

/* --------------------------------------------------------------------------
 * Records
 * -------------------------------------------------------------------------- */

al_potb_record al_potb_record_init(const al_pubkey *identity) {
    al_potb_record r;
    al_memzero(&r, sizeof(r));
    if (identity != NULL) {
        r.identity = *identity;
    }
    /* A multiplier's neutral value is 1, not 0. Zeroing the whole struct and
     * leaving it would give every new node a permanent weight of zero. */
    r.penalty_multiplier = AL_FIXED_ONE;
    /* No inbound edges yet, so dispersion is undefined; 1 is the un-penalised
     * reading and the near-zero uptime term is what actually holds a new node's
     * weight down. */
    r.tdi = AL_FIXED_ONE;
    return r;
}

/* --------------------------------------------------------------------------
 * Behaviour rates
 * -------------------------------------------------------------------------- */

al_fixed al_potb_correctness_rate(const al_potb_record *r) {
    if (r == NULL || r->responses_total == 0u) {
        /* No observations is not evidence of misbehaviour. */
        return AL_FIXED_ONE;
    }
    al_u64 correct = r->responses_correct;
    if (correct > r->responses_total) {
        /* Impossible from honest accounting; clamp rather than trust it. */
        correct = r->responses_total;
    }
    return al_fixed_from_ratio((al_i64)correct, (al_i64)r->responses_total);
}

al_fixed al_potb_miss_rate(const al_potb_record *r) {
    if (r == NULL || r->votes_expected == 0u) {
        return 0;
    }
    al_u64 cast = r->votes_cast;
    if (cast > r->votes_expected) {
        cast = r->votes_expected;
    }
    al_u64 missed = r->votes_expected - cast;
    return al_fixed_from_ratio((al_i64)missed, (al_i64)r->votes_expected);
}

/* Incorrect-response rate, the counterpart used by the response offences. */
al_fixed al_potb_error_rate(const al_potb_record *r) {
    if (r == NULL || r->responses_total == 0u) {
        return 0;
    }
    al_u64 correct = r->responses_correct;
    if (correct > r->responses_total) {
        correct = r->responses_total;
    }
    al_u64 wrong = r->responses_total - correct;
    return al_fixed_from_ratio((al_i64)wrong, (al_i64)r->responses_total);
}

/* --------------------------------------------------------------------------
 * TBS
 * -------------------------------------------------------------------------- */

al_fixed al_potb_loyalty_bonus(const al_potb_params *p, al_u32 uptime_days) {
    if (p == NULL || uptime_days < p->loyalty_threshold_days) {
        return 0;
    }
    al_u32   extra = uptime_days - p->loyalty_threshold_days;
    al_fixed bonus = al_fixed_mul(al_fixed_from_int((al_i64)extra),
                                  p->loyalty_rate_per_day);
    return al_fixed_min(bonus, p->cap_loyalty);
}

al_fixed al_potb_decay_multiplier(const al_potb_params *p, al_u32 idle_days) {
    if (p == NULL) {
        return AL_FIXED_ONE;
    }
    if (idle_days <= p->grace_period_days) {
        return AL_FIXED_ONE;
    }
    al_u32 past = idle_days - p->grace_period_days;
    /* The ratio goes into half_pow as two integers rather than as a pre-divided
     * fixed value: dividing first would round the exponent, and two nodes
     * rounding a different way would compute different scores. */
    return al_fixed_half_pow((al_i64)past, (al_i64)p->decay_half_life_days);
}

al_fixed al_potb_tbs(const al_potb_params *p, const al_potb_record *r,
                     al_u32 now_day) {
    if (p == NULL || r == NULL) {
        return 0;
    }
    if (r->permanently_banned) {
        return 0;
    }

    /* ln(1 + uptime * correctness). The product is formed in fixed point so a
     * node with 99% correctness over 1000 days scores below one with 100%. */
    al_fixed uptime    = al_fixed_from_int((al_i64)r->uptime_days);
    al_fixed effective = al_fixed_mul(uptime, al_potb_correctness_rate(r));
    al_fixed score     = al_fixed_ln1p(effective);

    score = al_fixed_add(score, al_potb_loyalty_bonus(p, r->uptime_days));

    /* Decay for time spent idle. now_day before last_active_day means the caller
     * passed an inconsistent day index; treat it as no idle time rather than
     * underflowing into a huge span. */
    if (now_day > r->last_active_day) {
        al_u32 idle = now_day - r->last_active_day;
        score = al_fixed_mul(score, al_potb_decay_multiplier(p, idle));
    }

    /* Accumulated slashing. Multiplicative, so penalties compound and the score
     * can approach zero without ever crossing it. */
    score = al_fixed_mul(score, al_fixed_clamp(r->penalty_multiplier, 0,
                                                AL_FIXED_ONE));

    return al_fixed_max(score, 0);
}

/* --------------------------------------------------------------------------
 * TGW
 * -------------------------------------------------------------------------- */

al_bool al_potb_is_suspicious_cluster(const al_potb_params *p,
                                      const al_potb_record *r) {
    if (p == NULL || r == NULL) {
        return AL_FALSE;
    }
    if (r->inbound_attestations == 0u) {
        return AL_FALSE;
    }
    /* Only small groups qualify: a large fraction of edges from a large group is
     * what a well-connected honest node looks like. */
    if (r->cluster_size == 0u || r->cluster_size > p->sybil_cluster_max_size) {
        return AL_FALSE;
    }
    al_fixed share = al_fixed_from_ratio((al_i64)r->inbound_from_cluster,
                                         (al_i64)r->inbound_attestations);
    return (share >= p->sybil_cluster_threshold) ? AL_TRUE : AL_FALSE;
}

al_fixed al_potb_tgw(const al_potb_params *p, const al_potb_record *r) {
    if (p == NULL || r == NULL) {
        return 0;
    }
    if (r->inbound_attestations == 0u) {
        return 0;   /* nobody has vouched for this node yet */
    }

    /*
     * Start from the share of inbound edges that come from *outside* the node's
     * own cluster. This is the SybilRank intuition in its simplest defensible
     * form: trust that flows in from the wider graph is worth something, trust
     * that circulates inside a group is worth close to nothing.
     */
    al_u32 external = (r->inbound_from_cluster <= r->inbound_attestations)
                          ? (r->inbound_attestations - r->inbound_from_cluster)
                          : 0u;
    al_fixed base = al_fixed_from_ratio((al_i64)external,
                                        (al_i64)r->inbound_attestations);

    /*
     * Diminishing credit for edge count, so a node with 200 inbound edges is not
     * worth twice one with 100. Without this the graph term would reward volume,
     * which is the cheapest thing for an attacker to manufacture.
     *
     * ln(1 + n) / ln(1 + 100) - normalised so 100 edges reaches 1.
     */
    al_fixed vol = al_fixed_ln1p(al_fixed_from_int((al_i64)r->inbound_attestations));
    al_fixed vol_norm = al_fixed_div(vol, al_fixed_ln1p(al_fixed_from_int(100)));
    vol_norm = al_fixed_clamp(vol_norm, 0, AL_FIXED_ONE);
    base = al_fixed_mul(base, vol_norm);

    /*
     * Temporal dispersion. Edges that all appeared inside one window are what a
     * farm coming online together produces; organic trust arrives scattered. A
     * low TDI scales the whole term down rather than zeroing it, because a low
     * reading is a signal and not a proof.
     */
    if (r->tdi < p->tdi_suspicious_below) {
        al_fixed factor = (p->tdi_suspicious_below > 0)
                              ? al_fixed_div(r->tdi, p->tdi_suspicious_below)
                              : 0;
        base = al_fixed_mul(base, al_fixed_clamp(factor, 0, AL_FIXED_ONE));
    }

    /*
     * External challenges. The protocol picks these pairings against nodes with
     * no existing edge, so unlike attestations they cannot be farmed internally -
     * which makes them the most trustworthy input here. A node that has answered
     * none yet is neither rewarded nor punished.
     */
    if (r->challenges_issued > 0u) {
        al_u32 passed = (r->challenges_passed <= r->challenges_issued)
                            ? r->challenges_passed
                            : r->challenges_issued;
        al_fixed pass_rate = al_fixed_from_ratio((al_i64)passed,
                                                 (al_i64)r->challenges_issued);
        /* Weighted 50/50 against the graph term: enough that failing challenges
         * hurts materially, not so much that the graph stops mattering. */
        base = al_fixed_add(al_fixed_mul(base, AL_FIXED_HALF),
                            al_fixed_mul(al_fixed_mul(base, AL_FIXED_HALF),
                                         pass_rate));
    }

    /* A closed cluster keeps a floor rather than dropping to zero, so a false
     * positive is recoverable: the node can still earn its way out by acquiring
     * external edges and answering challenges. */
    if (al_potb_is_suspicious_cluster(p, r)) {
        base = al_fixed_mul(base, AL_FX(1, 10));
    }

    return al_fixed_clamp(base, 0, p->cap_tgw);
}

/* --------------------------------------------------------------------------
 * NDM
 * -------------------------------------------------------------------------- */

al_fixed al_potb_ndm(const al_potb_params *p, const al_potb_record *r,
                     const al_potb_network_stats *net) {
    AL_UNUSED(p);
    if (r == NULL) {
        return AL_FIXED_ONE;
    }
    /* Unknown ASN is neutral. Penalising it would push operators to lie about
     * their network location, which makes the signal worse rather than better. */
    if (r->asn == 0u || r->asn_peer_count == 0u) {
        return AL_FIXED_ONE;
    }

    /*
     * 1 / sqrt(peers_in_asn), floored at 0.5.
     *
     * Square root rather than a reciprocal so the penalty grows slowly: a popular
     * cloud provider hosting a hundred honest nodes should not have each of them
     * scored at one percent. The floor bounds it further, and the whole
     * multiplier is documented as evadable with residential proxies - it is one
     * soft layer, not a defence anything rests on.
     */
    al_fixed peers = al_fixed_from_int((al_i64)r->asn_peer_count);
    al_fixed root  = al_fixed_sqrt(peers);
    if (root <= 0) {
        return AL_FIXED_ONE;
    }
    al_fixed ndm = al_fixed_div(AL_FIXED_ONE, root);

    /* A node in a small ASN relative to the network gets no bonus above 1: the
     * multiplier only ever discounts concentration, it never inflates. */
    AL_UNUSED(net);
    return al_fixed_clamp(ndm, AL_FIXED_HALF, AL_FIXED_ONE);
}

/* --------------------------------------------------------------------------
 * COD
 * -------------------------------------------------------------------------- */

al_fixed al_potb_cod(const al_potb_record *r) {
    if (r == NULL || r->correlation_score <= 0) {
        return AL_FIXED_ONE;
    }
    return al_fixed_div(AL_FIXED_ONE,
                        al_fixed_add(AL_FIXED_ONE, r->correlation_score));
}

/* --------------------------------------------------------------------------
 * Correlation signals
 * -------------------------------------------------------------------------- */

/* Absolute difference of two u32 as fixed point. */
al_fixed al_u32_diff_fx(al_u32 a, al_u32 b) {
    al_u32 d = (a > b) ? (a - b) : (b - a);
    return al_fixed_from_int((al_i64)d);
}

al_fixed al_potb_correlation_pair(const al_potb_record *a,
                                  const al_potb_record *b) {
    if (a == NULL || b == NULL) {
        return 0;
    }
    /* A node is not correlated with itself for this purpose - the caller's
     * pairwise loop would otherwise count every node once against itself. */
    if (al_bytes_eq(al_bytes_make(a->identity.bytes, AL_PUBKEY_SIZE),
                    al_bytes_make(b->identity.bytes, AL_PUBKEY_SIZE))) {
        return 0;
    }

    al_fixed score = 0;

    /*
     * Signal 1: registration in a nearby window.
     *
     * Independent operators join at unrelated times. A farm is provisioned in one
     * sitting, and even a patient attacker who staggers registration has to pick
     * the spacing - which is why this is worth something despite being cheap to
     * evade in isolation. Full credit inside a day, decaying to nothing at 30.
     */
    al_fixed reg_gap = al_u32_diff_fx(a->first_seen_day, b->first_seen_day);
    if (reg_gap < al_fixed_from_int(30)) {
        al_fixed closeness = al_fixed_sub(
            AL_FIXED_ONE, al_fixed_div(reg_gap, al_fixed_from_int(30)));
        score = al_fixed_add(score, al_fixed_mul(closeness, AL_FX(3, 10)));
    }

    /*
     * Signal 2: matching uptime history. Two nodes with the same uptime *and* the
     * same last-active day have been going up and down together, which is what
     * shared control looks like operationally.
     */
    al_fixed up_gap = al_u32_diff_fx(a->uptime_days, b->uptime_days);
    if (up_gap < al_fixed_from_int(7)) {
        al_fixed active_gap = al_u32_diff_fx(a->last_active_day,
                                            b->last_active_day);
        if (active_gap < al_fixed_from_int(2)) {
            score = al_fixed_add(score, AL_FX(3, 10));
        } else {
            score = al_fixed_add(score, AL_FX(1, 10));
        }
    }

    /* Signal 3: same ASN. Weak alone - honest nodes share hosts - so it carries
     * the smallest weight of the four and only matters in combination. */
    if (a->asn != 0u && a->asn == b->asn) {
        score = al_fixed_add(score, AL_FX(15, 100));
    }

    /* Signal 4: both inside small closed clusters with low dispersion. Two
     * separate signals agreeing is worth more than either alone. */
    if (a->tdi < AL_FX(2, 10) && b->tdi < AL_FX(2, 10) &&
        a->cluster_size > 0u && b->cluster_size > 0u) {
        score = al_fixed_add(score, AL_FX(25, 100));
    }

    return score;
}

al_fixed al_potb_correlation_score(const al_potb_record *const *group,
                                   al_size count) {
    if (group == NULL || count < 2u) {
        return 0;
    }
    /*
     * Mean pairwise correlation, not the sum.
     *
     * A sum would grow with group size, so naming a larger group would raise
     * every member's correlation without any new evidence - and the caller
     * chooses the group. Averaging makes the score a property of how alike the
     * members are, which is the thing being measured.
     */
    al_fixed total = 0;
    al_size  pairs = 0u;
    for (al_size i = 0u; i < count; ++i) {
        for (al_size j = i + 1u; j < count; ++j) {
            total = al_fixed_add(total,
                                 al_potb_correlation_pair(group[i], group[j]));
            ++pairs;
        }
    }
    if (pairs == 0u) {
        return 0;
    }
    al_fixed mean = al_fixed_div(total, al_fixed_from_int((al_i64)pairs));

    /*
     * Scale by group size, so a large uniformly-correlated group is dampened
     * harder than a pair. This is the part that actually bounds *joint* weight:
     * without it, a farm could grow arbitrarily wide at a fixed per-node cost.
     * ln(1 + n) keeps the growth gentle enough not to punish a genuine cohort of
     * operators who happened to start together.
     */
    al_fixed size_factor = al_fixed_ln1p(al_fixed_from_int((al_i64)count));
    return al_fixed_mul(mean, size_factor);
}

/* --------------------------------------------------------------------------
 * Final weight
 * -------------------------------------------------------------------------- */

void al_potb_weight_compute(const al_potb_params *p, const al_potb_record *r,
                            const al_potb_network_stats *net, al_u32 now_day,
                            al_potb_weight *out) {
    if (out == NULL) {
        return;
    }
    al_memzero(out, sizeof(*out));
    if (p == NULL || r == NULL) {
        return;
    }

    /* A banned node has no weight at all, and the components are left at zero so
     * a diagnostic reads "banned" rather than showing a score it cannot use. */
    if (r->permanently_banned || now_day < r->banned_until_day) {
        return;
    }

    out->tbs = al_potb_tbs(p, r, now_day);
    out->tgw = al_potb_tgw(p, r);
    out->ndm = al_potb_ndm(p, r, net);
    out->cod = al_potb_cod(r);

    out->tbs_capped = al_fixed_min(out->tbs, p->cap_tbs);
    out->tgw_capped = al_fixed_min(out->tgw, p->cap_tgw);

    al_fixed w = al_fixed_mul(out->tbs_capped, out->tgw_capped);
    w = al_fixed_mul(w, out->ndm);
    w = al_fixed_mul(w, out->cod);
    out->total = al_fixed_max(w, 0);
}

al_fixed al_potb_weight_total(const al_potb_params *p, const al_potb_record *r,
                             const al_potb_network_stats *net, al_u32 now_day) {
    al_potb_weight w;
    al_potb_weight_compute(p, r, net, now_day, &w);
    return w.total;
}

/* --------------------------------------------------------------------------
 * Levels
 * -------------------------------------------------------------------------- */

al_potb_level al_potb_level_of(const al_potb_params *p, const al_potb_record *r,
                               al_u32 now_day) {
    if (p == NULL || r == NULL) {
        return AL_POTB_LEVEL_RELAY;
    }
    if (r->permanently_banned || now_day < r->banned_until_day) {
        return AL_POTB_LEVEL_BANNED;
    }

    al_fixed tbs = al_potb_tbs(p, r, now_day);
    al_fixed tgw = al_potb_tgw(p, r);

    if (tbs >= p->min_tbs_validator && tgw >= p->min_tgw_validator) {
        return AL_POTB_LEVEL_VALIDATOR;
    }
    if (tbs >= p->min_tbs_candidate) {
        return AL_POTB_LEVEL_CANDIDATE;
    }
    return AL_POTB_LEVEL_RELAY;
}

const char *al_potb_level_str(al_potb_level level) {
    switch (level) {
        case AL_POTB_LEVEL_RELAY:     return "relay";
        case AL_POTB_LEVEL_CANDIDATE: return "candidate";
        case AL_POTB_LEVEL_VALIDATOR: return "validator";
        case AL_POTB_LEVEL_BANNED:    return "banned";
        case AL_POTB_LEVEL_SENTINEL:  break;
    }
    return "unknown";
}

/* --------------------------------------------------------------------------
 * Slashing
 * -------------------------------------------------------------------------- */

int al_fixed_cmp_asc(const void *a, const void *b) {
    al_fixed va = *(const al_fixed *)a;
    al_fixed vb = *(const al_fixed *)b;
    return (va > vb) - (va < vb);
}
al_u32 al_potb_quorum_threshold(al_u32 committee_size) {
    if (committee_size == 0u) {
        return 0u;
    }
    /* floor(2n/3) + 1: the standard BFT bound, tolerating f < n/3 faults. Done
     * in u64 so the multiply cannot overflow for any u32 input. */
    return (al_u32)(((al_u64)committee_size * 2u) / 3u + 1u);
}
