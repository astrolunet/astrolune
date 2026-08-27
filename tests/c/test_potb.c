/*
 * Proof of Trusted Behavior: scoring, committee selection, epoch seed, rewards.
 *
 * The coverage this suite is answering to is the nine-bullet list in
 * docs/08-implementation/implementation-status.md section 4. Each case names the
 * bullet it discharges.
 *
 * The expected values here are exact wherever the arithmetic is exact, in the
 * same spirit as tests/c/test_fixed.c: every number below is consensus-visible,
 * so bit-for-bit reproducibility is the property worth asserting and "close
 * enough" is not. AL_CHECK_NEAR_I64 appears only where two independent
 * fixed-point approximations compose and the last few ulp are genuinely the
 * representation's rather than the algorithm's.
 *
 * Where an expectation is a fraction it is written as FX(n, d) rather than as a
 * decimal literal, because al_fixed_from_ratio rounds half away from zero and a
 * hand-computed decimal would disagree with it by an ulp for most fractions.
 * Where a literal is unavoidable it carries INT64_C - see the note at
 * tests/c/test_fixed.c:168 for the MSVC failure that rule exists to prevent.
 *
 * One thing this suite deliberately does not do: decide anything. Two open
 * questions run through PoTB's parameters (Q15 on the miss penalties, Q20 on the
 * anti-Sybil claim). Where the code's behaviour is the subject of an open
 * question, the test pins what the code does today and says so in a comment, so
 * that a change is visible in a diff rather than settled by a test.
 */

#include "astrolune/arena.h"
#include "astrolune/potb.h"

#include "altest.h"

#define AL_TEST_SUITE_NAME "potb"

#define ONE  AL_FIXED_ONE
#define HALF AL_FIXED_HALF

/* The same spelling score.c uses for a literal fraction, so an expectation here
 * is the identical bit pattern the implementation computes. */
#define FX(n, d) al_fixed_from_ratio((al_i64)(n), (al_i64)(d))

/* --------------------------------------------------------------------------
 * Fixtures
 * -------------------------------------------------------------------------- */

/* Distinct, deterministic pubkeys. The byte pattern only has to differ per
 * index; nothing in this module verifies a key against a curve. */
static al_pubkey al_test_key(al_u32 i) {
    al_pubkey pk;
    memset(&pk, 0, sizeof(pk));
    pk.bytes[0] = (al_u8)(i & 0xffu);
    pk.bytes[1] = (al_u8)((i >> 8) & 0xffu);
    pk.bytes[2] = 0xa5u;   /* so index 0 is not an all-zero key */
    return pk;
}

/*
 * A node that is eligible for selection at full weight.
 *
 * VALIDATOR needs tbs >= 4 and tgw >= 0.3, so it needs both long uptime and
 * enough external attestations: 100 inbound edges is exactly where the
 * ln(1+n)/ln(101) volume term reaches full credit, and with none of them from
 * inside a cluster the base share is 1.0.
 */
static al_potb_record al_test_node(al_u32 i, al_u32 uptime_days) {
    al_pubkey      pk = al_test_key(i);
    al_potb_record r  = al_potb_record_init(&pk);
    r.uptime_days          = uptime_days;
    r.last_active_day      = 1000u;
    r.first_seen_day       = (uptime_days < 1000u) ? (1000u - uptime_days) : 0u;
    r.inbound_attestations = 100u;
    r.inbound_from_cluster = 0u;   /* all external -> base share 1.0 */
    r.cluster_size         = 0u;
    r.tdi                  = ONE;  /* no dispersion discount */
    r.challenges_issued    = 0u;
    r.asn                  = 0u;   /* unknown ASN is neutral: NDM == 1 */
    return r;
}

/* --------------------------------------------------------------------------
 * Parameters
 * -------------------------------------------------------------------------- */

AL_TEST(params_default_and_validate) {
    /* Bullet 1. Every default asserted against the value in score.c:20-71, so a
     * retune of a consensus parameter cannot land silently. */
    al_potb_params p = al_potb_params_default();

    AL_CHECK_EQ_U64(p.loyalty_threshold_days, 365u);
    AL_CHECK_EQ_I64(p.loyalty_rate_per_day, FX(1, 1000));
    AL_CHECK_EQ_I64(p.cap_loyalty, al_fixed_from_int(4));
    AL_CHECK_EQ_U64(p.grace_period_days, 60u);
    AL_CHECK_EQ_U64(p.decay_half_life_days, 21u);

    AL_CHECK_EQ_I64(p.cap_tbs, al_fixed_from_int(10));
    AL_CHECK_EQ_I64(p.cap_tgw, ONE);

    AL_CHECK_EQ_I64(p.sybil_cluster_threshold, FX(8, 10));
    AL_CHECK_EQ_U64(p.sybil_cluster_max_size, 50u);
    AL_CHECK_EQ_I64(p.tdi_suspicious_below, FX(2, 10));

    AL_CHECK_EQ_U64(p.committee_size, 100u);
    AL_CHECK_EQ_U64(p.committee_lifetime_blocks, 10u);
    AL_CHECK_EQ_I64(p.rotation_fraction, FX(1, 10));

    AL_CHECK_EQ_I64(p.min_tbs_candidate, al_fixed_from_int(3));
    AL_CHECK_EQ_I64(p.min_tbs_validator, al_fixed_from_int(4));
    AL_CHECK_EQ_I64(p.min_tgw_validator, FX(3, 10));
    AL_CHECK_EQ_I64(p.candidate_weight_factor, HALF);

    AL_CHECK_EQ_U64(p.epoch_days, 1u);

    AL_CHECK_EQ_U64(p.reward_flat_bp, 6000u);
    AL_CHECK_EQ_U64(p.reward_weighted_bp, 2500u);
    AL_CHECK_EQ_U64(p.reward_bonded_bp, 1500u);
    AL_CHECK_EQ_I64(p.reward_max_multiple, al_fixed_from_int(3));

    /* The defaults must themselves validate: a chain whose genesis parameters
     * are the specification's must start. */
    AL_CHECK_EQ_STATUS(al_potb_params_validate(&p), AL_OK);
    AL_CHECK_EQ_STATUS(al_potb_params_validate(NULL), AL_ERR_INVALID_ARG);

    /*
     * One rejection per branch, each from a fresh default. The status codes are
     * asserted individually rather than as "not AL_OK" because validate() is
     * called at genesis load and the code is what tells an operator which
     * parameter is wrong.
     */
#define AL_REJECT(mutation, want)                     \
    do {                                              \
        al_potb_params q = al_potb_params_default();  \
        mutation;                                     \
        AL_CHECK_EQ_STATUS(al_potb_params_validate(&q), (want)); \
    } while (0)

    /* Shares that do not partition the reward mint or burn on every block. */
    AL_REJECT(q.reward_flat_bp = 5000u, AL_ERR_INVALID_ARG);
    AL_REJECT(q.reward_weighted_bp = 0u, AL_ERR_INVALID_ARG);

    AL_REJECT(q.committee_size = 0u, AL_ERR_OUT_OF_RANGE);
    AL_REJECT(q.committee_size = AL_POTB_MAX_COMMITTEE + 1u, AL_ERR_OUT_OF_RANGE);
    /* Exactly at the cap is allowed - it is the size the struct is sized for. */
    AL_REJECT(q.committee_size = AL_POTB_MAX_COMMITTEE, AL_OK);

    AL_REJECT(q.committee_lifetime_blocks = 0u, AL_ERR_INVALID_ARG);

    /* Rotation must make progress and must not exceed the whole committee. */
    AL_REJECT(q.rotation_fraction = 0, AL_ERR_OUT_OF_RANGE);
    AL_REJECT(q.rotation_fraction = -ONE, AL_ERR_OUT_OF_RANGE);
    AL_REJECT(q.rotation_fraction = ONE + 1, AL_ERR_OUT_OF_RANGE);
    AL_REJECT(q.rotation_fraction = ONE, AL_OK);

    /* Zero would divide by zero in the decay curve. */
    AL_REJECT(q.decay_half_life_days = 0u, AL_ERR_INVALID_ARG);

    AL_REJECT(q.cap_tbs = 0, AL_ERR_OUT_OF_RANGE);
    AL_REJECT(q.cap_tgw = 0, AL_ERR_OUT_OF_RANGE);

    AL_REJECT(q.sybil_cluster_threshold = ONE + 1, AL_ERR_OUT_OF_RANGE);
    AL_REJECT(q.sybil_cluster_threshold = -1, AL_ERR_OUT_OF_RANGE);
    AL_REJECT(q.tdi_suspicious_below = -1, AL_ERR_OUT_OF_RANGE);
    AL_REJECT(q.tdi_suspicious_below = ONE + 1, AL_ERR_OUT_OF_RANGE);

    /* Below 1 would cap a node's reward under its own flat share. */
    AL_REJECT(q.reward_max_multiple = HALF, AL_ERR_OUT_OF_RANGE);
    AL_REJECT(q.reward_max_multiple = ONE, AL_OK);

    AL_REJECT(q.candidate_weight_factor = 0, AL_ERR_OUT_OF_RANGE);
    AL_REJECT(q.candidate_weight_factor = ONE + 1, AL_ERR_OUT_OF_RANGE);

    /* A validator threshold below the candidate one would stop the level
     * ordering being an ordering. */
    AL_REJECT(q.min_tbs_validator = FX(2, 1), AL_ERR_INVALID_ARG);
    AL_REJECT(q.min_tbs_candidate = FX(5, 1), AL_ERR_INVALID_ARG);
    /* Equal thresholds are consistent, if unusual. */
    AL_REJECT(q.min_tbs_candidate = al_fixed_from_int(4), AL_OK);

#undef AL_REJECT
}

/* --------------------------------------------------------------------------
 * Behaviour rates and the NULL contract
 * -------------------------------------------------------------------------- */

AL_TEST(rates_and_null_neutrality) {
    al_potb_params p  = al_potb_params_default();
    al_pubkey      pk = al_test_key(1u);
    al_potb_record r  = al_potb_record_init(&pk);

    /* record_init sets the two multiplier fields to their neutral value, not to
     * zero. A zeroed penalty_multiplier would give every new node a permanent
     * weight of zero, which is the bug the constructor exists to prevent. */
    AL_CHECK_EQ_I64(r.penalty_multiplier, ONE);
    AL_CHECK_EQ_I64(r.tdi, ONE);
    AL_CHECK_EQ_U64(r.uptime_days, 0u);
    AL_CHECK(al_bytes_eq(al_bytes_make(r.identity.bytes, AL_PUBKEY_SIZE),
                         al_bytes_make(pk.bytes, AL_PUBKEY_SIZE)));
    /* A NULL identity is a zeroed one, not a crash. */
    al_potb_record anon = al_potb_record_init(NULL);
    AL_CHECK_EQ_I64(anon.penalty_multiplier, ONE);

    /*
     * The NULL contract, which is an API convention rather than an accident:
     * pure scoring functions return a *neutral* value because they run in hot
     * loops over large candidate sets, and a status check per call would cost
     * more than it buys. Neutral is not uniformly zero - it is whatever leaves
     * the weight formula unchanged, which is 1 for a multiplier and 0 for a
     * term. Pinning both spellings is the point of this block.
     */
    AL_CHECK_EQ_I64(al_potb_correctness_rate(NULL), ONE);
    AL_CHECK_EQ_I64(al_potb_miss_rate(NULL), 0);
    AL_CHECK_EQ_I64(al_potb_tbs(NULL, &r, 0u), 0);
    AL_CHECK_EQ_I64(al_potb_tbs(&p, NULL, 0u), 0);
    AL_CHECK_EQ_I64(al_potb_loyalty_bonus(NULL, 5000u), 0);
    AL_CHECK_EQ_I64(al_potb_decay_multiplier(NULL, 5000u), ONE);
    AL_CHECK_EQ_I64(al_potb_tgw(NULL, &r), 0);
    AL_CHECK_EQ_I64(al_potb_tgw(&p, NULL), 0);
    AL_CHECK_EQ_I64(al_potb_ndm(&p, NULL, NULL), ONE);
    AL_CHECK_EQ_I64(al_potb_cod(NULL), ONE);
    AL_CHECK(!al_potb_is_suspicious_cluster(NULL, &r));
    AL_CHECK(!al_potb_is_suspicious_cluster(&p, NULL));
    AL_CHECK_EQ_I64(al_potb_correlation_pair(NULL, &r), 0);
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&r, NULL), 0);
    AL_CHECK_EQ_I64(al_potb_correlation_score(NULL, 5u), 0);
    AL_CHECK_EQ_I64(al_potb_weight_total(NULL, &r, NULL, 0u), 0);
    AL_CHECK_EQ_I64(al_potb_weight_total(&p, NULL, NULL, 0u), 0);
    AL_CHECK(al_potb_level_of(NULL, &r, 0u) == AL_POTB_LEVEL_RELAY);
    AL_CHECK(al_potb_level_of(&p, NULL, 0u) == AL_POTB_LEVEL_RELAY);

    /* weight_compute writes a zeroed struct rather than leaving the caller's
     * memory as it found it, so a caller cannot read a stale weight back. */
    al_potb_weight w;
    memset(&w, 0xff, sizeof(w));
    al_potb_weight_compute(NULL, &r, NULL, 0u, &w);
    AL_CHECK_EQ_I64(w.tbs, 0);
    AL_CHECK_EQ_I64(w.total, 0);
    al_potb_weight_compute(&p, &r, NULL, 0u, NULL);   /* must not crash */

    /* No observations is not evidence of misbehaviour: an unobserved node scores
     * a full correctness rate, and its lack of history is priced in by the
     * near-zero uptime term instead. */
    AL_CHECK_EQ_I64(al_potb_correctness_rate(&r), ONE);
    AL_CHECK_EQ_I64(al_potb_miss_rate(&r), 0);

    r.responses_total   = 100u;
    r.responses_correct = 95u;
    AL_CHECK_EQ_I64(al_potb_correctness_rate(&r), FX(95, 100));

    r.votes_expected = 100u;
    r.votes_cast     = 90u;
    AL_CHECK_EQ_I64(al_potb_miss_rate(&r), FX(10, 100));

    /* Counters that cannot arise from honest accounting are clamped rather than
     * trusted: subtracting them unchecked would underflow a u64 and produce a
     * rate near 1.8e10 instead of a rate. */
    r.responses_correct = 500u;
    AL_CHECK_EQ_I64(al_potb_correctness_rate(&r), ONE);
    r.votes_cast = 500u;
    AL_CHECK_EQ_I64(al_potb_miss_rate(&r), 0);

    /* A zero denominator is "no data", never a division. */
    r.responses_total = 0u;
    r.votes_expected  = 0u;
    AL_CHECK_EQ_I64(al_potb_correctness_rate(&r), ONE);
    AL_CHECK_EQ_I64(al_potb_miss_rate(&r), 0);
}

/* --------------------------------------------------------------------------
 * TBS
 * -------------------------------------------------------------------------- */

AL_TEST(tbs_monotonic_and_decay) {
    /* Bullet 3: TBS monotonic in uptime, decay correct across the grace
     * boundary, penalties never raising a score. */
    al_potb_params p = al_potb_params_default();

    /*
     * More uptime must never lower TBS. This is the property an operator's
     * incentive rests on: if the curve ever ticked downward, a node could
     * improve its standing by going offline, which is the opposite of what the
     * score is for. Checked over a decade of days, at the day granularity the
     * protocol actually counts in.
     */
    al_fixed prev = -1;
    for (al_u32 d = 0u; d <= 4000u; ++d) {
        al_potb_record r = al_test_node(1u, d);
        r.last_active_day = 4000u;
        al_fixed tbs = al_potb_tbs(&p, &r, 4000u);
        AL_CHECK(tbs >= prev);
        prev = tbs;
    }
    /* And it does not saturate on the way: ten years is well clear of one. */
    {
        al_potb_record young = al_test_node(1u, 365u);
        al_potb_record old   = al_test_node(2u, 3650u);
        young.last_active_day = 4000u;
        old.last_active_day   = 4000u;
        AL_CHECK(al_potb_tbs(&p, &old, 4000u) >
                 al_potb_tbs(&p, &young, 4000u));
    }

    al_potb_record r = al_test_node(1u, 1000u);
    r.last_active_day = 1000u;
    al_fixed clean = al_potb_tbs(&p, &r, 1000u);
    /* ln(1001) = 6.90875477932..., one ulp above the true 29672875833 - the
     * value test_fixed.c:165 pins for exactly this call. No loyalty term at
     * 1000 days of uptime past a 365-day threshold? There is one: 635 * 0.001.
     * Spelled as the arithmetic rather than a decimal so the expectation is the
     * bit pattern, not a rounding of it. */
    AL_CHECK_EQ_I64(clean,
                    al_fixed_add(INT64_C(29672875834),
                                 al_fixed_mul(al_fixed_from_int(635),
                                              p.loyalty_rate_per_day)));

    /* A penalty never raises a score, and compounds multiplicatively so no
     * sequence of them can drive it negative. */
    r.penalty_multiplier = FX(9, 10);
    al_fixed hurt = al_potb_tbs(&p, &r, 1000u);
    AL_CHECK(hurt < clean);
    AL_CHECK(hurt > 0);
    r.penalty_multiplier = 0;
    AL_CHECK_EQ_I64(al_potb_tbs(&p, &r, 1000u), 0);

    /* The multiplier is clamped into [0, 1] on use, so a corrupt record cannot
     * inflate its own score by claiming a multiplier above one. */
    r.penalty_multiplier = 2 * ONE;
    AL_CHECK_EQ_I64(al_potb_tbs(&p, &r, 1000u), clean);
    r.penalty_multiplier = -ONE;
    AL_CHECK_EQ_I64(al_potb_tbs(&p, &r, 1000u), 0);
    r.penalty_multiplier = ONE;

    /*
     * Decay. Exactly 1 inside the grace period - an operator taking a two-month
     * break keeps their history, which is the fix for a curve that decayed from
     * day one and so taught operators to fake uptime.
     */
    for (al_u32 idle = 0u; idle <= p.grace_period_days; ++idle) {
        AL_CHECK_EQ_I64(al_potb_decay_multiplier(&p, idle), ONE);
    }
    AL_CHECK(al_potb_decay_multiplier(&p, p.grace_period_days + 1u) < ONE);

    /* Exactly one half-life past the grace period halves it, exactly. The
     * exponent goes into half_pow as two integers precisely so that this is an
     * equality and not an approximation. */
    AL_CHECK_EQ_I64(al_potb_decay_multiplier(&p, 60u + 21u), HALF);
    AL_CHECK_EQ_I64(al_potb_decay_multiplier(&p, 60u + 42u), ONE / 4);

    /* Monotonically decreasing after the boundary: a decay curve that ever
     * ticked upward would let a node improve its score by waiting longer. */
    al_fixed last = ONE;
    for (al_u32 idle = 0u; idle <= 400u; ++idle) {
        al_fixed cur = al_potb_decay_multiplier(&p, idle);
        AL_CHECK(cur <= last);
        last = cur;
    }

    /* Decay reaches TBS through al_potb_tbs, not only through the helper. */
    AL_CHECK_EQ_I64(al_potb_tbs(&p, &r, 1000u + 60u), clean);
    AL_CHECK(al_potb_tbs(&p, &r, 1000u + 81u) < clean);
    AL_CHECK_NEAR_I64(al_potb_tbs(&p, &r, 1000u + 81u), clean / 2, 2);

    /*
     * now_day before last_active_day is an inconsistent day index from the
     * caller. It is treated as no idle time rather than underflowing the u32
     * into a span of four billion days, which would decay the score to zero.
     */
    {
        al_potb_record future = al_test_node(1u, 100u);
        future.last_active_day = 5000u;
        AL_CHECK_EQ_I64(al_potb_tbs(&p, &future, 100u),
                        al_fixed_ln1p(al_fixed_from_int(100)));
    }

    /*
     * The two ban flags are not symmetric, and the asymmetry is worth pinning
     * because it is the kind of thing a refactor smooths over: al_potb_tbs
     * checks only permanently_banned, whereas al_potb_weight_compute and
     * al_potb_level_of also check banned_until_day. A temporarily banned node
     * therefore still has a TBS - it just has no weight and no level.
     */
    {
        al_potb_record perm = al_test_node(3u, 1000u);
        perm.permanently_banned = AL_TRUE;
        AL_CHECK_EQ_I64(al_potb_tbs(&p, &perm, 1000u), 0);
        AL_CHECK_EQ_I64(al_potb_weight_total(&p, &perm, NULL, 1000u), 0);
        AL_CHECK(al_potb_level_of(&p, &perm, 1000u) == AL_POTB_LEVEL_BANNED);

        al_potb_record temp = al_test_node(4u, 1000u);
        temp.banned_until_day = 1100u;
        AL_CHECK(al_potb_tbs(&p, &temp, 1000u) > 0);   /* TBS survives ... */
        AL_CHECK_EQ_I64(al_potb_weight_total(&p, &temp, NULL, 1000u), 0);
        AL_CHECK(al_potb_level_of(&p, &temp, 1000u) == AL_POTB_LEVEL_BANNED);

        /* And the ban expires: now_day == banned_until_day is already free,
         * since the check is a strict now_day < banned_until_day. */
        AL_CHECK(al_potb_weight_total(&p, &temp, NULL, 1100u) > 0);
        AL_CHECK(al_potb_level_of(&p, &temp, 1100u) != AL_POTB_LEVEL_BANNED);
    }
}

AL_TEST(loyalty_bonus_threshold) {
    al_potb_params p = al_potb_params_default();

    /* Nothing before the threshold. A Sybil farm spun up last week gets none of
     * this term, which is the whole reason it has a threshold. */
    AL_CHECK_EQ_I64(al_potb_loyalty_bonus(&p, 0u), 0);
    AL_CHECK_EQ_I64(al_potb_loyalty_bonus(&p, 364u), 0);
    /* And nothing *at* the threshold either: the comparison admits 365 days but
     * the accrued extra is zero, so the curve is continuous across it. */
    AL_CHECK_EQ_I64(al_potb_loyalty_bonus(&p, 365u), 0);
    AL_CHECK_EQ_I64(al_potb_loyalty_bonus(&p, 366u), p.loyalty_rate_per_day);

    /*
     * 1000 days past the threshold accrues 1000 * 0.001. That is not quite 1.0:
     * 1/1000 is not representable in Q32.32, so the rate is 4294967 rather than
     * 4294967.296 and a thousand of them land 296 ulp below ONE. Asserted as the
     * exact integer because the shortfall is the representation's and a change
     * that shifted it would be a change to a consensus value.
     */
    AL_CHECK_EQ_I64(al_potb_loyalty_bonus(&p, 365u + 1000u), INT64_C(4294967000));
    AL_CHECK(al_potb_loyalty_bonus(&p, 365u + 1000u) < ONE);

    /* Capped, so a decade of uptime cannot dominate on seniority alone. */
    AL_CHECK_EQ_I64(al_potb_loyalty_bonus(&p, 365u + 5000u), p.cap_loyalty);
    AL_CHECK_EQ_I64(al_potb_loyalty_bonus(&p, 365u + 100000u), p.cap_loyalty);
    /* Exactly at the cap, not one ulp over: 4000 days * 0.001 is 4 - 1184 ulp,
     * still below the ceiling, so the min() has not yet engaged. */
    AL_CHECK(al_potb_loyalty_bonus(&p, 365u + 4000u) < p.cap_loyalty);

    /* Monotonic and non-negative across the whole domain. */
    al_fixed prev = -1;
    for (al_u32 d = 0u; d <= 6000u; ++d) {
        al_fixed b = al_potb_loyalty_bonus(&p, d);
        AL_CHECK(b >= prev);
        AL_CHECK(b <= p.cap_loyalty);
        prev = b;
    }
}

/* --------------------------------------------------------------------------
 * TGW, NDM, COD
 * -------------------------------------------------------------------------- */

AL_TEST(tgw_components) {
    al_potb_params p = al_potb_params_default();

    /* Nobody has vouched for this node yet. Zero, not neutral: the trust graph
     * term is a factor in a product, and an unvouched node genuinely has no
     * standing in the graph. */
    {
        al_potb_record r = al_test_node(1u, 1000u);
        r.inbound_attestations = 0u;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), 0);
    }

    /*
     * The fixture node: 100 external edges, full dispersion, no challenges. The
     * volume term is ln(1+n)/ln(101), so 100 edges is exactly where it reaches
     * one - and the division of a value by itself is exact in Q32.32, so this is
     * an equality rather than a tolerance.
     */
    al_potb_record full = al_test_node(1u, 1000u);
    AL_CHECK_EQ_I64(al_potb_tgw(&p, &full), ONE);

    /* Edges that circulate inside the node's own cluster are worth nothing: the
     * SybilRank intuition in its simplest defensible form. */
    {
        al_potb_record r = al_test_node(2u, 1000u);
        r.inbound_from_cluster = 100u;
        r.cluster_size         = 10u;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), 0);

        /* Half from outside is half the base share. cluster_size 10 with a 0.5
         * share is below the 0.8 cut-off, so the cluster floor does not apply
         * here - that is tested separately below. */
        r.inbound_from_cluster = 50u;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), HALF);

        /* A count above the total cannot underflow into a huge external share. */
        r.inbound_from_cluster = 500u;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), 0);
    }

    /*
     * Diminishing credit for edge count. Volume is the cheapest thing an
     * attacker can manufacture, so the term saturates: 200 edges is worth
     * exactly what 100 is, and 10 is worth ln(11)/ln(101) of it.
     */
    {
        al_potb_record few = al_test_node(3u, 1000u);
        few.inbound_attestations = 10u;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &few),
                        al_fixed_div(al_fixed_ln1p(al_fixed_from_int(10)),
                                     al_fixed_ln1p(al_fixed_from_int(100))));
        AL_CHECK(al_potb_tgw(&p, &few) < ONE);

        al_potb_record many = al_test_node(4u, 1000u);
        many.inbound_attestations = 200u;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &many), al_potb_tgw(&p, &full));
    }

    /*
     * Temporal dispersion. A low TDI is the signature of a farm coming online
     * together, and it scales the term down proportionally rather than zeroing
     * it, because a low reading is a signal and not a proof.
     */
    {
        al_potb_record r = al_test_node(5u, 1000u);
        r.tdi = FX(1, 10);   /* half the 0.2 suspicion threshold */
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r),
                        al_fixed_div(FX(1, 10), p.tdi_suspicious_below));
        /* Which is a half to within the two ulp the two ratios disagree by. */
        AL_CHECK_NEAR_I64(al_potb_tgw(&p, &r), HALF, 4);

        /* Exactly at the threshold is not suspicious: the comparison is strict. */
        r.tdi = p.tdi_suspicious_below;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), ONE);

        /* A zero reading zeroes the term rather than dividing by the threshold
         * and landing somewhere arbitrary. */
        r.tdi = 0;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), 0);
    }

    /*
     * External challenges, weighted 50/50 against the graph term. The protocol
     * chooses these pairings against nodes with no existing edge, so unlike
     * attestations they cannot be farmed internally - which is what earns them
     * half the weight of everything else put together.
     */
    {
        al_potb_record r = al_test_node(6u, 1000u);
        r.challenges_issued = 10u;
        r.challenges_passed = 0u;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), HALF);

        r.challenges_passed = 5u;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), HALF + ONE / 4);

        r.challenges_passed = 10u;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), ONE);   /* fully restored */

        /* More passed than issued is clamped, not credited. */
        r.challenges_passed = 50u;
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), ONE);
    }

    /*
     * The closed-cluster floor. A flagged node keeps a tenth of its score rather
     * than dropping to zero, so a false positive is recoverable: the node can
     * earn its way out with external edges and answered challenges. That
     * recoverability is the point - the check is a heuristic with false
     * positives by construction, and an unrecoverable penalty on a heuristic
     * would be a way to exclude honest operators permanently.
     */
    {
        al_potb_record r = al_test_node(7u, 1000u);
        r.inbound_from_cluster = 80u;   /* exactly the 0.8 threshold */
        r.cluster_size         = 10u;
        AL_CHECK(al_potb_is_suspicious_cluster(&p, &r));
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r),
                        al_fixed_mul(FX(2, 10), FX(1, 10)));
        AL_CHECK(al_potb_tgw(&p, &r) > 0);   /* a floor, never zero */

        /* One edge fewer and the share falls below the cut-off. */
        r.inbound_from_cluster = 79u;
        AL_CHECK(!al_potb_is_suspicious_cluster(&p, &r));
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), FX(21, 100));

        /* A large group with the same share is what a well-connected honest node
         * looks like, so only small clusters qualify. */
        r.inbound_from_cluster = 90u;
        r.cluster_size         = p.sybil_cluster_max_size;
        AL_CHECK(al_potb_is_suspicious_cluster(&p, &r));
        r.cluster_size = p.sybil_cluster_max_size + 1u;
        AL_CHECK(!al_potb_is_suspicious_cluster(&p, &r));

        /* And a cluster size of zero means "no cluster detected", not "a cluster
         * of nobody". */
        r.cluster_size = 0u;
        AL_CHECK(!al_potb_is_suspicious_cluster(&p, &r));
    }

    /* Clamped to cap_tgw, which is the hard ceiling from the specification. */
    {
        al_potb_params q = al_potb_params_default();
        q.cap_tgw = FX(3, 10);
        AL_CHECK_EQ_I64(al_potb_tgw(&q, &full), FX(3, 10));
    }
}

AL_TEST(ndm_and_cod) {
    al_potb_params p = al_potb_params_default();
    al_potb_record r = al_test_node(1u, 1000u);

    /* An unknown ASN is neutral. Penalising it would push operators to lie about
     * their network location, which makes the signal worse rather than better -
     * the multiplier is soft by design and documented as evadable. */
    AL_CHECK_EQ_I64(al_potb_ndm(&p, &r, NULL), ONE);
    r.asn            = 64512u;
    r.asn_peer_count = 0u;
    AL_CHECK_EQ_I64(al_potb_ndm(&p, &r, NULL), ONE);

    /* 1/sqrt(peers). Square root rather than a reciprocal so a cloud provider
     * hosting a hundred honest nodes does not score each of them at one per
     * cent. Both of these are exact: 1 and 4 are perfect squares. */
    r.asn_peer_count = 1u;
    AL_CHECK_EQ_I64(al_potb_ndm(&p, &r, NULL), ONE);
    r.asn_peer_count = 4u;
    AL_CHECK_EQ_I64(al_potb_ndm(&p, &r, NULL), HALF);

    r.asn_peer_count = 2u;
    AL_CHECK_EQ_I64(al_potb_ndm(&p, &r, NULL),
                    al_fixed_div(ONE, al_fixed_sqrt(2 * ONE)));

    /* Floored at 0.5, so concentration is discounted but never annihilated. */
    r.asn_peer_count = 100u;
    AL_CHECK_EQ_I64(al_potb_ndm(&p, &r, NULL), HALF);
    r.asn_peer_count = 1000000u;
    AL_CHECK_EQ_I64(al_potb_ndm(&p, &r, NULL), HALF);

    /* Monotonically non-increasing, and never above one: the multiplier only
     * ever discounts concentration, it never inflates a lone node. */
    al_fixed prev = ONE + 1;
    for (al_u32 n = 1u; n <= 300u; ++n) {
        r.asn_peer_count = n;
        al_fixed ndm = al_potb_ndm(&p, &r, NULL);
        AL_CHECK(ndm <= prev);
        AL_CHECK(ndm >= HALF && ndm <= ONE);
        prev = ndm;
    }

    /* COD = 1 / (1 + correlation_score). Exact at the integers. */
    al_potb_record c = al_test_node(2u, 1000u);
    AL_CHECK_EQ_I64(al_potb_cod(&c), ONE);
    c.correlation_score = -ONE;   /* nonsense input is neutral, not inverted */
    AL_CHECK_EQ_I64(al_potb_cod(&c), ONE);
    c.correlation_score = ONE;
    AL_CHECK_EQ_I64(al_potb_cod(&c), HALF);
    c.correlation_score = 3 * ONE;
    AL_CHECK_EQ_I64(al_potb_cod(&c), ONE / 4);
    c.correlation_score = al_fixed_from_int(9);
    /* A tenth, spelled as the division the implementation performs: al_fixed_div
     * truncates where al_fixed_from_ratio rounds half away from zero, so FX(1,10)
     * is one ulp above this. */
    AL_CHECK_EQ_I64(al_potb_cod(&c), al_fixed_div(ONE, al_fixed_from_int(10)));
    AL_CHECK_EQ_I64(al_potb_cod(&c), FX(1, 10) - 1);

    /* Strictly decreasing in the correlation score, and always positive: the
     * dampening bounds a group's joint weight without ever excluding it, which
     * is what leaves room for the appeal path the design says it needs. */
    prev = ONE + 1;
    for (al_i64 k = 0; k <= 200; ++k) {
        c.correlation_score = al_fixed_mul(al_fixed_from_int(k), FX(1, 10));
        al_fixed cod = al_potb_cod(&c);
        AL_CHECK(cod <= prev);
        AL_CHECK(cod > 0 && cod <= ONE);
        prev = cod;
    }
}

/* --------------------------------------------------------------------------
 * Correlation
 * -------------------------------------------------------------------------- */

/* Two records that share none of the four correlation signals. */
static void al_test_uncorrelated(al_potb_record *a, al_potb_record *b) {
    *a = al_test_node(10u, 100u);
    *b = al_test_node(11u, 300u);
    a->first_seen_day  = 0u;
    a->last_active_day = 1000u;
    b->first_seen_day  = 500u;
    b->last_active_day = 2000u;
}

AL_TEST(correlation_signals) {
    al_potb_record a, b;

    /* Baseline: nothing in common, nothing scored. */
    al_test_uncorrelated(&a, &b);
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), 0);
    /* And the relation is symmetric - it has to be, or a group's score would
     * depend on the order the caller happened to enumerate it in. */
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&b, &a), 0);

    /* Signal 1: registration in a nearby window. Full credit inside a day,
     * decaying linearly to nothing at 30. */
    al_test_uncorrelated(&a, &b);
    b.first_seen_day = a.first_seen_day;
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), FX(3, 10));
    b.first_seen_day = a.first_seen_day + 15u;
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b),
                    al_fixed_mul(HALF, FX(3, 10)));
    b.first_seen_day = a.first_seen_day + 29u;
    AL_CHECK(al_potb_correlation_pair(&a, &b) > 0);
    b.first_seen_day = a.first_seen_day + 30u;   /* strict <, so 30 is clear */
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), 0);

    /* Signal 2: going up and down together. Matching uptime alone is a tenth;
     * matching uptime *and* last-active day is three tenths, because two nodes
     * that restart in step are being operated in step. */
    al_test_uncorrelated(&a, &b);
    b.uptime_days     = a.uptime_days;
    b.last_active_day = a.last_active_day;
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), FX(3, 10));
    b.last_active_day = a.last_active_day + 5u;
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), FX(1, 10));
    b.last_active_day = a.last_active_day + 1u;   /* strict < 2 */
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), FX(3, 10));
    b.uptime_days = a.uptime_days + 7u;
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), 0);
    b.uptime_days = a.uptime_days + 6u;
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), FX(3, 10));

    /* Signal 3: same ASN. Weak alone - honest nodes share hosts - so it carries
     * the smallest of the four weights and only matters in combination. */
    al_test_uncorrelated(&a, &b);
    a.asn = 64512u;
    b.asn = 64512u;
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), FX(15, 100));
    b.asn = 64513u;
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), 0);
    /* Two unknown ASNs are not "the same ASN": zero means no data. */
    a.asn = 0u;
    b.asn = 0u;
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), 0);

    /* Signal 4: both inside small closed clusters with low dispersion. Two
     * separate signals agreeing is worth more than either alone. */
    al_test_uncorrelated(&a, &b);
    a.tdi          = FX(1, 10);
    b.tdi          = FX(1, 10);
    a.cluster_size = 5u;
    b.cluster_size = 5u;
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), FX(25, 100));
    b.tdi = ONE;                       /* only one node dispersion-flagged */
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), 0);
    b.tdi          = FX(1, 10);
    b.cluster_size = 0u;               /* only one node in a cluster */
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), 0);

    /*
     * All four together. 0.3 + 0.3 + 0.15 + 0.25 lands on exactly 1.0 in Q32.32:
     * the four ratios' rounding errors cancel, so this is an equality against
     * AL_FIXED_ONE and not a near-check.
     */
    al_test_uncorrelated(&a, &b);
    b.first_seen_day  = a.first_seen_day;
    b.uptime_days     = a.uptime_days;
    b.last_active_day = a.last_active_day;
    a.asn = 64512u;
    b.asn = 64512u;
    a.tdi = FX(1, 10);
    b.tdi = FX(1, 10);
    a.cluster_size = 5u;
    b.cluster_size = 5u;
    AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &b), ONE);

    /* A node is not correlated with itself, however many signals it shares with
     * itself. Without this the caller's pairwise loop would count every node
     * once against its own identity. */
    {
        al_potb_record self = a;
        self.identity = a.identity;
        AL_CHECK_EQ_I64(al_potb_correlation_pair(&a, &self), 0);
    }

    /*
     * The group score is the *mean* pairwise correlation, scaled by ln(1+n).
     *
     * Mean rather than sum, and that choice is load-bearing: the caller chooses
     * the group, so a sum would let anyone raise every member's correlation by
     * naming a larger group, with no new evidence at all.
     */
    {
        const al_potb_record *pairg[2];
        pairg[0] = &a;
        pairg[1] = &b;
        AL_CHECK_EQ_I64(al_potb_correlation_score(pairg, 2u),
                        al_fixed_ln1p(al_fixed_from_int(2)));

        /* Fewer than two nodes is not a group. */
        AL_CHECK_EQ_I64(al_potb_correlation_score(pairg, 1u), 0);
        AL_CHECK_EQ_I64(al_potb_correlation_score(pairg, 0u), 0);
    }

    /* Padding the group with unlike nodes lowers the mean, so it cannot be used
     * to inflate a score - and it lowers it faster than ln(1+n) raises it. */
    {
        al_potb_record c, d;
        al_test_uncorrelated(&c, &d);
        c.first_seen_day = 9000u;
        d.first_seen_day = 20000u;
        c.uptime_days    = 33u;
        d.uptime_days    = 777u;

        const al_potb_record *tight[2];
        tight[0] = &a;
        tight[1] = &b;
        const al_potb_record *padded[4];
        padded[0] = &a;
        padded[1] = &b;
        padded[2] = &c;
        padded[3] = &d;
        AL_CHECK(al_potb_correlation_score(padded, 4u) <
                 al_potb_correlation_score(tight, 2u));
    }

    /*
     * A NULL entry in the group. al_potb_correlation_score does not check
     * group[i], so a NULL contributes 0 through correlation_pair while still
     * counting toward the pair divisor - it dilutes the mean rather than being
     * skipped. Pinned rather than fixed: the caller builds the group, an entry
     * it left NULL is a caller bug, and diluting is the safe direction to fail
     * because it lowers a suppression multiplier's aggressiveness rather than
     * raising it.
     */
    {
        const al_potb_record *holed[3];
        holed[0] = &a;
        holed[1] = &b;
        holed[2] = NULL;
        /* Three pairs, only one of which scores, against ln(4). */
        AL_CHECK_EQ_I64(al_potb_correlation_score(holed, 3u),
                        al_fixed_mul(al_fixed_div(ONE, al_fixed_from_int(3)),
                                     al_fixed_ln1p(al_fixed_from_int(3))));

        const al_potb_record *empty[2];
        empty[0] = NULL;
        empty[1] = NULL;
        AL_CHECK_EQ_I64(al_potb_correlation_score(empty, 2u), 0);
    }
}

/* --------------------------------------------------------------------------
 * Levels
 * -------------------------------------------------------------------------- */

AL_TEST(level_boundaries) {
    al_potb_params p = al_potb_params_default();

    /*
     * The candidate floor is min_tbs_candidate = 3, and ln(1 + d) crosses it
     * between 19 and 20 days: ln(20) = 2.99573..., ln(21) = 3.04452... This
     * boundary is the arithmetic the anti-Sybil property actually rests on -
     * see antisybil_split_loses_eligibility - so it is pinned to the day.
     */
    {
        al_potb_record r = al_test_node(1u, 19u);
        AL_CHECK(al_potb_tbs(&p, &r, 1000u) < p.min_tbs_candidate);
        AL_CHECK(al_potb_level_of(&p, &r, 1000u) == AL_POTB_LEVEL_RELAY);

        al_potb_record s = al_test_node(2u, 20u);
        AL_CHECK(al_potb_tbs(&p, &s, 1000u) >= p.min_tbs_candidate);
        AL_CHECK(al_potb_level_of(&p, &s, 1000u) == AL_POTB_LEVEL_CANDIDATE);
    }

    /* The validator floor is 4, crossed between 53 and 54 days: ln(54) =
     * 3.98898..., ln(55) = 4.00733... */
    {
        al_potb_record r = al_test_node(3u, 53u);
        AL_CHECK(al_potb_level_of(&p, &r, 1000u) == AL_POTB_LEVEL_CANDIDATE);
        al_potb_record s = al_test_node(4u, 54u);
        AL_CHECK(al_potb_level_of(&p, &s, 1000u) == AL_POTB_LEVEL_VALIDATOR);
    }

    /*
     * Validator needs both thresholds. A node with a decade of flawless uptime
     * and no place in the trust graph stays a candidate, which is the whole
     * reason TGW is a separate factor: time alone is purchasable in advance, and
     * a farm that simply waits is the open risk the specification records.
     */
    {
        al_potb_record r = al_test_node(5u, 3650u);
        r.inbound_attestations = 0u;
        AL_CHECK(al_potb_tbs(&p, &r, 1000u) > p.min_tbs_validator);
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), 0);
        AL_CHECK(al_potb_level_of(&p, &r, 1000u) == AL_POTB_LEVEL_CANDIDATE);

        /*
         * Just below the TGW threshold, then exactly at it.
         *
         * 70 of 100 external edges is a base share of exactly min_tgw_validator:
         * al_fixed_from_ratio(30, 100) and AL_FX(3, 10) both round to
         * 1288490189, and the volume term at 100 edges is exactly one, so this
         * boundary is an equality and not an approximation. Spelled out because
         * it is the one threshold in this file where two differently-written
         * ratios have to agree to the ulp for the comparison to mean what it
         * reads as.
         */
        r.inbound_attestations = 100u;
        r.inbound_from_cluster = 71u;   /* external share 0.29 */
        r.cluster_size         = 0u;
        AL_CHECK(al_potb_tgw(&p, &r) < p.min_tgw_validator);
        AL_CHECK(al_potb_level_of(&p, &r, 1000u) == AL_POTB_LEVEL_CANDIDATE);
        r.inbound_from_cluster = 70u;   /* external share 0.30 */
        AL_CHECK_EQ_I64(al_potb_tgw(&p, &r), p.min_tgw_validator);
        AL_CHECK(al_potb_level_of(&p, &r, 1000u) == AL_POTB_LEVEL_VALIDATOR);
    }

    /* Banned outranks everything, and it is checked before the scores are even
     * computed - a diagnostic should read "banned", not report a score the node
     * cannot use. */
    {
        al_potb_record r = al_test_node(6u, 3650u);
        r.banned_until_day = 1001u;
        AL_CHECK(al_potb_level_of(&p, &r, 1000u) == AL_POTB_LEVEL_BANNED);
        AL_CHECK(al_potb_level_of(&p, &r, 1001u) == AL_POTB_LEVEL_VALIDATOR);
        r.permanently_banned = AL_TRUE;
        AL_CHECK(al_potb_level_of(&p, &r, 999999u) == AL_POTB_LEVEL_BANNED);
    }

    AL_CHECK_EQ_STR(al_potb_level_str(AL_POTB_LEVEL_RELAY), "relay");
    AL_CHECK_EQ_STR(al_potb_level_str(AL_POTB_LEVEL_CANDIDATE), "candidate");
    AL_CHECK_EQ_STR(al_potb_level_str(AL_POTB_LEVEL_VALIDATOR), "validator");
    AL_CHECK_EQ_STR(al_potb_level_str(AL_POTB_LEVEL_BANNED), "banned");
    /* The sentinel exists to pin the enum's width, not to name a level. */
    AL_CHECK_EQ_STR(al_potb_level_str(AL_POTB_LEVEL_SENTINEL), "unknown");
    AL_CHECK_EQ_STR(al_potb_level_str((al_potb_level)99), "unknown");

    AL_CHECK_EQ_STR(al_potb_offence_str(AL_POTB_OFFENCE_VOTE_MISS),
                    "vote-miss");
    AL_CHECK_EQ_STR(al_potb_offence_str(AL_POTB_OFFENCE_SYSTEMATIC_MISS),
                    "systematic-miss");
    AL_CHECK_EQ_STR(al_potb_offence_str(AL_POTB_OFFENCE_BAD_RESPONSE),
                    "bad-response");
    AL_CHECK_EQ_STR(al_potb_offence_str(AL_POTB_OFFENCE_SYSTEMATIC_BAD_RESPONSE),
                    "systematic-bad-response");
    AL_CHECK_EQ_STR(al_potb_offence_str(AL_POTB_OFFENCE_DOUBLE_SIGN),
                    "double-sign");
    AL_CHECK_EQ_STR(al_potb_offence_str(AL_POTB_OFFENCE_REPEAT_DOUBLE_SIGN),
                    "repeat-double-sign");
    AL_CHECK_EQ_STR(al_potb_offence_str((al_potb_offence)99), "unknown");
}

/* --------------------------------------------------------------------------
 * The anti-Sybil property
 * -------------------------------------------------------------------------- */

/*
 * Coverage bullet 4 of implementation-status.md 4 asks for a test that splitting
 * one N-day node into ten N/10-day nodes yields *less total TBS*. It does not,
 * and no choice of parameters makes it: log is concave, so a sum of logs always
 * exceeds the log of a sum. The claim in potb.md 3.1 - "the logarithm's
 * anti-Sybil property is preserved in full" - is an overclaim about TBS
 * considered alone, recorded as a divergence rather than smoothed over.
 *
 * Both real barriers are downstream of TBS, and both are testable:
 *
 *   1. the min_tbs_candidate eligibility floor, which is a step function and so
 *      not concave at all - split far enough and every piece scores zero
 *      *drawable* weight rather than merely less;
 *   2. the NDM x COD product, which prices the correlation a farm cannot avoid
 *      leaving behind.
 *
 * The three assertions below are in that order, and the first one asserts the
 * inconvenient direction on purpose. A test that quietly omitted it would leave
 * a reader believing the doc.
 */
AL_TEST(antisybil_split_loses_eligibility) {
    al_potb_params p = al_potb_params_default();

    /*
     * 1. Raw TBS: splitting *wins*, by a factor of five.
     *
     * One node at 3650 days scores ln(3651) + 3285 * 0.001 = 11.49. Ten at 365
     * days score 10 * ln(366) = 59.03 - and they get no loyalty bonus at all,
     * since the bonus is k * (d - 365) and d is exactly 365. So the gap is
     * entirely concavity, not a tuning accident.
     */
    {
        al_potb_record solo = al_test_node(1u, 3650u);
        al_fixed       one_big = al_potb_tbs(&p, &solo, 1000u);

        al_fixed split_total = 0;
        for (al_u32 i = 0u; i < 10u; ++i) {
            al_potb_record piece = al_test_node(100u + i, 365u);
            split_total = al_fixed_add(split_total,
                                       al_potb_tbs(&p, &piece, 1000u));
        }
        AL_CHECK(split_total > one_big);
        /* Roughly five times, and pinned so a retune that changes the shape of
         * the curve shows up here rather than only in a simulation. */
        AL_CHECK(split_total > al_fixed_mul(one_big, al_fixed_from_int(4)));
        AL_CHECK(split_total < al_fixed_mul(one_big, al_fixed_from_int(6)));

        /* The loyalty bonus is exactly zero at the threshold day. */
        al_potb_record at_threshold = al_test_node(2u, p.loyalty_threshold_days);
        AL_CHECK_EQ_I64(al_potb_loyalty_bonus(&p, p.loyalty_threshold_days), 0);
        AL_CHECK_EQ_I64(al_potb_tbs(&p, &at_threshold, 1000u),
                        al_fixed_ln1p(al_fixed_from_int(365)));
    }

    /*
     * 2. The eligibility floor is where the split actually dies.
     *
     * ln(1 + d) >= 3 needs d >= 20 (see level_boundaries), so splitting 3650
     * node-days 200 ways gives 18 days each - every piece below the candidate
     * floor, every piece a relay, every piece drawn with weight zero. Selection
     * does not return a weaker committee, it returns none: there is no drawable
     * weight in the entire pool.
     *
     * This is the barrier that is genuinely a step rather than a curve, and so
     * the only one concavity cannot erode.
     */
    {
        al_arena a;
        AL_CHECK_EQ_STATUS(al_arena_init(&a, 64u * 1024u), AL_OK);

        static al_potb_record        recs[200];
        static const al_potb_record *cands[200];
        for (al_u32 i = 0u; i < 200u; ++i) {
            recs[i]  = al_test_node(200u + i, 3650u / 200u);   /* 18 days */
            cands[i] = &recs[i];
        }
        AL_CHECK_EQ_U64(recs[0].uptime_days, 18u);
        AL_CHECK(al_potb_tbs(&p, &recs[0], 1000u) < p.min_tbs_candidate);
        AL_CHECK(al_potb_level_of(&p, &recs[0], 1000u) == AL_POTB_LEVEL_RELAY);

        al_hash256 seed = al_hash_zero();
        static al_potb_committee out;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 200u, NULL, &seed, 1u, 1000u,
                                     &a, &out),
            AL_ERR_NOT_FOUND);
        AL_CHECK_EQ_U64(out.size, 0u);

        /* Whereas the unsplit node is eligible on its own. */
        static al_potb_record        solo_rec;
        static const al_potb_record *solo_cand[1];
        solo_rec     = al_test_node(3u, 3650u);
        solo_cand[0] = &solo_rec;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, solo_cand, 1u, NULL, &seed, 1u, 1000u,
                                     &a, &out),
            AL_OK);
        AL_CHECK_EQ_U64(out.size, 1u);

        al_arena_destroy(&a);
    }

    /*
     * 3. And the weight product prices what survives.
     *
     * Ten farm nodes with the same ASN (peer count 10), the same registration
     * day, the same uptime and last-active day, each with tdi = 0.1 and inside a
     * cluster - which is what a farm looks like even when every individual node
     * passes every individual check. Per-pair correlation is the full
     * 0.3 + 0.3 + 0.15 + 0.25 = 1.0, so:
     *
     *   correlation_score = 1.0 * ln(11)   = 2.398
     *   COD               = 1 / 3.398      = 0.294
     *   NDM               = 1 / sqrt(10)   = 0.316, floored to 0.5
     *   TGW               = 0.1 / 0.2      = 0.5
     *
     * against a solo node of identical uptime scoring 1.0 on all three. Roughly
     * a thirteenfold discount per node; asserted at eightfold so an ulp or a
     * small retune does not make this fail spuriously.
     */
    {
        static al_potb_record        farm[10];
        static const al_potb_record *group[10];
        for (al_u32 i = 0u; i < 10u; ++i) {
            farm[i]                 = al_test_node(300u + i, 365u);
            farm[i].asn             = 64512u;
            farm[i].asn_peer_count  = 10u;
            farm[i].first_seen_day  = 635u;
            farm[i].last_active_day = 1000u;
            farm[i].tdi             = FX(1, 10);
            farm[i].cluster_size    = 10u;
            group[i]                = &farm[i];
        }
        /* Every pair maxes out all four signals. */
        AL_CHECK_EQ_I64(al_potb_correlation_pair(&farm[0], &farm[1]), ONE);

        al_fixed score = al_potb_correlation_score(group, 10u);
        AL_CHECK_EQ_I64(score, al_fixed_ln1p(al_fixed_from_int(10)));
        for (al_u32 i = 0u; i < 10u; ++i) {
            farm[i].correlation_score = score;
        }

        al_potb_record solo = al_test_node(4u, 365u);
        al_fixed       w_solo = al_potb_weight_total(&p, &solo, NULL, 1000u);
        al_fixed       w_farm = al_potb_weight_total(&p, &farm[0], NULL, 1000u);

        AL_CHECK(w_solo > 0 && w_farm > 0);
        AL_CHECK(al_fixed_mul(w_farm, al_fixed_from_int(8)) < w_solo);

        /*
         * And the combined weight of all ten is *below* the single node's,
         * despite ten times the node-days: 0.5 * 0.5 * 0.294 is a discount of
         * about 13.6x per node, so ten of them come to roughly 0.74 of one
         * undiscounted operator. This is the anti-Sybil property genuinely
         * holding - at the weight level, where the doc claims it for TBS.
         *
         * With the emphasis on *detected*. Every term above is driven by a
         * correlation signal the farm left behind; a patient attacker who
         * staggers registration, spreads ASNs and lets TDI rise pays none of it.
         * That is exactly the open risk in potb.md 7, and this assertion should
         * be read as pinning the arithmetic rather than as evidence the risk is
         * closed.
         */
        AL_CHECK(al_fixed_mul(w_farm, al_fixed_from_int(10)) < w_solo);

        /* Each factor pulls its stated weight, so a regression in one is visible
         * rather than masked by the others. */
        al_potb_weight parts;
        al_potb_weight_compute(&p, &farm[0], NULL, 1000u, &parts);
        AL_CHECK_EQ_I64(parts.ndm, HALF);
        AL_CHECK_EQ_I64(parts.cod, al_fixed_div(ONE, al_fixed_add(ONE, score)));
        AL_CHECK_EQ_I64(parts.tgw, al_fixed_div(FX(1, 10),
                                                p.tdi_suspicious_below));
        AL_CHECK_EQ_I64(parts.total,
                        al_fixed_mul(al_fixed_mul(al_fixed_mul(parts.tbs_capped,
                                                               parts.tgw_capped),
                                                  parts.ndm),
                                     parts.cod));
    }
}

/* --------------------------------------------------------------------------
 * Slashing
 * -------------------------------------------------------------------------- */

AL_TEST(slashing_relativity) {
    al_potb_params p = al_potb_params_default();

    /*
     * The penalty table, asserted exactly against potb.md 8.1.
     *
     * VOTE_MISS and SYSTEMATIC_MISS are both 0.95 today, though the table
     * describes the first as "no penalty" and only the second as -5%. That is
     * open question Q15 and a test may not settle it: pinning the value makes a
     * future change visible, while asserting the doc's reading would fail today
     * and would amount to this suite deciding a consensus rate. The distinction
     * currently lives in whether al_potb_slash *applies* the factor at all, not
     * in the factor itself - which is what the excuse path below tests.
     */
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_VOTE_MISS),
                    FX(95, 100));
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_SYSTEMATIC_MISS),
                    FX(95, 100));
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_BAD_RESPONSE),
                    FX(90, 100));
    AL_CHECK_EQ_I64(
        al_potb_penalty_for(AL_POTB_OFFENCE_SYSTEMATIC_BAD_RESPONSE),
        FX(80, 100));
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_DOUBLE_SIGN),
                    FX(10, 100));
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_REPEAT_DOUBLE_SIGN), 0);
    /* An unrecognised offence is neutral, not maximally punitive: a node must not
     * be destroyed by a code path that does not know what it is looking at. */
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_SENTINEL), ONE);
    AL_CHECK_EQ_I64(al_potb_penalty_for((al_potb_offence)99), ONE);

    /*
     * The median rule: strictly more than twice the median is anomalous. The
     * comparison itself is static inside score.c, so it is driven here through
     * al_potb_slash, which is where it is observable anyway - excused offences
     * return AL_ERR_NOT_FOUND and leave the record untouched.
     */

    al_potb_network_stats net;
    memset(&net, 0, sizeof(net));
    net.node_count        = 1000u;
    net.median_miss_rate  = FX(1, 10);
    net.median_error_rate = FX(1, 10);

    /* At the median: excused, and the record is left completely alone. */
    {
        al_potb_record r  = al_test_node(1u, 400u);
        r.votes_expected  = 100u;
        r.votes_cast      = 90u;   /* miss rate 0.10 */
        AL_CHECK_EQ_STATUS(al_potb_slash(&p, &r, &net,
                                         AL_POTB_OFFENCE_VOTE_MISS, 1000u),
                           AL_ERR_NOT_FOUND);
        AL_CHECK_EQ_I64(r.penalty_multiplier, ONE);
        AL_CHECK_EQ_U64(r.banned_until_day, 0u);
    }

    /* At three times the median: the penalty lands. */
    {
        al_potb_record r = al_test_node(2u, 400u);
        r.votes_expected = 100u;
        r.votes_cast     = 70u;   /* miss rate 0.30 > 0.20 */
        AL_CHECK_EQ_STATUS(al_potb_slash(&p, &r, &net,
                                         AL_POTB_OFFENCE_VOTE_MISS, 1000u),
                           AL_OK);
        AL_CHECK_EQ_I64(r.penalty_multiplier, FX(95, 100));
    }

    /* Bad responses are judged against the error median, not the miss median. */
    {
        al_potb_record r    = al_test_node(3u, 400u);
        r.responses_total   = 100u;
        r.responses_correct = 95u;   /* error rate 0.05, below the median */
        AL_CHECK_EQ_STATUS(al_potb_slash(&p, &r, &net,
                                         AL_POTB_OFFENCE_BAD_RESPONSE, 1000u),
                           AL_ERR_NOT_FOUND);
        r.responses_correct = 60u;   /* error rate 0.40 */
        AL_CHECK_EQ_STATUS(al_potb_slash(&p, &r, &net,
                                         AL_POTB_OFFENCE_BAD_RESPONSE, 1000u),
                           AL_OK);
        AL_CHECK_EQ_I64(r.penalty_multiplier, FX(90, 100));
    }

    /*
     * Only those two offences are excusable. Systematic patterns and
     * double-signing land regardless of what the rest of the network is doing,
     * because "everyone else was also double-signing" is not a defence.
     */
    {
        al_potb_record r = al_test_node(4u, 400u);
        r.votes_expected = 100u;
        r.votes_cast     = 100u;   /* a spotless record */
        AL_CHECK_EQ_STATUS(al_potb_slash(&p, &r, &net,
                                         AL_POTB_OFFENCE_SYSTEMATIC_MISS,
                                         1000u),
                           AL_OK);
        AL_CHECK_EQ_I64(r.penalty_multiplier, FX(95, 100));
    }

    /*
     * With no network statistics there is nothing to be relative *to*, so the
     * excuse path is skipped entirely and the penalty always applies. Convenient
     * for testing compounding: penalties multiply rather than subtract, so no
     * sequence of them can drive a score negative, and 0.9 * 0.9 is exact in
     * Q32.32 because both factors are dyadic-free but their product fits.
     */
    {
        al_potb_record r = al_test_node(5u, 400u);
        AL_CHECK_EQ_STATUS(al_potb_slash(&p, &r, NULL,
                                         AL_POTB_OFFENCE_BAD_RESPONSE, 1000u),
                           AL_OK);
        AL_CHECK_EQ_I64(r.penalty_multiplier, FX(90, 100));
        AL_CHECK_EQ_STATUS(al_potb_slash(&p, &r, NULL,
                                         AL_POTB_OFFENCE_BAD_RESPONSE, 1000u),
                           AL_OK);
        AL_CHECK_EQ_I64(r.penalty_multiplier,
                        al_fixed_mul(FX(90, 100), FX(90, 100)));

        /* Twenty more, to show it converges toward zero and never crosses it. */
        for (al_u32 i = 0u; i < 20u; ++i) {
            AL_CHECK_EQ_STATUS(al_potb_slash(&p, &r, NULL,
                                             AL_POTB_OFFENCE_BAD_RESPONSE,
                                             1000u),
                               AL_OK);
        }
        AL_CHECK(r.penalty_multiplier >= 0);
        AL_CHECK(r.penalty_multiplier < FX(20, 100));
        AL_CHECK(al_potb_tbs(&p, &r, 1000u) >= 0);
    }

    /* Double-signing: 90% off and a 14-day ban, both from the same call. */
    {
        al_potb_record r = al_test_node(6u, 400u);
        AL_CHECK_EQ_STATUS(al_potb_slash(&p, &r, &net,
                                         AL_POTB_OFFENCE_DOUBLE_SIGN, 1000u),
                           AL_OK);
        AL_CHECK_EQ_I64(r.penalty_multiplier, FX(10, 100));
        AL_CHECK_EQ_U64(r.banned_until_day, 1014u);
        AL_CHECK(!r.permanently_banned);
        /* Banned means no weight, even though TBS itself is still positive. */
        AL_CHECK(al_potb_tbs(&p, &r, 1000u) > 0);
        AL_CHECK_EQ_I64(al_potb_weight_total(&p, &r, &net, 1000u), 0);
        AL_CHECK(al_potb_level_of(&p, &r, 1000u) == AL_POTB_LEVEL_BANNED);
        /* And on the expiry day itself the node is free again. */
        AL_CHECK(al_potb_weight_total(&p, &r, &net, 1014u) > 0);

        /* A repeat ends the identity. The multiplier goes to zero as well as the
         * flag, so nothing downstream can resurrect it by clearing one field. */
        AL_CHECK_EQ_STATUS(al_potb_slash(&p, &r, &net,
                                         AL_POTB_OFFENCE_REPEAT_DOUBLE_SIGN,
                                         1014u),
                           AL_OK);
        AL_CHECK(r.permanently_banned);
        AL_CHECK_EQ_I64(r.penalty_multiplier, 0);
        AL_CHECK_EQ_I64(al_potb_tbs(&p, &r, 999999u), 0);
        AL_CHECK_EQ_I64(al_potb_weight_total(&p, &r, &net, 999999u), 0);

        /* Slashing a dead identity succeeds and changes nothing - the ban day is
         * not even pushed out. Idempotent, so two validators reporting the same
         * offence cannot diverge, and a permanent ban is genuinely terminal
         * rather than a state later calls keep rewriting. */
        AL_CHECK_EQ_STATUS(al_potb_slash(&p, &r, &net,
                                         AL_POTB_OFFENCE_DOUBLE_SIGN, 2000u),
                           AL_OK);
        AL_CHECK_EQ_U64(r.banned_until_day, 1014u);
        AL_CHECK(r.permanently_banned);
        AL_CHECK_EQ_I64(r.penalty_multiplier, 0);
    }

    /* Mutating functions reject NULL rather than returning a neutral value, the
     * opposite of the scoring functions - there is no neutral way to not-mutate
     * something the caller believes was mutated. */
    {
        al_potb_record r = al_test_node(7u, 400u);
        AL_CHECK_EQ_STATUS(al_potb_slash(NULL, &r, &net,
                                         AL_POTB_OFFENCE_DOUBLE_SIGN, 1000u),
                           AL_ERR_INVALID_ARG);
        AL_CHECK_EQ_STATUS(al_potb_slash(&p, NULL, &net,
                                         AL_POTB_OFFENCE_DOUBLE_SIGN, 1000u),
                           AL_ERR_INVALID_ARG);
        AL_CHECK_EQ_I64(r.penalty_multiplier, ONE);
    }
}

AL_TEST(quorum_threshold) {
    /* floor(2n/3) + 1. Byzantine agreement needs more than two thirds, and the
     * +1 is what turns "at least two thirds" into "more than". */
    AL_CHECK_EQ_U64(al_potb_quorum_threshold(0u), 0u);   /* nobody, not one */
    AL_CHECK_EQ_U64(al_potb_quorum_threshold(1u), 1u);
    AL_CHECK_EQ_U64(al_potb_quorum_threshold(2u), 2u);
    AL_CHECK_EQ_U64(al_potb_quorum_threshold(3u), 3u);
    AL_CHECK_EQ_U64(al_potb_quorum_threshold(4u), 3u);
    AL_CHECK_EQ_U64(al_potb_quorum_threshold(10u), 7u);
    AL_CHECK_EQ_U64(al_potb_quorum_threshold(100u), 67u);
    AL_CHECK_EQ_U64(al_potb_quorum_threshold(AL_POTB_MAX_COMMITTEE), 342u);

    /* Two thirds may not be enough and the threshold must exceed it. Checked
     * across the whole committee range, since this is the one inequality BFT
     * safety rests on. */
    for (al_u32 n = 1u; n <= AL_POTB_MAX_COMMITTEE; ++n) {
        al_u32 q = al_potb_quorum_threshold(n);
        AL_CHECK(q <= n);
        AL_CHECK((al_u64)q * 3u > (al_u64)n * 2u);
        /* And no smaller value would do, so the threshold is not merely safe but
         * tight - a looser one would cost liveness for nothing. */
        AL_CHECK((al_u64)(q - 1u) * 3u <= (al_u64)n * 2u);
    }

    /* The multiply is widened to 64 bits inside, so a nonsense size cannot wrap
     * into a tiny quorum - which would be the dangerous direction to fail. */
    {
        al_u32 q = al_potb_quorum_threshold(UINT32_MAX);
        AL_CHECK_EQ_U64(q, (al_u32)(((al_u64)UINT32_MAX * 2u) / 3u + 1u));
        AL_CHECK((al_u64)q * 3u > (al_u64)UINT32_MAX * 2u);
    }
}

/* --------------------------------------------------------------------------
 * Committee selection
 * -------------------------------------------------------------------------- */

/*
 * Committees are ~20.5 KB apiece (512 keys plus 512 weights), so every one of
 * them below is static rather than a stack local: two on one frame is 41 KB,
 * which is fine on a default Windows stack and not fine everywhere.
 */

/* Fill a candidate pool with eligible validators of varied weight. Uptimes are
 * spread so the draw has something to be proportional to. */
static void al_test_pool(al_potb_record *recs, const al_potb_record **cands,
                         al_u32 n, al_u32 base) {
    for (al_u32 i = 0u; i < n; ++i) {
        recs[i]  = al_test_node(base + i, 100u + i * 37u);
        cands[i] = &recs[i];
    }
}

AL_TEST(committee_determinism) {
    al_potb_params p = al_potb_params_default();
    al_arena       a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 64u * 1024u), AL_OK);

    static al_potb_record        recs[50];
    static const al_potb_record *cands[50];
    al_test_pool(recs, cands, 50u, 1000u);

    al_hash256 seed;
    memset(&seed, 0xa7, sizeof(seed));

    /*
     * The property the whole design rests on: two nodes given the same seed, the
     * same height, the same day and the same candidate list must produce
     * byte-identical committees. If they do not, they disagree about who may vote
     * on finality, and the chain splits without anybody misbehaving.
     */
    static al_potb_committee c1;
    static al_potb_committee c2;
    AL_CHECK_EQ_STATUS(
        al_potb_committee_select(&p, cands, 50u, NULL, &seed, 42u, 1000u, &a, &c1),
        AL_OK);
    AL_CHECK_EQ_STATUS(
        al_potb_committee_select(&p, cands, 50u, NULL, &seed, 42u, 1000u, &a, &c2),
        AL_OK);

    AL_CHECK_EQ_U64(c1.size, c2.size);
    AL_CHECK_EQ_U64(c1.size, 50u);   /* fewer eligible than committee_size */
    AL_CHECK(memcmp(c1.members, c2.members, c1.size * sizeof(c1.members[0])) == 0);
    AL_CHECK(memcmp(c1.weights, c2.weights, c1.size * sizeof(c1.weights[0])) == 0);
    AL_CHECK_EQ_U64(c1.formed_at, 42u);
    AL_CHECK(al_bytes_eq(al_bytes_make(c1.seed.bytes, AL_HASH_SIZE),
                         al_bytes_make(seed.bytes, AL_HASH_SIZE)));

    /*
     * One flipped seed bit changes the draw. With 50 candidates and a target of
     * 100 every candidate is drawn either way, so the *set* is necessarily
     * identical - what must differ is the order, which is what determines which
     * seats survive a later rotation. Comparing sets here would be a test that
     * cannot fail.
     */
    {
        al_hash256 other = seed;
        other.bytes[0] ^= 0x01u;
        static al_potb_committee c3;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 50u, NULL, &other, 42u, 1000u,
                                     &a, &c3),
            AL_OK);
        AL_CHECK_EQ_U64(c3.size, c1.size);
        AL_CHECK(memcmp(c1.members, c3.members,
                        c1.size * sizeof(c1.members[0])) != 0);
    }

    /* And so does the height, which is mixed into the hash chain alongside the
     * seed - otherwise one epoch seed would give every block in the epoch the
     * same committee order. */
    {
        static al_potb_committee c4;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 50u, NULL, &seed, 43u, 1000u,
                                     &a, &c4),
            AL_OK);
        AL_CHECK(memcmp(c1.members, c4.members,
                        c1.size * sizeof(c1.members[0])) != 0);
        AL_CHECK_EQ_U64(c4.formed_at, 43u);
    }

    /* Candidate order is not consensus-visible: the pool build and the swap-remove
     * are the same for every node given the same list, but a node that enumerates
     * its candidate set differently must still land on the same committee. It
     * does not - and that is worth knowing precisely, so it is pinned as the
     * requirement it places on the caller rather than asserted away.
     *
     * Reversing the list changes the draw, so *the caller* must present
     * candidates in a canonical order. Nothing in this API enforces that, and
     * nothing in the tree yet defines it - it belongs with the genesis and block
     * formats that do not exist. Recorded here so the requirement is written down
     * somewhere executable.
     */
    {
        static const al_potb_record *rev[50];
        for (al_u32 i = 0u; i < 50u; ++i) {
            rev[i] = cands[49u - i];
        }
        static al_potb_committee c5;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, rev, 50u, NULL, &seed, 42u, 1000u, &a,
                                     &c5),
            AL_OK);
        AL_CHECK_EQ_U64(c5.size, c1.size);
        AL_CHECK(memcmp(c1.members, c5.members,
                        c1.size * sizeof(c1.members[0])) != 0);
    }

    al_arena_destroy(&a);
}

AL_TEST(committee_sampling) {
    al_potb_params p = al_potb_params_default();
    al_arena       a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 64u * 1024u), AL_OK);

    al_hash256 seed;
    memset(&seed, 0x3c, sizeof(seed));

    static al_potb_record        recs[300];
    static const al_potb_record *cands[300];
    al_test_pool(recs, cands, 300u, 2000u);

    static al_potb_committee c;
    AL_CHECK_EQ_STATUS(
        al_potb_committee_select(&p, cands, 300u, NULL, &seed, 7u, 1000u, &a, &c),
        AL_OK);
    AL_CHECK_EQ_U64(c.size, p.committee_size);

    /* Nobody sits twice. A duplicated member would vote twice toward a quorum of
     * two thirds, so one node holding two seats out of a hundred is worth two
     * honest nodes - the sampling is without replacement precisely to stop that. */
    for (al_u32 i = 0u; i < c.size; ++i) {
        for (al_u32 j = i + 1u; j < c.size; ++j) {
            AL_CHECK(!al_bytes_eq(al_bytes_make(c.members[i].bytes, AL_PUBKEY_SIZE),
                                  al_bytes_make(c.members[j].bytes,
                                                AL_PUBKEY_SIZE)));
        }
    }

    /* Every member is a real candidate with a positive recorded weight. */
    for (al_u32 i = 0u; i < c.size; ++i) {
        AL_CHECK(c.weights[i] > 0);
        al_bool found = AL_FALSE;
        for (al_u32 k = 0u; k < 300u; ++k) {
            if (al_bytes_eq(al_bytes_make(c.members[i].bytes, AL_PUBKEY_SIZE),
                            al_bytes_make(recs[k].identity.bytes,
                                          AL_PUBKEY_SIZE))) {
                found = AL_TRUE;
                break;
            }
        }
        AL_CHECK(found);
    }

    /*
     * Banned nodes are never drawn, by either route. A permanent ban and an
     * unexpired temporary ban must both exclude, because a node the chain has
     * condemned voting on finality is the outcome slashing exists to prevent.
     */
    {
        static al_potb_record        mixed[100];
        static const al_potb_record *mixed_c[100];
        al_test_pool(mixed, mixed_c, 100u, 3000u);
        for (al_u32 i = 0u; i < 40u; ++i) {
            mixed[i].permanently_banned = AL_TRUE;
        }
        for (al_u32 i = 40u; i < 80u; ++i) {
            /* Expiring at 1005, not far in the future: the fixtures were last
             * active on day 1000, and probing a distant day would decay every
             * node below the candidate floor and yield an empty committee for a
             * reason that has nothing to do with bans. */
            mixed[i].banned_until_day = 1005u;
        }
        static al_potb_committee bc;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, mixed_c, 100u, NULL, &seed, 7u, 1000u,
                                     &a, &bc),
            AL_OK);
        AL_CHECK_EQ_U64(bc.size, 20u);   /* only the 20 unbanned */
        for (al_u32 i = 0u; i < 80u; ++i) {
            AL_CHECK(!al_potb_committee_contains(&bc, &mixed[i].identity));
        }
        for (al_u32 i = 80u; i < 100u; ++i) {
            AL_CHECK(al_potb_committee_contains(&bc, &mixed[i].identity));
        }

        /* Once the temporary bans expire those nodes are drawable again - a ban is
         * a suspension, not a deletion. The 40 permanent ones stay out. */
        static al_potb_committee bc2;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, mixed_c, 100u, NULL, &seed, 7u, 1005u,
                                     &a, &bc2),
            AL_OK);
        AL_CHECK_EQ_U64(bc2.size, 60u);
        for (al_u32 i = 0u; i < 40u; ++i) {
            AL_CHECK(!al_potb_committee_contains(&bc2, &mixed[i].identity));
        }
    }

    /* Relays are not drawn either: below the candidate floor is not "low weight",
     * it is no weight at all. */
    {
        static al_potb_record        young[20];
        static const al_potb_record *young_c[20];
        for (al_u32 i = 0u; i < 20u; ++i) {
            young[i]   = al_test_node(4000u + i, 19u);   /* below min_tbs */
            young_c[i] = &young[i];
        }
        static al_potb_committee yc;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, young_c, 20u, NULL, &seed, 7u, 1000u,
                                     &a, &yc),
            AL_ERR_NOT_FOUND);
        AL_CHECK_EQ_U64(yc.size, 0u);
    }

    /*
     * Candidates are drawn at candidate_weight_factor of their weight, so a
     * committee-candidate counts for half a validator in the draw. Trial
     * participation at reduced influence is the whole point of the level.
     */
    {
        al_potb_record cand = al_test_node(5000u, 30u);   /* tbs ~3.4: CANDIDATE */
        AL_CHECK(al_potb_level_of(&p, &cand, 1000u) == AL_POTB_LEVEL_CANDIDATE);
        static al_potb_record        one[1];
        static const al_potb_record *one_c[1];
        one[0]  = cand;
        one_c[0] = &one[0];
        static al_potb_committee cc;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, one_c, 1u, NULL, &seed, 7u, 1000u, &a,
                                     &cc),
            AL_OK);
        AL_CHECK_EQ_U64(cc.size, 1u);
        AL_CHECK_EQ_I64(cc.weights[0],
                        al_fixed_mul(al_potb_weight_total(&p, &cand, NULL, 1000u),
                                     p.candidate_weight_factor));
    }

    /* Fewer eligible nodes than the target is a small committee, not an error: a
     * chain that refused to start until it had a hundred validators would never
     * start. */
    {
        static al_potb_committee sc;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 7u, NULL, &seed, 7u, 1000u, &a,
                                     &sc),
            AL_OK);
        AL_CHECK_EQ_U64(sc.size, 7u);
    }

    /*
     * The arena is restored to its entry mark on every path, success or failure.
     * Selection runs once per block for the life of the chain, so a scratch
     * allocation that outlived the call would be an unbounded leak in the hottest
     * loop in the system.
     */
    {
        al_size before = al_arena_used(&a);
        static al_potb_committee ac;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 300u, NULL, &seed, 9u, 1000u,
                                     &a, &ac),
            AL_OK);
        AL_CHECK_EQ_U64(al_arena_used(&a), before);

        /* Including the failing paths, which are the ones that usually leak. */
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 0u, NULL, &seed, 9u, 1000u, &a,
                                     &ac),
            AL_ERR_NOT_FOUND);
        AL_CHECK_EQ_U64(al_arena_used(&a), before);

        static al_potb_record        none[4];
        static const al_potb_record *none_c[4];
        for (al_u32 i = 0u; i < 4u; ++i) {
            none[i]   = al_test_node(6000u + i, 400u);
            none[i].permanently_banned = AL_TRUE;
            none_c[i] = &none[i];
        }
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, none_c, 4u, NULL, &seed, 9u, 1000u, &a,
                                     &ac),
            AL_ERR_NOT_FOUND);
        AL_CHECK_EQ_U64(al_arena_used(&a), before);
        AL_CHECK_EQ_U64(ac.size, 0u);
    }

    /* Argument checks. An empty candidate list with a NULL pointer is allowed -
     * "no candidates" is a state, not a caller bug - but a nonzero count with a
     * NULL pointer is. */
    {
        static al_potb_committee ec;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, NULL, 0u, NULL, &seed, 1u, 1000u, &a,
                                     &ec),
            AL_ERR_NOT_FOUND);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, NULL, 5u, NULL, &seed, 1u, 1000u, &a,
                                     &ec),
            AL_ERR_INVALID_ARG);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(NULL, cands, 50u, NULL, &seed, 1u, 1000u,
                                     &a, &ec),
            AL_ERR_INVALID_ARG);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 50u, NULL, NULL, 1u, 1000u, &a,
                                     &ec),
            AL_ERR_INVALID_ARG);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 50u, NULL, &seed, 1u, 1000u,
                                     NULL, &ec),
            AL_ERR_INVALID_ARG);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 50u, NULL, &seed, 1u, 1000u, &a,
                                     NULL),
            AL_ERR_INVALID_ARG);

        /* An out-of-range committee size is rejected before anything is written,
         * so a caller cannot get a committee of 513 keys into a 512-key array. */
        al_potb_params q = al_potb_params_default();
        q.committee_size = 0u;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&q, cands, 50u, NULL, &seed, 1u, 1000u, &a,
                                     &ec),
            AL_ERR_OUT_OF_RANGE);
        q.committee_size = AL_POTB_MAX_COMMITTEE + 1u;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&q, cands, 50u, NULL, &seed, 1u, 1000u, &a,
                                     &ec),
            AL_ERR_OUT_OF_RANGE);
        q.committee_size = AL_POTB_MAX_COMMITTEE;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&q, cands, 300u, NULL, &seed, 1u, 1000u,
                                     &a, &ec),
            AL_OK);
        AL_CHECK_EQ_U64(ec.size, 300u);
    }

    /* Membership test, over a committee and over an empty one. Not
     * constant-time, deliberately: who sits on a committee is public. */
    {
        AL_CHECK(al_potb_committee_contains(&c, &c.members[0]));
        al_pubkey absent = al_test_key(999999u);
        AL_CHECK(!al_potb_committee_contains(&c, &absent));
        AL_CHECK(!al_potb_committee_contains(NULL, &absent));
        AL_CHECK(!al_potb_committee_contains(&c, NULL));
    }

    al_arena_destroy(&a);
}

/* --------------------------------------------------------------------------
 * Committee rotation
 * -------------------------------------------------------------------------- */

/* How many of `before`'s members are no longer in `after`. */
static al_u32 al_test_departed(const al_potb_committee *before,
                               const al_potb_committee *after) {
    al_u32 gone = 0u;
    for (al_u32 i = 0u; i < before->size; ++i) {
        if (!al_potb_committee_contains(after, &before->members[i])) {
            ++gone;
        }
    }
    return gone;
}

AL_TEST(committee_rotation) {
    al_potb_params p = al_potb_params_default();
    al_arena       a;
    AL_CHECK_EQ_STATUS(al_arena_init(&a, 128u * 1024u), AL_OK);

    al_hash256 seed;
    memset(&seed, 0x11, sizeof(seed));

    static al_potb_record        recs[300];
    static const al_potb_record *cands[300];
    al_test_pool(recs, cands, 300u, 7000u);

    static al_potb_committee c;
    AL_CHECK_EQ_STATUS(
        al_potb_committee_select(&p, cands, 300u, NULL, &seed, 100u, 1000u, &a, &c),
        AL_OK);
    AL_CHECK_EQ_U64(c.size, 100u);

    /*
     * Partial rotation: round(0.1 * 100) = 10 seats turn over per block, so full
     * turnover takes committee_lifetime_blocks. Replacing all hundred every block
     * is the networking load the design explicitly rejected; never replacing any
     * is the predictability it exists to prevent.
     */
    {
        static al_potb_committee before;
        before = c;

        al_hash256 rot_seed;
        memset(&rot_seed, 0x22, sizeof(rot_seed));
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &c, cands, 300u, NULL, &rot_seed, 101u,
                                     1000u, &a),
            AL_OK);

        AL_CHECK_EQ_U64(c.size, 100u);   /* refilled back to target */
        AL_CHECK_EQ_U64(al_test_departed(&before, &c), 10u);

        /* formed_at dates the committee's formation and rotation extends a
         * committee rather than creating one, so it is deliberately untouched -
         * the caller's lifetime accounting against committee_lifetime_blocks
         * depends on that. The seed is updated, so the rotation is auditable. */
        AL_CHECK_EQ_U64(c.formed_at, 100u);
        AL_CHECK(al_bytes_eq(al_bytes_make(c.seed.bytes, AL_HASH_SIZE),
                             al_bytes_make(rot_seed.bytes, AL_HASH_SIZE)));

        /* No duplicates afterwards: an evicted member is excluded from the refill
         * pool, so it cannot be drawn straight back into a second seat. */
        for (al_u32 i = 0u; i < c.size; ++i) {
            for (al_u32 j = i + 1u; j < c.size; ++j) {
                AL_CHECK(!al_bytes_eq(
                    al_bytes_make(c.members[i].bytes, AL_PUBKEY_SIZE),
                    al_bytes_make(c.members[j].bytes, AL_PUBKEY_SIZE)));
            }
        }

        /* Deterministic, like selection: same committee, same seed, same height,
         * same result. */
        static al_potb_committee r1;
        static al_potb_committee r2;
        r1 = before;
        r2 = before;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &r1, cands, 300u, NULL, &rot_seed, 101u,
                                     1000u, &a),
            AL_OK);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &r2, cands, 300u, NULL, &rot_seed, 101u,
                                     1000u, &a),
            AL_OK);
        AL_CHECK_EQ_U64(r1.size, r2.size);
        AL_CHECK(memcmp(r1.members, r2.members,
                        r1.size * sizeof(r1.members[0])) == 0);
        AL_CHECK(memcmp(r1.weights, r2.weights,
                        r1.size * sizeof(r1.weights[0])) == 0);
    }

    /*
     * The floor of one, so rotation always makes progress. Without it a committee
     * small enough for round(fraction * size) to reach zero would freeze for the
     * rest of its life - exactly the predictability partial rotation exists to
     * prevent.
     *
     * Where the floor actually bites is below five, not at five: the comment at
     * committee.c:390-396 offers "size 5, fraction 0.1 -> 0.5, rounding that to
     * zero would freeze the committee" as the motivating case, but
     * al_fixed_to_int_round rounds half away from zero, so 0.5 already gives 1 and
     * the floor is not reached. It is size 4 (0.4 -> 0) and below that needs it.
     * Both are pinned; the source comment's example is imprecise about which case
     * is load-bearing, not wrong about the need for the floor.
     */
    {
        al_potb_params q = al_potb_params_default();

        AL_CHECK_EQ_I64(al_fixed_to_int_round(
                            al_fixed_mul(al_fixed_from_int(5),
                                         q.rotation_fraction)),
                        1);   /* rounds up on its own */
        AL_CHECK_EQ_I64(al_fixed_to_int_round(
                            al_fixed_mul(al_fixed_from_int(4),
                                         q.rotation_fraction)),
                        0);   /* would freeze without the floor */

        static al_potb_record        small[4];
        static const al_potb_record *small_c[4];
        al_test_pool(small, small_c, 4u, 8000u);
        q.committee_size = 4u;

        static al_potb_committee sc;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&q, small_c, 4u, NULL, &seed, 1u, 1000u, &a,
                                     &sc),
            AL_OK);
        AL_CHECK_EQ_U64(sc.size, 4u);

        /* With no spare candidates the evicted seat is refilled by the same node,
         * so the membership is unchanged - the eviction still happened, and this
         * is what "rotation with nobody to rotate to" looks like. Pinned because
         * it means a small network's committee is *not* unpredictable, which is a
         * security property of the network's size rather than of the rotation. */
        static al_potb_committee sbefore;
        sbefore = sc;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&q, &sc, small_c, 4u, NULL, &seed, 2u, 1000u,
                                     &a),
            AL_OK);
        AL_CHECK_EQ_U64(sc.size, 4u);
        AL_CHECK_EQ_U64(al_test_departed(&sbefore, &sc), 0u);

        /* Given somewhere to rotate to, exactly one seat changes hands. */
        static al_potb_record        wide[20];
        static const al_potb_record *wide_c[20];
        al_test_pool(wide, wide_c, 20u, 8100u);
        static al_potb_committee wc;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&q, wide_c, 20u, NULL, &seed, 1u, 1000u, &a,
                                     &wc),
            AL_OK);
        AL_CHECK_EQ_U64(wc.size, 4u);
        static al_potb_committee wbefore;
        wbefore = wc;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&q, &wc, wide_c, 20u, NULL, &seed, 2u, 1000u,
                                     &a),
            AL_OK);
        AL_CHECK_EQ_U64(wc.size, 4u);
        AL_CHECK_EQ_U64(al_test_departed(&wbefore, &wc), 1u);

        /* And a committee of one still turns over, which is the degenerate case the
         * floor exists for. */
        q.committee_size = 1u;
        static al_potb_committee oc;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&q, wide_c, 20u, NULL, &seed, 1u, 1000u, &a,
                                     &oc),
            AL_OK);
        AL_CHECK_EQ_U64(oc.size, 1u);
        static al_potb_committee obefore;
        obefore = oc;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&q, &oc, wide_c, 20u, NULL, &seed, 2u, 1000u,
                                     &a),
            AL_OK);
        AL_CHECK_EQ_U64(oc.size, 1u);
        AL_CHECK_EQ_U64(al_test_departed(&obefore, &oc), 1u);
    }

    /*
     * Newly ineligible members are evicted unconditionally, on top of the
     * rotation budget. A member proven to have double-signed since the committee
     * formed must leave now, not when its seat comes up - waiting would leave a
     * node the chain has already condemned voting on finality for up to ten more
     * blocks.
     */
    {
        static al_potb_committee before;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 300u, NULL, &seed, 200u, 1000u,
                                     &a, &c),
            AL_OK);
        before = c;

        /* Ban three sitting members, one by each route. */
        al_pubkey banned[3];
        for (al_u32 k = 0u; k < 3u; ++k) {
            banned[k] = c.members[k * 7u];
            for (al_u32 i = 0u; i < 300u; ++i) {
                if (al_bytes_eq(al_bytes_make(recs[i].identity.bytes,
                                              AL_PUBKEY_SIZE),
                                al_bytes_make(banned[k].bytes, AL_PUBKEY_SIZE))) {
                    if (k == 0u) {
                        recs[i].permanently_banned = AL_TRUE;
                    } else if (k == 1u) {
                        recs[i].banned_until_day = 1005u;
                    } else {
                        /* Slashed into the ban rather than having the field set by
                         * hand, so the two paths are known to agree. */
                        AL_CHECK_EQ_STATUS(
                            al_potb_slash(&p, &recs[i], NULL,
                                          AL_POTB_OFFENCE_DOUBLE_SIGN, 1000u),
                            AL_OK);
                    }
                    break;
                }
            }
        }

        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &c, cands, 300u, NULL, &seed, 201u,
                                     1000u, &a),
            AL_OK);
        for (al_u32 k = 0u; k < 3u; ++k) {
            AL_CHECK(!al_potb_committee_contains(&c, &banned[k]));
        }
        /* More departures than the rotation budget: the three evictions are extra,
         * not a substitute. (The chain may also draw an evicted seat, so this is a
         * lower bound rather than exactly 13.) */
        AL_CHECK(al_test_departed(&before, &c) > 10u);
        AL_CHECK_EQ_U64(c.size, 100u);

        /* Clear the bans again so later blocks in this case see a clean pool. */
        for (al_u32 i = 0u; i < 300u; ++i) {
            recs[i].permanently_banned = AL_FALSE;
            recs[i].banned_until_day   = 0u;
            recs[i].penalty_multiplier = ONE;
        }
    }

    /* A member that has vanished from the candidate set is evicted too: the set is
     * the chain's view of who exists, and a seat held by a record nobody has is
     * unauditable. */
    {
        static al_potb_committee before;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 300u, NULL, &seed, 300u, 1000u,
                                     &a, &c),
            AL_OK);
        before = c;

        /* Shrink the visible candidate list to the last 250, dropping some sitting
         * members entirely. */
        static const al_potb_record *fewer[250];
        for (al_u32 i = 0u; i < 250u; ++i) {
            fewer[i] = cands[50u + i];
        }
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &c, fewer, 250u, NULL, &seed, 301u,
                                     1000u, &a),
            AL_OK);
        for (al_u32 i = 0u; i < 50u; ++i) {
            AL_CHECK(!al_potb_committee_contains(&c, &recs[i].identity));
        }
        AL_CHECK(al_test_departed(&before, &c) >= 10u);
    }

    /*
     * A committee can *grow*. Rotation refills to p->committee_size, not to the
     * committee's prior size, so a chain that started with seven eligible nodes
     * grows toward its target as the network does - without a separate re-election
     * step, and without the seven having to stand down.
     */
    {
        static al_potb_committee grow;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 7u, NULL, &seed, 400u, 1000u, &a,
                                     &grow),
            AL_OK);
        AL_CHECK_EQ_U64(grow.size, 7u);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &grow, cands, 300u, NULL, &seed, 401u,
                                     1000u, &a),
            AL_OK);
        AL_CHECK_EQ_U64(grow.size, p.committee_size);
    }

    /* An all-ineligible candidate set halts the committee, and that is reported as
     * a failure rather than as an empty success - an empty committee is a halted
     * chain. */
    {
        static al_potb_record        dead[20];
        static const al_potb_record *dead_c[20];
        for (al_u32 i = 0u; i < 20u; ++i) {
            dead[i] = al_test_node(9000u + i, 400u);
            dead_c[i] = &dead[i];
        }
        static al_potb_committee dc;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, dead_c, 20u, NULL, &seed, 500u, 1000u,
                                     &a, &dc),
            AL_OK);
        AL_CHECK_EQ_U64(dc.size, 20u);
        for (al_u32 i = 0u; i < 20u; ++i) {
            dead[i].permanently_banned = AL_TRUE;
        }
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &dc, dead_c, 20u, NULL, &seed, 501u,
                                     1000u, &a),
            AL_ERR_NOT_FOUND);
        AL_CHECK_EQ_U64(dc.size, 0u);
    }

    /*
     * The arena is restored on every path.
     *
     * Known wart, recorded rather than asserted: rotation evicts *before* it
     * allocates the refill pool, so an AL_ERR_OUT_OF_MEMORY return would leave
     * the caller's committee already shrunk with no restoration - a partial
     * mutation on a failure path. It is not reachable from a test, because the
     * arena grows on demand and the allocation cannot fail here, and reordering
     * the eviction after the allocation is a change to consensus-affecting code
     * that belongs in its own commit rather than smuggled in with a test suite.
     */
    {
        al_size before_used = al_arena_used(&a);
        static al_potb_committee ac;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 300u, NULL, &seed, 600u, 1000u,
                                     &a, &ac),
            AL_OK);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &ac, cands, 300u, NULL, &seed, 601u,
                                     1000u, &a),
            AL_OK);
        AL_CHECK_EQ_U64(al_arena_used(&a), before_used);

        /* And across the failing path. */
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &ac, NULL, 0u, NULL, &seed, 602u, 1000u,
                                     &a),
            AL_ERR_NOT_FOUND);
        AL_CHECK_EQ_U64(al_arena_used(&a), before_used);
    }

    /* Argument checks, matching selection's. */
    {
        static al_potb_committee ec;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_select(&p, cands, 300u, NULL, &seed, 700u, 1000u,
                                     &a, &ec),
            AL_OK);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(NULL, &ec, cands, 300u, NULL, &seed, 701u,
                                     1000u, &a),
            AL_ERR_INVALID_ARG);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, NULL, cands, 300u, NULL, &seed, 701u,
                                     1000u, &a),
            AL_ERR_INVALID_ARG);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &ec, cands, 300u, NULL, NULL, 701u,
                                     1000u, &a),
            AL_ERR_INVALID_ARG);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &ec, cands, 300u, NULL, &seed, 701u,
                                     1000u, NULL),
            AL_ERR_INVALID_ARG);
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &ec, NULL, 5u, NULL, &seed, 701u, 1000u,
                                     &a),
            AL_ERR_INVALID_ARG);
        /* All of which left the committee alone. */
        AL_CHECK_EQ_U64(ec.size, 100u);

        al_potb_params q = al_potb_params_default();
        q.committee_size = 0u;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&q, &ec, cands, 300u, NULL, &seed, 701u,
                                     1000u, &a),
            AL_ERR_OUT_OF_RANGE);
        q.committee_size = AL_POTB_MAX_COMMITTEE + 1u;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&q, &ec, cands, 300u, NULL, &seed, 701u,
                                     1000u, &a),
            AL_ERR_OUT_OF_RANGE);

        /* A committee whose size field is beyond the array is rejected rather than
         * read out of bounds. */
        ec.size = AL_POTB_MAX_COMMITTEE + 1u;
        AL_CHECK_EQ_STATUS(
            al_potb_committee_rotate(&p, &ec, cands, 300u, NULL, &seed, 701u,
                                     1000u, &a),
            AL_ERR_OUT_OF_RANGE);
    }

    al_arena_destroy(&a);
}

/* --------------------------------------------------------------------------
 * Epoch seed
 * -------------------------------------------------------------------------- */

AL_TEST(epoch_seed_commit_reveal) {
    al_pubkey  alice = al_test_key(1u);
    al_pubkey  bob   = al_test_key(2u);
    al_hash256 ra, rb, rc;
    memset(&ra, 0x01, sizeof(ra));
    memset(&rb, 0x02, sizeof(rb));
    memset(&rc, 0x03, sizeof(rc));

    /* Commit-reveal: the check accepts the real preimage and rejects every near
     * miss. Constant-time, because the value being checked is one an adversary
     * chose and the verdict is not public until the round closes. */
    al_hash256 commit_a;
    al_potb_epoch_seed_commit(&alice, &ra, &commit_a);
    AL_CHECK(al_potb_epoch_seed_check(&alice, &ra, &commit_a));
    AL_CHECK(!al_potb_epoch_seed_check(&alice, &rb, &commit_a));  /* wrong reveal */
    AL_CHECK(!al_potb_epoch_seed_check(&bob, &ra, &commit_a));    /* wrong node   */
    {
        al_hash256 tampered = commit_a;
        tampered.bytes[31] ^= 0x01u;
        AL_CHECK(!al_potb_epoch_seed_check(&alice, &ra, &tampered));
    }
    /* NULL is a failed check, not a passing one: an absent commitment must never
     * verify. */
    AL_CHECK(!al_potb_epoch_seed_check(NULL, &ra, &commit_a));
    AL_CHECK(!al_potb_epoch_seed_check(&alice, NULL, &commit_a));
    AL_CHECK(!al_potb_epoch_seed_check(&alice, &ra, NULL));

    /* The commitment binds the contributor as well as the reveal, so one
     * participant cannot republish another's commitment as its own. */
    {
        al_hash256 commit_b;
        al_potb_epoch_seed_commit(&bob, &ra, &commit_b);
        AL_CHECK(!al_bytes_eq(al_bytes_make(commit_a.bytes, AL_HASH_SIZE),
                              al_bytes_make(commit_b.bytes, AL_HASH_SIZE)));
    }

    /*
     * The load-bearing separation: a published commitment is not the value it
     * later contributes. The two are hashed under different domain tags precisely
     * so this holds - derive both from one tagged hash and the whole epoch seed
     * becomes computable from the commit round alone, leaving the reveal round
     * protecting nothing.
     */
    {
        al_hash256 mixed = al_hash_zero();
        al_potb_epoch_seed_mix(&mixed, &alice, &ra);
        AL_CHECK(!al_bytes_eq(al_bytes_make(mixed.bytes, AL_HASH_SIZE),
                              al_bytes_make(commit_a.bytes, AL_HASH_SIZE)));
        /* And neither equals the reveal itself. */
        AL_CHECK(!al_bytes_eq(al_bytes_make(mixed.bytes, AL_HASH_SIZE),
                              al_bytes_make(ra.bytes, AL_HASH_SIZE)));
    }

    /*
     * Mixing is order-independent, so a late reveal cannot reorder the result and
     * no participant gains anything by revealing last. XOR of tagged hashes, which
     * is commutative and associative.
     */
    al_pubkey carol = al_test_key(3u);
    al_hash256 forward = al_hash_zero();
    al_potb_epoch_seed_mix(&forward, &alice, &ra);
    al_potb_epoch_seed_mix(&forward, &bob, &rb);
    al_potb_epoch_seed_mix(&forward, &carol, &rc);

    al_hash256 backward = al_hash_zero();
    al_potb_epoch_seed_mix(&backward, &carol, &rc);
    al_potb_epoch_seed_mix(&backward, &bob, &rb);
    al_potb_epoch_seed_mix(&backward, &alice, &ra);
    AL_CHECK(al_bytes_eq(al_bytes_make(forward.bytes, AL_HASH_SIZE),
                         al_bytes_make(backward.bytes, AL_HASH_SIZE)));

    /* A contribution is not the same as no contribution. */
    AL_CHECK(!al_bytes_eq(al_bytes_make(forward.bytes, AL_HASH_SIZE),
                          al_bytes_make(al_hash_zero().bytes, AL_HASH_SIZE)));

    /*
     * The flip side of order-independence, and the reason it is pinned here: XOR
     * is its own inverse, so mixing the same contribution twice *cancels* it.
     *
     * That means the arithmetic offers no protection against a duplicate reveal -
     * a participant whose contribution is folded in twice has removed it, and a
     * caller that accepted two reveals from one key would silently drop that
     * key's entropy. Rejecting duplicates is the protocol layer's job, and nothing
     * in this API does it or can. Recorded as a requirement on the epoch pipeline
     * that does not exist yet.
     */
    {
        al_hash256 doubled = al_hash_zero();
        al_potb_epoch_seed_mix(&doubled, &alice, &ra);
        al_potb_epoch_seed_mix(&doubled, &alice, &ra);
        AL_CHECK(al_bytes_eq(al_bytes_make(doubled.bytes, AL_HASH_SIZE),
                             al_bytes_make(al_hash_zero().bytes, AL_HASH_SIZE)));
    }

    /* Any NULL argument leaves the seed completely untouched - no partial write,
     * so a caller cannot corrupt a half-built seed by passing a missing reveal. */
    {
        al_hash256 seed = forward;
        al_potb_epoch_seed_mix(&seed, NULL, &ra);
        AL_CHECK(al_bytes_eq(al_bytes_make(seed.bytes, AL_HASH_SIZE),
                             al_bytes_make(forward.bytes, AL_HASH_SIZE)));
        al_potb_epoch_seed_mix(&seed, &alice, NULL);
        AL_CHECK(al_bytes_eq(al_bytes_make(seed.bytes, AL_HASH_SIZE),
                             al_bytes_make(forward.bytes, AL_HASH_SIZE)));
        al_potb_epoch_seed_mix(NULL, &alice, &ra);   /* must not crash */
    }

    /* Commit tolerates NULL by producing a zero hash rather than leaving the
     * output undefined, and ignores a NULL output entirely. */
    {
        al_hash256 out;
        memset(&out, 0xff, sizeof(out));
        al_potb_epoch_seed_commit(NULL, &ra, &out);
        AL_CHECK(al_bytes_eq(al_bytes_make(out.bytes, AL_HASH_SIZE),
                             al_bytes_make(al_hash_zero().bytes, AL_HASH_SIZE)));
        memset(&out, 0xff, sizeof(out));
        al_potb_epoch_seed_commit(&alice, NULL, &out);
        AL_CHECK(al_bytes_eq(al_bytes_make(out.bytes, AL_HASH_SIZE),
                             al_bytes_make(al_hash_zero().bytes, AL_HASH_SIZE)));
        al_potb_epoch_seed_commit(&alice, &ra, NULL);   /* must not crash */
    }

    /*
     * Finalisation binds the epoch number, so the same set of reveals cannot be
     * replayed into a later epoch to reproduce a known committee.
     */
    al_hash256 final_1, final_2;
    al_potb_epoch_seed_finalise(&forward, 1u, NULL, &final_1);
    al_potb_epoch_seed_finalise(&forward, 2u, NULL, &final_2);
    AL_CHECK(!al_bytes_eq(al_bytes_make(final_1.bytes, AL_HASH_SIZE),
                          al_bytes_make(final_2.bytes, AL_HASH_SIZE)));
    /* Deterministic, like everything else here. */
    {
        al_hash256 again;
        al_potb_epoch_seed_finalise(&forward, 1u, NULL, &again);
        AL_CHECK(al_bytes_eq(al_bytes_make(final_1.bytes, AL_HASH_SIZE),
                             al_bytes_make(again.bytes, AL_HASH_SIZE)));
    }

    /*
     * The VDF branch is a different preimage, not an optional extra hashed over
     * the same bytes: 80 bytes against 40. The two branches are the honest range
     * for block time in the specification, and which one a network takes changes
     * every seed it ever produces - so they must not be confusable.
     */
    {
        al_vdf_output vdf;
        memset(&vdf, 0, sizeof(vdf));
        memset(&vdf.value, 0x5a, sizeof(vdf.value));
        vdf.iterations = 1000u;

        al_hash256 with_vdf;
        al_potb_epoch_seed_finalise(&forward, 1u, &vdf, &with_vdf);
        AL_CHECK(!al_bytes_eq(al_bytes_make(with_vdf.bytes, AL_HASH_SIZE),
                              al_bytes_make(final_1.bytes, AL_HASH_SIZE)));

        /* The iteration count is bound too, so a proof of less work than claimed
         * is a different seed. */
        al_hash256 fewer;
        vdf.iterations = 999u;
        al_potb_epoch_seed_finalise(&forward, 1u, &vdf, &fewer);
        AL_CHECK(!al_bytes_eq(al_bytes_make(with_vdf.bytes, AL_HASH_SIZE),
                              al_bytes_make(fewer.bytes, AL_HASH_SIZE)));
    }

    /* A missing mixed seed yields zero rather than an uninitialised hash, and a
     * NULL output is a no-op. */
    {
        al_hash256 out;
        memset(&out, 0xff, sizeof(out));
        al_potb_epoch_seed_finalise(NULL, 1u, NULL, &out);
        AL_CHECK(al_bytes_eq(al_bytes_make(out.bytes, AL_HASH_SIZE),
                             al_bytes_make(al_hash_zero().bytes, AL_HASH_SIZE)));
        al_potb_epoch_seed_finalise(&forward, 1u, NULL, NULL);
    }

    /*
     * Golden vectors. Everything above would still pass if a domain tag or a field
     * order changed, because it only compares these functions against each other.
     * These four pin the actual bytes, so a change to a tag, to the field order,
     * or to the length prefix is caught here rather than by a chain split.
     *
     * Generated from this implementation, so they certify stability rather than
     * correctness against an external specification - there is no external
     * specification for these yet.
     */
    {
        al_pubkey  k = al_test_key(1u);   /* a5 in byte 2, zero elsewhere */
        al_hash256 r;
        memset(&r, 0x01, sizeof(r));

        al_hash256 commit;
        al_potb_epoch_seed_commit(&k, &r, &commit);
        AL_CHECK_HASH_HEX(commit,
            "546fb9cd17fe3669bb51f52688364b37ed4c6d0b72beb2f11db7d0af17a3be3c");

        al_hash256 mixed = al_hash_zero();
        al_potb_epoch_seed_mix(&mixed, &k, &r);
        AL_CHECK_HASH_HEX(mixed,
            "828b023f9013c9085044d85e9f13104bfd1a2040de20e37f22600ce9526fb2dd");

        al_hash256 fin;
        al_potb_epoch_seed_finalise(&mixed, 7u, NULL, &fin);
        AL_CHECK_HASH_HEX(fin,
            "ac552aa062f84a30aad6459765f87b5f6ea279ccc70eeb38bac09aa31deba1c0");

        al_vdf_output vdf;
        memset(&vdf, 0, sizeof(vdf));
        memset(&vdf.value, 0x5a, sizeof(vdf.value));
        vdf.iterations = 1000u;
        al_hash256 fin_vdf;
        al_potb_epoch_seed_finalise(&mixed, 7u, &vdf, &fin_vdf);
        AL_CHECK_HASH_HEX(fin_vdf,
            "b6e48863d1b35cf6caff85a9b8042ec09ce59153c2253a31fbab1acd272c7967");
    }
}

/*
 * Reward splitting: the three buckets, the 3x ceiling, and the trim order.
 *
 * This case is also the regression test for the cap defect. al_scale_by_fixed
 * clamps its fraction to 1, so scaling the flat share *up* by
 * reward_max_multiple through it yielded the flat share itself: the cap equalled
 * the flat share, out->total exceeded it on every call, and the trim below zeroed
 * both the weighted and the bonded bucket - forty percent of every block reward,
 * on every block. The two assertions marked "regression" below are the ones that
 * fail without the al_mul_amount_sat fix in committee.c.
 *
 * The committee is built by hand rather than by selection, because the weights
 * are the input here and selection would decide them.
 */
AL_TEST(rewards_split_and_cap) {
    al_potb_params p = al_potb_params_default();

    static al_potb_committee c;
    memset(&c, 0, sizeof(c));
    c.size = 10u;
    for (al_u32 i = 0u; i < c.size; ++i) {
        c.members[i] = al_test_key(600u + i);
        c.weights[i] = ONE;
    }

    const al_amount reward = 1000000u;

    /* --- the documented split, at equal weight and equal bond ------------- */
    /*
     * 60/25/15 of 1000000 is 600000/250000/150000; ten equal members take a tenth
     * of each. flat is exact because the bucket divides evenly by the committee
     * size. weighted and bonded are one unit low: the member's share is a Q32.32
     * ratio, and 1/10 is not representable, so scaling by it truncates. Two units
     * of tolerance rather than an exact expectation, because the amount that gets
     * lost there depends on the bucket size and pinning it would be pinning the
     * rounding of an intermediate rather than the payout.
     */
    al_potb_reward_split s;
    al_potb_reward_for(&p, reward, &c, 0u, 100u, 1000u, &s);
    AL_CHECK_EQ_U64(s.flat, 60000u);
    AL_CHECK_NEAR_I64((al_i64)s.weighted, 25000, 2);
    AL_CHECK_NEAR_I64((al_i64)s.bonded, 15000, 2);
    AL_CHECK_EQ_U64(s.total, s.flat + s.weighted + s.bonded);

    /* Regression: both were identically zero before the cap was fixed. */
    AL_CHECK(s.weighted > 0u);
    AL_CHECK(s.bonded > 0u);

    /* The whole committee's payout never exceeds the block reward. Only the
     * truncation remainders are unaccounted for, and they are burned. */
    {
        al_amount paid = 0u;
        for (al_u32 i = 0u; i < c.size; ++i) {
            al_potb_reward_split m;
            al_potb_reward_for(&p, reward, &c, i, 100u, 1000u, &m);
            AL_CHECK_EQ_U64(m.total, m.flat + m.weighted + m.bonded);
            paid += m.total;
        }
        AL_CHECK(paid <= reward);
        AL_CHECK(paid > reward - (al_amount)c.size * 3u);   /* nothing large lost */
    }

    /* --- the ceiling trims bonded, then weighted, and never flat ---------- */
    /*
     * Member 0 holds 91 of 100 weight units and the entire bond, so it earns
     * 227499 weighted and the full 150000 bonded on top of its 60000 flat -
     * 437499 against a cap of 3 x 60000. The trim takes the whole bonded bucket
     * and 107499 of the weighted one.
     *
     * The three results are exact even though the weighted share itself is not:
     * once the cap binds, weighted becomes cap - flat - bonded, so the ulp lost
     * in the 0.91 ratio is trimmed away rather than paid out. Which is worth
     * stating - the capped payout is a function of the flat share alone, so every
     * node agrees on it regardless of how the weights round.
     */
    c.weights[0] = al_fixed_from_int(91);
    al_potb_reward_for(&p, reward, &c, 0u, 1000u, 1000u, &s);
    AL_CHECK_EQ_U64(s.flat, 60000u);         /* never trimmed */
    AL_CHECK_EQ_U64(s.bonded, 0u);           /* trimmed first, to nothing */
    AL_CHECK_EQ_U64(s.weighted, 120000u);    /* trimmed second, partially */
    AL_CHECK_EQ_U64(s.total, 180000u);       /* exactly 3 x flat */

    /* --- a bond buys reward share and never voting weight ---------------- */
    /*
     * Member 1 posts no bond at all. It keeps its full flat share and its full
     * weighted share; the bond's entire effect is the third bucket. This is the
     * design's stated guarantee that running unbonded is a smaller reward and
     * never a smaller vote - the weight it was selected with is untouched, and
     * so is the equal share it gets for having done the work.
     */
    al_potb_reward_for(&p, reward, &c, 1u, 0u, 1000u, &s);
    AL_CHECK_EQ_U64(s.flat, 60000u);
    AL_CHECK(s.weighted > 0u);
    AL_CHECK_EQ_U64(s.bonded, 0u);
    AL_CHECK_EQ_U64(s.total, s.flat + s.weighted);

    /* Nobody bonded: the bucket is simply not paid, and no divide by zero. */
    al_potb_reward_for(&p, reward, &c, 1u, 0u, 0u, &s);
    AL_CHECK_EQ_U64(s.bonded, 0u);
    /* A bond with no total is the same: the share is undefined, not infinite. */
    al_potb_reward_for(&p, reward, &c, 1u, 500u, 0u, &s);
    AL_CHECK_EQ_U64(s.bonded, 0u);
    /*
     * A bond larger than the total is clamped to the total rather than paying out
     * a share above 1. The clamp is observable as two calls agreeing: bonding
     * exactly the total and bonding five times it produce identical splits.
     *
     * It cannot be observed as "the member receives the whole bonded bucket",
     * because at the default parameters a sole bonder in a committee of ten is
     * always cap-bound: the bonded bucket is 15% of the block and the flat share
     * is 6%, so flat + weighted + bonded reaches 3.5x the flat share and the
     * ceiling trims it back to 3x. Which is worth stating plainly - the 15%
     * infrastructure bucket cannot be concentrated on one identity, whatever the
     * bond, and the ceiling rather than the bond arithmetic is what stops it.
     */
    {
        al_potb_reward_split exact, over;
        al_potb_reward_for(&p, reward, &c, 1u, 1000u, 1000u, &exact);
        al_potb_reward_for(&p, reward, &c, 1u, 5000u, 1000u, &over);
        AL_CHECK_EQ_U64(over.flat, exact.flat);
        AL_CHECK_EQ_U64(over.weighted, exact.weighted);
        AL_CHECK_EQ_U64(over.bonded, exact.bonded);
        AL_CHECK_EQ_U64(over.total, exact.total);
        AL_CHECK(exact.bonded > 0u);
        AL_CHECK_EQ_U64(exact.total, 180000u);   /* cap-bound, as described */
    }

    c.weights[0] = ONE;

    /* --- zero total weight: the weighted bucket is skipped ---------------- */
    {
        static al_potb_committee zc;
        memset(&zc, 0, sizeof(zc));
        zc.size = 4u;
        for (al_u32 i = 0u; i < zc.size; ++i) {
            zc.members[i] = al_test_key(700u + i);
            zc.weights[i] = 0;
        }
        al_potb_reward_for(&p, reward, &zc, 0u, 0u, 0u, &s);
        AL_CHECK_EQ_U64(s.weighted, 0u);
        AL_CHECK_EQ_U64(s.flat, 150000u);    /* 600000 / 4 */
        AL_CHECK_EQ_U64(s.total, 150000u);
    }

    /* --- the null and out-of-range contract ------------------------------- */
    /* Every rejected form zeroes the output first, so a caller that ignores the
     * absence of a status code still reads zeros rather than stale values. */
    {
        al_potb_reward_split junk;
        memset(&junk, 0xff, sizeof(junk));

        al_potb_reward_for(NULL, reward, &c, 0u, 0u, 0u, &junk);
        AL_CHECK_EQ_U64(junk.flat, 0u);
        AL_CHECK_EQ_U64(junk.total, 0u);

        memset(&junk, 0xff, sizeof(junk));
        al_potb_reward_for(&p, reward, NULL, 0u, 0u, 0u, &junk);
        AL_CHECK_EQ_U64(junk.total, 0u);

        memset(&junk, 0xff, sizeof(junk));
        al_potb_reward_for(&p, reward, &c, c.size, 0u, 0u, &junk);
        AL_CHECK_EQ_U64(junk.total, 0u);

        memset(&junk, 0xff, sizeof(junk));
        al_potb_reward_for(&p, reward, &c, 9999u, 0u, 0u, &junk);
        AL_CHECK_EQ_U64(junk.total, 0u);

        static al_potb_committee empty;
        memset(&empty, 0, sizeof(empty));
        memset(&junk, 0xff, sizeof(junk));
        al_potb_reward_for(&p, reward, &empty, 0u, 0u, 0u, &junk);
        AL_CHECK_EQ_U64(junk.total, 0u);

        /* No out parameter is a no-op rather than a write through NULL. */
        al_potb_reward_for(&p, reward, &c, 0u, 0u, 0u, NULL);

        /* A zero block reward pays nothing and divides nothing by zero. */
        al_potb_reward_for(&p, 0u, &c, 0u, 100u, 1000u, &s);
        AL_CHECK_EQ_U64(s.total, 0u);
    }

    /* --- the top of the range -------------------------------------------- */
    /*
     * al_bp_of, al_scale_by_fixed, al_mul_amount_sat and al_ratio_u64 are all
     * static in committee.c, so they are driven through the public entry point
     * rather than called directly - including the .c here would duplicate every
     * symbol against the linked al_potb.
     *
     * A block reward of UINT64_MAX with the whole bond on one member exercises
     * every one of the four overflow guards at once: amount * bp would wrap above
     * ~1.8e15, amount * frac would need 96 bits, a bond above INT64_MAX cast to
     * signed would come out negative and pay a negative share, and the cap
     * multiplies *up* by three.
     *
     * The flat share is stated in the split form on purpose: it is the only way
     * to write floor(amount * 6000 / 10000) without a 128-bit type, which is
     * exactly why the implementation is shaped that way.
     */
    {
        const al_amount big = UINT64_MAX;
        const al_amount q   = big / 10000u;
        const al_amount r   = big % 10000u;
        const al_amount flat_bucket     = q * 6000u + (r * 6000u) / 10000u;
        const al_amount weighted_bucket = q * 2500u + (r * 2500u) / 10000u;

        al_potb_reward_for(&p, big, &c, 0u, big, big, &s);

        AL_CHECK_EQ_U64(s.flat, flat_bucket / 10u);
        AL_CHECK_EQ_U64(s.total, s.flat + s.weighted + s.bonded);

        /* Nothing wrapped: no bucket is larger than the reward it came out of,
         * and none of them came out negative through a signed intermediate. */
        AL_CHECK(s.flat     <= big);
        AL_CHECK(s.weighted <= big);
        AL_CHECK(s.bonded   <= big);

        /*
         * The cap binds here, and the excess fits inside the bonded bucket, so
         * bonded absorbs all of it and weighted is paid in full. total is exactly
         * three times flat - the cap arithmetic saturates nowhere at this
         * magnitude, because 3 x flat is still under a fifth of the range.
         */
        AL_CHECK_EQ_U64(s.total, s.flat * 3u);
        AL_CHECK(s.bonded > 0u);

        /*
         * The weighted share is a tenth of its bucket, but 1/10 is not
         * representable in Q32.32 and al_fixed_div truncates, so the payout is
         * short by bucket x (1/10 - share) where the difference is below one ulp.
         * At this magnitude that is around 6.4e8 base units - an absolute
         * tolerance of two would be meaningless, so the bound is derived from the
         * bucket instead: one ulp of Q32.32 is a shift of 32.
         *
         * Worth being precise about what this is. It is not a defect: every node
         * computes the identical truncated figure, so consensus holds, and the
         * shortfall is 1.4e-10 of the bucket. It is the reason the split does not
         * sum to the block reward, alongside the flat remainder - both are burned.
         */
        AL_CHECK_NEAR_I64((al_i64)s.weighted, (al_i64)(weighted_bucket / 10u),
                          (al_i64)(weighted_bucket >> 32) + 2);
    }

    /*
     * The cap saturates rather than wrapping when the flat share is itself near
     * the top of the range. Three times a flat share above UINT64_MAX/3 cannot be
     * represented, so al_mul_amount_sat returns UINT64_MAX and the cap simply
     * never binds - which is the right answer, since no payout can exceed the
     * range either. A wrapping multiply would have produced a small cap and
     * trimmed a legitimate payout to nothing.
     *
     * A committee of one takes the whole flat bucket, so 60% of UINT64_MAX is the
     * flat share: 1.1e19, well above UINT64_MAX/3.
     */
    {
        static al_potb_committee one;
        memset(&one, 0, sizeof(one));
        one.size       = 1u;
        one.members[0] = al_test_key(800u);
        one.weights[0] = ONE;

        const al_amount big = UINT64_MAX;
        al_potb_reward_for(&p, big, &one, 0u, big, big, &s);

        AL_CHECK(s.flat > UINT64_MAX / 3u);      /* the cap must saturate */
        AL_CHECK_EQ_U64(s.total, s.flat + s.weighted + s.bonded);
        AL_CHECK(s.total >= s.flat);             /* not trimmed below flat */
        AL_CHECK(s.weighted > 0u);
        AL_CHECK(s.bonded > 0u);
        AL_CHECK(s.total <= big);
    }
}

AL_TEST_MAIN {
    AL_RUN(params_default_and_validate);
    AL_RUN(rates_and_null_neutrality);
    AL_RUN(tbs_monotonic_and_decay);
    AL_RUN(loyalty_bonus_threshold);
    AL_RUN(tgw_components);
    AL_RUN(ndm_and_cod);
    AL_RUN(correlation_signals);
    AL_RUN(level_boundaries);
    AL_RUN(antisybil_split_loses_eligibility);
    AL_RUN(slashing_relativity);
    AL_RUN(quorum_threshold);
    AL_RUN(committee_determinism);
    AL_RUN(committee_sampling);
    AL_RUN(committee_rotation);
    AL_RUN(epoch_seed_commit_reveal);
    AL_RUN(rewards_split_and_cap);
}
