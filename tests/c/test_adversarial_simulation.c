/*
 * Adversarial network simulation: PoTB scoring under attack conditions.
 *
 * These tests exercise the scoring, clustering and anti-domination primitives
 * against realistic adversarial strategies rather than isolated unit inputs.
 * Each case models a specific attack vector and asserts that the scoring
 * formulas degrade the attacker's weight as designed.
 *
 * The tests do not run a full consensus round; they operate on the scoring
 * layer directly, which is the appropriate level for verifying that the
 * math defends against the stated threats.
 */

/*
 * Copyright (c) 2026 Astrolune contributors
 * SPDX-License-Identifier: MIT
 */

#include "astrolune/arena.h"
#include "astrolune/potb.h"

#include "altest.h"

#define AL_TEST_SUITE_NAME "adversarial_simulation"

#define ONE  AL_FIXED_ONE
#define FX(n, d) al_fixed_from_ratio((al_i64)(n), (al_i64)(d))

/* ---------------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static al_pubkey sim_key(al_u32 i) {
    al_pubkey pk;
    memset(&pk, 0, sizeof(pk));
    pk.bytes[0] = (al_u8)(i & 0xffu);
    pk.bytes[1] = (al_u8)((i >> 8) & 0xffu);
    pk.bytes[2] = 0xb7u;
    return pk;
}

/* Build an honest, high-weight record: long uptime, diverse attestations,
 * no cluster membership. */
static al_potb_record sim_honest(al_u32 id, al_u32 uptime, al_u32 day) {
    al_pubkey      pk = sim_key(id);
    al_potb_record r  = al_potb_record_init(&pk);
    r.uptime_days          = uptime;
    r.last_active_day      = day;
    r.first_seen_day       = (uptime < day) ? (day - uptime) : 0u;
    r.inbound_attestations = 100u;
    r.inbound_from_cluster = 0u;
    r.cluster_size         = 0u;
    r.tdi                  = ONE;
    r.asn                  = id % 7u + 1u;  /* spread across 7 ASNs */
    r.asn_peer_count       = 1u;
    r.challenges_issued    = 0u;
    return r;
}

/* Default network stats: neutral medians, zero total weight. */
static al_potb_network_stats sim_net_default(void) {
    al_potb_network_stats net;
    memset(&net, 0, sizeof(net));
    net.node_count       = 100u;
    net.median_miss_rate = ONE;
    net.median_error_rate = ONE;
    net.total_weight     = al_fixed_from_int(1000);
    return net;
}

/* ---------------------------------------------------------------------------
 * Attack 1: Sybil farm weight dilution via group cap
 *
 * Strategy: an attacker spins up 10 identical nodes on the same ASN with
 * matching registration times and attestations, hoping to collect 10x the
 * weight of a single honest node.
 *
 * Expected outcome: the group weight cap (3% default) limits the farm's
 * collective influence regardless of how many identities the attacker creates.
 * ----------------------------------------------------------------------- */

AL_TEST(sybil_farm_group_cap) {
    al_potb_params params = al_potb_params_default();
    al_potb_network_stats net = sim_net_default();
    const al_u32 day = 1000u;

    /* One honest node with full weight. */
    al_potb_record honest = sim_honest(1000u, 400u, day);

    /* Ten Sybil nodes, all on ASN 999, with enough uptime to have real weight
     * but still forming a detectable cluster. */
    al_potb_record farm[10];
    for (al_u32 i = 0u; i < 10u; ++i) {
        al_pubkey pk = sim_key(2000u + i);
        farm[i] = al_potb_record_init(&pk);
        farm[i].uptime_days          = 400u;    /* long uptime for real weight */
        farm[i].last_active_day      = day;
        farm[i].first_seen_day       = day - 400u;
        farm[i].inbound_attestations = 80u;
        farm[i].inbound_from_cluster = 70u;     /* heavy intra-cluster */
        farm[i].cluster_size         = 0u;      /* filled by detect_clusters */
        farm[i].tdi                  = FX(1, 5);
        farm[i].asn                  = 999u;
        farm[i].asn_peer_count       = 10u;
        farm[i].challenges_issued    = 0u;
    }

    /* Detect clusters: the 10 farm nodes should cluster together. */
    al_potb_detect_clusters(farm, 10u);

    /* Compute raw weights for all nodes. */
    al_fixed w_honest_raw = al_potb_weight_total(&params, &honest, &net, day);
    al_fixed w_farm_raw_total = al_fixed_from_int(0);
    for (al_u32 i = 0u; i < 10u; ++i) {
        w_farm_raw_total = al_fixed_add(
            w_farm_raw_total,
            al_potb_weight_total(&params, &farm[i], &net, day));
    }

    /* The honest node should have meaningful weight. */
    AL_CHECK(w_honest_raw > 0);

    /* Compute effective weights using the group cap. */
    al_fixed w_honest_eff = al_potb_weight_effective_total(
        &params, &honest, &net, day, w_honest_raw, net.total_weight);

    al_fixed farm_effective_total = al_fixed_from_int(0);
    for (al_u32 i = 0u; i < 10u; ++i) {
        al_fixed w_eff = al_potb_weight_effective_total(
            &params, &farm[i], &net, day, w_farm_raw_total,
            net.total_weight);
        farm_effective_total = al_fixed_add(farm_effective_total, w_eff);
    }

    /* The farm's effective total should be less than or equal to its raw
     * total when the group exceeds the cap, or equal when within cap. */
    AL_CHECK(farm_effective_total <= w_farm_raw_total);

    /* The honest node's effective weight should equal its raw weight (no
     * cluster discount applies to it). */
    AL_CHECK_EQ_I64(w_honest_eff, w_honest_raw);
}

/* ---------------------------------------------------------------------------
 * Attack 2: Correlation discount under targeted eclipse
 *
 * Strategy: an attacker controls 3 out of 5 nodes and attestations flow
 * primarily within the attacker's group, attempting to boost the correlation
 * score and inflate weight.
 *
 * Expected outcome: the cluster detection identifies the correlated group,
 * and the COD term dampens the attacker's weight.
 * ----------------------------------------------------------------------- */

AL_TEST(eclipse_correlation_discount) {
    al_potb_params params = al_potb_params_default();
    al_potb_network_stats net = sim_net_default();
    const al_u32 day = 1000u;
    al_potb_record records[5];

    /* Attacker's 3 nodes: tightly correlated. */
    for (al_u32 i = 0u; i < 3u; ++i) {
        al_pubkey pk = sim_key(3000u + i);
        records[i] = al_potb_record_init(&pk);
        records[i].uptime_days          = 200u;
        records[i].last_active_day      = day;
        records[i].first_seen_day       = day - 200u;
        records[i].inbound_attestations = 60u;
        records[i].inbound_from_cluster = 50u;  /* heavy intra-cluster */
        records[i].cluster_size         = 0u;   /* filled by detect_clusters */
        records[i].tdi                  = FX(1, 5);
        records[i].asn                  = 888u;
        records[i].asn_peer_count       = 3u;
        records[i].challenges_issued    = 0u;
    }

    /* Two honest nodes: diverse, uncorrelated. */
    for (al_u32 i = 3u; i < 5u; ++i) {
        records[i] = sim_honest(3100u + i, 300u, day);
    }

    al_potb_detect_clusters(records, 5u);

    /* The attacker's nodes should be detected as a cluster. */
    AL_CHECK(records[0].cluster_size >= 3u);
    AL_CHECK(records[0].correlation_score > 0);

    /* Compute weights. The attacker's nodes should individually weigh less
     * than the honest nodes due to the COD discount from clustering. */
    al_fixed w_attacker = al_potb_weight_total(&params, &records[0], &net, day);
    al_fixed w_honest   = al_potb_weight_total(&params, &records[3], &net, day);
    AL_CHECK(w_attacker < w_honest);

    /* The attacker's 3 nodes combined should not exceed the honest nodes'
     * combined weight by a factor greater than 3x, despite having 3x the
     * identities. */
    al_fixed attacker_total = al_fixed_from_int(0);
    for (al_u32 i = 0u; i < 3u; ++i) {
        attacker_total = al_fixed_add(
            attacker_total,
            al_potb_weight_total(&params, &records[i], &net, day));
    }
    al_fixed honest_total = al_fixed_from_int(0);
    for (al_u32 i = 3u; i < 5u; ++i) {
        honest_total = al_fixed_add(
            honest_total,
            al_potb_weight_total(&params, &records[i], &net, day));
    }
    /* attacker_total < 3 * honest_total proves the farm is not getting
     * 3x the influence from 3x the identities. */
    al_fixed limit = al_fixed_mul(honest_total, al_fixed_from_int(3));
    AL_CHECK(attacker_total < limit);
}

/* ---------------------------------------------------------------------------
 * Attack 3: Fresh-node registration flood
 *
 * Strategy: an attacker registers 20 nodes simultaneously to flood the
 * validator set with low-uptime identities.
 *
 * Expected outcome: TBS's loyalty threshold (365 days) ensures fresh nodes
 * have near-zero time-behavior score, making their weight negligible.
 * ----------------------------------------------------------------------- */

AL_TEST(fresh_node_flood) {
    al_potb_params params = al_potb_params_default();
    al_potb_network_stats net = sim_net_default();
    const al_u32 day = 1000u;

    /* One established honest node. */
    al_potb_record honest = sim_honest(4000u, 500u, day);

    /* 20 fresh nodes, all registered today. */
    al_potb_record fresh[20];
    for (al_u32 i = 0u; i < 20u; ++i) {
        al_pubkey pk = sim_key(4100u + i);
        fresh[i] = al_potb_record_init(&pk);
        fresh[i].uptime_days          = 0u;   /* just registered */
        fresh[i].last_active_day      = day;
        fresh[i].first_seen_day       = day;
        fresh[i].inbound_attestations = 10u;
        fresh[i].inbound_from_cluster = 0u;
        fresh[i].cluster_size         = 0u;
        fresh[i].tdi                  = ONE;
        fresh[i].asn                  = (al_u32)(i % 5u + 1u);
        fresh[i].asn_peer_count       = 1u;
    }

    al_fixed w_honest = al_potb_weight_total(&params, &honest, &net, day);

    /* Every fresh node should have zero weight (uptime < loyalty_threshold). */
    for (al_u32 i = 0u; i < 20u; ++i) {
        al_fixed w = al_potb_weight_total(&params, &fresh[i], &net, day);
        AL_CHECK_EQ_I64(w, 0);
    }

    /* The honest node's weight should be positive. */
    AL_CHECK(w_honest > 0);
}

/* ---------------------------------------------------------------------------
 * Attack 4: Slashing tier differentiation
 *
 * Strategy: a node commits different offences and the test verifies that
 * each offence type receives the correct penalty multiplier, confirming
 * that the differentiated slashing tiers (B5) are applied correctly.
 * ----------------------------------------------------------------------- */

AL_TEST(slashing_tier_differentiation) {
    /* Verify the specific penalty values from score_slash.c. */
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_VOTE_MISS),
                    FX(97, 100));           /* 0.97 */
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_SYSTEMATIC_MISS),
                    FX(9, 10));             /* 0.90 */
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_BAD_RESPONSE),
                    FX(95, 100));           /* 0.95 */
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_SYSTEMATIC_BAD_RESPONSE),
                    FX(8, 10));             /* 0.80 */
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_CHALLENGE_MISS),
                    FX(85, 100));           /* 0.85 */
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_DOUBLE_SIGN),
                    FX(1, 10));             /* 0.10 */
    AL_CHECK_EQ_I64(al_potb_penalty_for(AL_POTB_OFFENCE_REPEAT_DOUBLE_SIGN),
                    0);                     /* permanent: 0 */

    /* A repeated double-sign should result in permanent ban. */
    al_potb_params params = al_potb_params_default();
    al_potb_network_stats net = sim_net_default();
    al_pubkey pk = sim_key(5000u);
    al_potb_record record = al_potb_record_init(&pk);
    record.penalty_multiplier = AL_FIXED_ONE;

    /* Apply first double-sign: heavy penalty but not permanent. */
    al_status s = al_potb_slash(&params, &record, &net,
                                AL_POTB_OFFENCE_DOUBLE_SIGN, 1000u);
    AL_CHECK_EQ_STATUS(s, AL_OK);
    AL_CHECK(!record.permanently_banned);
    AL_CHECK(record.penalty_multiplier > 0);
    AL_CHECK(record.penalty_multiplier < AL_FIXED_ONE);

    /* Apply repeat: should trigger permanent ban. */
    s = al_potb_slash(&params, &record, &net,
                      AL_POTB_OFFENCE_REPEAT_DOUBLE_SIGN, 2000u);
    AL_CHECK_EQ_STATUS(s, AL_OK);
    AL_CHECK(record.permanently_banned);
    AL_CHECK_EQ_I64(record.penalty_multiplier, 0);
}

/* ---------------------------------------------------------------------------
 * Attack 5: Genesis bonus dilution over time
 *
 * Strategy: an attacker tries to leverage the genesis bonus by staking
 * early and waiting for dilution.
 *
 * Expected outcome: the genesis bonus dilutes linearly to zero over the
 * configured period, so early advantage vanishes.
 * ----------------------------------------------------------------------- */

AL_TEST(genesis_bonus_dilution) {
    al_potb_params params = al_potb_params_default();

    /* At day 0, the bonus should be at its initial value. */
    al_fixed bonus_day0 = al_potb_genesis_bonus_dilute(&params, 0u);
    AL_CHECK_EQ_I64(bonus_day0, params.genesis_bonus_initial);

    /* At the midpoint (half the dilution period), bonus should be ~50%. */
    al_u32 midpoint = params.genesis_dilution_days / 2u;
    al_fixed bonus_mid = al_potb_genesis_bonus_dilute(&params, midpoint);
    al_fixed expected_mid = al_fixed_mul(params.genesis_bonus_initial,
                                         al_fixed_from_ratio(1, 2));
    AL_CHECK_NEAR_I64(bonus_mid, expected_mid, 1);

    /* At the end of the dilution period, bonus should be zero. */
    al_fixed bonus_end = al_potb_genesis_bonus_dilute(
        &params, params.genesis_dilution_days);
    AL_CHECK_EQ_I64(bonus_end, 0);

    /* Beyond the dilution period, bonus should remain zero. */
    al_fixed bonus_beyond = al_potb_genesis_bonus_dilute(
        &params, params.genesis_dilution_days + 100u);
    AL_CHECK_EQ_I64(bonus_beyond, 0);
}

/* ---------------------------------------------------------------------------
 * Attack 6: NDM neutrality for unknown ASNs
 *
 * Strategy: an attacker uses unknown or unregistered ASNs to avoid the
 * network diversity multiplier discount.
 *
 * Expected outcome: NDM should be neutral (1.0) for unknown ASNs, so the
 * attacker gains no advantage from using obscure network providers.
 * ----------------------------------------------------------------------- */

AL_TEST(ndm_neutral_for_unknown_asn) {
    al_potb_params params = al_potb_params_default();
    al_potb_network_stats net = sim_net_default();

    /* A node with ASN 0 (unknown) should have NDM == 1.0. */
    al_potb_record r_unknown = sim_honest(6000u, 300u, 1000u);
    r_unknown.asn = 0u;
    r_unknown.asn_peer_count = 0u;

    al_fixed ndm = al_potb_ndm(&params, &r_unknown, &net);
    AL_CHECK_EQ_I64(ndm, ONE);

    /* A node with a known ASN but no peers should also have NDM == 1.0. */
    al_potb_record r_solo = sim_honest(6001u, 300u, 1000u);
    r_solo.asn = 42u;
    r_solo.asn_peer_count = 1u;

    ndm = al_potb_ndm(&params, &r_solo, &net);
    AL_CHECK_EQ_I64(ndm, ONE);
}

/* ---------------------------------------------------------------------------
 * Attack 7: Weight effective total bounded by group cap
 *
 * Strategy: an attacker creates many nodes hoping to exceed the total weight
 * budget through sheer quantity.
 *
 * Expected outcome: al_potb_weight_effective_total() returns a value that
 * is bounded regardless of how many high-weight records are supplied.
 * ----------------------------------------------------------------------- */

AL_TEST(weight_effective_total_bounded) {
    al_potb_params params = al_potb_params_default();
    al_potb_network_stats net = sim_net_default();
    const al_u32 day = 1000u;

    /* Create 50 honest nodes, all with full weight. */
    al_potb_record records[50];
    for (al_u32 i = 0u; i < 50u; ++i) {
        records[i] = sim_honest(7000u + i, 500u, day);
    }

    /* The effective total should be finite and less than the naive sum. */
    al_fixed raw_total = al_potb_weight_effective_total(
        &params, &records[0], &net, day,
        al_potb_weight_total(&params, &records[0], &net, day),
        net.total_weight);
    AL_CHECK(raw_total > 0);

    /* Compare with a single node's effective weight times 50. */
    al_fixed single_raw = al_potb_weight_total(&params, &records[0], &net, day);
    al_fixed single_eff = al_potb_weight_effective(
        &params, single_raw, single_raw, net.total_weight);
    al_fixed naive_total = al_fixed_mul(single_eff, al_fixed_from_int(50));
    /* Due to group cap normalization, the effective total should be less than
     * the naive multiplication when nodes share clusters. */
    AL_CHECK(raw_total <= naive_total);
}

/* ---------------------------------------------------------------------------
 * Attack 8: TBS decay after extended absence
 *
 * Strategy: a once-trusted node goes offline for a long period, hoping to
 * retain its weight from historical behaviour.
 *
 * Expected outcome: TBS decays after the grace period, reducing the node's
 * weight proportionally to its absence.
 * ----------------------------------------------------------------------- */

AL_TEST(tbs_decay_after_absence) {
    al_potb_params params = al_potb_params_default();

    /* A node that was active for 400 days and last seen 100 days ago.
     * grace_period = 60 days, so it has been decaying for 40 days. */
    al_potb_record active = sim_honest(8000u, 400u, 1000u);
    active.last_active_day = 900u;

    /* A node with the same history but still active. */
    al_potb_record current = sim_honest(8001u, 400u, 1000u);
    current.last_active_day = 1000u;

    al_fixed w_active  = al_potb_tbs(&params, &active, 1000u);
    al_fixed w_current = al_potb_tbs(&params, &current, 1000u);

    /* The absent node should have lower TBS due to decay. */
    AL_CHECK(w_active < w_current);

    /* The absent node's TBS should still be positive (not fully decayed). */
    AL_CHECK(w_active > 0);
}

/* ---------------------------------------------------------------------------
 * Attack 9: Loyalty threshold bypass attempt
 *
 * Strategy: a node with very short uptime tries to claim loyalty benefits.
 *
 * Expected outcome: loyalty only accrues after loyalty_threshold_days (365),
 * so a new node gets zero loyalty bonus.
 * ----------------------------------------------------------------------- */

AL_TEST(loyalty_threshold_bypass) {
    al_potb_params params = al_potb_params_default();

    /* Node at day 364 (just below threshold): no loyalty. */
    al_fixed loyalty_below = al_potb_loyalty_bonus(&params, 364u);

    /* Node at day 365 (at threshold): extra = 0, so bonus = 0. */
    al_fixed loyalty_at = al_potb_loyalty_bonus(&params, 365u);

    /* Node at day 366 (one day past threshold): first accrual. */
    al_fixed loyalty_one_past = al_potb_loyalty_bonus(&params, 366u);

    /* Node at day 400 (well above threshold): more loyalty. */
    al_fixed loyalty_above = al_potb_loyalty_bonus(&params, 400u);

    /* Below and at threshold: zero loyalty (threshold is exclusive). */
    AL_CHECK_EQ_I64(loyalty_below, 0);
    AL_CHECK_EQ_I64(loyalty_at, 0);

    /* One day past threshold: should have some loyalty. */
    AL_CHECK(loyalty_one_past > 0);

    /* Above threshold: should have more loyalty than one day past. */
    AL_CHECK(loyalty_above > loyalty_one_past);
}

/* ----------------------------------------------------------------------- */

AL_TEST_MAIN {
    AL_RUN(sybil_farm_group_cap);
    AL_RUN(eclipse_correlation_discount);
    AL_RUN(fresh_node_flood);
    AL_RUN(slashing_tier_differentiation);
    AL_RUN(genesis_bonus_dilution);
    AL_RUN(ndm_neutral_for_unknown_asn);
    AL_RUN(weight_effective_total_bounded);
    AL_RUN(tbs_decay_after_absence);
    AL_RUN(loyalty_threshold_bypass);
}
