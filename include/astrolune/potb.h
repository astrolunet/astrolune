/*
 * astrolune/potb.h - Proof of Trusted Behavior scoring and committee selection.
 *
 * This header is the executable form of docs/01-consensus/potb.md. Where the two
 * disagree the specification is wrong, because this is what nodes actually run.
 *
 * The weight of a node is
 *
 *     Weight = min(TBS, CAP_TBS) * min(TGW, CAP_TGW) * NDM * COD
 *
 * and the four factors answer four different questions:
 *
 *   TBS  how long has this node behaved correctly?          (time + behaviour)
 *   TGW  where does it sit in the trust graph?              (anti-Sybil)
 *   NDM  is its network location diverse?                   (soft ASN signal)
 *   COD  does it look statistically like part of a farm?    (anti-correlation)
 *
 * Determinism
 * ------------------------------------------------------------------------
 * Every number here is an integer or an al_fixed. There is no floating point in
 * this module and there must never be: two validators computing different
 * weights from the same inputs is a chain split, not a rounding difference. The
 * logarithm, the decay curve and the threshold comparison all go through
 * astrolune/fixed.h, which is bit-identical across platforms.
 *
 * Everything in this module is a pure function of explicitly passed state. There
 * is no global, no clock read and no allocation on the scoring path: the caller
 * supplies `now_day` rather than the module calling time(), because a consensus
 * rule may not depend on the local wall clock.
 *
 * Honest status
 * ------------------------------------------------------------------------
 * TGW and COD are heuristics, not proofs. They raise the cost of a Sybil attack;
 * they do not make one impossible, and this file does not pretend otherwise. The
 * open risks are enumerated in docs/01-consensus/potb.md section 7 and are the
 * reason the parameters below are all tunable rather than baked in.
 */

#ifndef ASTROLUNE_POTB_H
#define ASTROLUNE_POTB_H

#include "astrolune/arena.h"
#include "astrolune/base.h"
#include "astrolune/crypto.h"
#include "astrolune/fixed.h"

AL_EXTERN_C_BEGIN

/* --------------------------------------------------------------------------
 * Protocol parameters
 *
 * Grouped in a struct rather than spread across #defines so that a simulation
 * can sweep them, and so that the values a node used are recoverable from a log
 * line. al_potb_params_default() returns the values in the specification.
 *
 * Changing any of these changes consensus. They are part of the chain's identity
 * and belong in the genesis block, not in a config file a node operator edits.
 * -------------------------------------------------------------------------- */

typedef struct al_potb_params {
    /* --- TBS: time and behaviour ------------------------------------------ */

    /* Days of uptime before loyalty accrues. A Sybil farm spun up last week gets
     * nothing from this term; that is its whole purpose. */
    al_u32 loyalty_threshold_days;
    /* Loyalty gained per day past the threshold, as a fixed-point rate. */
    al_fixed loyalty_rate_per_day;
    /* Ceiling on the loyalty term alone, so a decade of uptime cannot dominate
     * on seniority by itself. */
    al_fixed cap_loyalty;

    /* Idle days tolerated before decay begins. An operator taking a two-month
     * break should not lose their history - the original design decayed from day
     * one, which punished honest absence and taught operators to fake uptime. */
    al_u32 grace_period_days;
    /* Half-life of the decay past the grace period, in days. */
    al_u32 decay_half_life_days;

    /* --- Caps ------------------------------------------------------------- */

    /* Hard ceilings on the two main factors. Together with the per-node share
     * limit these are what bound any single identity's influence. */
    al_fixed cap_tbs;
    al_fixed cap_tgw;

    /* --- Trust graph ------------------------------------------------------ */

    /* A cluster is suspicious when this share or more of a node's inbound
     * attestations come from one small group with no external links. Q32.32
     * fraction; the specification's value is 0.8. */
    al_fixed sybil_cluster_threshold;
    /* Cluster sizes at or below this are candidates for the check above. */
    al_u32 sybil_cluster_max_size;
    /* Temporal dispersion at or below this is treated as coordinated launch and
     * discounts the inbound edges from that window. */
    al_fixed tdi_suspicious_below;

    /* --- Committee -------------------------------------------------------- */

    al_u32 committee_size;
    /* Blocks a committee lives for before its membership has fully turned over. */
    al_u32 committee_lifetime_blocks;
    /* Share of the committee replaced each block, as a Q32.32 fraction. Partial
     * rotation: replacing all 100 members every 400ms is not a networking load
     * the design can carry, and it is not necessary - a full turnover across ten
     * blocks already denies an attacker a stable predictable committee. */
    al_fixed rotation_fraction;

    /* Minimum TBS to be considered for a committee at all (level 2). */
    al_fixed min_tbs_candidate;
    /* Minimum TBS and TGW to carry full weight (level 3). */
    al_fixed min_tbs_validator;
    al_fixed min_tgw_validator;
    /* Weight a candidate-level node is drawn with, as a fraction of its computed
     * weight. Candidates take part so that the set can grow and so a young node
     * has a path in, but at a discount, because they have less history behind
     * them. A parameter rather than a constant in the selection code: it is a
     * consensus value and it belongs where the others are. */
    al_fixed candidate_weight_factor;

    /* --- Epoch ------------------------------------------------------------ */

    /* Length of an epoch in days. TGW is recomputed and external challenges are
     * issued at epoch boundaries. */
    al_u32 epoch_days;

    /* --- Rewards ---------------------------------------------------------- */

    /* Split in basis points, and it must total 10000. Flat/weighted/bonded:
     * equal share for honest participation, a weighted share for tenure, and a
     * bonded share that compensates infrastructure cost. The bond deliberately
     * does not touch consensus weight - that would make this a stake-weighted
     * system wearing a different name. */
    al_u16 reward_flat_bp;
    al_u16 reward_weighted_bp;
    al_u16 reward_bonded_bp;
    /* Ceiling on any one node's reward as a multiple of the flat share. */
    al_fixed reward_max_multiple;
} al_potb_params;

/* The parameters from the specification. */
AL_PUBLIC al_potb_params al_potb_params_default(void);

/* Reject a parameter set that cannot be consistent - reward shares that do not
 * total 10000, a zero committee, a rotation fraction outside (0, 1]. Called at
 * genesis load so a misconfigured chain fails to start instead of forking. */
AL_PUBLIC AL_NODISCARD al_status al_potb_params_validate(const al_potb_params *p);

/* --------------------------------------------------------------------------
 * Node behaviour record
 *
 * The observable history of one node, as every other node sees it. This is
 * consensus state: it is derived from on-chain evidence, so all nodes hold the
 * same record for a given identity and therefore compute the same weight.
 *
 * Time is counted in protocol days - the day index of the chain, derived from
 * block height, never from a local clock.
 * -------------------------------------------------------------------------- */

typedef struct al_potb_record {
    al_pubkey identity;

    /* Days this node has been observed live. Not wall-clock age: a node that
     * registered a year ago and ran for a week has uptime_days == 7. */
    al_u32 uptime_days;
    /* Protocol day of the most recent observed activity, for decay. */
    al_u32 last_active_day;
    /* Protocol day the identity first appeared, for the temporal checks. */
    al_u32 first_seen_day;

    /* Correctness over the trailing window, as a Q32.32 fraction in [0, 1].
     * Held as a ratio of counters rather than a running average so it is exactly
     * reproducible from the counters below. */
    al_u64 responses_total;
    al_u64 responses_correct;

    /* Vote participation over the trailing window. Misses are judged against the
     * network median, not against zero - see al_potb_slash_for_misses. */
    al_u64 votes_expected;
    al_u64 votes_cast;

    /* Accumulated penalty, as a multiplier in [0, 1] applied to TBS. Slashing
     * multiplies rather than subtracts so repeated offences compound and no
     * sequence of penalties can drive the score negative. */
    al_fixed penalty_multiplier;

    /* Protocol day the node's committee ban expires; 0 when not banned. */
    al_u32 banned_until_day;
    /* Set once double-signing has been proven twice. Permanent. */
    al_bool permanently_banned;

    /* --- Trust graph inputs ---------------------------------------------- */

    /* Inbound attestations from distinct identities. */
    al_u32 inbound_attestations;
    /* How many of those come from within the node's own detected cluster. */
    al_u32 inbound_from_cluster;
    /* Size of that cluster. */
    al_u32 cluster_size;
    /* Temporal dispersion index of the inbound edges, Q32.32 in [0, 1].
     * Low means the edges all appeared at once, which is what a coordinated
     * launch looks like and what organic growth does not. */
    al_fixed tdi;
    /* External challenges issued to this node and how many it answered. The
     * protocol forces these against nodes with no existing edge, so a cluster
     * cannot stay inside itself. */
    al_u32 challenges_issued;
    al_u32 challenges_passed;

    /* --- Network diversity ----------------------------------------------- */

    /* Autonomous system number, 0 when unknown. */
    al_u32 asn;
    /* Nodes sharing this ASN, which is what makes the multiplier soft: it is
     * evadable with residential proxies and is one layer, not a defence. */
    al_u32 asn_peer_count;

    /* --- Correlation ------------------------------------------------------ */

    /* Correlation score against the node's suspected group, Q32.32 and >= 0.
     * Computed by al_potb_correlation_score over a candidate group. */
    al_fixed correlation_score;

    /* --- Rewards ---------------------------------------------------------- */

    /* Voluntary operational bond. Affects only the bonded reward share, never
     * weight. */
    al_amount operational_bond;
} al_potb_record;

/* Zeroed record with the multiplier fields set to 1, which is the correct
 * neutral start - a zeroed penalty_multiplier would mean a brand new node has
 * weight zero forever. */
AL_PUBLIC al_potb_record al_potb_record_init(const al_pubkey *identity);

/* --------------------------------------------------------------------------
 * Network aggregates
 *
 * Values that can only be computed across the whole validator set, and which the
 * per-node scoring needs. Passed in explicitly so that scoring stays a pure
 * function and so a simulation can supply synthetic aggregates.
 * -------------------------------------------------------------------------- */

typedef struct al_potb_network_stats {
    al_u32 node_count;
    /* Median vote-miss rate across the network, Q32.32. The reference point for
     * differentiated slashing: an outage that hits everyone raises the median and
     * so does not punish the nodes caught in it. */
    al_fixed median_miss_rate;
    /* Median incorrect-response rate, same role. */
    al_fixed median_error_rate;
    /* Total weight, for share calculations. */
    al_fixed total_weight;
} al_potb_network_stats;

/* --------------------------------------------------------------------------
 * Score components
 * -------------------------------------------------------------------------- */

/* Correctness as a Q32.32 fraction. A node with no observations yields 1: it has
 * not been caught doing anything wrong, and its lack of history is already
 * priced in by a near-zero uptime term. */
AL_PUBLIC al_fixed al_potb_correctness_rate(const al_potb_record *r);

/* Vote participation miss rate, Q32.32. */
AL_PUBLIC al_fixed al_potb_miss_rate(const al_potb_record *r);

/*
 * Time-Behavior Score.
 *
 *   TBS = ln(1 + uptime_days * correctness_rate) + loyalty_bonus(uptime_days)
 *
 * The logarithm is the anti-Sybil term: splitting one long-lived node into ten
 * fresh ones loses most of the score, because ln is concave. The additive
 * loyalty term exists because the logarithm alone made year three nearly
 * indistinguishable from year one, which told honest long-term operators that
 * continuing to run was worth nothing.
 *
 * Decay past the grace period and the accumulated penalty multiplier are both
 * applied here, so the returned value is the TBS the weight formula uses.
 */
AL_PUBLIC al_fixed al_potb_tbs(const al_potb_params *p, const al_potb_record *r,
                     al_u32 now_day);

/* The loyalty term alone, exposed for tests and diagnostics. */
AL_PUBLIC al_fixed al_potb_loyalty_bonus(const al_potb_params *p, al_u32 uptime_days);

/* The decay multiplier for a given idle span: 1 inside the grace period, then
 * 0.5^((idle - grace) / half_life). */
AL_PUBLIC al_fixed al_potb_decay_multiplier(const al_potb_params *p, al_u32 idle_days);

/*
 * Trust Graph Weight.
 *
 * SybilRank-style: a node's score comes from how well connected it is to the
 * rest of the graph rather than from how many edges it has, so a dense cluster
 * of mutual attestations is worth little. Two additional inputs harden it:
 *
 *   - TDI discounts edges that all appeared in one narrow window, the signature
 *     of a farm coming online together.
 *   - External challenge results carry weight, because the protocol chooses those
 *     pairings, so a cluster cannot manufacture them internally.
 *
 * Honest limitation: this raises the cost of a patient, well-funded attacker who
 * grows a graph slowly and answers challenges. It does not defeat one.
 */
AL_PUBLIC al_fixed al_potb_tgw(const al_potb_params *p, const al_potb_record *r);

/* AL_TRUE when the node's inbound edges look like a closed cluster by the
 * threshold rule in the specification. */
AL_PUBLIC AL_NODISCARD al_bool al_potb_is_suspicious_cluster(const al_potb_params *p,
                                                   const al_potb_record *r);

/* Network Diversity Multiplier. Soft by design and documented as evadable. */
AL_PUBLIC al_fixed al_potb_ndm(const al_potb_params *p, const al_potb_record *r,
                     const al_potb_network_stats *net);

/*
 * Cluster Ownership Dampening: COD = 1 / (1 + correlation_score).
 *
 * The point is to bound the *joint* weight of a group that individually passes
 * every check. Correlated nodes each get their weight cut, so the group's total
 * falls even though no single member was ever proven to be a Sybil.
 *
 * This is a statistical signal and it has false positives - two honest operators
 * in one datacentre with similar usage patterns will correlate. A network that
 * deploys this needs an appeal path for nodes wrongly caught, which is a
 * governance question this module cannot answer.
 */
AL_PUBLIC al_fixed al_potb_cod(const al_potb_record *r);

/* --------------------------------------------------------------------------
 * Correlation
 * -------------------------------------------------------------------------- */

/* One node's contribution to a group's correlation, from the signals in the
 * specification: similar online patterns, similar TBS growth, registration in
 * nearby windows, overlapping ASN. Summed over the group by the caller and
 * written back into each record's correlation_score. */
AL_PUBLIC al_fixed al_potb_correlation_pair(const al_potb_record *a,
                                  const al_potb_record *b);

/* Total correlation of a candidate group. O(n^2) in the group size, which is
 * fine: it runs once per epoch over groups of tens, not per block. */
AL_PUBLIC al_fixed al_potb_correlation_score(const al_potb_record *const *group,
                                   al_size count);

/* --------------------------------------------------------------------------
 * Final weight
 * -------------------------------------------------------------------------- */

/* Every component of one node's weight, kept together so a node can explain a
 * weight rather than just report it. Diagnosability matters here: an operator
 * who sees their weight drop needs to know which factor did it. */
typedef struct al_potb_weight {
    al_fixed tbs;
    al_fixed tgw;
    al_fixed ndm;
    al_fixed cod;
    al_fixed tbs_capped;
    al_fixed tgw_capped;
    al_fixed total;
} al_potb_weight;

/* Weight = min(TBS, CAP_TBS) * min(TGW, CAP_TGW) * NDM * COD, with the
 * intermediate values retained. A banned node scores zero. */
AL_PUBLIC void al_potb_weight_compute(const al_potb_params *p, const al_potb_record *r,
                            const al_potb_network_stats *net, al_u32 now_day,
                            al_potb_weight *out);

/* Just the total, for callers that do not need the breakdown. */
AL_PUBLIC al_fixed al_potb_weight_total(const al_potb_params *p, const al_potb_record *r,
                             const al_potb_network_stats *net, al_u32 now_day);

/* --------------------------------------------------------------------------
 * Node levels
 * -------------------------------------------------------------------------- */

typedef enum al_potb_level {
    /* Stores the chain, validates locally, relays. Available immediately. */
    AL_POTB_LEVEL_RELAY = 0,
    /* May be drawn into a committee at reduced weight. */
    AL_POTB_LEVEL_CANDIDATE = 1,
    /* Full weight, participates in finalisation. */
    AL_POTB_LEVEL_VALIDATOR = 2,
    /* Banned: excluded from committees. */
    AL_POTB_LEVEL_BANNED = 3,
    AL_POTB_LEVEL_SENTINEL = 0x7fffffff
} al_potb_level;

AL_PUBLIC al_potb_level al_potb_level_of(const al_potb_params *p, const al_potb_record *r,
                               al_u32 now_day);
AL_PUBLIC const char *al_potb_level_str(al_potb_level level);

/* --------------------------------------------------------------------------
 * Slashing
 * -------------------------------------------------------------------------- */

typedef enum al_potb_offence {
    /* A single miss, judged against the network median. */
    AL_POTB_OFFENCE_VOTE_MISS = 0,
    /* Misses persistently above the median. */
    AL_POTB_OFFENCE_SYSTEMATIC_MISS,
    /* One bad response - possibly a network fault, so treated lightly. */
    AL_POTB_OFFENCE_BAD_RESPONSE,
    /* Bad responses at a rate the median does not explain. */
    AL_POTB_OFFENCE_SYSTEMATIC_BAD_RESPONSE,
    /* Two signatures at one height. Cryptographically unambiguous and
     * impossible by accident, which is why it is the one severe penalty. */
    AL_POTB_OFFENCE_DOUBLE_SIGN,
    AL_POTB_OFFENCE_REPEAT_DOUBLE_SIGN,
    AL_POTB_OFFENCE_SENTINEL = 0x7fffffff
} al_potb_offence;

AL_PUBLIC const char *al_potb_offence_str(al_potb_offence offence);

/* The multiplier an offence applies to TBS: 0.9 for a single bad response, 0.1
 * for double-signing, and so on. */
AL_PUBLIC al_fixed al_potb_penalty_for(al_potb_offence offence);

/*
 * Apply an offence to a record.
 *
 * `net` is required because the light offences are relative: a node that missed
 * votes during a network-wide incident has not misbehaved, and slashing it would
 * punish honesty. Returns AL_OK when a penalty was applied, AL_ERR_NOT_FOUND
 * when the offence was excused as within network noise.
 */
AL_PUBLIC al_status al_potb_slash(const al_potb_params *p, al_potb_record *r,
                        const al_potb_network_stats *net,
                        al_potb_offence offence, al_u32 now_day);

/* --------------------------------------------------------------------------
 * Committee selection
 *
 * Members are drawn by VRF, weighted by al_potb_weight_total. The seed comes
 * from the epoch's commit-reveal (hardened by the VDF, if that branch is taken)
 * and is passed in rather than derived here.
 * -------------------------------------------------------------------------- */

/* Cap on committee size, so selection needs no allocation. */
#define AL_POTB_MAX_COMMITTEE 512

typedef struct al_potb_committee {
    al_u32    size;
    al_pubkey members[AL_POTB_MAX_COMMITTEE];
    /* Weight each member was selected with, for reward splitting. */
    al_fixed  weights[AL_POTB_MAX_COMMITTEE];
    /* Block height this committee was formed at. */
    al_height formed_at;
    /* The seed it was drawn from, so the selection is auditable after the fact. */
    al_hash256 seed;
} al_potb_committee;

/*
 * Select a committee from the candidate set.
 *
 * Weighted sampling without replacement, driven by a hash chain from `seed`, so
 * every node performs the identical draw. Candidates below the level threshold
 * are skipped and banned nodes are excluded.
 *
 * `scratch` holds one weight per candidate for the duration of the call. It is an
 * explicit parameter rather than an internal buffer because the alternative
 * shapes are both worse: a fixed-size array would cap the candidate set at a
 * compile-time constant, and recomputing weights on every draw would evaluate a
 * logarithm per candidate per slot - a hundred draws over ten thousand
 * candidates, on a node that has 400ms to produce a block. The arena is reset to
 * its entry mark before returning, so the call leaves no allocation behind.
 *
 * AL_ERR_OUT_OF_RANGE if params->committee_size exceeds AL_POTB_MAX_COMMITTEE,
 * and AL_ERR_NOT_FOUND if no candidate is eligible. Selecting fewer members than
 * requested is not an error - a young network legitimately has fewer eligible
 * nodes than a full committee, and refusing to form one would halt the chain.
 */
AL_PUBLIC AL_NODISCARD al_status al_potb_committee_select(
    const al_potb_params *p, const al_potb_record *const *candidates,
    al_size candidate_count, const al_potb_network_stats *net,
    const al_hash256 *seed, al_height height, al_u32 now_day,
    al_arena *scratch, al_potb_committee *out);

/*
 * Rotate part of a committee, which is what actually runs between blocks.
 *
 * Replaces round(rotation_fraction * size) members, chosen by the seed, with
 * fresh draws. Full turnover takes committee_lifetime_blocks. This is the fix
 * for the original full-rotation design: re-selecting and re-distributing an
 * entire committee every 400ms is a networking cost the design cannot pay, while
 * partial rotation still denies an attacker a predictable membership.
 *
 * Members that have since been banned are evicted regardless of the rotation
 * count - a committee is a set of nodes the chain currently trusts, and leaving
 * a proven double-signer seated until its slot came up would be indefensible.
 */
AL_PUBLIC AL_NODISCARD al_status al_potb_committee_rotate(
    const al_potb_params *p, al_potb_committee *committee,
    const al_potb_record *const *candidates, al_size candidate_count,
    const al_potb_network_stats *net, const al_hash256 *seed, al_height height,
    al_u32 now_day, al_arena *scratch);

/* Membership test. Linear over at most 512 keys. */
AL_PUBLIC AL_NODISCARD al_bool al_potb_committee_contains(const al_potb_committee *c,
                                                const al_pubkey *pk);

/* Votes needed for BFT finality: floor(2n/3) + 1. */
AL_PUBLIC al_u32 al_potb_quorum_threshold(al_u32 committee_size);

/* --------------------------------------------------------------------------
 * Epoch seed
 * -------------------------------------------------------------------------- */

/*
 * Fold one participant's revealed contribution into the epoch seed.
 *
 * Commit-reveal: contributions are committed to before any is revealed, so no
 * participant can choose theirs in response to the others. The residual attack
 * is that the last revealer sees the outcome and may withhold - which is what
 * the VDF is meant to close, and why al_potb_epoch_seed_finalise takes a VDF
 * output. Order-independent (each contribution is folded by XOR of its tagged
 * hash) so late arrivals cannot reorder the result.
 *
 * The commitment and the folded contribution are hashed under *different* domain
 * tags, and that is load-bearing rather than tidiness. Deriving both from one
 * tagged hash would make the published commitment equal to the value it later
 * contributes, so the whole seed would be computable from the commit round alone
 * and the reveal round would protect nothing.
 */
AL_PUBLIC void al_potb_epoch_seed_mix(al_hash256 *seed, const al_pubkey *contributor,
                            const al_hash256 *reveal);

/* Commitment for a reveal: the tagged hash a participant publishes first. */
AL_PUBLIC void al_potb_epoch_seed_commit(const al_pubkey *contributor,
                              const al_hash256 *reveal, al_hash256 *out);

/* AL_TRUE when `reveal` is the preimage of a previously published commitment.
 * Constant-time, because a reveal is checked against a value an adversary chose
 * and the comparison result is not public until the round closes. */
AL_PUBLIC AL_NODISCARD al_bool al_potb_epoch_seed_check(const al_pubkey *contributor,
                                              const al_hash256 *reveal,
                                              const al_hash256 *commitment);

/* Finalise the seed for an epoch, optionally through a VDF. Pass NULL for
 * `vdf` to take the VRF-only branch - faster blocks, weaker protection against
 * timing manipulation. The choice is documented as open in the specification and
 * is deliberately a parameter rather than a decision made here. */
AL_PUBLIC void al_potb_epoch_seed_finalise(const al_hash256 *mixed, al_u64 epoch,
                                const al_vdf_output *vdf, al_hash256 *out);

/* --------------------------------------------------------------------------
 * Rewards
 * -------------------------------------------------------------------------- */

typedef struct al_potb_reward_split {
    al_amount flat;      /* equal share for participating honestly       */
    al_amount weighted;  /* share for tenure, by weight                  */
    al_amount bonded;    /* share for infrastructure, by bond            */
    al_amount total;
} al_potb_reward_split;

/*
 * One member's reward from a block.
 *
 * The bonded component is why this takes a bond at all, and the reason it does
 * not feed weight bears repeating: a bond that bought consensus influence would
 * make this proof-of-stake with extra steps. It buys a share of one reward
 * bucket, nothing more.
 *
 * Both the member's own bond and the committee's total are needed, because the
 * bonded share is a ratio. An earlier signature took only the total, which made
 * the bucket unpayable - a reminder that a reward split is a ratio at every
 * level, not a lookup.
 */
AL_PUBLIC void al_potb_reward_for(const al_potb_params *p, al_amount block_reward,
                       const al_potb_committee *committee, al_u32 member_index,
                       al_amount member_bond, al_amount total_bond,
                       al_potb_reward_split *out);

AL_EXTERN_C_END

#endif /* ASTROLUNE_POTB_H */
