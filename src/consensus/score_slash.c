/*
 * Slashing, offence penalties, appeal resolution.
 */

#include "score_internal.h"

/* --------------------------------------------------------------------------
 * Slashing
 * -------------------------------------------------------------------------- */

const char *al_potb_offence_str(al_potb_offence offence) {
    switch (offence) {
        case AL_POTB_OFFENCE_VOTE_MISS:              return "vote-miss";
        case AL_POTB_OFFENCE_SYSTEMATIC_MISS:        return "systematic-miss";
        case AL_POTB_OFFENCE_BAD_RESPONSE:           return "bad-response";
        case AL_POTB_OFFENCE_SYSTEMATIC_BAD_RESPONSE:
            return "systematic-bad-response";
        case AL_POTB_OFFENCE_DOUBLE_SIGN:            return "double-sign";
        case AL_POTB_OFFENCE_REPEAT_DOUBLE_SIGN:     return "repeat-double-sign";
        case AL_POTB_OFFENCE_CHALLENGE_MISS:         return "challenge-miss";
        case AL_POTB_OFFENCE_SENTINEL:               break;
    }
    return "unknown";
}

al_fixed al_potb_penalty_for(al_potb_offence offence) {
    switch (offence) {
        case AL_POTB_OFFENCE_VOTE_MISS:       return AL_FX(95, 100);
        case AL_POTB_OFFENCE_SYSTEMATIC_MISS: return AL_FX(95, 100);
        case AL_POTB_OFFENCE_BAD_RESPONSE:    return AL_FX(90, 100);
        case AL_POTB_OFFENCE_SYSTEMATIC_BAD_RESPONSE: return AL_FX(80, 100);
        case AL_POTB_OFFENCE_DOUBLE_SIGN:     return AL_FX(10, 100);
        case AL_POTB_OFFENCE_REPEAT_DOUBLE_SIGN: return 0;
        case AL_POTB_OFFENCE_CHALLENGE_MISS:  return AL_FX(80, 100);
        case AL_POTB_OFFENCE_SENTINEL:        break;
    }
    return AL_FIXED_ONE;
}

al_bool al_potb_exceeds_median(al_fixed rate, al_fixed median) {
    al_fixed limit = al_fixed_mul(median, al_fixed_from_int(2));
    return (rate > limit) ? AL_TRUE : AL_FALSE;
}

al_status al_potb_slash(const al_potb_params *p, al_potb_record *r,
                        const al_potb_network_stats *net,
                        al_potb_offence offence, al_u32 now_day) {
    if (p == NULL || r == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    if (r->permanently_banned) {
        return AL_OK;
    }

    if (net != NULL) {
        if (offence == AL_POTB_OFFENCE_VOTE_MISS) {
            if (!al_potb_exceeds_median(al_potb_miss_rate(r),
                                        net->median_miss_rate)) {
                return AL_ERR_NOT_FOUND;
            }
        } else if (offence == AL_POTB_OFFENCE_BAD_RESPONSE) {
            if (!al_potb_exceeds_median(al_potb_error_rate(r),
                                        net->median_error_rate)) {
                return AL_ERR_NOT_FOUND;
            }
        } else if (offence == AL_POTB_OFFENCE_CHALLENGE_MISS) {
            if (!al_potb_exceeds_median(al_potb_miss_rate(r),
                                        net->median_miss_rate)) {
                return AL_ERR_NOT_FOUND;
            }
        }
    }

    al_fixed factor = al_potb_penalty_for(offence);
    r->penalty_multiplier = al_fixed_clamp(
        al_fixed_mul(r->penalty_multiplier, factor), 0, AL_FIXED_ONE);

    if (offence == AL_POTB_OFFENCE_DOUBLE_SIGN) {
        r->banned_until_day = now_day + 14u;
    } else if (offence == AL_POTB_OFFENCE_REPEAT_DOUBLE_SIGN) {
        r->permanently_banned = AL_TRUE;
        r->penalty_multiplier = 0;
    }
    return AL_OK;
}

/* --------------------------------------------------------------------------
 * Appeal (B4)
 * -------------------------------------------------------------------------- */

al_status al_potb_appeal_resolve(
    const al_potb_params *p, al_potb_record *record,
    al_potb_appeal *appeal, al_u32 grant_votes, al_u32 total_votes,
    al_u32 now_day) {
    if (p == NULL || record == NULL || appeal == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    if (appeal->status != AL_POTB_APPEAL_PENDING) {
        return AL_ERR_INVALID_ARG;
    }
    if (total_votes == 0u) {
        return AL_ERR_INVALID_ARG;
    }

    al_u32 quorum = al_potb_quorum_threshold(total_votes);
    if (grant_votes >= quorum) {
        appeal->status = AL_POTB_APPEAL_GRANTED;
        record->penalty_multiplier = AL_FIXED_ONE;
    } else {
        appeal->status = AL_POTB_APPEAL_DENIED;
    }
    appeal->resolved_day = now_day;
    return AL_OK;
}
