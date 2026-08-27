#include "astrolune/base.h"
#include "internal/common.h"

static al_status resource_add_one(al_u64 a, al_u64 b, al_u64 *out) {
    return al_add_overflow_u64(a, b, out) ? AL_ERR_ARITH_OVERFLOW : AL_OK;
}

static al_status resource_fee_one(al_u64 used, al_u64 price,
                                  al_u64 *total) {
    al_u64 charge = 0u;
    if (al_mul_overflow_u64(used, price, &charge) ||
        al_add_overflow_u64(*total, charge, total)) {
        return AL_ERR_ARITH_OVERFLOW;
    }
    return AL_OK;
}

/* Computes floor(value * numerator / denominator / 8) without requiring a
 * compiler-specific 128-bit integer. Splitting value at the denominator keeps
 * both multiplications bounded while preserving the exact integer result. */
static al_status fee_delta(al_u64 value, al_u64 numerator,
                           al_u64 denominator, al_u64 *out) {
    if (denominator == 0u || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }

    al_u64 quotient = value / denominator;
    al_u64 remainder = value % denominator;
    al_u64 high = 0u;
    al_u64 low = 0u;
    if (al_mul_overflow_u64(quotient, numerator, &high) ||
        al_mul_overflow_u64(remainder, numerator, &low)) {
        return AL_ERR_ARITH_OVERFLOW;
    }
    low /= denominator;
    if (al_add_overflow_u64(high, low, out)) {
        return AL_ERR_ARITH_OVERFLOW;
    }
    *out /= 8u;
    return AL_OK;
}

static al_status fee_next_one(al_u64 price, al_u64 used, al_u64 target,
                              al_u64 *out) {
    if (out == NULL || target == 0u) {
        return AL_ERR_INVALID_ARG;
    }
    if (price == 0u) {
        price = 1u;
    }
    if (used == target) {
        *out = price;
        return AL_OK;
    }

    al_u64 distance = (used > target) ? used - target : target - used;
    al_u64 delta = 0u;
    AL_TRY(fee_delta(price, distance, target, &delta));
    if (used > target) {
        if (delta == 0u) {
            delta = 1u;
        }
        if (al_add_overflow_u64(price, delta, out)) {
            return AL_ERR_ARITH_OVERFLOW;
        }
    } else {
        *out = (delta >= price) ? 1u : price - delta;
    }
    return AL_OK;
}

al_resources al_resources_zero(void) {
    const al_resources zero = { 0u, 0u, 0u, 0u };
    return zero;
}

al_status al_resources_add(al_resources a, al_resources b,
                           al_resources *out) {
    if (out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_resources result;
    AL_TRY(resource_add_one(a.compute, b.compute, &result.compute));
    AL_TRY(resource_add_one(a.memory, b.memory, &result.memory));
    AL_TRY(resource_add_one(a.storage, b.storage, &result.storage));
    AL_TRY(resource_add_one(a.bandwidth, b.bandwidth, &result.bandwidth));
    *out = result;
    return AL_OK;
}

al_bool al_resources_within(al_resources used, al_resources limit) {
    return (used.compute <= limit.compute && used.memory <= limit.memory &&
            used.storage <= limit.storage &&
            used.bandwidth <= limit.bandwidth) ? AL_TRUE : AL_FALSE;
}

al_status al_resources_fee(al_resources used, al_resources prices,
                           al_amount *out) {
    if (out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_u64 total = 0u;
    AL_TRY(resource_fee_one(used.compute, prices.compute, &total));
    AL_TRY(resource_fee_one(used.memory, prices.memory, &total));
    AL_TRY(resource_fee_one(used.storage, prices.storage, &total));
    AL_TRY(resource_fee_one(used.bandwidth, prices.bandwidth, &total));
    *out = total;
    return AL_OK;
}

al_status al_fee_next_base_prices(al_resources parent_prices,
                                  al_resources parent_used,
                                  al_resources target,
                                  al_resources *out) {
    if (out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_resources result;
    AL_TRY(fee_next_one(parent_prices.compute, parent_used.compute,
                        target.compute, &result.compute));
    AL_TRY(fee_next_one(parent_prices.memory, parent_used.memory,
                        target.memory, &result.memory));
    AL_TRY(fee_next_one(parent_prices.storage, parent_used.storage,
                        target.storage, &result.storage));
    AL_TRY(fee_next_one(parent_prices.bandwidth, parent_used.bandwidth,
                        target.bandwidth, &result.bandwidth));
    *out = result;
    return AL_OK;
}
