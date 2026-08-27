#include "altest.h"
#include "astrolune/base.h"

AL_TEST(arithmetic) {
    const al_resources a = { 1u, 2u, 3u, 4u };
    const al_resources b = { 5u, 6u, 7u, 8u };
    al_resources sum;
    AL_CHECK_EQ_STATUS(al_resources_add(a, b, &sum), AL_OK);
    AL_CHECK_EQ_U64(sum.compute, 6u);
    AL_CHECK_EQ_U64(sum.memory, 8u);
    AL_CHECK_EQ_U64(sum.storage, 10u);
    AL_CHECK_EQ_U64(sum.bandwidth, 12u);
    AL_CHECK(al_resources_within(a, b));
    AL_CHECK(!al_resources_within(b, a));

    const al_resources overflow = { UINT64_MAX, 0u, 0u, 0u };
    AL_CHECK_EQ_STATUS(al_resources_add(overflow, a, &sum),
                       AL_ERR_ARITH_OVERFLOW);
    AL_CHECK_EQ_STATUS(al_resources_add(a, b, NULL), AL_ERR_INVALID_ARG);
}

AL_TEST(fees) {
    const al_resources used = { 3u, 4u, 5u, 6u };
    const al_resources prices = { 2u, 3u, 4u, 5u };
    al_amount fee = 0u;
    AL_CHECK_EQ_STATUS(al_resources_fee(used, prices, &fee), AL_OK);
    AL_CHECK_EQ_U64(fee, 68u);

    const al_resources overflow = { UINT64_MAX, 0u, 0u, 0u };
    AL_CHECK_EQ_STATUS(al_resources_fee(overflow, prices, &fee),
                       AL_ERR_ARITH_OVERFLOW);
}

AL_TEST(base_price_adjustment) {
    const al_resources prices = { 100u, 100u, 1u, 8u };
    const al_resources target = { 100u, 100u, 100u, 100u };
    const al_resources used = { 200u, 0u, 101u, 100u };
    al_resources next;
    AL_CHECK_EQ_STATUS(al_fee_next_base_prices(prices, used, target, &next),
                       AL_OK);
    AL_CHECK_EQ_U64(next.compute, 112u);
    AL_CHECK_EQ_U64(next.memory, 88u);
    AL_CHECK_EQ_U64(next.storage, 2u);
    AL_CHECK_EQ_U64(next.bandwidth, 8u);

    al_resources bad_target = target;
    bad_target.compute = 0u;
    AL_CHECK_EQ_STATUS(
        al_fee_next_base_prices(prices, used, bad_target, &next),
        AL_ERR_INVALID_ARG);
}

#define AL_TEST_SUITE_NAME "test_resource"
AL_TEST_MAIN {
    AL_RUN(arithmetic);
    AL_RUN(fees);
    AL_RUN(base_price_adjustment);
}
