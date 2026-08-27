#ifndef ASTROLUNE_TEST_STATE_FIXTURE_H
#define ASTROLUNE_TEST_STATE_FIXTURE_H

#include "altest.h"
#include "astrolune/state.h"

#define AL_TEST_STATE_NODE_CAPACITY 8192u
#define AL_TEST_STATE_VALUE_CAPACITY 512u

typedef struct al_test_state_fixture {
    al_arena               arena;
    al_state_memory_store  memory;
    al_state_memory_node  *nodes;
    al_state_memory_value *values;
    al_state_store         store;
    al_state               state;
} al_test_state_fixture;

static void al_test_state_fixture_init(al_test_state_fixture *fixture,
                                       al_amount deposit_per_byte) {
    memset(fixture, 0, sizeof(*fixture));
    AL_CHECK_EQ_STATUS(al_arena_init(&fixture->arena, 0u), AL_OK);
    fixture->nodes = AL_ARENA_NEW_ARRAY(&fixture->arena,
                                        al_state_memory_node,
                                        AL_TEST_STATE_NODE_CAPACITY);
    fixture->values = AL_ARENA_NEW_ARRAY(&fixture->arena,
                                          al_state_memory_value,
                                          AL_TEST_STATE_VALUE_CAPACITY);
    AL_CHECK(fixture->nodes != NULL);
    AL_CHECK(fixture->values != NULL);
    AL_CHECK_EQ_STATUS(al_state_memory_store_init(
                           &fixture->memory, fixture->nodes,
                           AL_TEST_STATE_NODE_CAPACITY, fixture->values,
                           AL_TEST_STATE_VALUE_CAPACITY, &fixture->arena),
                       AL_OK);
    fixture->store = al_state_memory_store_interface(&fixture->memory);
    AL_CHECK_EQ_STATUS(al_state_init(&fixture->state, &fixture->store,
                                    &fixture->arena, deposit_per_byte),
                       AL_OK);
}

static void al_test_state_fixture_destroy(al_test_state_fixture *fixture) {
    al_arena_destroy(&fixture->arena);
}

#endif /* ASTROLUNE_TEST_STATE_FIXTURE_H */
