# The daemon: durable node + P2P + RPC behind one event loop.

astrolune_add_core_library(al_daemon
    SOURCES
        helpers.c consensus.c p2p_handlers.c
        block_producer.c rpc.c event_loop.c
        lifecycle.c random.c config.c signing_journal.c
    DEPS al_node al_net al_rpc al_crypto al_log
)
add_library(Astrolune::daemon ALIAS al_daemon)

target_include_directories(al_daemon PUBLIC "${PROJECT_SOURCE_DIR}/src/daemon")

if(WIN32)
  target_link_libraries(al_daemon PRIVATE bcrypt)
endif()
