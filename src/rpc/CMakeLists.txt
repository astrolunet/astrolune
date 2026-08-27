# The RPC surface: JSON codec and the HTTP/1.1 JSON-RPC listener.
#
# al_rpc knows nothing about the node: handlers are injected function pointers,
# so the module can be exercised against a fake handler in isolation.

astrolune_add_core_library(al_rpc
    SOURCES json.c server.c
    DEPS al_base al_net
)
add_library(Astrolune::rpc ALIAS al_rpc)

target_include_directories(al_rpc PUBLIC "${PROJECT_SOURCE_DIR}/src/rpc")
