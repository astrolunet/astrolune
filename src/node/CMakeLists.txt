# Local node policy. This remains separate from Astrolune::core: mempool and
# ingress behavior are node policy, while block validity is consensus.

astrolune_add_core_library(al_node
    SOURCES node.c storage.c
    DEPS al_block
)
add_library(Astrolune::node ALIAS al_node)

target_include_directories(al_node PUBLIC "${PROJECT_SOURCE_DIR}/src/node")

if(WIN32)
  target_link_libraries(al_node PRIVATE ws2_32)
endif()
