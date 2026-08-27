# The P2P transport: sockets, wire codec and peer manager.
#
# al_net depends only on al_base and al_crypto. Block validity never enters
# this layer - objects cross it as opaque canonical bytes and the owner of the
# handlers decides what is true.

astrolune_add_core_library(al_net
    SOURCES net.c wire.c p2p.c
    DEPS al_base al_crypto al_potb
)
add_library(Astrolune::net ALIAS al_net)

target_include_directories(al_net PUBLIC "${PROJECT_SOURCE_DIR}/src/net")

if(WIN32)
  target_link_libraries(al_net PRIVATE ws2_32)
endif()
