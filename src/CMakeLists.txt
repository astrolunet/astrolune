# The C consensus core.
#
# Split into several small static libraries rather than one big one. Three
# reasons, in order of how much they matter:
#
#   1. Dependency direction is enforced by the build. al_base cannot reach into
#      the VM, and the VM cannot reach into consensus, because those targets are
#      simply not linked. A single library would let any file include any other
#      and the layering would rot within a month.
#   2. Incremental builds stay small. Touching the VM does not relink the crypto.
#   3. A minimal node can link only what it needs.
#
# The cost is a handful of extra CMake lines, which is nothing next to being able
# to see the architecture in the build graph.

# --- al_base: types, status codes, arena, byte views, fixed point -------------
#
# Depends on nothing but the C standard library. Everything else depends on it.
astrolune_add_core_library(al_base
    SOURCES
        base/status.c
        base/resource.c
        base/arena.c
        base/bytes.c
        base/fixed.c
        base/address_text.c
        base/toml.c
)

# --- al_crypto: SHA-256, HMAC, HKDF, Merkle, keys, signatures -----------------
#
# Signatures are selected at configure time. VRF/VDF remain an explicitly
# insecure shared development implementation until their protocol choices are
# resolved, so even a sodium build does not claim full production security.
if(ASTROLUNE_CRYPTO_BACKEND STREQUAL "dev")
  set(ASTROLUNE_SIGNATURE_SOURCE crypto/dev_backend.c)
  set(ASTROLUNE_CRYPTO_PRIVATE_DEPS "")
  set(ASTROLUNE_CRYPTO_DEFINES "")
elseif(ASTROLUNE_CRYPTO_BACKEND STREQUAL "sodium")
  find_package(Sodium 1.0.18 REQUIRED)
  set(ASTROLUNE_SIGNATURE_SOURCE crypto/sodium_backend.c)
  set(ASTROLUNE_CRYPTO_PRIVATE_DEPS Sodium::Sodium)
  set(ASTROLUNE_CRYPTO_DEFINES ASTROLUNE_HAS_SODIUM)
else()
  message(FATAL_ERROR
      "Unknown ASTROLUNE_CRYPTO_BACKEND='${ASTROLUNE_CRYPTO_BACKEND}'. "
      "Expected dev or sodium.")
endif()

astrolune_add_core_library(al_crypto
    SOURCES
        crypto/sha256.c
        crypto/hmac.c
        crypto/merkle.c
        crypto/keys.c
        crypto/signer.c
        ${ASTROLUNE_SIGNATURE_SOURCE}
    DEPS
        al_base
    PRIVATE_DEPS
        ${ASTROLUNE_CRYPTO_PRIVATE_DEPS}
)
target_compile_definitions(al_crypto PRIVATE ${ASTROLUNE_CRYPTO_DEFINES})

# --- al_potb: the consensus scoring, committee selection and rewards ----------
#
# Depends on al_crypto for the VRF and the hash chain that drives selection, and
# on al_base for the fixed-point arithmetic every score goes through. Notably it
# does *not* depend on networking or storage: PoTB is a pure function of state
# that has already been agreed, which is what makes it testable in isolation and
# simulatable without a network.
astrolune_add_core_library(al_potb
    SOURCES
        consensus/score.c
        consensus/score_anti_domination.c
        consensus/score_slash.c
        consensus/committee.c
        consensus/finality.c
        consensus/validator_set.c
        consensus/evidence.c
    DEPS
        al_base
        al_crypto
        al_state
)
target_include_directories(al_potb PUBLIC
    "${PROJECT_SOURCE_DIR}/src/consensus")

astrolune_add_core_library(al_state
    SOURCES state/state.c
    DEPS al_base al_crypto
)

astrolune_add_core_library(al_vm
    SOURCES
        vm/vm.c
        vm/decode.c
        vm/container.c
    DEPS al_base al_crypto al_state
)

astrolune_add_core_library(al_tx
    SOURCES tx/tx.c
    DEPS al_base al_crypto al_state al_vm
)

astrolune_add_core_library(al_block
    SOURCES chain/block.c
    DEPS al_base al_crypto al_potb al_state al_vm al_tx
)

# --- Node, networking and applications ---------------------------------------
#
# The layering stays enforced by the link graph: al_node knows nothing about
# sockets, al_net knows nothing about block validity (it moves bytes and calls
# back), and the daemon is the only component that sees all of them.

if(ASTROLUNE_BUILD_NODE)
  if(NOT ASTROLUNE_BUILD_CORE)
    message(FATAL_ERROR
        "ASTROLUNE_BUILD_NODE=ON requires ASTROLUNE_BUILD_CORE=ON.")
  endif()
  add_subdirectory(node)
endif()

# Logging is always available.
add_subdirectory(log)

if(ASTROLUNE_BUILD_NETWORK)
  if(NOT ASTROLUNE_BUILD_NODE)
    message(FATAL_ERROR
        "ASTROLUNE_BUILD_NETWORK=ON requires ASTROLUNE_BUILD_NODE=ON.")
  endif()
  add_subdirectory(net)
  add_subdirectory(rpc)
  add_subdirectory(daemon)
endif()

if(ASTROLUNE_BUILD_NETWORK OR ASTROLUNE_BUILD_NODE)
  add_subdirectory(apps)
endif()

# --- astrolune_core: the whole core as one link target -----------------------
#
# An INTERFACE library, so it adds no archive of its own: consumers that do not
# care about the internal split just link this.
add_library(astrolune_core INTERFACE)
add_library(Astrolune::core ALIAS astrolune_core)
target_link_libraries(astrolune_core INTERFACE
    al_base
    al_crypto
    al_potb
    al_state
    al_vm
    al_tx
    al_block
)
