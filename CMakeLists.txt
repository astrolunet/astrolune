# Astrolune - a decentralised network built on the PoTB consensus model.
#
# Layout
#   include/astrolune/  public C ABI, compiled by both C and C++
#   src/base|crypto|consensus|state|vm|tx|chain
#                       the C23 consensus core (hot path), one library each
#   src/node/           durable storage, mempool and block-ingress runtime
#   src/net/            P2P transport: sockets, wire protocol, peer manager
#   src/rpc/            JSON-RPC server over a minimal HTTP/1.1 listener
#   src/daemon/         long-running node service gluing node + net + rpc
#   src/apps/alnode/    command-line entry point and daemon launcher
#   tools/              Trocto/Regol contract-language compiler (C++23)
#   examples/           sample contracts for the trocto CLI
#   abi/                C/C++ boundary and ABI manifest enforcement
#   tests/              CTest suite
#   fuzz/               decoder fuzz targets and corpora
#   docs/               specification
#
# Quick start:
#   cmake --preset dev && cmake --build --preset dev && ctest --preset dev

cmake_minimum_required(VERSION 3.25)

# Read the version from a single file so tags, packaging and --version agree.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" ASTROLUNE_VERSION_RAW
     LIMIT_COUNT 1)
string(STRIP "${ASTROLUNE_VERSION_RAW}" ASTROLUNE_VERSION_RAW)

project(Astrolune
    VERSION   ${ASTROLUNE_VERSION_RAW}
    LANGUAGES C CXX
    DESCRIPTION "PoTB consensus network with its own VM and contract language"
    HOMEPAGE_URL "https://github.com/astrolune/astrolune"
)

# Building in the source tree makes `git status` useless and is almost always a
# mistake, so refuse it early with an actionable message.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR
      "In-source builds are not supported.\n"
      "Use a preset instead:  cmake --preset dev")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Default to a build type that is useful rather than to none at all: an
# unspecified CMAKE_BUILD_TYPE produces an unoptimised, unchecked binary, which
# is the worst of both worlds.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

include(AstroluneOptions)
include(AstroluneStandards)
include(AstroluneWarnings)
include(AstroluneSanitizers)
include(AstroluneTargets)

# --- Subdirectories ----------------------------------------------------------
#
# Each component is added only if its directory is present, and a missing
# component is reported rather than silently skipped so a genuine typo or a
# partial clone stays visible.

function(astrolune_add_component dir purpose)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${dir}/CMakeLists.txt")
    add_subdirectory(${dir})
  else()
    message(STATUS "Astrolune: skipping ${dir}/ - not present yet (${purpose})")
  endif()
endfunction()

if(ASTROLUNE_BUILD_CORE)
  add_subdirectory(src)
endif()

if(ASTROLUNE_BUILD_TOOLS)
  if(NOT ASTROLUNE_BUILD_CORE)
    message(FATAL_ERROR
        "ASTROLUNE_BUILD_TOOLS=ON requires ASTROLUNE_BUILD_CORE=ON: the ABI "
        "boundary checks and the contract compiler link against the core.")
  endif()
  astrolune_add_component(abi "C/C++ boundary and ABI manifest checks")
  astrolune_add_component(tools "Trocto/Regol contract compiler")
endif()

if(ASTROLUNE_BUILD_TESTS)
  enable_testing()
  astrolune_add_component(tests "CTest suite")
endif()

if(ASTROLUNE_BUILD_BENCH)
  astrolune_add_component(bench "microbenchmarks")
endif()

if(ASTROLUNE_BUILD_FUZZERS)
  astrolune_add_component(fuzz "decoder fuzz and corpus runners")
endif()

astrolune_report_configuration()
