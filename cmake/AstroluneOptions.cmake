# Astrolune build options.
#
# Every option is scoped so a low-end machine can build only what it needs:
# `-DASTROLUNE_BUILD_TOOLS=OFF -DASTROLUNE_BUILD_TESTS=OFF` leaves just the C
# core and the node binary, which is the smallest useful build.

include_guard(GLOBAL)

include(CMakeDependentOption)

option(ASTROLUNE_BUILD_CORE    "Build the C consensus/VM core"        ON)
option(ASTROLUNE_BUILD_NODE    "Build the node runtime and storage"   ON)
option(ASTROLUNE_BUILD_NETWORK "Build P2P, RPC and the daemon"        ON)
option(ASTROLUNE_BUILD_TOOLS   "Build the ABI boundary checks and C++ tooling" ON)
option(ASTROLUNE_BUILD_TESTS   "Build the test suite"                 ON)
option(ASTROLUNE_BUILD_BENCH   "Build microbenchmarks"                OFF)
option(ASTROLUNE_BUILD_FUZZERS "Build decoder fuzz/corpus targets"    ON)
option(ASTROLUNE_LIBFUZZER     "Link fuzz targets with Clang libFuzzer" OFF)

option(ASTROLUNE_WERROR        "Treat warnings as errors"             OFF)
option(ASTROLUNE_LTO           "Enable link-time optimisation in Release" OFF)
option(ASTROLUNE_UNITY         "Enable unity builds (faster clean builds)" OFF)
option(ASTROLUNE_NATIVE_ARCH   "Optimise for the building machine's CPU" OFF)

# Signature implementations are selected explicitly. Keeping development as the
# default preserves dependency-free simulation builds; production-oriented
# builds opt into the reviewed libsodium implementation and must provide it.
set(ASTROLUNE_CRYPTO_BACKEND "dev" CACHE STRING
    "Signature backend: dev|sodium")
set_property(CACHE ASTROLUNE_CRYPTO_BACKEND PROPERTY STRINGS dev sodium)

set(ASTROLUNE_SANITIZER "none" CACHE STRING
    "Sanitizer to enable: none|address|undefined|address+undefined|thread|memory")
set_property(CACHE ASTROLUNE_SANITIZER PROPERTY STRINGS
    none address undefined address+undefined thread memory)

# The VM interpreter dispatch strategy. `auto` picks computed goto where the
# compiler supports the labels-as-values extension (GCC/Clang) and a switch
# otherwise (MSVC). Forcing `switch` is useful when profiling.
set(ASTROLUNE_VM_DISPATCH "auto" CACHE STRING "VM dispatch: auto|goto|switch")
set_property(CACHE ASTROLUNE_VM_DISPATCH PROPERTY STRINGS auto goto switch)

# --- Derived / reported state ------------------------------------------------

if(ASTROLUNE_UNITY)
  set(CMAKE_UNITY_BUILD ON)
  # 8 translation units per batch keeps peak memory low enough for a 4 GB box
  # while still cutting most of the per-file compiler startup cost.
  set(CMAKE_UNITY_BUILD_BATCH_SIZE 8)
endif()

function(astrolune_report_configuration)
  message(STATUS "")
  message(STATUS "Astrolune ${PROJECT_VERSION}")
  message(STATUS "  build type      : ${CMAKE_BUILD_TYPE}")
  message(STATUS "  C compiler      : ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
  message(STATUS "  C++ compiler    : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
  message(STATUS "  core / node     : ${ASTROLUNE_BUILD_CORE} / ${ASTROLUNE_BUILD_NODE}")
  message(STATUS "  tools           : ${ASTROLUNE_BUILD_TOOLS}")
  message(STATUS "  apps / tests    : ${ASTROLUNE_BUILD_APPS} / ${ASTROLUNE_BUILD_TESTS}")
  message(STATUS "  vm dispatch     : ${ASTROLUNE_VM_DISPATCH}")
  message(STATUS "  crypto backend  : ${ASTROLUNE_CRYPTO_BACKEND}")
  message(STATUS "  sanitizer       : ${ASTROLUNE_SANITIZER}")
  message(STATUS "  lto / unity     : ${ASTROLUNE_LTO} / ${ASTROLUNE_UNITY}")
  message(STATUS "")
endfunction()
