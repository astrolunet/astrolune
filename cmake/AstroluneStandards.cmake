# Language standards for the mixed C / C++ build.
#
# Astrolune deliberately uses two languages with different rules:
#
#   * The core is C23. It is the code that runs on every node for every block,
#     so it stays free of hidden allocations, exceptions and vtables.
#   * The tooling is C++23. It runs once on a developer's machine, so richer
#     abstractions are worth the compile time.
#
# The two meet only at the public C ABI in `include/astrolune/`, which is
# compiled by both languages and therefore restricted to a portable subset
# (see docs/02-architecture/c-cpp-boundary.md).
#
# Portability note that shaped this file: MSVC reports `__STDC_VERSION__`
# 202312L but does not implement all of C23. Verified missing on MSVC 19.51:
# `nullptr`, `constexpr`, and enums with a fixed underlying type. The core
# therefore targets a portable C23 subset and routes the gaps through the
# compatibility macros in `include/astrolune/base.h`.

include_guard(GLOBAL)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED OFF)   # fall back rather than fail on old toolchains
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Always emit compile_commands.json: clangd, clang-tidy and the editor
# integrations all read it, and it costs nothing to produce.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(astrolune_std INTERFACE)
add_library(Astrolune::std ALIAS astrolune_std)

if(MSVC)
  target_compile_options(astrolune_std INTERFACE
      # Report the real __cplusplus value instead of the 199711L stub.
      /Zc:__cplusplus
      # Conformant preprocessor; required for __VA_OPT__ and predictable
      # macro expansion in the shared C/C++ headers.
      /Zc:preprocessor
      # Standard-conformant behaviour, minus the MSVC extensions.
      /permissive-
      # Source and execution charsets are UTF-8 on every platform.
      /utf-8
      # ISO volatile semantics. MSVC's default on x86/x64 gives volatile
      # accesses acquire/release semantics, which is a stronger guarantee than
      # the standard makes and hides missing-atomic bugs that then show up on
      # ARM64, where the default is already ISO.
      /volatile:iso
      # String literals are const, so writing through one fails to compile
      # instead of faulting at runtime.
      /Zc:strictStrings
      # C11/C17 atomics in C mode. MSVC gates <stdatomic.h> behind this flag and
      # otherwise hard-errors with "C atomic support is not enabled".
      $<$<COMPILE_LANGUAGE:C>:/experimental:c11atomics>
  )
  # MSVC keys the C++ standard off _MSVC_LANG; make the intent explicit.
  target_compile_definitions(astrolune_std INTERFACE
      _CRT_SECURE_NO_WARNINGS
      _CRT_NONSTDC_NO_WARNINGS
      NOMINMAX
      WIN32_LEAN_AND_MEAN
  )
else()
  target_compile_definitions(astrolune_std INTERFACE
      _POSIX_C_SOURCE=200809L
  )
endif()

# --- Optional codegen knobs --------------------------------------------------

if(ASTROLUNE_NATIVE_ARCH AND NOT MSVC)
  include(CheckCCompilerFlag)
  check_c_compiler_flag(-march=native ASTROLUNE_HAS_MARCH_NATIVE)
  if(ASTROLUNE_HAS_MARCH_NATIVE)
    target_compile_options(astrolune_std INTERFACE -march=native)
  endif()
endif()

if(ASTROLUNE_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ASTROLUNE_IPO_OK OUTPUT ASTROLUNE_IPO_ERR)
  if(ASTROLUNE_IPO_OK)
    # Release only: LTO roughly doubles link time, which is exactly what we do
    # not want in the edit/build/test loop.
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
  else()
    message(WARNING "LTO requested but unsupported: ${ASTROLUNE_IPO_ERR}")
  endif()
endif()
