# Warning configuration.
#
# Consensus code is held to a stricter standard than tooling: a warning in the
# VM or the scoring math can mean a chain split, so the core opts into the
# pedantic set. The tooling gets the same base warnings minus the ones that
# fight idiomatic modern C++.

include_guard(GLOBAL)

add_library(astrolune_warnings INTERFACE)
add_library(Astrolune::warnings ALIAS astrolune_warnings)

if(MSVC)
  target_compile_options(astrolune_warnings INTERFACE
      /W4
      /w14242  # lossy conversion
      /w14254  # lossy bitfield conversion
      /w14263  # member function does not override
      /w14265  # non-virtual destructor
      /w14287  # unsigned/negative constant mismatch
      /w14296  # expression always true/false
      /w14311  # pointer truncation
      /w14545  # malformed comma expression
      /w14546  # call missing argument list
      /w14547  # operator with no effect
      /w14549  # operator before comma has no effect
      /w14555  # expression has no effect
      /w14619  # unknown #pragma warning
      /w14640  # non-thread-safe static init
      /w14826  # sign-extending conversion
      /w14905  # wide string literal cast
      /w14906  # string literal cast
      /w14928  # illegal copy-initialisation
      # Silenced deliberately:
      /wd4200  # zero-sized array in struct: used intentionally for flexible
               # array members in the bytecode and state structures.
  )
else()
  target_compile_options(astrolune_warnings INTERFACE
      -Wall
      -Wextra
      -Wpedantic
      -Wshadow
      -Wconversion
      -Wsign-conversion
      -Wcast-qual
      -Wcast-align
      -Wdouble-promotion
      -Wformat=2
      -Wundef
      -Wwrite-strings
      -Wpointer-arith
      -Wswitch-enum
      -Wvla
      $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes>
      $<$<COMPILE_LANGUAGE:C>:-Wmissing-prototypes>
      $<$<COMPILE_LANGUAGE:C>:-Wbad-function-cast>
      $<$<COMPILE_LANGUAGE:C>:-Wnested-externs>
      $<$<COMPILE_LANGUAGE:CXX>:-Wnon-virtual-dtor>
      $<$<COMPILE_LANGUAGE:CXX>:-Woverloaded-virtual>
      $<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>
  )
  if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(astrolune_warnings INTERFACE
        -Wlogical-op
        -Wduplicated-cond
        -Wduplicated-branches
        $<$<COMPILE_LANGUAGE:C>:-Wjump-misses-init>
    )
  endif()
endif()

if(ASTROLUNE_WERROR)
  if(MSVC)
    target_compile_options(astrolune_warnings INTERFACE /WX)
  else()
    target_compile_options(astrolune_warnings INTERFACE -Werror)
  endif()
endif()
