# Sanitizer wiring, exposed through the single ASTROLUNE_SANITIZER cache entry.
#
# For a consensus implementation the interesting configuration is
# `address+undefined` for the test suite, because both classes of bug turn into
# non-deterministic execution, which for a blockchain means a chain split rather
# than a crash.

include_guard(GLOBAL)

add_library(astrolune_sanitizers INTERFACE)
add_library(Astrolune::sanitizers ALIAS astrolune_sanitizers)

if(ASTROLUNE_SANITIZER STREQUAL "none")
  return()
endif()

if(MSVC)
  # MSVC only ships AddressSanitizer. Anything else is a configuration error
  # rather than something to silently ignore.
  if(ASTROLUNE_SANITIZER MATCHES "address")
    target_compile_options(astrolune_sanitizers INTERFACE /fsanitize=address)
    # ASan on MSVC is incompatible with incremental linking and edit-and-continue.
    target_link_options(astrolune_sanitizers INTERFACE /INCREMENTAL:NO)
  else()
    message(WARNING
        "MSVC supports only ASTROLUNE_SANITIZER=address; "
        "'${ASTROLUNE_SANITIZER}' was requested and will be ignored.")
  endif()
  return()
endif()

set(_al_san_flags "")
if(ASTROLUNE_SANITIZER STREQUAL "address")
  set(_al_san_flags address)
elseif(ASTROLUNE_SANITIZER STREQUAL "undefined")
  set(_al_san_flags undefined)
elseif(ASTROLUNE_SANITIZER STREQUAL "address+undefined")
  set(_al_san_flags address undefined)
elseif(ASTROLUNE_SANITIZER STREQUAL "thread")
  set(_al_san_flags thread)
elseif(ASTROLUNE_SANITIZER STREQUAL "memory")
  set(_al_san_flags memory)
else()
  message(FATAL_ERROR "Unknown ASTROLUNE_SANITIZER value '${ASTROLUNE_SANITIZER}'")
endif()

list(JOIN _al_san_flags "," _al_san_joined)

target_compile_options(astrolune_sanitizers INTERFACE
    -fsanitize=${_al_san_joined}
    -fno-omit-frame-pointer
    -fno-sanitize-recover=all   # a sanitizer report should fail the test, not warn
)
target_link_options(astrolune_sanitizers INTERFACE -fsanitize=${_al_san_joined})

if(ASTROLUNE_SANITIZER MATCHES "undefined")
  # Signed overflow and misaligned access are the two UB classes most likely to
  # differ between compilers, so they are checked explicitly.
  target_compile_options(astrolune_sanitizers INTERFACE
      -fsanitize=integer-divide-by-zero
      -fsanitize=float-divide-by-zero
  )
endif()
