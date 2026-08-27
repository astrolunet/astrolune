# Locate libsodium without assuming a package manager or a CMake config file.
#
# Set Sodium_ROOT (or CMAKE_PREFIX_PATH) when libsodium is installed outside a
# standard prefix. The imported target keeps include and link details out of the
# core target and works with shared as well as static package-manager builds.

find_path(Sodium_INCLUDE_DIR
    NAMES sodium.h
    HINTS ${Sodium_ROOT} ENV Sodium_ROOT
    PATH_SUFFIXES include
)

find_library(Sodium_LIBRARY
    NAMES sodium libsodium
    HINTS ${Sodium_ROOT} ENV Sodium_ROOT
    PATH_SUFFIXES lib lib64
)

if(Sodium_INCLUDE_DIR AND EXISTS "${Sodium_INCLUDE_DIR}/sodium/version.h")
  file(STRINGS "${Sodium_INCLUDE_DIR}/sodium/version.h" _sodium_version_line
       REGEX "^[ \t]*#define[ \t]+SODIUM_VERSION_STRING[ \t]+\"[^\"]+\"")
  string(REGEX REPLACE
      ".*SODIUM_VERSION_STRING[ \t]+\"([^\"]+)\".*" "\\1"
      Sodium_VERSION "${_sodium_version_line}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium
    REQUIRED_VARS Sodium_LIBRARY Sodium_INCLUDE_DIR
    VERSION_VAR Sodium_VERSION
)

if(Sodium_FOUND AND NOT TARGET Sodium::Sodium)
  add_library(Sodium::Sodium UNKNOWN IMPORTED)
  set_target_properties(Sodium::Sodium PROPERTIES
      IMPORTED_LOCATION "${Sodium_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${Sodium_INCLUDE_DIR}"
  )
endif()

mark_as_advanced(Sodium_INCLUDE_DIR Sodium_LIBRARY)
