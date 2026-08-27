# Helpers that give every Astrolune target the same shape.
#
#   astrolune_add_core_library()  - a C23 static library
#   astrolune_add_tool_library()  - a C++23 static library in the tooling tree
#   astrolune_add_executable()    - an executable
#   astrolune_add_test()          - an executable registered with CTest
#
# Keeping the boilerplate here is what makes the per-directory CMakeLists files
# short, and it guarantees that no core library accidentally picks up a C++
# dependency.

include_guard(GLOBAL)

# Common properties for anything we build.
function(_astrolune_common_setup target)
  target_link_libraries(${target} PRIVATE
      Astrolune::warnings
      Astrolune::sanitizers
  )
  target_link_libraries(${target} PUBLIC Astrolune::std)

  set_target_properties(${target} PROPERTIES
      POSITION_INDEPENDENT_CODE ON
      # Keep build artefacts out of the source tree and in one predictable place
      # so `cmake --build` output is easy to find and easy to clean.
      ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )
endfunction()

# A static library that is part of the C consensus core.
#
#   astrolune_add_core_library(al_vm SOURCES vm.c gas.c DEPS al_base al_crypto)
function(astrolune_add_core_library name)
  cmake_parse_arguments(ARG "" "" "SOURCES;DEPS;PRIVATE_DEPS" ${ARGN})

  add_library(${name} STATIC ${ARG_SOURCES})
  add_library(Astrolune::${name} ALIAS ${name})

  target_include_directories(${name}
      PUBLIC  "${PROJECT_SOURCE_DIR}/include"
      PRIVATE "${PROJECT_SOURCE_DIR}/src"
  )
  target_link_libraries(${name} PUBLIC ${ARG_DEPS})
  if(ARG_PRIVATE_DEPS)
    target_link_libraries(${name} PRIVATE ${ARG_PRIVATE_DEPS})
  endif()

  # The core is C only. Enforce it here rather than discovering a stray .cpp
  # three months later when someone tries to build for an embedded target.
  set_target_properties(${name} PROPERTIES
      C_STANDARD ${CMAKE_C_STANDARD}
      LINKER_LANGUAGE C
  )
  _astrolune_common_setup(${name})
endfunction()

# A static library in the C++23 tooling tree (compilers, SDK).
function(astrolune_add_tool_library name)
  cmake_parse_arguments(ARG "" "" "SOURCES;DEPS;PRIVATE_DEPS" ${ARGN})

  add_library(${name} STATIC ${ARG_SOURCES})
  add_library(Astrolune::${name} ALIAS ${name})

  target_include_directories(${name}
      PUBLIC  "${PROJECT_SOURCE_DIR}/include"
              "${PROJECT_SOURCE_DIR}/tools/include"
      PRIVATE "${PROJECT_SOURCE_DIR}/tools"
  )
  target_link_libraries(${name} PUBLIC ${ARG_DEPS})
  if(ARG_PRIVATE_DEPS)
    target_link_libraries(${name} PRIVATE ${ARG_PRIVATE_DEPS})
  endif()

  set_target_properties(${name} PROPERTIES
      CXX_STANDARD ${CMAKE_CXX_STANDARD}
      LINKER_LANGUAGE CXX
  )
  if(MSVC)
    # The tooling uses std::string/iostream freely; MSVC needs /EHsc for the
    # C++ runtime to behave, and warnings-as-errors stays consistent with the
    # core's strictness.
    target_compile_options(${name} PRIVATE "/EHsc")
  endif()
  _astrolune_common_setup(${name})
endfunction()

# An executable. `LANG` selects which include/standard set it gets.
function(astrolune_add_executable name)
  cmake_parse_arguments(ARG "" "LANG" "SOURCES;DEPS" ${ARGN})
  if(NOT ARG_LANG)
    set(ARG_LANG C)
  endif()

  add_executable(${name} ${ARG_SOURCES})
  target_include_directories(${name} PRIVATE
      "${PROJECT_SOURCE_DIR}/include"
      "${PROJECT_SOURCE_DIR}/tools/include"
  )
  target_link_libraries(${name} PRIVATE ${ARG_DEPS})
  set_target_properties(${name} PROPERTIES LINKER_LANGUAGE ${ARG_LANG})
  if(MSVC AND ARG_LANG STREQUAL "CXX")
    target_compile_options(${name} PRIVATE "/EHsc")
  endif()
  _astrolune_common_setup(${name})
endfunction()

# A test executable, registered with CTest.
function(astrolune_add_test name)
  cmake_parse_arguments(ARG "" "LANG" "SOURCES;DEPS" ${ARGN})
  if(NOT ARG_LANG)
    set(ARG_LANG C)
  endif()

  add_executable(${name} ${ARG_SOURCES})
  target_include_directories(${name} PRIVATE
      "${PROJECT_SOURCE_DIR}/include"
      "${PROJECT_SOURCE_DIR}/tests"
  )
  if(ARG_LANG STREQUAL "CXX")
    target_include_directories(${name} PRIVATE
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_SOURCE_DIR}/tools/include")
  else()
    target_include_directories(${name} PRIVATE "${PROJECT_SOURCE_DIR}/src")
  endif()
  target_link_libraries(${name} PRIVATE ${ARG_DEPS})
  set_target_properties(${name} PROPERTIES LINKER_LANGUAGE ${ARG_LANG})
  if(MSVC AND ARG_LANG STREQUAL "CXX")
    target_compile_options(${name} PRIVATE "/EHsc")
  endif()
  _astrolune_common_setup(${name})

  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES TIMEOUT 120)
endfunction()
