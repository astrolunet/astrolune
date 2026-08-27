# The C/C++ boundary check.
#
# One executable, three checks, none of them a runtime test:
#
#   compile   - each public header compiles as C++23, alone (header_*.cpp) and
#               alongside the others, twice (header_all.cpp)
#   layout    - abi_contract.h is compiled by contract_c.c as C and by
#               contract_cxx.cpp as C++, so every size, alignment and offset is
#               asserted against one set of literals from both languages
#   link      - boundary_symbols.cpp takes the address of all 221 public
#               functions, so a header that forgot AL_EXTERN_C_BEGIN becomes an
#               unresolved external instead of a review finding
#
# Not registered with CTest, and it has no assertions that can fail at runtime.
# The build succeeding is the result. Registering it would say the check runs when
# ctest runs, and it does not - it runs when the compiler and the linker run,
# which is strictly earlier and strictly harder to skip.
#
# It is an executable rather than a library for the same reason: archiving the
# objects into a static library would never resolve a symbol, and the link check
# would silently pass forever.

astrolune_add_executable(al_abi_boundary
    LANG CXX
    SOURCES
        # The layout contract, once per language. Editing one without the other
        # destroys the property the pair exists to establish.
        contract_c.c
        contract_cxx.cpp

        # One translation unit per public header. A header that fails to include
        # its own dependencies compiles fine in company and fails only here.
        header_base.cpp
        header_bytes.cpp
        header_arena.cpp
        header_fixed.cpp
        header_hash.cpp
        header_crypto.cpp
        header_potb.cpp
        header_block.cpp
        header_state.cpp
        header_tx.cpp
        header_vm.cpp

        # All eleven together, twice: macro collisions and include guards.
        header_all.cpp

        # The link check, and something for the linker to link.
        boundary_symbols.cpp
        boundary_main.cpp
    DEPS Astrolune::core
)

# The dist preset sets CMAKE_UNITY_BUILD, which would concatenate the sources
# above into a handful of translation units - collapsing every header_*.cpp into
# one file and making the standalone-header check equivalent to header_all.cpp.
# It would still compile, still link, and still report success, having stopped
# checking the thing it was written to check. That is the worst possible outcome
# for a tripwire, so unity is off here regardless of the preset.
set_target_properties(al_abi_boundary PROPERTIES UNITY_BUILD OFF)

astrolune_add_executable(al_abi_manifest_check
    LANG CXX
    SOURCES manifest_check.cpp
)
target_compile_definitions(al_abi_manifest_check PRIVATE
    AL_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)

# An ALL target makes omissions fail during every normal build, before a linker
# happens to expose them through a downstream consumer.
add_custom_target(al_abi_manifest ALL
    COMMAND $<TARGET_FILE:al_abi_manifest_check>
    DEPENDS al_abi_manifest_check
    VERBATIM
)
