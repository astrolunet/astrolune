# The C++23 tooling tree: the Trocto/Regol contract-language compiler.

# The compiler links the core for container encoding, tagged hashing and
# authoritative validation - it must agree with the node byte-for-byte.
astrolune_add_tool_library(trocto
    SOURCES
        trocto/src/lexer.cpp
        trocto/src/encoder.cpp
        trocto/src/regol.cpp
        trocto/src/parser.cpp
        trocto/src/lower.cpp
        trocto/src/trocto.cpp
    DEPS Astrolune::core
)
target_include_directories(trocto PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/trocto/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/trocto/src"
)

astrolune_add_executable(trocto_cli
    LANG CXX
    SOURCES trocto/apps/trocto/main.cpp
    DEPS trocto
)
set_target_properties(trocto_cli PROPERTIES OUTPUT_NAME trocto)
