# The C++23 tooling tree: the Trocto/Regol contract-language compiler.

# The compiler links the core for container encoding, tagged hashing and
# authoritative validation - it must agree with the node byte-for-byte.
astrolune_add_tool_library(trocto
    SOURCES
        trocto/lexer.cpp
        trocto/encoder.cpp
        trocto/regol.cpp
        trocto/parser.cpp
        trocto/lower.cpp
        trocto/trocto.cpp
    DEPS Astrolune::core
)

astrolune_add_executable(trocto_cli
    LANG CXX
    SOURCES apps/trocto/main.cpp
    DEPS trocto
)
set_target_properties(trocto_cli PROPERTIES OUTPUT_NAME trocto)
