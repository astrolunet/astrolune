function(astrolune_add_fuzzer name source dependency corpus)
  astrolune_add_executable(${name}
      SOURCES ${source}
      DEPS ${dependency}
  )
  target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  if(ASTROLUNE_LIBFUZZER)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
      message(FATAL_ERROR "ASTROLUNE_LIBFUZZER requires Clang")
    endif()
    target_compile_definitions(${name} PRIVATE AL_LIBFUZZER=1)
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
  elseif(ASTROLUNE_BUILD_TESTS)
    add_test(NAME ${name}_corpus
             COMMAND ${name} "${CMAKE_CURRENT_SOURCE_DIR}/${corpus}")
    set_tests_properties(${name}_corpus PROPERTIES TIMEOUT 30)
  endif()
endfunction()

astrolune_add_fuzzer(fuzz_tx fuzz_tx.c al_tx corpus/tx/golden.hex)
astrolune_add_fuzzer(fuzz_alvm fuzz_alvm.c al_vm corpus/alvm/golden.hex)
astrolune_add_fuzzer(fuzz_block_genesis fuzz_block_genesis.c al_block
                     corpus/block_genesis/golden_block.hex)
astrolune_add_fuzzer(fuzz_smt_proof fuzz_smt_proof.c al_state
                     corpus/smt_proof/golden_absence.hex)

# Corpus maintenance: the golden genesis entry must always decode cleanly, so
# regenerating it after an encoding change is a first-class target.
astrolune_add_executable(gen_block_genesis_corpus
    SOURCES gen_block_genesis_corpus.c
    DEPS al_block
)
