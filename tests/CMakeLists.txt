# The test suite.
#
# One executable per subject rather than one binary for everything. CTest can
# then run them in parallel, a failure names the area rather than a line number,
# and rebuilding after touching the VM does not relink the crypto tests.

astrolune_add_test(test_arena  SOURCES c/test_arena.c  DEPS al_base)
astrolune_add_test(test_bytes  SOURCES c/test_bytes.c  DEPS al_base)
astrolune_add_test(test_fixed  SOURCES c/test_fixed.c  DEPS al_base)
astrolune_add_test(test_resource SOURCES c/test_resource.c DEPS al_base)
astrolune_add_test(test_hash   SOURCES c/test_hash.c   DEPS al_crypto)
astrolune_add_test(test_merkle SOURCES c/test_merkle.c DEPS al_crypto)
astrolune_add_test(test_crypto SOURCES c/test_crypto.c DEPS al_crypto)
astrolune_add_test(test_signer SOURCES c/test_signer.c DEPS al_crypto)
astrolune_add_test(test_potb   SOURCES c/test_potb.c   DEPS al_potb)
astrolune_add_test(test_consensus SOURCES c/test_consensus.c DEPS al_potb)
astrolune_add_test(test_adversarial SOURCES c/test_adversarial.c DEPS al_potb)
astrolune_add_test(test_evidence_e2e SOURCES c/test_evidence_e2e.c DEPS al_tx al_potb al_state)
astrolune_add_test(test_cpp_headers LANG CXX SOURCES c/test_cpp_headers.cpp DEPS astrolune_core)
astrolune_add_test(test_vm    SOURCES c/test_vm.c    DEPS al_vm al_crypto al_state)
astrolune_add_test(test_state SOURCES c/test_state.c DEPS al_state)
astrolune_add_test(test_tx    SOURCES c/test_tx.c    DEPS al_tx al_vm al_potb al_block)
astrolune_add_test(test_block SOURCES c/test_block.c DEPS al_block)
if(TARGET al_node)
  astrolune_add_test(test_node SOURCES c/test_node.c DEPS al_node)
  astrolune_add_test(test_contract_flow SOURCES c/test_contract_flow.c DEPS al_node al_vm)
endif()
if(TARGET al_net)
  astrolune_add_test(test_net SOURCES c/test_net.c DEPS al_net)
endif()
if(TARGET al_rpc)
  astrolune_add_test(test_rpc SOURCES c/test_rpc.c DEPS al_rpc)
endif()
if(TARGET al_daemon)
  astrolune_add_test(test_signing_journal
      SOURCES c/test_signing_journal.c DEPS al_daemon)
  astrolune_add_test(test_config
      SOURCES c/test_config.c DEPS al_base)
endif()
if(TARGET trocto)
  astrolune_add_test(test_lang LANG CXX
      SOURCES cxx/test_lang.cpp DEPS trocto al_vm al_crypto al_node al_tx)
endif()

astrolune_add_executable(determinism_fixture
    SOURCES c/determinism_fixture.c
    DEPS al_block
)
