/*
 * The boundary check's entry point.
 *
 * Why an executable at all? Because the interesting half of the check is the
 * link. A static library would archive the objects and never resolve a symbol,
 * so a header missing AL_EXTERN_C_BEGIN would sail through. An executable has to
 * bind every relocation in boundary_symbols.cpp against the core libraries,
 * and that is the check. main() exists to give the linker a reason to do its
 * job.
 *
 * Running it is optional - the build succeeding is the result. What it prints is
 * the pinned surface, in a form a reader can compare against
 * docs/08-implementation/core-api.md without recompiling anything.
 */

#include <cstdio>

#include "boundary.hpp"

#include "astrolune/arena.h"
#include "astrolune/base.h"
#include "astrolune/block.h"
#include "astrolune/bytes.h"
#include "astrolune/crypto.h"
#include "astrolune/fixed.h"
#include "astrolune/hash.h"
#include "astrolune/potb.h"
#include "astrolune/state.h"
#include "astrolune/tx.h"
#include "astrolune/vm.h"

namespace {

void report_line(const char *what, al_size value)
{
    std::printf("  %-28s %8zu\n", what, value);
}

}  /* namespace */

int main(void)
{
    std::printf("astrolune C/C++ boundary - %s\n\n", al_version_string());

    std::printf("public functions reachable from C++ with C linkage: %zu\n",
                al_abi_symbol_count);

    /* Defensive rather than meaningful: a null here would mean the compiler
     * folded away an address-of, which no implementation does. Cheap to check,
     * and it keeps the table referenced at runtime as well as at link time. */
    al_size null_entries = 0;
    for (al_size i = 0; i < al_abi_symbol_count; ++i) {
        if (al_abi_symbols[i] == nullptr) {
            ++null_entries;
        }
    }
    if (null_entries != 0) {
        std::printf("FAIL: %zu null entries in the symbol table\n",
                    null_entries);
        return 1;
    }

    std::printf("\npinned sizes (identical in C and C++, asserted in both)\n");
    report_line("al_hash256", sizeof(al_hash256));
    report_line("al_address", sizeof(al_address));
    report_line("al_pubkey", sizeof(al_pubkey));
    report_line("al_seckey", sizeof(al_seckey));
    report_line("al_sig", sizeof(al_sig));
    report_line("al_vrf_proof", sizeof(al_vrf_proof));
    report_line("al_fixed", sizeof(al_fixed));
    report_line("al_bytes", sizeof(al_bytes));
    report_line("al_reader", sizeof(al_reader));
    report_line("al_writer", sizeof(al_writer));
    report_line("al_arena", sizeof(al_arena));
    report_line("al_sha256_ctx", sizeof(al_sha256_ctx));
    report_line("al_hmac_ctx", sizeof(al_hmac_ctx));
    report_line("al_potb_params", sizeof(al_potb_params));
    report_line("al_potb_record", sizeof(al_potb_record));
    report_line("al_potb_weight", sizeof(al_potb_weight));
    report_line("al_potb_committee", sizeof(al_potb_committee));
    report_line("al_block_header", sizeof(al_block_header));
    report_line("al_genesis", sizeof(al_genesis));
    report_line("al_account", sizeof(al_account));
    report_line("al_state", sizeof(al_state));
    report_line("al_state_txn", sizeof(al_state_txn));
    report_line("al_transaction", sizeof(al_transaction));
    report_line("al_receipt", sizeof(al_receipt));
    report_line("al_vm_config", sizeof(al_vm_config));
    report_line("al_vm_execution_context", sizeof(al_vm_execution_context));
    report_line("al_vm_result", sizeof(al_vm_result));

    /*
     * Two calls across the boundary, so the report is evidence that the ABI
     * works and not only that it links. al_status_str returns a pointer into
     * static storage and al_crypto_backend_name is the same shape - both are C
     * functions returning C strings to a C++ caller.
     */
    std::printf("\nlive calls into the C core\n");
    std::printf("  al_status_str(AL_OK)         %s\n", al_status_str(AL_OK));
    std::printf("  al_status_str(NOT_CANONICAL) %s\n",
                al_status_str(AL_ERR_NOT_CANONICAL));
    std::printf("  al_crypto_backend_name()     %s\n",
                al_crypto_backend_name());

    /*
     * Reported, not asserted, and reported honestly. The development backend
     * verifies a signature by hashing the public key and the message, so any
     * key's signature can be forged. AL_FALSE is the correct answer here and
     * this program must never be the reason someone changes it - see
     * docs/02-architecture/cryptography.md section 3.
     */
    std::printf("  al_crypto_is_secure()        %s\n",
                al_crypto_is_secure() ? "AL_TRUE" : "AL_FALSE  (expected: the "
                "backend is an insecure development stub)");

    return 0;
}
