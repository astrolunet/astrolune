#include "astrolune/block.h"
#include "fuzz_input.h"

int LLVMFuzzerTestOneInput(const al_u8 *data, al_size size) {
    al_u8 *allocation;
    al_size normalized_size;
    data = fuzz_normalize(data, size, &normalized_size, &allocation);
    if (normalized_size != 0u) {
        al_bytes encoded = al_bytes_make(data + 1u, normalized_size - 1u);
        if (data[0] == 0u) {
            al_transaction transactions[64];
            al_block block;
            (void)al_block_decode(encoded, transactions,
                                  AL_COUNTOF(transactions), &block);
        } else {
            al_genesis genesis;
            al_genesis_allocation allocations[AL_GENESIS_MAX_ALLOCATIONS];
            (void)al_genesis_decode(encoded, allocations,
                                    AL_COUNTOF(allocations), &genesis);
        }
    }
    free(allocation);
    return 0;
}
