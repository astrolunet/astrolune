#include "astrolune/state.h"
#include "fuzz_input.h"

int LLVMFuzzerTestOneInput(const al_u8 *data, al_size size) {
    al_u8 *allocation;
    al_size normalized_size;
    data = fuzz_normalize(data, size, &normalized_size, &allocation);
    al_hash256 siblings[AL_STATE_TREE_DEPTH];
    al_smt_proof proof;
    (void)al_smt_proof_decode(al_bytes_make(data, normalized_size), siblings,
                              AL_COUNTOF(siblings), &proof);
    free(allocation);
    return 0;
}
