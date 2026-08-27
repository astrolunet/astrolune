#include "astrolune/vm.h"
#include "fuzz_input.h"

int LLVMFuzzerTestOneInput(const al_u8 *data, al_size size) {
    al_u8 *allocation;
    al_size normalized_size;
    data = fuzz_normalize(data, size, &normalized_size, &allocation);
    al_arena arena;
    if (al_arena_init(&arena, 0u) == AL_OK) {
        (void)al_vm_validate(al_bytes_make(data, normalized_size), NULL, &arena);
        al_arena_destroy(&arena);
    }
    free(allocation);
    return 0;
}
