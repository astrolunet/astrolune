#include "astrolune/tx.h"
#include "fuzz_input.h"

int LLVMFuzzerTestOneInput(const al_u8 *data, al_size size) {
    al_u8 *allocation;
    al_size normalized_size;
    data = fuzz_normalize(data, size, &normalized_size, &allocation);
    al_transaction transaction;
    al_status tx_status = al_tx_decode(
        al_bytes_make(data, normalized_size), &transaction);
    (void)tx_status;
    al_event event;
    al_status event_status = al_event_decode(
        al_bytes_make(data, normalized_size), &event);
    (void)event_status;
    al_arena arena;
    if (al_arena_init(&arena, 0u) == AL_OK) {
        al_receipt receipt;
        al_status receipt_status = al_receipt_decode(
            al_bytes_make(data, normalized_size), &arena, &receipt);
        (void)receipt_status;
        al_arena_destroy(&arena);
    }
    free(allocation);
    return 0;
}
