/*
 * Regenerate the block/genesis fuzz corpus.
 *
 * The golden inputs here must decode successfully, so every change to the
 * canonical genesis encoding requires regenerating them. Run:
 *
 *     gen_block_genesis_corpus <output.hex>
 *
 * which writes a "hex:"-prefixed corpus entry containing one canonical
 * genesis (selector byte 0x01, empty allocation table).
 */

#include "astrolune/block.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        (void)fprintf(stderr, "usage: %s <output.hex>\n", argv[0]);
        return 2;
    }

    al_genesis genesis;
    memset(&genesis, 0, sizeof(genesis));
    genesis.version = AL_GENESIS_VERSION;
    genesis.chain_id = 0x41535452u; /* "ASTR" */
    genesis.initial_state_root = al_hash_zero();
    al_resources limit = { 1000000u, 1000000u, 1000000u, 1000000u };
    genesis.fees.block_limit = limit;
    al_resources target = { 500000u, 500000u, 500000u, 500000u };
    genesis.fees.target = target;
    al_resources price = { 1u, 1u, 1u, 1u };
    genesis.fees.initial_base_price = price;
    genesis.fees.storage_deposit_per_byte = 2u;
    genesis.schedule = al_vm_resource_schedule_default();
    genesis.vm_stack_limit = AL_VM_DEFAULT_STACK;
    genesis.vm_memory_limit = AL_VM_DEFAULT_MEMORY;
    genesis.vm_call_depth_limit = AL_VM_DEFAULT_CALL_DEPTH;
    genesis.potb = al_potb_params_default();

    /* Selector byte 0x01: the fuzzer treats the remainder as a genesis. */
    al_u8 entry[1 + 4096];
    entry[0] = 1u;
    al_size encoded_size = 0u;
    al_status status =
        al_genesis_encode(&genesis,
                          (al_bytes_mut){ entry + 1u, sizeof(entry) - 1u },
                          &encoded_size);
    if (status != AL_OK) {
        (void)fprintf(stderr, "error: encode failed: %s\n",
                      al_status_str(status));
        return 1;
    }

    FILE *out = fopen(argv[1], "wb");
    if (out == NULL) return 1;
    (void)fprintf(out, "hex:");
    for (al_size i = 0u; i < encoded_size + 1u; ++i) {
        (void)fprintf(out, "%02x", entry[i]);
    }
    (void)fprintf(out, "\n");
    (void)fclose(out);
    return 0;
}
