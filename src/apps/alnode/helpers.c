/*
 * alnode_helpers.c — shared utility functions for the alnode CLI.
 */

#include "alnode.h"
#include "random.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Calldata encoding                                                   */
/* ------------------------------------------------------------------ */

void store_le64_local(al_u8 *p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) {
        p[i] = (al_u8)((v >> (i * 8)) & 0xffu);
    }
}

/* ------------------------------------------------------------------ */
/* Reporting                                                           */
/* ------------------------------------------------------------------ */

int report_status(const char *operation, al_status status) {
    (void)fprintf(stderr, "alnode: %s: %s\n", operation,
                  al_status_str(status));
    return 1;
}

void warn_insecure_crypto(void) {
    if (!al_crypto_is_secure()) {
        (void)fprintf(stderr,
                      "warning: cryptographic backend '%s' is not "
                      "production-safe\n",
                      al_crypto_backend_name());
    }
}

/* ------------------------------------------------------------------ */
/* Parsing helpers                                                     */
/* ------------------------------------------------------------------ */

al_status parse_chain_id(const char *text, al_u32 *out) {
    if (text == NULL || out == NULL || text[0] == '\0') {
        return AL_ERR_INVALID_ARG;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0u ||
        value > UINT32_MAX) {
        return AL_ERR_OUT_OF_RANGE;
    }
    *out = (al_u32)value;
    return AL_OK;
}

al_status parse_u64_arg(const char *text, uint64_t *out) {
    if (text == NULL || out == NULL || text[0] == '\0') {
        return AL_ERR_INVALID_ARG;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return AL_ERR_OUT_OF_RANGE;
    }
    *out = (uint64_t)value;
    return AL_OK;
}

al_status parse_address_text(const char *text, al_address *out) {
    if (text == NULL) return AL_ERR_INVALID_ARG;
    if (strncmp(text, "al1", 3) == 0) {
        return al_address_from_bech32(text, out);
    }
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2u;
    char buffer[AL_ADDRESS_SIZE * 2u + 1u];
    if (strlen(text) != AL_ADDRESS_SIZE * 2u) return AL_ERR_INVALID_ARG;
    memcpy(buffer, text, AL_ADDRESS_SIZE * 2u);
    buffer[AL_ADDRESS_SIZE * 2u] = '\0';
    return al_hex_decode(buffer, out->bytes, sizeof(out->bytes), NULL);
}

/* ------------------------------------------------------------------ */
/* Key management                                                      */
/* ------------------------------------------------------------------ */

int command_keygen(const char *seed_text) {
    al_keypair keypair;
    if (seed_text != NULL) {
        al_u8 seed[32];
        if (strlen(seed_text) != 64u ||
            al_hex_decode(seed_text, seed, sizeof(seed), NULL) != AL_OK) {
            return report_status("invalid seed", AL_ERR_MALFORMED);
        }
        al_status status = al_keypair_from_seed(seed, &keypair);
        if (status != AL_OK) return report_status("derive key", status);
        al_secure_zero(seed, sizeof(seed));
        (void)printf("seed %s\n", seed_text);
    } else {
        if (!al_net_init()) {
            return report_status("open entropy source", AL_ERR_IO);
        }
        al_u8 seed[32];
        if (!os_random_bytes(seed, sizeof(seed))) {
            return report_status("read entropy", AL_ERR_IO);
        }
        al_status status = al_keypair_from_seed(seed, &keypair);
        if (status != AL_OK) return report_status("derive key", status);
        char seed_hex[65];
        status = al_hex_encode(al_bytes_make(seed, sizeof(seed)), seed_hex,
                               sizeof(seed_hex));
        al_secure_zero(seed, sizeof(seed));
        if (status != AL_OK) return report_status("encode seed", status);
        (void)printf("seed %s\n", seed_hex);
    }

    al_address address;
    al_address_from_pubkey(&keypair.pk, &address);
    char public_hex[AL_PUBKEY_SIZE * 2u + 1u];
    al_status status = al_hex_encode(
        al_bytes_make(keypair.pk.bytes, AL_PUBKEY_SIZE), public_hex,
        sizeof(public_hex));
    if (status != AL_OK) return report_status("encode public key", status);
    (void)printf("public_key %s\n", public_hex);
    char text[AL_ADDRESS_TEXT_SIZE];
    if (al_address_to_bech32(&address, text, sizeof(text)) == AL_OK) {
        (void)printf("address %s\n", text);
    } else {
        char address_hex[AL_ADDRESS_HEX_SIZE];
        al_address_to_hex(&address, address_hex);
        (void)printf("address 0x%s\n", address_hex);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* File I/O                                                            */
/* ------------------------------------------------------------------ */

al_status write_file(const char *path, al_bytes bytes) {
    FILE *file = fopen(path, "wb");
    if (file == NULL) return AL_ERR_IO;
    al_size written = fwrite(bytes.data, 1u, bytes.len, file);
    int close_status = fclose(file);
    return written == bytes.len && close_status == 0 ? AL_OK : AL_ERR_IO;
}

al_status read_file(const char *path, al_u8 **data_out, al_size *size_out) {
    if (path == NULL || data_out == NULL || size_out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    *data_out = NULL;
    *size_out = 0u;

    FILE *file = fopen(path, "rb");
    if (file == NULL) return AL_ERR_NOT_FOUND;
    if (fseek(file, 0, SEEK_END) != 0) {
        (void)fclose(file);
        return AL_ERR_IO;
    }
    long length = ftell(file);
    if (length <= 0 || (unsigned long)length > ALNODE_MAX_INPUT_SIZE ||
        fseek(file, 0, SEEK_SET) != 0) {
        (void)fclose(file);
        return length > 0 ? AL_ERR_OUT_OF_RANGE : AL_ERR_IO;
    }

    al_u8 *data = (al_u8 *)malloc((al_size)length);
    if (data == NULL) {
        (void)fclose(file);
        return AL_ERR_OUT_OF_MEMORY;
    }
    al_size size = fread(data, 1u, (al_size)length, file);
    int close_status = fclose(file);
    if (size != (al_size)length || close_status != 0) {
        free(data);
        return AL_ERR_IO;
    }
    *data_out = data;
    *size_out = size;
    return AL_OK;
}

/* ------------------------------------------------------------------ */
/* Runtime lifecycle                                                   */
/* ------------------------------------------------------------------ */

static al_status runtime_open_memory(alnode_runtime *runtime,
                                     al_amount deposit_per_byte) {
    runtime->nodes = (al_state_memory_node *)calloc(
        ALNODE_STATE_NODE_CAPACITY, sizeof(*runtime->nodes));
    runtime->values = (al_state_memory_value *)calloc(
        ALNODE_STATE_VALUE_CAPACITY, sizeof(*runtime->values));
    if (runtime->nodes == NULL || runtime->values == NULL) {
        return AL_ERR_OUT_OF_MEMORY;
    }

    al_status status = al_arena_init(&runtime->arena, 1024u * 1024u);
    if (status == AL_OK) {
        status = al_state_memory_store_init(
            &runtime->memory, runtime->nodes, ALNODE_STATE_NODE_CAPACITY,
            runtime->values, ALNODE_STATE_VALUE_CAPACITY, &runtime->arena);
    }
    if (status == AL_OK) {
        runtime->store =
            al_state_memory_store_interface(&runtime->memory);
        status = al_state_init(&runtime->state, &runtime->store,
                               &runtime->arena, deposit_per_byte);
    }
    if (status == AL_OK) return AL_OK;

    al_arena_destroy(&runtime->arena);
    free(runtime->nodes);
    free(runtime->values);
    runtime->nodes = NULL;
    runtime->values = NULL;
    return status;
}

static al_status runtime_open_durable(alnode_runtime *runtime,
                                      const char *directory) {
    al_status status = al_arena_init(&runtime->arena, 1024u * 1024u);
    if (status == AL_OK) {
        status = al_node_storage_open(&runtime->storage, directory,
                                      &runtime->genesis);
    }
    if (status == AL_OK) {
        status = al_node_storage_prepare_genesis(&runtime->storage,
                                                 &runtime->genesis,
                                                 &runtime->arena);
    }
    if (status == AL_OK) {
        runtime->store = al_node_storage_state_store(&runtime->storage);
        al_state_snapshot snapshot;
        status = al_node_storage_state_snapshot(&runtime->storage,
                                                &snapshot);
        if (status == AL_OK) {
            status = al_state_open(
                &runtime->state, &runtime->store, &runtime->arena,
                runtime->genesis.fees.storage_deposit_per_byte,
                snapshot.height, &snapshot.root);
        }
    }
    if (status != AL_OK) {
        al_node_storage_close(&runtime->storage);
        al_arena_destroy(&runtime->arena);
        return status;
    }
    runtime->durable = AL_TRUE;
    return AL_OK;
}

void runtime_destroy(alnode_runtime *runtime) {
    if (runtime == NULL) return;
    al_arena_destroy(&runtime->execution_arena);
    free(runtime->transactions);
    free(runtime->receipts);
    al_node_storage_close(&runtime->storage);
    al_arena_destroy(&runtime->arena);
    free(runtime->nodes);
    free(runtime->values);
    memset(runtime, 0, sizeof(*runtime));
}

al_status runtime_open(alnode_runtime *runtime, const char *genesis_path,
                       const char *data_directory) {
    memset(runtime, 0, sizeof(*runtime));

    al_u8 *genesis_bytes = NULL;
    al_size genesis_size = 0u;
    const al_block_header *head = NULL;
    al_status status = read_file(genesis_path, &genesis_bytes,
                                 &genesis_size);
    if (status == AL_OK) {
        status = al_genesis_decode(
            al_bytes_make(genesis_bytes, genesis_size), runtime->allocations,
            AL_COUNTOF(runtime->allocations), &runtime->genesis);
    }
    free(genesis_bytes);
    if (status != AL_OK) return status;

    status = data_directory == NULL
                 ? runtime_open_memory(
                       runtime,
                       runtime->genesis.fees.storage_deposit_per_byte)
                 : runtime_open_durable(runtime, data_directory);
    if (status != AL_OK) goto fail;
    if (!runtime->durable &&
        !al_hash_eq(&runtime->state.root,
                    &runtime->genesis.initial_state_root)) {
        status = AL_ERR_UNSUPPORTED;
        goto fail;
    }

    runtime->transactions = (al_transaction *)calloc(
        AL_BLOCK_MAX_TRANSACTIONS, sizeof(*runtime->transactions));
    runtime->receipts = (al_receipt *)calloc(AL_BLOCK_MAX_TRANSACTIONS,
                                             sizeof(*runtime->receipts));
    if (runtime->transactions == NULL || runtime->receipts == NULL) {
        status = AL_ERR_OUT_OF_MEMORY;
        goto fail;
    }

    status = al_arena_init(&runtime->execution_arena, 1024u * 1024u);
    if (status != AL_OK) goto fail;

    al_node_buffers buffers;
    memset(&buffers, 0, sizeof(buffers));
    buffers.block_transactions = runtime->transactions;
    buffers.block_transaction_capacity = AL_BLOCK_MAX_TRANSACTIONS;
    buffers.receipts = runtime->receipts;
    buffers.receipt_capacity = AL_BLOCK_MAX_TRANSACTIONS;
    head = runtime->durable ? al_node_storage_head(&runtime->storage) : NULL;
    status = al_node_open(&runtime->node, &runtime->genesis,
                          &runtime->state, &runtime->execution_arena,
                          buffers, head);
    if (status != AL_OK) goto fail;
    return AL_OK;

fail:
    runtime_destroy(runtime);
    return status;
}
