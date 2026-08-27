/*
 * alnode - the Astrolune command line.
 *
 * Offline commands operate on files and exit; `run` starts the networked
 * daemon that participates in gossip and serves RPC.
 */

#include "astrolune/block.h"
#include "astrolune/bytes.h"
#include "astrolune/crypto.h"
#include "astrolune/hash.h"
#include "astrolune/log.h"
#include "astrolune/state.h"

#include "config.h"
#include "daemon.h"
#include "net.h"
#include "node.h"
#include "random.h"
#include "storage.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Little-endian helpers for calldata packing; the canonical encoding is
 * little-endian everywhere (see astrolune/bytes.h). */
static uint64_t load_le64_local(const al_u8 *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static void store_le64_local(al_u8 *p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) {
        p[i] = (al_u8)((v >> (i * 8)) & 0xffu);
    }
}

#if defined(AL_OS_WINDOWS)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <signal.h>
#endif

#define ALNODE_MAX_INPUT_SIZE       (64u * 1024u * 1024u)
#define ALNODE_STATE_NODE_CAPACITY  262144u
#define ALNODE_STATE_VALUE_CAPACITY 16384u

/* Set by the console handler; the daemon polls it every tick. */
static volatile int g_stop_requested = 0;

#if defined(AL_OS_WINDOWS)
static BOOL WINAPI console_handler(DWORD event) {
    AL_UNUSED(event);
    g_stop_requested = 1;
    return TRUE;
}
#else
static void interrupt_handler(int signal_number) {
    (void)signal_number;
    g_stop_requested = 1;
}
#endif

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

typedef struct alnode_runtime {
    al_genesis genesis;
    /* Borrowed by runtime.genesis after decoding. */
    al_genesis_allocation allocations[AL_GENESIS_MAX_ALLOCATIONS];

    al_arena               arena;
    al_state_memory_node  *nodes;
    al_state_memory_value  *values;
    al_state_memory_store   memory;
    al_state_store          store;
    al_state                state;
    al_node_storage         storage;
    al_bool                 durable;

    al_arena        execution_arena;
    al_transaction *transactions;
    al_receipt     *receipts;
    al_node         node;
} alnode_runtime;

static int report_status(const char *operation, al_status status) {
    (void)fprintf(stderr, "alnode: %s: %s\n", operation,
                  al_status_str(status));
    return 1;
}

static void warn_insecure_crypto(void) {
    if (!al_crypto_is_secure()) {
        (void)fprintf(stderr,
                      "warning: cryptographic backend '%s' is not "
                      "production-safe\n",
                      al_crypto_backend_name());
    }
}

static al_status parse_chain_id(const char *text, al_u32 *out) {
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

static al_status write_file(const char *path, al_bytes bytes) {
    FILE *file = fopen(path, "wb");
    if (file == NULL) return AL_ERR_IO;
    al_size written = fwrite(bytes.data, 1u, bytes.len, file);
    int close_status = fclose(file);
    return written == bytes.len && close_status == 0 ? AL_OK : AL_ERR_IO;
}

static al_status read_file(const char *path, al_u8 **data_out,
                           al_size *size_out) {
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
        /* Rebuild the prefunded tree on first start with a new directory. */
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

static void runtime_destroy(alnode_runtime *runtime) {
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

/*
 * Open a runtime around a genesis file. With data_directory == NULL the
 * state is an in-memory store bound to the genesis initial root; otherwise
 * the durable store is opened (or created).
 */
static al_status runtime_open(alnode_runtime *runtime,
                              const char *genesis_path,
                              const char *data_directory) {
    memset(runtime, 0, sizeof(*runtime));

    al_u8 *genesis_bytes = NULL;
    al_size genesis_size = 0u;
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
        /* The in-memory path can only replay from an empty initial tree; a
         * genesis with prefunded accounts needs durable replay instead. */
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
    const al_block_header *head =
        runtime->durable ? al_node_storage_head(&runtime->storage) : NULL;
    status = al_node_open(&runtime->node, &runtime->genesis,
                          &runtime->state, &runtime->execution_arena,
                          buffers, head);
    if (status != AL_OK) goto fail;
    return AL_OK;

fail:
    runtime_destroy(runtime);
    return status;
}

/* ------------------------------------------------------------------ */
/* Chain commands                                                      */
/* ------------------------------------------------------------------ */

static void print_head(const al_node *node) {
    char root_hex[AL_HASH_HEX_SIZE];
    al_hash_to_hex(&node->head.state_root, root_hex);
    (void)printf("height %llu  state %s\n",
                 (unsigned long long)node->head.height, root_hex);
}

static al_status replay_blocks(alnode_runtime *runtime, int block_count,
                               char **block_paths, al_bool print_blocks) {
    for (int i = 0; i < block_count; ++i) {
        al_u8 *block_bytes = NULL;
        al_size block_size = 0u;
        al_status status = read_file(block_paths[i], &block_bytes,
                                     &block_size);
        if (status == AL_OK) {
            status = al_node_accept_encoded_block(
                &runtime->node, al_bytes_make(block_bytes, block_size));
        }
        if (status == AL_OK && runtime->durable) {
            status = al_node_storage_commit_block(
                &runtime->storage, &runtime->state,
                al_bytes_make(block_bytes, block_size));
        }
        free(block_bytes);
        if (status != AL_OK) {
            (void)fprintf(stderr, "alnode: block '%s': %s\n", block_paths[i],
                          al_status_str(status));
            return status;
        }
        if (print_blocks) print_head(&runtime->node);
    }
    return AL_OK;
}

typedef struct allocation_arg {
    al_address address;
    al_amount  balance;
} allocation_arg;

static int compare_allocations(const void *left, const void *right) {
    return al_address_cmp(&((const allocation_arg *)left)->address,
                          &((const allocation_arg *)right)->address);
}

/* Parse "<address>=<decimal-amount>" allocation arguments; the address may
 * be bech32 ("al1…", the user-facing form) or 64 hex chars. */
static al_status parse_allocations(int count, char **arguments,
                                   allocation_arg *out, al_size *count_out) {
    *count_out = 0u;
    for (int i = 0; i < count; ++i) {
        const char *argument = arguments[i];
        const char *equals = strchr(argument, '=');
        if (equals == NULL || equals == argument || equals[1] == '\0') {
            return AL_ERR_INVALID_ARG;
        }

        allocation_arg entry;
        if (strncmp(argument, "al1", 3) == 0) {
            char address_text[128];
            al_size address_len = (al_size)(equals - argument);
            if (address_len >= sizeof(address_text)) return AL_ERR_INVALID_ARG;
            memcpy(address_text, argument, address_len);
            address_text[address_len] = '\0';
            if (al_address_from_bech32(address_text, &entry.address) !=
                AL_OK) {
                return AL_ERR_MALFORMED;
            }
        } else {
            if ((al_size)(equals - argument) != AL_ADDRESS_SIZE * 2u) {
                return AL_ERR_INVALID_ARG;
            }
            char address_text[AL_ADDRESS_SIZE * 2u + 1u];
            memcpy(address_text, argument, AL_ADDRESS_SIZE * 2u);
            address_text[AL_ADDRESS_SIZE * 2u] = '\0';
            if (al_hex_decode(address_text, entry.address.bytes,
                              AL_ADDRESS_SIZE, NULL) != AL_OK) {
                return AL_ERR_MALFORMED;
            }
        }
        errno = 0;
        char *end = NULL;
        unsigned long long amount = strtoull(equals + 1u, &end, 10);
        if (errno != 0 || end == equals + 1u || *end != '\0' ||
            amount == 0ull) {
            return AL_ERR_OUT_OF_RANGE;
        }
        entry.balance = (al_amount)amount;
        out[(*count_out)++] = entry;
    }
    /* Genesis validation requires strictly increasing order; sorting here
     * makes the canonical form automatic for operators. */
    if (*count_out > 1u) {
        qsort(out, *count_out, sizeof(*out), compare_allocations);
    }
    return AL_OK;
}

static int command_init_genesis(const char *path, const char *chain_id_text,
                                int allocation_count, char **allocations_raw) {
    al_u32 chain_id = 1u;
    if (chain_id_text != NULL) {
        al_status status = parse_chain_id(chain_id_text, &chain_id);
        if (status != AL_OK) {
            return report_status("invalid chain id", status);
        }
    }

    allocation_arg parsed[AL_GENESIS_MAX_ALLOCATIONS];
    al_size parsed_count = 0u;
    al_status status =
        parse_allocations(allocation_count, allocations_raw, parsed,
                          &parsed_count);
    if (status != AL_OK) {
        return report_status("invalid allocation", status);
    }

    /* The initial root must commit exactly the prefunded accounts, so build
     * them into a scratch tree before sealing the genesis. */
    al_arena arena;
    al_state_memory_store memory;
    status = al_arena_init(&arena, 1024u * 1024u);
    al_state_memory_node *nodes = (al_state_memory_node *)calloc(
        ALNODE_STATE_NODE_CAPACITY, sizeof(*nodes));
    al_state_memory_value *values = (al_state_memory_value *)calloc(
        ALNODE_STATE_VALUE_CAPACITY, sizeof(*values));
    al_state state;
    memset(&state, 0, sizeof(state));
    if (status == AL_OK && (nodes == NULL || values == NULL)) {
        status = AL_ERR_OUT_OF_MEMORY;
    }
    if (status == AL_OK) {
        status = al_state_memory_store_init(&memory, nodes,
                                            ALNODE_STATE_NODE_CAPACITY,
                                            values,
                                            ALNODE_STATE_VALUE_CAPACITY,
                                            &arena);
    }
    if (status == AL_OK) {
        al_state_store store = al_state_memory_store_interface(&memory);
        status = al_state_init(&state, &store, &arena, 1u);
    }
    for (al_size i = 0u; status == AL_OK && i < parsed_count; ++i) {
        al_account account;
        memset(&account, 0, sizeof(account));
        account.address = parsed[i].address;
        account.balance = parsed[i].balance;
        status = al_state_upsert(&state, &account);
    }
    if (status != AL_OK) {
        free(nodes);
        free(values);
        al_arena_destroy(&arena);
        return report_status("build initial state", status);
    }

    al_genesis genesis;
    memset(&genesis, 0, sizeof(genesis));
    genesis.version = AL_GENESIS_VERSION;
    genesis.chain_id = chain_id;
    genesis.initial_state_root = state.root;
    al_resources limits = { 1000000u, 1000000u, 1000000u, 1000000u };
    genesis.fees.block_limit = limits;
    al_resources target = { 500000u, 500000u, 500000u, 500000u };
    genesis.fees.target = target;
    al_resources price = { 1u, 1u, 1u, 1u };
    genesis.fees.initial_base_price = price;
    genesis.fees.storage_deposit_per_byte = 1u;
    genesis.schedule = al_vm_resource_schedule_default();
    genesis.vm_stack_limit = AL_VM_DEFAULT_STACK;
    genesis.vm_memory_limit = AL_VM_DEFAULT_MEMORY;
    genesis.vm_call_depth_limit = AL_VM_DEFAULT_CALL_DEPTH;
    genesis.potb = al_potb_params_default();
    if (parsed_count != 0u) {
        genesis.allocations = (const al_genesis_allocation *)parsed;
        genesis.allocation_count = parsed_count;
    }

    al_u8 encoded[4096];
    al_size encoded_size = 0u;
    status = al_genesis_encode(&genesis,
                               (al_bytes_mut){ encoded, sizeof(encoded) },
                               &encoded_size);
    if (status == AL_OK) {
        status = write_file(path, al_bytes_make(encoded, encoded_size));
    }

    if (status == AL_OK) {
        al_hash256 hash;
        al_genesis_hash(&genesis, &hash);
        char hash_hex[AL_HASH_HEX_SIZE];
        al_hash_to_hex(&hash, hash_hex);
        (void)printf("genesis %s\nchain %u\naccounts %llu\nroot ",
                     hash_hex, chain_id,
                     (unsigned long long)parsed_count);
        char root_hex[AL_HASH_HEX_SIZE];
        al_hash_to_hex(&genesis.initial_state_root, root_hex);
        (void)printf("%s\n", root_hex);
    }
    al_arena_destroy(&arena);
    free(nodes);
    free(values);
    return status == AL_OK ? 0 : report_status("write genesis", status);
}

static int command_verify_chain(int file_count, char **files) {
    alnode_runtime runtime;
    al_status status = runtime_open(&runtime, files[0], NULL);
    if (status == AL_ERR_UNSUPPORTED) {
        (void)fprintf(stderr,
                      "alnode: this genesis carries prefunded accounts; "
                      "offline verification needs an empty initial state\n");
        return 1;
    }
    if (status != AL_OK) {
        return report_status("open genesis", status);
    }
    status = replay_blocks(&runtime, file_count - 1, files + 1, AL_TRUE);

    if (status == AL_OK) {
        al_hash256 genesis_hash;
        al_genesis_hash(&runtime.genesis, &genesis_hash);
        char genesis_hex[AL_HASH_HEX_SIZE];
        al_hash_to_hex(&genesis_hash, genesis_hex);
        (void)printf("verified %llu block(s) on %s\n",
                     (unsigned long long)runtime.node.stats.blocks_accepted,
                     genesis_hex);
    }
    runtime_destroy(&runtime);
    return status == AL_OK ? 0 : 1;
}

static int command_produce_block(const char *genesis_path,
                                 const char *output_path, int block_count,
                                 char **block_paths,
                                 const char *data_directory) {
    alnode_runtime runtime;
    al_status status = runtime_open(&runtime, genesis_path, data_directory);
    if (status != AL_OK) return report_status("open genesis", status);
    status = replay_blocks(&runtime, block_count, block_paths, AL_FALSE);

    al_u8 encoded[4096];
    al_size encoded_size = 0u;
    if (status == AL_OK) {
        /* The offline producer signs with the deterministic devnet key so
         * that replaying the same genesis always yields the same identity. */
        al_hash256 genesis_hash;
        al_genesis_hash(&runtime.genesis, &genesis_hash);
        al_keypair proposer;
        memset(&proposer, 0, sizeof(proposer));
        status = al_keypair_from_seed(genesis_hash.bytes, &proposer);

        if (status == AL_OK) {
            al_node_proposal proposal;
            memset(&proposal, 0, sizeof(proposal));
            proposal.protocol_day =
                runtime.node.has_head ? runtime.node.head.protocol_day : 0u;
            proposal.proposer = proposer.pk;
            al_address_from_pubkey(&proposer.pk, &proposal.tip_flat);
            proposal.tip_weighted = proposal.tip_flat;
            proposal.tip_bonded = proposal.tip_flat;
            proposal.transaction_limit = runtime.node.mempool_count;
            status = al_node_produce_block(
                &runtime.node, &proposal,
                (al_bytes_mut){ encoded, sizeof(encoded) }, &encoded_size);
        }
    }
    if (status == AL_OK) {
        status = write_file(output_path,
                            al_bytes_make(encoded, encoded_size));
    }
    if (status == AL_OK && runtime.durable) {
        status = al_node_storage_commit_block(
            &runtime.storage, &runtime.state,
            al_bytes_make(encoded, encoded_size));
    }
    if (status == AL_OK) {
        al_hash256 block_hash;
        al_block_header_hash(&runtime.node.head, &block_hash);
        char hash_hex[AL_HASH_HEX_SIZE];
        al_hash_to_hex(&block_hash, hash_hex);
        print_head(&runtime.node);
        (void)printf("block %s\n", hash_hex);
    }
    runtime_destroy(&runtime);
    return status == AL_OK ? 0 : report_status("produce block", status);
}

static int command_init_node(const char *genesis_path,
                             const char *data_directory) {
    alnode_runtime runtime;
    al_status status = runtime_open(&runtime, genesis_path, data_directory);
    if (status != AL_OK) {
        return report_status("open node storage", status);
    }
    if (al_node_head(&runtime.node) == NULL) {
        char root_hex[AL_HASH_HEX_SIZE];
        al_hash_to_hex(&runtime.state.root, root_hex);
        (void)printf("initialized state %s\n", root_hex);
    } else {
        print_head(&runtime.node);
    }
    runtime_destroy(&runtime);
    return 0;
}

static int command_import_blocks(const char *genesis_path,
                                 const char *data_directory,
                                 int block_count, char **block_paths) {
    alnode_runtime runtime;
    al_status status = runtime_open(&runtime, genesis_path, data_directory);
    if (status != AL_OK) {
        return report_status("open node storage", status);
    }
    status = replay_blocks(&runtime, block_count, block_paths, AL_TRUE);
    if (status == AL_OK) {
        (void)printf("stored %llu block(s)\n",
                     (unsigned long long)al_node_storage_block_count(
                         &runtime.storage));
    }
    runtime_destroy(&runtime);
    return status == AL_OK ? 0 : 1;
}

static int command_node_head(const char *genesis_path,
                             const char *data_directory) {
    alnode_runtime runtime;
    al_status status = runtime_open(&runtime, genesis_path, data_directory);
    if (status != AL_OK) {
        return report_status("open node storage", status);
    }
    if (al_node_head(&runtime.node) == NULL) {
        (void)printf("empty chain\n");
    } else {
        print_head(&runtime.node);
    }
    runtime_destroy(&runtime);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Key management                                                      */
/* ------------------------------------------------------------------ */

/*
 * Derive and print an identity so genesis files can fund an operator's
 * address before the node ever runs:
 *
 *     alnode keygen [--seed <64-hex>]
 *
 * Without --seed a fresh random identity is generated and its seed printed;
 * keep it, it is the only way to reproduce the address.
 */
static int command_keygen(const char *seed_text) {
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
        (void)al_hex_encode(al_bytes_make(seed, sizeof(seed)), seed_hex,
                            sizeof(seed_hex));
        al_secure_zero(seed, sizeof(seed));
        (void)printf("seed %s\n", seed_hex);
    }

    al_address address;
    al_address_from_pubkey(&keypair.pk, &address);
    char public_hex[AL_PUBKEY_SIZE * 2u + 1u];
    (void)al_hex_encode(al_bytes_make(keypair.pk.bytes, AL_PUBKEY_SIZE),
                        public_hex, sizeof(public_hex));
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
/* Transaction construction and simulation                             */
/* ------------------------------------------------------------------ */

static al_status parse_u64_arg(const char *text, uint64_t *out) {
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

static al_status parse_address_text(const char *text, al_address *out) {
    if (text == NULL) return AL_ERR_INVALID_ARG;
    /* Bech32 ("al1…") is the user-facing form; raw hex stays accepted so
     * existing scripts and fixtures keep working. */
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

/* Print an address the way users see it everywhere: bech32. */
static void print_address(const al_address *address) {
    char text[AL_ADDRESS_TEXT_SIZE];
    if (al_address_to_bech32(address, text, sizeof(text)) != AL_OK) {
        (void)printf("(address encode failed)\n");
        return;
    }
    (void)printf("%s\n", text);
}

/* Devnet signing convention: an explicit seed wins; otherwise the
 * deterministic genesis-derived identity that `produce-block` uses. */
static al_status resolve_signer(const char *seed_text,
                                const al_genesis *genesis,
                                al_keypair *out) {
    al_u8 seed[32];
    if (seed_text != NULL) {
        if (strlen(seed_text) != 64u ||
            al_hex_decode(seed_text, seed, sizeof(seed), NULL) != AL_OK) {
            return AL_ERR_MALFORMED;
        }
    } else {
        al_hash256 genesis_hash;
        al_genesis_hash(genesis, &genesis_hash);
        memcpy(seed, genesis_hash.bytes, sizeof(seed));
    }
    al_status status = al_keypair_from_seed(seed, out);
    al_secure_zero(seed, sizeof(seed));
    return status;
}

typedef struct tx_options {
    const char *seed;
    const char *output;
    uint64_t nonce;
    uint64_t value;
    al_u32 chain_id;
    al_bool chain_id_set;
    al_bool entrypoint_set;
    uint64_t args[64];
    al_size arg_count;
    const char *target;      /* address hex */
    uint64_t entrypoint;
} tx_options;

static void tx_defaults(tx_options *options) {
    memset(options, 0, sizeof(*options));
    options->entrypoint = 0;
}

/* Parses "--flag value" pairs interleaved with positional arguments, so both
 * `make-tx deploy f.bin -o x` and `make-tx deploy -o x f.bin` work. */
static al_bool tx_parse(int argc, char **argv, int start, tx_options *options,
                        const char *positionals[], int positional_cap,
                        int *pos_count) {
    *pos_count = 0;
    int i = start;
    while (i < argc) {
        const char *argument = argv[i];
        if (argument[0] == '-' && argument[1] != '\0') {
            if (strcmp(argument, "--seed") == 0 && i + 1 < argc) {
                options->seed = argv[++i];
            } else if (strcmp(argument, "-o") == 0 && i + 1 < argc) {
                options->output = argv[++i];
            } else if (strcmp(argument, "--nonce") == 0 && i + 1 < argc) {
                if (parse_u64_arg(argv[++i], &options->nonce) != AL_OK) {
                    return AL_FALSE;
                }
            } else if (strcmp(argument, "--value") == 0 && i + 1 < argc) {
                if (parse_u64_arg(argv[++i], &options->value) != AL_OK) {
                    return AL_FALSE;
                }
            } else if (strcmp(argument, "--chain-id") == 0 && i + 1 < argc) {
                uint64_t parsed = 0;
                if (parse_u64_arg(argv[++i], &parsed) != AL_OK ||
                    parsed == 0 || parsed > UINT32_MAX)
                    return AL_FALSE;
                options->chain_id = (al_u32)parsed;
                options->chain_id_set = AL_TRUE;
            } else if (strcmp(argument, "--entry") == 0 && i + 1 < argc) {
                if (parse_u64_arg(argv[++i], &options->entrypoint) != AL_OK ||
                    options->entrypoint > UINT32_MAX)
                    return AL_FALSE;
                options->entrypoint_set = AL_TRUE;
            } else if (strcmp(argument, "--to") == 0 && i + 1 < argc) {
                options->target = argv[++i];
            } else if (strcmp(argument, "-a") == 0 && i + 1 < argc) {
                if (options->arg_count >= AL_COUNTOF(options->args) ||
                    parse_u64_arg(argv[++i],
                                  &options->args[options->arg_count]) !=
                        AL_OK) {
                    return AL_FALSE;
                }
                options->arg_count++;
            } else {
                return AL_FALSE;
            }
            ++i;
            continue;
        }
        if (*pos_count >= positional_cap) return AL_FALSE;
        positionals[(*pos_count)++] = argv[i++];
    }
    return AL_TRUE;
}

static al_status write_hex_stream(FILE *file, const al_u8 *data,
                                  al_size length) {
    static const char digits[] = "0123456789abcdef";
    for (al_size i = 0u; i < length; ++i) {
        char pair[2] = { digits[data[i] >> 4], digits[data[i] & 15u] };
        if (fwrite(pair, 1u, 2u, file) != 2u) return AL_ERR_IO;
    }
    return AL_OK;
}

static al_status sign_and_encode(al_transaction *tx, const al_keypair *kp,
                                 const char *output_path) {
    tx->version = AL_TX_VERSION;
    tx->sender = kp->pk;
    AL_TRY(al_tx_sign(tx, &kp->sk));

    /* Heap, not stack: the size limit is 1 MiB and CLI stacks are not. */
    al_u8 *encoded = (al_u8 *)malloc(AL_TX_MAX_SIZE);
    if (encoded == NULL) return AL_ERR_OUT_OF_MEMORY;
    al_size encoded_size = 0u;
    al_status status =
        al_tx_encode(tx, (al_bytes_mut){ encoded, AL_TX_MAX_SIZE },
                     &encoded_size);
    if (status != AL_OK) {
        free(encoded);
        return status;
    }

    if (output_path == NULL) {
        status = write_hex_stream(stdout, encoded, encoded_size);
        (void)printf("\n");
    } else {
        FILE *file = fopen(output_path, "wb");
        if (file == NULL) {
            free(encoded);
            return AL_ERR_IO;
        }
        status = write_hex_stream(file, encoded, encoded_size);
        int close_status = fclose(file);
        if (status == AL_OK && close_status != 0) status = AL_ERR_IO;
    }
    free(encoded);
    return status;
}

static int command_make_tx(int argc, char **argv) {
    if (argc < 3) return report_status("make-tx", AL_ERR_INVALID_ARG);
    const char *kind = argv[2];

    tx_options options;
    tx_defaults(&options);
    const char *positionals[4] = { 0 };
    int positional_count = 0;
    if (!tx_parse(argc, argv, 3, &options, positionals, 4,
                  &positional_count)) {
        return report_status("make-tx flags", AL_ERR_INVALID_ARG);
    }
    const char *file_or_target =
        positional_count > 0 ? positionals[0] : NULL;
    const char *extra = positional_count > 1 ? positionals[1] : NULL;
    if (positional_count > 2) {
        return report_status("make-tx", AL_ERR_INVALID_ARG);
    }

    al_transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.chain_id = options.chain_id;
    tx.nonce = options.nonce;
    tx.expiry_height = options.nonce + 1000u; /* generous offline default */
    /* Defaults match the development genesis so transactions actually fit
     * its block limits; operators can override per field later if needed. */
    tx.resource_limit.compute = 1000000u;
    tx.resource_limit.memory = 1000000u;
    tx.resource_limit.storage = 1000000u;
    tx.resource_limit.bandwidth = 1000000u;
    tx.max_base_price.compute = 10000u;
    tx.max_base_price.memory = 10000u;
    tx.max_base_price.storage = 10000u;
    tx.max_base_price.bandwidth = 10000u;

    if (strcmp(kind, "deploy") == 0) {
        if (file_or_target == NULL) {
            return report_status("deploy needs a container file",
                                 AL_ERR_INVALID_ARG);
        }
        al_u8 *container = NULL;
        al_size container_size = 0u;
        al_status status = read_file(file_or_target, &container,
                                     &container_size);
        if (status != AL_OK) {
            return report_status("read container", status);
        }
        tx.type = AL_TX_DEPLOY;
        tx.body.deploy.value = options.value;
        tx.body.deploy.container =
            al_bytes_make(container, container_size);
        al_keypair signer;
        if (options.seed == NULL) {
            free(container);
            return report_status("make-tx deploy needs --seed",
                                 AL_ERR_INVALID_ARG);
        }
        status = resolve_signer(options.seed, NULL, &signer);
        if (status == AL_OK) {
            status = sign_and_encode(&tx, &signer, options.output);
        }
        al_secure_zero(container, container_size);
        free(container);
        return status == AL_OK ? 0
                               : report_status("encode transaction", status);
    } else if (strcmp(kind, "call") == 0 || strcmp(kind, "transfer") == 0) {
        al_address target;
        al_status status = parse_address_text(file_or_target, &target);
        if (status != AL_OK) {
            return report_status("target address", status);
        }
        if (strcmp(kind, "transfer") == 0) {
            if (extra == NULL ||
                parse_u64_arg(extra, &tx.body.transfer.amount) != AL_OK) {
                return report_status("transfer needs an amount",
                                     AL_ERR_INVALID_ARG);
            }
            tx.type = AL_TX_TRANSFER;
            tx.body.transfer.recipient = target;
        } else {
            tx.type = AL_TX_CALL;
            tx.body.call.contract = target;
            tx.body.call.value = options.value;
            /* The entrypoint is the second positional (`call <addr> <entry>`)
             * unless --entry overrode it. */
            if (!options.entrypoint_set) {
                if (extra == NULL ||
                    parse_u64_arg(extra, &options.entrypoint) != AL_OK ||
                    options.entrypoint > UINT32_MAX) {
                    return report_status("call needs an entrypoint index",
                                         AL_ERR_INVALID_ARG);
                }
                extra = NULL;
            }
            tx.body.call.entrypoint = (al_u32)options.entrypoint;
            static al_u8 calldata[8u * 64u];
            for (al_size i = 0u; i < options.arg_count; ++i) {
                store_le64_local(calldata + i * 8u, options.args[i]);
            }
            tx.body.call.calldata =
                al_bytes_make(calldata, options.arg_count * 8u);
        }
        if (options.seed == NULL) {
            return report_status("make-tx needs --seed",
                                 AL_ERR_INVALID_ARG);
        }
        al_keypair signer;
        status = resolve_signer(options.seed, NULL, &signer);
        if (status != AL_OK) return report_status("signer", status);
        status = sign_and_encode(&tx, &signer, options.output);
        return status == AL_OK ? 0
                               : report_status("encode transaction", status);
    }
    return report_status("unknown transaction kind", AL_ERR_INVALID_ARG);
}

static int command_contract_address(int argc, char **argv) {
    tx_options options;
    tx_defaults(&options);
    const char *positionals[2] = { 0 };
    int positional_count = 0;
    if (argc < 3 || !tx_parse(argc, argv, 2, &options, positionals, 2,
                              &positional_count) ||
        positional_count != 1) {
        return report_status(
            "contract-address <container.bin> --seed <64-hex> [--nonce N]",
            AL_ERR_INVALID_ARG);
    }
    al_u8 *container = NULL;
    al_size container_size = 0u;
    al_status status = read_file(positionals[0], &container,
                                 &container_size);
    if (status != AL_OK) return report_status("read container", status);

    al_keypair deployer;
    status = resolve_signer(options.seed, NULL, &deployer);
    if (status != AL_OK) {
        free(container);
        return report_status("contract-address needs --seed", status);
    }
    {
        al_address deployer_address;
        al_address_from_pubkey(&deployer.pk, &deployer_address);
        al_hash256 code_hash;
        al_sha256_bytes(al_bytes_make(container, container_size),
                        &code_hash);
        al_address contract;
        al_address_for_contract(&deployer_address, options.nonce, &code_hash,
                                &contract);
        char text[AL_ADDRESS_TEXT_SIZE];
        if (al_address_to_bech32(&contract, text, sizeof(text)) == AL_OK) {
            (void)printf("%s\n", text);
        } else {
            char hex[AL_ADDRESS_HEX_SIZE];
            al_address_to_hex(&contract, hex);
            (void)printf("0x%s\n", hex);
        }
    }
    free(container);
    return 0;
}

/*
 * Simulate one CALL against durable state without touching it: snapshot,
 * apply, restore. This is how wallets read contract state between blocks.
 */
static int command_simulate(int argc, char **argv) {
    tx_options options;
    tx_defaults(&options);
    const char *positionals[3] = { 0 };
    int positional_count = 0;
    if (argc < 3 || !tx_parse(argc, argv, 2, &options, positionals, 3,
                              &positional_count) ||
        positional_count != 2 || options.target == NULL) {
        return report_status(
            "simulate <genesis> <datadir> --to <addr> --entry N [-a v]...",
            AL_ERR_INVALID_ARG);
    }

    const char *genesis_path = positionals[0];
    const char *datadir = positionals[1];

    alnode_runtime runtime;
    al_status status = runtime_open(&runtime, genesis_path, datadir);
    if (status != AL_OK) return report_status("open node storage", status);

    al_keypair signer;
    status = resolve_signer(options.seed, &runtime.genesis, &signer);
    if (status != AL_OK) goto done;

    al_account sender_account;
    al_address sender_address;
    al_address_from_pubkey(&signer.pk, &sender_address);
    status = al_state_get(&runtime.state, &sender_address, &sender_account);
    uint64_t nonce = 0u;
    if (status == AL_OK) {
        nonce = sender_account.nonce;
    } else if (status != AL_ERR_NOT_FOUND) {
        goto done;
    }

    {
        static al_u8 calldata[512];
        if (options.arg_count > AL_COUNTOF(options.args)) {
            status = AL_ERR_OUT_OF_RANGE;
            goto done;
        }
        for (al_size i = 0u; i < options.arg_count; ++i) {
            store_le64_local(calldata + i * 8u, options.args[i]);
        }

        al_transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = AL_TX_VERSION;
        tx.chain_id = runtime.genesis.chain_id;
        tx.expiry_height = nonce + 128u;
        tx.sender = signer.pk;
        tx.nonce = nonce;
        tx.resource_limit.compute = 1000000u;
        tx.resource_limit.memory = 1000000u;
        tx.resource_limit.storage = 1000000u;
        tx.resource_limit.bandwidth = 1000000u;
        tx.max_base_price.compute = 10000u;
        tx.max_base_price.memory = 10000u;
        tx.max_base_price.storage = 10000u;
        tx.max_base_price.bandwidth = 10000u;
        tx.type = AL_TX_CALL;
        if (parse_address_text(options.target, &tx.body.call.contract) !=
            AL_OK) {
            status = AL_ERR_INVALID_ARG;
            goto done;
        }
        tx.body.call.entrypoint = (al_u32)options.entrypoint;
        tx.body.call.calldata =
            al_bytes_make(calldata, options.arg_count * 8u);
        AL_TRY(al_tx_sign(&tx, &signer.sk));

        al_tx_context context;
        memset(&context, 0, sizeof(context));
        context.chain_id = runtime.genesis.chain_id;
        context.block_height =
            runtime.node.has_head ? runtime.node.head.height + 1u : 0u;
        context.protocol_day =
            runtime.node.has_head ? runtime.node.head.protocol_day : 0u;
        context.base_prices = runtime.node.has_head
                                  ? runtime.node.head.base_prices
                                  : runtime.genesis.fees.initial_base_price;
        context.tip_flat = sender_address;
        context.tip_weighted = sender_address;
        context.tip_bonded = sender_address;
        context.vm.stack_limit = runtime.genesis.vm_stack_limit;
        context.vm.memory_limit = runtime.genesis.vm_memory_limit;
        context.vm.call_depth_limit = runtime.genesis.vm_call_depth_limit;
        context.vm.resource_limit = runtime.genesis.fees.block_limit;
        context.vm.schedule = &runtime.genesis.schedule;
        context.arena = &runtime.execution_arena;

        al_arena_mark scratch = al_arena_save(&runtime.execution_arena);
        al_state_snapshot rollback =
            al_state_snapshot_take(&runtime.state);
        al_receipt receipt;
        status = al_tx_apply(&tx, &runtime.state, &context, &receipt);
                /* Return data lives in the scratch arena; copy everything the
         * report needs out before any restore reclaims the region. */
        char data_hex[129] = { 0 };
        al_u64 returned_u64 = 0u;
        if (receipt.return_data.len != 0u) {
            al_size shown = receipt.return_data.len < 64u
                                ? receipt.return_data.len
                                : 64u;
            if (al_hex_encode(
                    al_bytes_slice(receipt.return_data, 0u, shown),
                    data_hex, sizeof(data_hex)) != AL_OK) {
                status = AL_ERR_BUFFER_TOO_SMALL;
            }
        }
        if (receipt.return_data.len >= 8u) {
            memcpy(&returned_u64, receipt.return_data.data,
                   sizeof(returned_u64)); /* little-endian by definition */
        }
        /* Simulation must not leave a trace in committed state. */
        al_status restore_status =
            al_state_snapshot_restore(&runtime.state, rollback);
        al_arena_restore(&runtime.execution_arena, scratch);
        if (restore_status != AL_OK) {
            status = restore_status;
            goto done;
        }

        if (status == AL_OK || status == AL_ERR_REVERTED) {
            (void)printf("status %s\n",
                         al_ok(receipt.status) ? "ok"
                             : receipt.status == AL_ERR_REVERTED
                                   ? "reverted"
                                   : al_status_str(receipt.status));
            (void)printf("data %s\n", data_hex);
            if (receipt.return_data.len >= 8u) {
                (void)printf("u64 %llu\n",
                             (unsigned long long)returned_u64);
            }
            (void)printf("events %llu\n",
                         (unsigned long long)receipt.event_count);
            status = AL_OK;
            goto done;
        }
    }

done:
    runtime_destroy(&runtime);
    return status == AL_OK ? 0 : report_status("simulate", status);
}

/* ------------------------------------------------------------------ */
/* Daemon command                                                      */
/* ------------------------------------------------------------------ */

typedef struct run_options {
    const char *genesis_path;
    const char *config_path;
    const char *data_dir;
    char        p2p_host_storage[64];
    const char *p2p_host;
    al_u16      p2p_port;
    al_bool     enable_p2p;
    char        rpc_host_storage[64];
    const char *rpc_host;
    al_u16      rpc_port;
    al_bool     enable_rpc;
    al_bool     enable_unsafe_rpc;
    al_bool     allow_insecure_crypto;
    const char *bootstrap[AL_DAEMON_MAX_BOOTSTRAP];
    al_size     bootstrap_count;
    const char *validators[AL_DAEMON_MAX_VALIDATORS];
    al_size     validator_count;
    const char *proposer_seed;
    al_u32      block_interval_ms;
    al_u32      round_timeout_ms;
    al_bool     produce_empty_blocks;
    const char *log_level;
} run_options;

static al_bool is_loopback_host(const char *host) {
    return host != NULL &&
           (strcmp(host, "127.0.0.1") == 0 || strcmp(host, "localhost") == 0)
               ? AL_TRUE
               : AL_FALSE;
}

static int command_run(const run_options *options) {
    /* Initialise logging. */
    al_log_level level = AL_LOG_INFO;
    if (options->log_level) {
        if (strcmp(options->log_level, "trace") == 0) level = AL_LOG_TRACE;
        else if (strcmp(options->log_level, "debug") == 0) level = AL_LOG_DEBUG;
        else if (strcmp(options->log_level, "info") == 0) level = AL_LOG_INFO;
        else if (strcmp(options->log_level, "warn") == 0) level = AL_LOG_WARN;
        else if (strcmp(options->log_level, "error") == 0) level = AL_LOG_ERROR;
        else if (strcmp(options->log_level, "fatal") == 0) level = AL_LOG_FATAL;
        else if (strcmp(options->log_level, "silent") == 0) level = AL_LOG_SILENT;
        else {
            (void)fprintf(stderr, "alnode: unknown log level '%s'\n",
                          options->log_level);
            return 2;
        }
    }
    al_log_set_level(level);

    if (!al_net_init()) {
        AL_LOG_ERROR("alnode", "failed to initialise networking");
        return 1;
    }

    al_daemon_config config;
    memset(&config, 0, sizeof(config));
    config.data_dir = options->data_dir;
    config.enable_p2p = options->enable_p2p;
    config.p2p_host = options->p2p_host;
    config.p2p_port = options->p2p_port;
    config.enable_rpc = options->enable_rpc;
    config.rpc_host = options->rpc_host;
    config.rpc_port = options->rpc_port;
    config.enable_unsafe_rpc = options->enable_unsafe_rpc;
    config.allow_insecure_crypto = options->allow_insecure_crypto;
    for (al_size i = 0u; i < options->bootstrap_count; ++i) {
        config.bootstrap[i] = options->bootstrap[i];
    }
    config.bootstrap_count = options->bootstrap_count;
    for (al_size i = 0u; i < options->validator_count; ++i) {
        config.validators[i] = options->validators[i];
    }
    config.validator_count = options->validator_count;
    config.block_interval_ms = options->block_interval_ms;
    config.round_timeout_ms = options->round_timeout_ms;
    config.produce_empty_blocks = options->produce_empty_blocks;
    config.proposer_seed = options->proposer_seed;
    config.stop_flag = &g_stop_requested;

    /* Load config file (CLI flags already set take precedence). */
    if (options->config_path != NULL) {
        al_status cfg_status = al_daemon_config_load(options->config_path,
                                                      &config);
        if (cfg_status != AL_OK) {
            AL_LOG_ERROR("alnode", "failed to load config '%s': %s",
                         options->config_path, al_status_str(cfg_status));
            return 2;
        }
        AL_LOG_INFO("alnode", "loaded config from %s", options->config_path);
    }

    if (!al_crypto_is_secure() && !config.allow_insecure_crypto) {
        AL_LOG_ERROR("alnode",
                     "refusing insecure crypto backend '%s'; use "
                     "--allow-insecure-crypto to override the deployment gate",
                     al_crypto_backend_name());
        return 2;
    }
    if (config.enable_rpc && config.enable_unsafe_rpc &&
        !is_loopback_host(config.rpc_host)) {
        AL_LOG_ERROR("alnode",
                     "unsafe RPC methods require a loopback RPC bind");
        return 2;
    }

    al_daemon *daemon = NULL;
    al_status status = al_daemon_open(&config, options->genesis_path,
                                      &daemon);
    if (status != AL_OK) {
        AL_LOG_ERROR("alnode", "failed to start node: %s",
                     al_status_str(status));
        return 1;
    }

    AL_LOG_INFO("alnode", "proposer %s", al_daemon_proposer_address(daemon));
    AL_LOG_INFO("alnode", "p2p %s:%u  rpc %s:%u  ctrl-c to stop",
                config.enable_p2p && config.p2p_host != NULL
                    ? config.p2p_host
                    : (config.enable_p2p ? "0.0.0.0" : "off"),
                (unsigned)config.p2p_port,
                config.enable_rpc && config.rpc_host != NULL
                    ? config.rpc_host
                    : (config.enable_rpc ? "127.0.0.1" : "off"),
                (unsigned)config.rpc_port);

    (void)al_daemon_run(daemon);
    al_daemon_close(daemon);
    al_log_shutdown();
    al_net_shutdown();
    AL_LOG_INFO("alnode", "stopped");
    return 0;
}

static al_bool parse_port(const char *text, al_u16 *out) {
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0u ||
        value > 65535ul) {
        return AL_FALSE;
    }
    *out = (al_u16)value;
    return AL_TRUE;
}

/* "[host:]port" for --p2p/--rpc. A missing host keeps the default binding.
 * `host_storage` receives the host copy so repeated flags stay independent. */
static al_bool parse_endpoint_option(const char *text, char *host_storage,
                                     al_size capacity, const char **host,
                                     al_u16 *port) {
    const char *separator = strrchr(text, ':');
    if (separator != NULL) {
        size_t host_len = (size_t)(separator - text);
        if (host_len >= capacity) return AL_FALSE;
        memcpy(host_storage, text, host_len);
        host_storage[host_len] = '\0';
        *host = host_storage;
        return parse_port(separator + 1u, port);
    }
    return parse_port(text, port);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

static void print_usage(const char *program) {
    (void)fprintf(stderr,
        "usage:\n"
        "  %s --version\n"
        "  %s crypto-status\n"
        "  %s keygen [--seed <64-hex>]\n"
        "  %s make-tx deploy <container.bin> -o out.txhex --seed <hex>\n"
        "        [--nonce N] [--value V] [--chain-id N]\n"
        "  %s make-tx call <contract> <entry> [-a u64]... -o out.txhex\n"
        "        --seed <hex> [--nonce N] [--value V]\n"
        "  %s make-tx transfer <to> <amount> -o out.txhex --seed <hex>\n"
        "  %s contract-address <container.bin> --seed <hex> [--nonce N]\n"
        "  %s simulate <genesis> <datadir> --to <contract> --entry N\n"
        "        [-a u64]... [--seed <hex>]\n"
        "  %s init-genesis <file> [chain-id] [<address>=<amount> ...]\n"
        "  %s verify-chain <genesis> [block ...]\n"
        "  %s produce-block <genesis> <output> [block ...]\n"
        "  %s init-node <genesis> <data-dir>\n"
        "  %s import-blocks <genesis> <data-dir> <block ...>\n"
        "  %s node-head <genesis> <data-dir>\n"
        "  %s produce-node-block <genesis> <data-dir> <output>\n"
        "  %s run <genesis> --datadir <dir> [--config config.toml]\n"
        "        [--p2p [host:]port] [--rpc [host:]port] [--peer host:port]...\n"
        "        [--validator <public-key-hex>]...\n"
        "        [--interval ms] [--round-timeout ms] [--empty]\n"
        "        [--no-p2p] [--no-rpc]\n"
        "        [--allow-insecure-crypto] [--unsafe-rpc]\n"
        "        [--proposer-seed <64-hex>] [--log-level trace|debug|info|warn|error|silent]\n",
        program, program, program, program, program, program, program,
        program, program, program, program, program, program, program,
        program, program);
}

int main(int argc, char **argv) {
#if defined(AL_OS_WINDOWS)
    (void)SetConsoleCtrlHandler(console_handler, TRUE);
#else
    (void)signal(SIGINT, interrupt_handler);
#endif

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        (void)printf("alnode %s\n", al_version_string());
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "crypto-status") == 0) {
        (void)printf("%s: %s\n", al_crypto_backend_name(),
                     al_crypto_is_secure() ? "secure" : "not production-safe");
        return al_crypto_is_secure() ? 0 : 2;
    }
    if (argc == 2 && strcmp(argv[1], "keygen") == 0) {
        warn_insecure_crypto();
        return command_keygen(NULL);
    }
    if (argc == 4 && strcmp(argv[1], "keygen") == 0 &&
        strcmp(argv[2], "--seed") == 0) {
        return command_keygen(argv[3]);
    }

    warn_insecure_crypto();

    if (strcmp(argv[1], "run") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            return 2;
        }
        run_options options;
        memset(&options, 0, sizeof(options));
        options.genesis_path = argv[2];
        options.p2p_port = 44001u;
        options.enable_p2p = AL_TRUE;
        options.rpc_port = 44002u;
        options.rpc_host = "127.0.0.1";
        options.enable_rpc = AL_TRUE;
        options.block_interval_ms = 2000u;
        options.round_timeout_ms = 6000u;

        for (int i = 3; i < argc; ++i) {
            const char *flag = argv[i];
#define NEXT_VALUE()                                                           \
    (++i >= argc                                                               \
         ? (print_usage(argv[0]), (const char *)NULL)                          \
         : argv[i])
            if (strcmp(flag, "--config") == 0) {
                options.config_path = NEXT_VALUE();
            } else if (strcmp(flag, "--datadir") == 0) {
                options.data_dir = NEXT_VALUE();
            } else if (strcmp(flag, "--p2p") == 0) {
                const char *value = NEXT_VALUE();
                if (value == NULL ||
                    !parse_endpoint_option(value, options.p2p_host_storage,
                                           sizeof(options.p2p_host_storage),
                                           &options.p2p_host,
                                           &options.p2p_port)) {
                    (void)fprintf(stderr, "alnode: invalid --p2p\n");
                    return 2;
                }
            } else if (strcmp(flag, "--rpc") == 0) {
                const char *value = NEXT_VALUE();
                if (value == NULL ||
                    !parse_endpoint_option(value, options.rpc_host_storage,
                                           sizeof(options.rpc_host_storage),
                                           &options.rpc_host,
                                           &options.rpc_port)) {
                    (void)fprintf(stderr, "alnode: invalid --rpc\n");
                    return 2;
                }
            } else if (strcmp(flag, "--peer") == 0) {
                const char *value = NEXT_VALUE();
                if (value == NULL ||
                    options.bootstrap_count >= AL_DAEMON_MAX_BOOTSTRAP) {
                    print_usage(argv[0]);
                    return 2;
                }
                options.bootstrap[options.bootstrap_count++] = value;
            } else if (strcmp(flag, "--validator") == 0) {
                const char *value = NEXT_VALUE();
                if (value == NULL ||
                    options.validator_count >= AL_DAEMON_MAX_VALIDATORS) {
                    (void)fprintf(stderr, "alnode: too many validators\n");
                    return 2;
                }
                options.validators[options.validator_count++] = value;
            } else if (strcmp(flag, "--interval") == 0) {
                const char *value = NEXT_VALUE();
                if (value == NULL || *value == '\0') {
                    (void)fprintf(stderr, "alnode: --interval needs a value\n");
                    return 2;
                }
                errno = 0;
                char *end = NULL;
                unsigned long parsed = strtoul(value, &end, 10);
                if (errno != 0 || end == value || *end != '\0' ||
                    parsed > 3600000ul) {
                    (void)fprintf(stderr, "alnode: invalid --interval '%s'\n",
                                  value);
                    return 2;
                }
                options.block_interval_ms = (al_u32)parsed;
            } else if (strcmp(flag, "--proposer-seed") == 0) {
                const char *value = NEXT_VALUE();
                options.proposer_seed = value;
            } else if (strcmp(flag, "--round-timeout") == 0) {
                const char *value = NEXT_VALUE();
                if (value == NULL || *value == '\0') {
                    (void)fprintf(stderr,
                                  "alnode: --round-timeout needs a value\n");
                    return 2;
                }
                errno = 0;
                char *end = NULL;
                unsigned long parsed = strtoul(value, &end, 10);
                if (errno != 0 || end == value || *end != '\0' ||
                    parsed < 100ul || parsed > 3600000ul) {
                    (void)fprintf(stderr,
                                  "alnode: invalid --round-timeout '%s'\n",
                                  value);
                    return 2;
                }
                options.round_timeout_ms = (al_u32)parsed;
            } else if (strcmp(flag, "--empty") == 0) {
                options.produce_empty_blocks = AL_TRUE;
            } else if (strcmp(flag, "--no-p2p") == 0) {
                options.enable_p2p = AL_FALSE;
            } else if (strcmp(flag, "--no-rpc") == 0) {
                options.enable_rpc = AL_FALSE;
            } else if (strcmp(flag, "--allow-insecure-crypto") == 0) {
                options.allow_insecure_crypto = AL_TRUE;
            } else if (strcmp(flag, "--unsafe-rpc") == 0) {
                options.enable_unsafe_rpc = AL_TRUE;
            } else if (strcmp(flag, "--log-level") == 0) {
                options.log_level = NEXT_VALUE();
            } else {
                (void)fprintf(stderr, "alnode: unknown flag '%s'\n", flag);
                print_usage(argv[0]);
                return 2;
            }
#undef NEXT_VALUE
        }
        if (options.data_dir == NULL) {
            (void)fprintf(stderr, "alnode: run requires --datadir\n");
            return 2;
        }
        return command_run(&options);
    }

    if (argc >= 3 && strcmp(argv[1], "make-tx") == 0) {
        warn_insecure_crypto();
        return command_make_tx(argc, argv);
    }
    if (argc >= 2 && strcmp(argv[1], "contract-address") == 0) {
        return command_contract_address(argc, argv);
    }
    if (argc >= 2 && strcmp(argv[1], "simulate") == 0) {
        warn_insecure_crypto();
        return command_simulate(argc, argv);
    }

    if (argc >= 3 && strcmp(argv[1], "init-genesis") == 0) {
        const char *chain_id_text = argc >= 4 ? argv[3] : NULL;
        int extra = argc - 4;
        return command_init_genesis(argv[2], chain_id_text,
                                    extra > 0 ? extra : 0,
                                    extra > 0 ? argv + 4 : NULL);
    }
    if (argc >= 3 && strcmp(argv[1], "verify-chain") == 0) {
        return command_verify_chain(argc - 2, argv + 2);
    }
    if (argc >= 4 && strcmp(argv[1], "produce-block") == 0) {
        return command_produce_block(argv[2], argv[3], argc - 4, argv + 4,
                                     NULL);
    }
    if (argc == 4 && strcmp(argv[1], "init-node") == 0) {
        return command_init_node(argv[2], argv[3]);
    }
    if (argc >= 4 && strcmp(argv[1], "import-blocks") == 0) {
        return command_import_blocks(argv[2], argv[3], argc - 4, argv + 4);
    }
    if (argc == 4 && strcmp(argv[1], "node-head") == 0) {
        return command_node_head(argv[2], argv[3]);
    }
    if (argc == 5 && strcmp(argv[1], "produce-node-block") == 0) {
        return command_produce_block(argv[2], argv[4], 0, NULL, argv[3]);
    }

    print_usage(argv[0]);
    return 2;
}
