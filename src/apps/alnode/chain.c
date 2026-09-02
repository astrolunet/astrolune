/*
 * chain.c — chain subcommands: init-genesis, verify-chain, produce-block,
 *           init-node, import-blocks, node-head.
 */

#include "alnode.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

void print_head(const al_node *node) {
    char root_hex[AL_HASH_HEX_SIZE];
    al_hash_to_hex(&node->head.state_root, root_hex);
    (void)printf("height %llu  state %s\n",
                 (unsigned long long)node->head.height, root_hex);
}

al_status replay_blocks(alnode_runtime *runtime, int block_count,
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
    if (*count_out > 1u) {
        qsort(out, *count_out, sizeof(*out), compare_allocations);
    }
    return AL_OK;
}

int command_init_genesis(const char *path, const char *chain_id_text,
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

int command_verify_chain(int file_count, char **files) {
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

int command_produce_block(const char *genesis_path,
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

int command_init_node(const char *genesis_path,
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

int command_import_blocks(const char *genesis_path,
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

int command_node_head(const char *genesis_path,
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
