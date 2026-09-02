/*
 * tx.c — transaction construction, signing, simulation and contract-address
 *        prediction.
 */

#include "alnode.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

al_status resolve_signer(const char *seed_text, const al_genesis *genesis,
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

void tx_defaults(tx_options *options) {
    memset(options, 0, sizeof(*options));
    options->entrypoint = 0;
}

al_bool tx_parse(int argc, char **argv, int start, tx_options *options,
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

al_status sign_and_encode(al_transaction *tx, const al_keypair *kp,
                          const char *output_path) {
    tx->version = AL_TX_VERSION;
    tx->sender = kp->pk;
    AL_TRY(al_tx_sign(tx, &kp->sk));

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

int command_make_tx(int argc, char **argv) {
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
    tx.expiry_height = options.nonce + 1000u;
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

int command_contract_address(int argc, char **argv) {
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

int command_simulate(int argc, char **argv) {
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
    uint64_t nonce = 0u;
    al_status status = runtime_open(&runtime, genesis_path, datadir);
    if (status != AL_OK) return report_status("open node storage", status);

    al_keypair signer;
    status = resolve_signer(options.seed, &runtime.genesis, &signer);
    if (status != AL_OK) goto done;

    al_account sender_account;
    al_address sender_address;
    al_address_from_pubkey(&signer.pk, &sender_address);
    status = al_state_get(&runtime.state, &sender_address, &sender_account);
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
        status = al_tx_sign(&tx, &signer.sk);
        if (status != AL_OK) goto done;

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
        context.potb_params = &runtime.genesis.potb;

        al_arena_mark scratch = al_arena_save(&runtime.execution_arena);
        al_state_snapshot rollback =
            al_state_snapshot_take(&runtime.state);
        al_receipt receipt;
        status = al_tx_apply(&tx, &runtime.state, &context, &receipt);
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
                   sizeof(returned_u64));
        }
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
