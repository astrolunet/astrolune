/*
 * main.c — thin CLI dispatcher for alnode.
 */

#include "alnode.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Forward declaration from daemon.c */
void alnode_install_signal_handlers(void);

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
        "  %s run <genesis> --datadir <dir> --config <config.toml>\n"
        "        [--p2p [host:]port] [--rpc [host:]port] [--peer host:port]...\n"
        "        [--validator <public-key-hex>]...\n"
        "        [--interval ms] [--round-timeout ms] [--empty]\n"
        "        [--no-p2p] [--no-rpc]\n"
        "        [--allow-insecure-crypto] [--unsafe-rpc]\n"
        "        [--rpc-token <bearer-token>]\n"
        "        [--proposer-seed <64-hex>] [--proposer-passphrase <passphrase>]\n"
        "        [--log-level trace|debug|info|warn|error|silent]\n"
        "        [--no-config]\n",
        program, program, program, program, program, program, program,
        program, program, program, program, program, program, program,
        program, program);
}

int main(int argc, char **argv) {
    alnode_install_signal_handlers();

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
            } else if (strcmp(flag, "--proposer-passphrase") == 0) {
                const char *value = NEXT_VALUE();
                options.proposer_passphrase = value;
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
            } else if (strcmp(flag, "--rpc-token") == 0) {
                options.rpc_token = NEXT_VALUE();
            } else if (strcmp(flag, "--log-level") == 0) {
                options.log_level = NEXT_VALUE();
            } else if (strcmp(flag, "--no-config") == 0) {
                options.no_config = AL_TRUE;
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
        if (options.config_path == NULL && !options.no_config) {
            (void)fprintf(stderr,
                "alnode: run requires --config <config.toml> or --no-config\n");
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
