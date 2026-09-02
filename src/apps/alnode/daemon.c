/*
 * daemon.c — the `run` subcommand: parse options, start the daemon loop.
 */

#include "alnode.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

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

al_bool parse_port(const char *text, al_u16 *out) {
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

al_bool parse_endpoint_option(const char *text, char *host_storage,
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

static al_bool is_loopback_host(const char *host) {
    return host != NULL &&
           (strcmp(host, "127.0.0.1") == 0 || strcmp(host, "localhost") == 0)
               ? AL_TRUE
               : AL_FALSE;
}

int command_run(const run_options *options) {
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
    config.rpc_token = options->rpc_token;
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
    config.proposer_passphrase = options->proposer_passphrase;
    config.stop_flag = &g_stop_requested;

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

    al_status val_status = al_daemon_config_validate(&config);
    if (val_status != AL_OK) {
        AL_LOG_ERROR("alnode", "invalid configuration: %s",
                     al_status_str(val_status));
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

    al_bool clean_shutdown = al_daemon_run(daemon);
    al_daemon_close(daemon);
    AL_LOG_INFO("alnode", "stopped");
    al_log_shutdown();
    al_net_shutdown();
    return clean_shutdown ? 0 : 1;
}

void alnode_install_signal_handlers(void) {
#if defined(AL_OS_WINDOWS)
    (void)SetConsoleCtrlHandler(console_handler, TRUE);
#else
    (void)signal(SIGINT, interrupt_handler);
#endif
}
