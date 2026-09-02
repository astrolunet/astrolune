/*
 * TOML config loader and validator tests.
 *
 * The config functions are defined inline here to avoid linking al_daemon,
 * which pulls in network/state libraries that crash at startup in tests.
 */

#include "altest.h"
#include "astrolune/toml.h"
#include <string.h>
#include <stdlib.h>

#define AL_TEST_SUITE_NAME "config"

/* ------------------------------------------------------------------ */
/* Minimal config struct (subset of al_daemon_config used for testing)  */
/* ------------------------------------------------------------------ */

#define CFG_MAX_BOOTSTRAP 16u
#define CFG_MAX_VALIDATORS 16u

typedef struct test_config {
    const char *data_dir;
    al_bool     enable_p2p;
    const char *p2p_host;
    al_u16      p2p_port;
    al_bool     enable_rpc;
    const char *rpc_host;
    al_u16      rpc_port;
    al_bool     enable_unsafe_rpc;
    const char *rpc_token;
    al_bool     allow_insecure_crypto;
    const char *bootstrap[CFG_MAX_BOOTSTRAP];
    al_size     bootstrap_count;
    const char *validators[CFG_MAX_VALIDATORS];
    al_size     validator_count;
    const char *proposer_seed;
    const char *proposer_passphrase;
    al_u32 block_interval_ms;
    al_u32 round_timeout_ms;
    al_bool produce_empty_blocks;
    const char *log_level;
    al_bool require_encrypted_transport;
    char owned_strings[64][256];
    al_size owned_string_count;
} test_config;

/* ------------------------------------------------------------------ */
/* Config helpers (copied from daemon/config.c for test isolation)      */
/* ------------------------------------------------------------------ */

static char *cfg_copy_string(test_config *config, const char *value) {
    al_size len = strlen(value);
    if (len >= sizeof(config->owned_strings[0]) ||
        config->owned_string_count >= 64u) {
        return NULL;
    }
    char *copy = config->owned_strings[config->owned_string_count++];
    memcpy(copy, value, len + 1u);
    return copy;
}

static void cfg_set_string(test_config *config, const al_toml_value *tbl,
                           const char *key, const char **field) {
    if (*field != NULL) return;
    const char *val;
    if (al_toml_string(tbl, key, &val))
        *field = cfg_copy_string(config, val);
}

static void cfg_set_port(const al_toml_value *tbl, const char *key,
                         al_u16 *field, al_bool *enabled) {
    al_i64 val;
    if (al_toml_i64(tbl, key, &val) && val >= 0 && val <= 65535) {
        *field = (al_u16)val;
        if (enabled) *enabled = AL_TRUE;
    }
}

static void cfg_set_bool(const al_toml_value *tbl, const char *key,
                         al_bool *field) {
    al_bool val;
    if (al_toml_bool(tbl, key, &val))
        *field = val;
}

static void cfg_set_u32(const al_toml_value *tbl, const char *key,
                        al_u32 *field) {
    al_i64 val;
    if (al_toml_i64(tbl, key, &val) && val >= 0)
        *field = (al_u32)val;
}

static al_status test_config_load_memory(const char *text, al_size len,
                                         test_config *config) {
    (void)len;
    if (!text || !config) return AL_ERR_INVALID_ARG;

    al_toml_value *root = NULL;
    AL_TRY(al_toml_parse(text, &root));

    const al_toml_value *node = al_toml_get(root, "node");
    if (node) {
        cfg_set_string(config, node, "data_dir", &config->data_dir);
        cfg_set_bool(node, "allow_insecure_crypto",
                     &config->allow_insecure_crypto);
    }

    const al_toml_value *p2p = al_toml_get(root, "p2p");
    if (p2p) {
        cfg_set_string(config, p2p, "host", &config->p2p_host);
        cfg_set_port(p2p, "port", &config->p2p_port, &config->enable_p2p);
        cfg_set_bool(p2p, "enabled", &config->enable_p2p);
        cfg_set_bool(p2p, "require_encryption",
                     &config->require_encrypted_transport);
    }

    const al_toml_value *rpc = al_toml_get(root, "rpc");
    if (rpc) {
        cfg_set_string(config, rpc, "host", &config->rpc_host);
        cfg_set_port(rpc, "port", &config->rpc_port, &config->enable_rpc);
        cfg_set_bool(rpc, "enabled", &config->enable_rpc);
        cfg_set_bool(rpc, "unsafe_methods", &config->enable_unsafe_rpc);
        cfg_set_string(config, rpc, "token", &config->rpc_token);
    }

    const al_toml_value *blocks = al_toml_get(root, "blocks");
    if (blocks) {
        cfg_set_u32(blocks, "interval_ms", &config->block_interval_ms);
        cfg_set_bool(blocks, "empty", &config->produce_empty_blocks);
    }

    const al_toml_value *proposer = al_toml_get(root, "proposer");
    if (proposer) {
        cfg_set_string(config, proposer, "seed", &config->proposer_seed);
        cfg_set_string(config, proposer, "passphrase", &config->proposer_passphrase);
    }

    const al_toml_value *log = al_toml_get(root, "log");
    if (log) {
        cfg_set_string(config, log, "level", &config->log_level);
    }

    const al_toml_value *consensus = al_toml_get(root, "consensus");
    if (consensus) {
        cfg_set_u32(consensus, "round_timeout_ms",
                    &config->round_timeout_ms);
        const al_toml_value *validators = al_toml_get(consensus, "validators");
        if (validators && validators->kind == AL_TOML_ARRAY) {
            for (al_size i = 0u;
                 i < validators->count &&
                 config->validator_count < CFG_MAX_VALIDATORS;
                 ++i) {
                const al_toml_value *item = validators->items[i];
                if (item && item->kind == AL_TOML_STRING && item->string) {
                    config->validators[config->validator_count++] =
                        cfg_copy_string(config, item->string);
                }
            }
        }
    }

    al_toml_free(root);
    return AL_OK;
}

static al_bool log_level_valid(const char *level) {
    if (level == NULL) return AL_TRUE;
    return strcmp(level, "trace") == 0 || strcmp(level, "debug") == 0 ||
           strcmp(level, "info") == 0 || strcmp(level, "warn") == 0 ||
           strcmp(level, "error") == 0 || strcmp(level, "fatal") == 0 ||
           strcmp(level, "silent") == 0;
}

static al_status test_config_validate(const test_config *config) {
    if (config == NULL) return AL_ERR_INVALID_ARG;
    if (config->data_dir == NULL || config->data_dir[0] == '\0') {
        return AL_ERR_INVALID_ARG;
    }
    if (!log_level_valid(config->log_level)) {
        return AL_ERR_INVALID_ARG;
    }
    return AL_OK;
}

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

AL_TEST(config_parse_minimal) {
    const char *toml =
        "[node]\n"
        "data_dir = \"./data\"\n";
    test_config config;
    memset(&config, 0, sizeof(config));
    AL_CHECK_EQ_STATUS(test_config_load_memory(toml, strlen(toml), &config),
                       AL_OK);
    AL_CHECK_EQ_STR(config.data_dir, "./data");
}

AL_TEST(config_parse_all_sections) {
    const char *toml =
        "[node]\n"
        "data_dir = \"/tmp/chain\"\n"
        "allow_insecure_crypto = true\n"
        "\n"
        "[log]\n"
        "level = \"debug\"\n"
        "\n"
        "[p2p]\n"
        "host = \"0.0.0.0\"\n"
        "port = 9000\n"
        "enabled = true\n"
        "require_encryption = true\n"
        "\n"
        "[rpc]\n"
        "host = \"127.0.0.1\"\n"
        "port = 9001\n"
        "enabled = true\n"
        "unsafe_methods = true\n"
        "token = \"secret\"\n"
        "\n"
        "[blocks]\n"
        "interval_ms = 500\n"
        "empty = true\n"
        "\n"
        "[consensus]\n"
        "round_timeout_ms = 3000\n"
        "validators = [\"aaaa\", \"bbbb\"]\n"
        "\n"
        "[proposer]\n"
        "seed = \"1122334455667788990011223344556677889900112233445566778899001122\"\n"
        "passphrase = \"pw\"\n";

    test_config config;
    memset(&config, 0, sizeof(config));
    AL_CHECK_EQ_STATUS(test_config_load_memory(toml, strlen(toml), &config),
                       AL_OK);

    AL_CHECK_EQ_STR(config.data_dir, "/tmp/chain");
    AL_CHECK(config.allow_insecure_crypto == AL_TRUE);
    AL_CHECK_EQ_STR(config.log_level, "debug");
    AL_CHECK_EQ_STR(config.p2p_host, "0.0.0.0");
    AL_CHECK(config.enable_p2p == AL_TRUE);
    AL_CHECK(config.require_encrypted_transport == AL_TRUE);
    AL_CHECK_EQ_STR(config.rpc_host, "127.0.0.1");
    AL_CHECK(config.enable_rpc == AL_TRUE);
    AL_CHECK(config.enable_unsafe_rpc == AL_TRUE);
    AL_CHECK_EQ_STR(config.rpc_token, "secret");
    AL_CHECK(config.block_interval_ms == 500);
    AL_CHECK(config.produce_empty_blocks == AL_TRUE);
    AL_CHECK(config.round_timeout_ms == 3000);
    AL_CHECK(config.validator_count == 2u);
    AL_CHECK_EQ_STR(config.validators[0], "aaaa");
    AL_CHECK_EQ_STR(config.validators[1], "bbbb");
    AL_CHECK_EQ_STR(config.proposer_seed,
                    "1122334455667788990011223344556677889900112233445566778899001122");
    AL_CHECK_EQ_STR(config.proposer_passphrase, "pw");
}

AL_TEST(cli_overrides_config) {
    const char *toml =
        "[node]\n"
        "data_dir = \"./from-toml\"\n"
        "[p2p]\n"
        "port = 1111\n";

    test_config config;
    memset(&config, 0, sizeof(config));
    config.data_dir = "./from-cli";
    AL_CHECK_EQ_STATUS(test_config_load_memory(toml, strlen(toml), &config),
                       AL_OK);
    AL_CHECK_EQ_STR(config.data_dir, "./from-cli");
    AL_CHECK(config.p2p_port == 1111);
}

AL_TEST(config_log_levels) {
    const char *levels[] = { "trace", "debug", "info", "warn", "error",
                             "fatal", "silent" };
    for (al_size i = 0u; i < 7u; ++i) {
        char toml[128];
        (void)snprintf(toml, sizeof(toml),
                       "[node]\ndata_dir = \".\"\n[log]\nlevel = \"%s\"\n",
                       levels[i]);
        test_config config;
        memset(&config, 0, sizeof(config));
        AL_CHECK_EQ_STATUS(
            test_config_load_memory(toml, strlen(toml), &config), AL_OK);
        AL_CHECK_EQ_STR(config.log_level, levels[i]);
    }
}

AL_TEST(config_log_level_invalid) {
    const char *toml =
        "[node]\n"
        "data_dir = \".\"\n"
        "[log]\n"
        "level = \"bogus\"\n";
    test_config config;
    memset(&config, 0, sizeof(config));
    AL_CHECK_EQ_STATUS(test_config_load_memory(toml, strlen(toml), &config),
                       AL_OK);
    AL_CHECK_EQ_STATUS(test_config_validate(&config), AL_ERR_INVALID_ARG);
}

AL_TEST(config_validate_ok) {
    test_config config;
    memset(&config, 0, sizeof(config));
    config.data_dir = "./data";
    AL_CHECK_EQ_STATUS(test_config_validate(&config), AL_OK);
}

AL_TEST(config_validate_no_data_dir) {
    test_config config;
    memset(&config, 0, sizeof(config));
    AL_CHECK_EQ_STATUS(test_config_validate(&config), AL_ERR_INVALID_ARG);
}

AL_TEST(config_validate_empty_data_dir) {
    test_config config;
    memset(&config, 0, sizeof(config));
    config.data_dir = "";
    AL_CHECK_EQ_STATUS(test_config_validate(&config), AL_ERR_INVALID_ARG);
}

AL_TEST(config_validate_null) {
    AL_CHECK_EQ_STATUS(test_config_validate(NULL), AL_ERR_INVALID_ARG);
}

AL_TEST(config_missing_sections_ok) {
    const char *toml = "[node]\ndata_dir = \".\"\n";
    test_config config;
    memset(&config, 0, sizeof(config));
    AL_CHECK_EQ_STATUS(test_config_load_memory(toml, strlen(toml), &config),
                       AL_OK);
    AL_CHECK(config.p2p_port == 0);
    AL_CHECK(config.rpc_port == 0);
    AL_CHECK(config.log_level == NULL);
}

AL_TEST(config_empty_toml) {
    const char *toml = "";
    test_config config;
    memset(&config, 0, sizeof(config));
    AL_CHECK_EQ_STATUS(test_config_load_memory(toml, 0, &config), AL_OK);
    AL_CHECK_EQ_STATUS(test_config_validate(&config), AL_ERR_INVALID_ARG);
}

/* ------------------------------------------------------------------ */
/* Runner                                                               */
/* ------------------------------------------------------------------ */

AL_TEST_MAIN {
    AL_RUN(config_parse_minimal);
    AL_RUN(config_parse_all_sections);
    AL_RUN(cli_overrides_config);
    AL_RUN(config_log_levels);
    AL_RUN(config_log_level_invalid);
    AL_RUN(config_validate_ok);
    AL_RUN(config_validate_no_data_dir);
    AL_RUN(config_validate_empty_data_dir);
    AL_RUN(config_validate_null);
    AL_RUN(config_missing_sections_ok);
    AL_RUN(config_empty_toml);
}
