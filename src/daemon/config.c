/* TOML config file loader. See config.h for the public API. */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* File reading                                                        */
/* ------------------------------------------------------------------ */

static al_status read_config_file(const char *path, char **out, al_size *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return AL_ERR_NOT_FOUND;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len < 0 || len > 1024 * 1024) { fclose(f); return AL_ERR_OUT_OF_RANGE; }
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((al_size)len + 1u);
    if (!buf) { fclose(f); return AL_ERR_OUT_OF_MEMORY; }
    al_size nread = fread(buf, 1u, (al_size)len, f);
    fclose(f);
    buf[nread] = '\0';
    *out = buf;
    *out_len = nread;
    return AL_OK;
}

/* ------------------------------------------------------------------ */
/* TOML helpers                                                         */
/* ------------------------------------------------------------------ */

/* Set a config string field only if the TOML key exists and the field
 * is currently NULL (i.e. not already set by CLI). */
static void config_set_string(const al_toml_value *tbl, const char *key,
                              const char **field) {
    if (*field != NULL) return;
    const char *val;
    if (al_toml_string(tbl, key, &val))
        *field = val;
}

/* Set a config u16 field only if the TOML key exists. */
static void config_set_port(const al_toml_value *tbl, const char *key,
                            al_u16 *field, al_bool *enabled) {
    al_i64 val;
    if (al_toml_i64(tbl, key, &val) && val >= 0 && val <= 65535) {
        *field = (al_u16)val;
        if (enabled) *enabled = AL_TRUE;
    }
}

/* Set a config bool field only if the TOML key exists. */
static void config_set_bool(const al_toml_value *tbl, const char *key,
                            al_bool *field) {
    al_bool val;
    if (al_toml_bool(tbl, key, &val))
        *field = val;
}

/* Set a config u32 field only if the TOML key exists. */
static void config_set_u32(const al_toml_value *tbl, const char *key,
                           al_u32 *field) {
    al_i64 val;
    if (al_toml_i64(tbl, key, &val) && val >= 0)
        *field = (al_u32)val;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

al_status al_daemon_config_load_memory(const char *text, al_size len,
                                        al_daemon_config *config) {
    (void)len;
    if (!text || !config) return AL_ERR_INVALID_ARG;

    al_toml_value *root = NULL;
    AL_TRY(al_toml_parse(text, &root));

    /* [node] */
    const al_toml_value *node = al_toml_get(root, "node");
    if (node) {
        config_set_string(node, "data_dir", &config->data_dir);
        config_set_bool(node, "allow_insecure_crypto",
                        &config->allow_insecure_crypto);
    }

    /* [p2p] */
    const al_toml_value *p2p = al_toml_get(root, "p2p");
    if (p2p) {
        config_set_string(p2p, "host", &config->p2p_host);
        config_set_port(p2p, "port", &config->p2p_port, &config->enable_p2p);
        config_set_bool(p2p, "enabled", &config->enable_p2p);
        config_set_bool(p2p, "require_encryption",
                        &config->require_encrypted_transport);
    }

    /* [rpc] */
    const al_toml_value *rpc = al_toml_get(root, "rpc");
    if (rpc) {
        config_set_string(rpc, "host", &config->rpc_host);
        config_set_port(rpc, "port", &config->rpc_port, &config->enable_rpc);
        config_set_bool(rpc, "enabled", &config->enable_rpc);
        config_set_bool(rpc, "unsafe_methods", &config->enable_unsafe_rpc);
        config_set_string(rpc, "token", &config->rpc_token);
    }

    /* [blocks] */
    const al_toml_value *blocks = al_toml_get(root, "blocks");
    if (blocks) {
        config_set_u32(blocks, "interval_ms", &config->block_interval_ms);
        config_set_bool(blocks, "empty", &config->produce_empty_blocks);
    }

    /* [proposer] */
    const al_toml_value *proposer = al_toml_get(root, "proposer");
    if (proposer) {
        config_set_string(proposer, "seed", &config->proposer_seed);
        config_set_string(proposer, "passphrase", &config->proposer_passphrase);
    }

    /* [log] */
    const al_toml_value *log = al_toml_get(root, "log");
    if (log) {
        config_set_string(log, "level", &config->log_level);
    }

    /* [[bootstrap]] - array of peer endpoints */
    const al_toml_value *bootstrap_arr = al_toml_get(root, "bootstrap");
    if (bootstrap_arr && bootstrap_arr->kind == AL_TOML_ARRAY) {
        for (al_size i = 0;
             i < bootstrap_arr->count && config->bootstrap_count < AL_DAEMON_MAX_BOOTSTRAP;
             i++) {
            const al_toml_value *item = bootstrap_arr->items[i];
            if (item && item->kind == AL_TOML_STRING && item->string) {
                config->bootstrap[config->bootstrap_count++] = item->string;
            }
        }
    }

    /* Also support [bootstrap] as a sub-table with numbered entries:
     * [bootstrap]
     * peer1 = "host:port"
     * peer2 = "host:port"
     */
    const al_toml_value *bootstrap_tbl = al_toml_get(root, "bootstrap");
    if (bootstrap_tbl && bootstrap_tbl->kind == AL_TOML_TABLE) {
        for (al_size i = 0;
             i < bootstrap_tbl->length && config->bootstrap_count < AL_DAEMON_MAX_BOOTSTRAP;
             i++) {
            const char *val;
            if (al_toml_as_string(bootstrap_tbl->values[i], &val) && val) {
                config->bootstrap[config->bootstrap_count++] = val;
            }
        }
    }

    /* [consensus] validators = ["<public-key-hex>", ...] */
    const al_toml_value *consensus = al_toml_get(root, "consensus");
    if (consensus) {
        config_set_u32(consensus, "round_timeout_ms",
                       &config->round_timeout_ms);
        const al_toml_value *validators = al_toml_get(consensus, "validators");
        if (validators && validators->kind == AL_TOML_ARRAY) {
            for (al_size i = 0u;
                 i < validators->count &&
                 config->validator_count < AL_DAEMON_MAX_VALIDATORS;
                 ++i) {
                const al_toml_value *item = validators->items[i];
                if (item && item->kind == AL_TOML_STRING && item->string) {
                    config->validators[config->validator_count++] =
                        item->string;
                }
            }
        }
    }

    /* al_toml_free(root); — intentionally leaked; parsed once at startup. */
    return AL_OK;
}

al_status al_daemon_config_load(const char *path, al_daemon_config *config) {
    if (!path || !config) return AL_ERR_INVALID_ARG;
    char *text = NULL;
    al_size len = 0;
    AL_TRY(read_config_file(path, &text, &len));
    al_status s = al_daemon_config_load_memory(text, len, config);
    free(text);
    return s;
}

/* ------------------------------------------------------------------ */
/* Validation                                                           */
/* ------------------------------------------------------------------ */

static al_bool log_level_valid(const char *level) {
    if (level == NULL) return AL_TRUE; /* NULL = use default */
    return strcmp(level, "trace") == 0 || strcmp(level, "debug") == 0 ||
           strcmp(level, "info") == 0 || strcmp(level, "warn") == 0 ||
           strcmp(level, "error") == 0 || strcmp(level, "fatal") == 0 ||
           strcmp(level, "silent") == 0;
}

al_status al_daemon_config_validate(const al_daemon_config *config) {
    if (config == NULL) return AL_ERR_INVALID_ARG;
    if (config->data_dir == NULL || config->data_dir[0] == '\0') {
        return AL_ERR_INVALID_ARG;
    }
    if (!log_level_valid(config->log_level)) {
        return AL_ERR_INVALID_ARG;
    }
    return AL_OK;
}
