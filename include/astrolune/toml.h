/*
 * Minimal TOML parser for configuration files.
 *
 * Supports: key = value (string, integer, boolean), [sections],
 * dotted keys, # comments, inline tables { k = v }, and string arrays.
 * Intentionally minimal — enough for node configuration, not a full spec.
 */

#ifndef ASTROLUNE_TOML_H
#define ASTROLUNE_TOML_H

#include "astrolune/base.h"

AL_EXTERN_C_BEGIN

typedef enum al_toml_kind {
    AL_TOML_STRING = 0,
    AL_TOML_INTEGER,
    AL_TOML_BOOLEAN,
    AL_TOML_ARRAY,
    AL_TOML_TABLE,
    AL_TOML_KIND_SENTINEL = 0x7fffffff
} al_toml_kind;

typedef struct al_toml_value al_toml_value;

struct al_toml_value {
    al_toml_kind kind;
    /* AL_TOML_STRING */
    char        *string;
    /* AL_TOML_INTEGER */
    al_i64       integer;
    /* AL_TOML_BOOLEAN */
    al_bool      boolean;
    /* AL_TOML_ARRAY: homogeneous array of values */
    al_toml_value **items;
    al_size        count;
    /* AL_TOML_TABLE: key-value pairs */
    char         **keys;
    al_toml_value **values;
    al_size        length;
};

/* Parse a NUL-terminated TOML string. Returns AL_OK on success.
 * The result must be freed with al_toml_free. */
AL_NODISCARD al_status al_toml_parse(const char *text, al_toml_value **out);
void al_toml_free(al_toml_value *value);

/* Table lookup. Returns NULL if not found or not a table. */
const al_toml_value *al_toml_get(const al_toml_value *table, const char *key);

/* Nested lookup: "section.key" traverses tables. */
const al_toml_value *al_toml_get_path(const al_toml_value *root,
                                      const char *path);

/* Type-safe accessors; return AL_FALSE on type mismatch or NULL input. */
AL_NODISCARD al_bool al_toml_as_string(const al_toml_value *value, const char **out);
AL_NODISCARD al_bool al_toml_as_i64(const al_toml_value *value, al_i64 *out);
AL_NODISCARD al_bool al_toml_as_bool(const al_toml_value *value, al_bool *out);

/* Convenience: lookup + convert in one call. Returns AL_FALSE on
 * missing key or type mismatch. */
AL_NODISCARD al_bool al_toml_string(const al_toml_value *table,
                                    const char *key, const char **out);
AL_NODISCARD al_bool al_toml_i64(const al_toml_value *table,
                                 const char *key, al_i64 *out);
AL_NODISCARD al_bool al_toml_bool(const al_toml_value *table,
                                  const char *key, al_bool *out);

AL_EXTERN_C_END

#endif /* ASTROLUNE_TOML_H */
