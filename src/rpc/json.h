/*
 * Minimal JSON for the RPC server.
 *
 * The node speaks JSON-RPC 2.0, and the dependency rule of this project says
 * that means writing a JSON parser. It is deliberately small:
 *
 *   - the parser builds a plain DOM with malloc'd nodes; requests are bounded
 *     by the HTTP body limit, so worst-case memory is known;
 *   - objects, arrays, strings, booleans, null and numbers are supported;
 *     numbers are stored as u64/i64 doubles-free - consensus values never go
 *     near floating point;
 *   - \uXXXX escapes decode to UTF-8; unpaired surrogates are rejected;
 *   - the writer is a growable byte buffer with correct string escaping.
 */

#ifndef ASTROLUNE_RPC_JSON_H
#define ASTROLUNE_RPC_JSON_H

#include "astrolune/base.h"
#include "astrolune/bytes.h"

AL_EXTERN_C_BEGIN

typedef enum al_json_kind {
    AL_JSON_NULL = 0,
    AL_JSON_FALSE,
    AL_JSON_TRUE,
    AL_JSON_U64,
    AL_JSON_I64,
    AL_JSON_STRING,
    AL_JSON_ARRAY,
    AL_JSON_OBJECT,
    AL_JSON_KIND_SENTINEL = 0x7fffffff
} al_json_kind;

typedef struct al_json_value al_json_value;

struct al_json_value {
    al_json_kind kind;
    /* AL_JSON_U64 / AL_JSON_I64 */
    al_u64 u64_value;
    al_i64 i64_value;
    /* AL_JSON_STRING: NUL-terminated, owned. */
    char *string;
    /* AL_JSON_ARRAY / AL_JSON_OBJECT: element/key-value storage. For objects,
     * children[i] is the value and keys[i] its key. */
    al_json_value **children;
    char **keys;
    al_size count;
};

/* Parse `text` (NUL-terminated). Returns AL_ERR_MALFORMED on invalid input.
 * A successful parse must be released with al_json_free. */
AL_NODISCARD al_status al_json_parse(const char *text, al_json_value **out);
void al_json_free(al_json_value *value);

/* Object member lookup by key. Returns NULL when absent or not an object. */
const al_json_value *al_json_get(const al_json_value *object, const char *key);

/* Convenience accessors; NULL-safe and type-checked. */
AL_NODISCARD al_bool al_json_as_u64(const al_json_value *value, al_u64 *out);
AL_NODISCARD const char *al_json_as_string(const al_json_value *value);

/* --- Writer -----------------------------------------------------------------
 * Growable output buffer. Every append can fail only through allocation;
 * failures latch into status and surface at al_json_writer_finish.
 * -------------------------------------------------------------------------- */

typedef struct al_json_writer {
    char    *data;
    al_size  len;
    al_size  cap;
    al_status status;   /* sticky */
} al_json_writer;

void al_json_writer_init(al_json_writer *writer);
void al_json_writer_free(al_json_writer *writer);

void al_json_writer_raw(al_json_writer *writer, const char *text);
void al_json_writer_u64(al_json_writer *writer, al_u64 value);
void al_json_writer_i64(al_json_writer *writer, al_i64 value);
/* Appends the quoted-and-escaped form including surrounding quotes. */
void al_json_writer_string(al_json_writer *writer, const char *text);
/* Appends raw bytes as a hex string ("0x…" included). */
void al_json_writer_hex(al_json_writer *writer, al_bytes data);

AL_NODISCARD al_status al_json_writer_finish(const al_json_writer *writer);
/* Borrowed, NUL-terminated view of what has been written so far. */
const char *al_json_writer_text(const al_json_writer *writer);

AL_EXTERN_C_END

#endif /* ASTROLUNE_RPC_JSON_H */
