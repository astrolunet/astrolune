/* Minimal JSON parser and writer. See json.h for the contract. */

#include "json.h"
#include "internal/common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Requests are bounded by the RPC body limit; a parse depth beyond this is
 * indistinguishable from an attack and is rejected outright. */
#define JSON_MAX_DEPTH 32u

/* --- Parser ----------------------------------------------------------------- */

typedef struct json_parser {
    const char *text;
    al_size     pos;
    al_size     depth;
    al_status   status;
} json_parser;

static void skip_whitespace(json_parser *p) {
    while (p->text[p->pos] == ' ' || p->text[p->pos] == '\t' ||
           p->text[p->pos] == '\n' || p->text[p->pos] == '\r') {
        p->pos++;
    }
}

static char peek(json_parser *p) {
    return p->text[p->pos];
}

static void fail(json_parser *p, al_status status) {
    if (p->status == AL_OK) p->status = status;
}

static char next_char(json_parser *p) {
    char c = p->text[p->pos];
    if (c != '\0') p->pos++;
    return c;
}

static al_bool consume(json_parser *p, char expected) {
    if (peek(p) != expected) {
        fail(p, AL_ERR_MALFORMED);
        return AL_FALSE;
    }
    p->pos++;
    return AL_TRUE;
}

static char *parse_string_raw(json_parser *p) {
    if (!consume(p, '"')) return NULL;

    /* Decode into a growable buffer. The decoded form is never longer than
     * the source escape sequence it came from. */
    al_size cap = 16u;
    al_size len = 0u;
    char *out = (char *)malloc(cap);
    if (out == NULL) {
        fail(p, AL_ERR_OUT_OF_MEMORY);
        return NULL;
    }

    for (;;) {
        char c = next_char(p);
        if (c == '\0') {
            fail(p, AL_ERR_TRUNCATED);
            free(out);
            return NULL;
        }
        if (c == '"') break;

        /* Ensure room for a UTF-8 lead byte plus three continuation bytes
         * and the terminator in the worst case. */
        if (len + 4u + 1u > cap) {
            cap *= 2u;
            char *grown = (char *)realloc(out, cap);
            if (grown == NULL) {
                fail(p, AL_ERR_OUT_OF_MEMORY);
                free(out);
                return NULL;
            }
            out = grown;
        }

        if (c != '\\') {
            out[len++] = c;
            continue;
        }

        char escape = next_char(p);
        switch (escape) {
        case '"': out[len++] = '"'; break;
        case '\\': out[len++] = '\\'; break;
        case '/': out[len++] = '/'; break;
        case 'b': out[len++] = '\b'; break;
        case 'f': out[len++] = '\f'; break;
        case 'n': out[len++] = '\n'; break;
        case 'r': out[len++] = '\r'; break;
        case 't': out[len++] = '\t'; break;
        case 'u': {
            unsigned code = 0u;
            for (int i = 0; i < 4; ++i) {
                char hex = next_char(p);
                unsigned digit;
                if (hex >= '0' && hex <= '9') {
                    digit = (unsigned)(hex - '0');
                } else if (hex >= 'a' && hex <= 'f') {
                    digit = (unsigned)(hex - 'a') + 10u;
                } else if (hex >= 'A' && hex <= 'F') {
                    digit = (unsigned)(hex - 'A') + 10u;
                } else {
                    fail(p, AL_ERR_MALFORMED);
                    free(out);
                    return NULL;
                }
                code = code * 16u + digit;
            }
            if (code < 0x80u) {
                out[len++] = (char)code;
            } else if (code < 0x800u) {
                out[len++] = (char)(0xC0u | (code >> 6));
                out[len++] = (char)(0x80u | (code & 0x3Fu));
            } else {
                /* Surrogate halves would need pairing; the RPC surface has no
                 * use for astral characters, so reject them as malformed. */
                if (code >= 0xD800u && code <= 0xDFFFu) {
                    fail(p, AL_ERR_MALFORMED);
                    free(out);
                    return NULL;
                }
                out[len++] = (char)(0xE0u | (code >> 12));
                out[len++] = (char)(0x80u | ((code >> 6) & 0x3Fu));
                out[len++] = (char)(0x80u | (code & 0x3Fu));
            }
            break;
        }
        default:
            fail(p, AL_ERR_MALFORMED);
            free(out);
            return NULL;
        }
    }
    out[len] = '\0';
    return out;
}

static al_json_value *value_new(al_json_kind kind) {
    al_json_value *value = (al_json_value *)calloc(1u, sizeof(*value));
    if (value != NULL) value->kind = kind;
    return value;
}

static al_status array_append(al_json_value *parent, char *key,
                              al_json_value *child) {
    al_json_value **children = (al_json_value **)realloc(
        parent->children, (parent->count + 1u) * sizeof(*children));
    if (children == NULL) return AL_ERR_OUT_OF_MEMORY;
    parent->children = children;
    if (key != NULL) {
        char **keys =
            (char **)realloc(parent->keys, (parent->count + 1u) * sizeof(*keys));
        if (keys == NULL) return AL_ERR_OUT_OF_MEMORY;
        parent->keys = keys;
        parent->keys[parent->count] = key;
    }
    parent->children[parent->count] = child;
    parent->count++;
    return AL_OK;
}

static al_json_value *parse_value(json_parser *p);

/* Numbers: integers only. A decimal point or exponent makes the value unfit
 * for consensus arithmetic and is rejected rather than rounded silently. */
static al_json_value *parse_number(json_parser *p) {
    al_size start = p->pos;
    al_bool negative = AL_FALSE;
    if (peek(p) == '-') {
        negative = AL_TRUE;
        p->pos++;
    }
    while (peek(p) >= '0' && peek(p) <= '9') p->pos++;
    if (peek(p) == '.' || peek(p) == 'e' || peek(p) == 'E') {
        fail(p, AL_ERR_UNSUPPORTED);
        return NULL;
    }
    if (p->pos == start || (negative && p->pos == start + 1u)) {
        fail(p, AL_ERR_MALFORMED);
        return NULL;
    }

    char buffer[32];
    al_size digits = p->pos - start;
    if (digits >= sizeof(buffer)) {
        fail(p, AL_ERR_OUT_OF_RANGE);
        return NULL;
    }
    memcpy(buffer, p->text + start, digits);
    buffer[digits] = '\0';

    al_json_value *value = NULL;
    if (negative) {
        value = value_new(AL_JSON_I64);
        if (value != NULL) value->i64_value = strtoll(buffer, NULL, 10);
    } else {
        value = value_new(AL_JSON_U64);
        if (value != NULL) value->u64_value = strtoull(buffer, NULL, 10);
    }
    if (value == NULL) fail(p, AL_ERR_OUT_OF_MEMORY);
    return value;
}

static al_json_value *parse_value(json_parser *p) {
    if (p->status != AL_OK) return NULL;
    if (++p->depth > JSON_MAX_DEPTH) {
        fail(p, AL_ERR_OUT_OF_RANGE);
        return NULL;
    }

    skip_whitespace(p);
    al_json_value *result = NULL;
    char c = peek(p);

    if (c == '{') {
        p->pos++;
        result = value_new(AL_JSON_OBJECT);
        if (result == NULL) {
            fail(p, AL_ERR_OUT_OF_MEMORY);
        } else {
            skip_whitespace(p);
            if (peek(p) == '}') {
                p->pos++;
            } else {
                for (;;) {
                    char *key = parse_string_raw(p);
                    if (key == NULL) break;
                    skip_whitespace(p);
                    if (!consume(p, ':')) {
                        free(key);
                        break;
                    }
                    al_json_value *child = parse_value(p);
                    if (child == NULL || array_append(result, key, child) !=
                                             AL_OK) {
                        free(key);
                        break;
                    }
                    skip_whitespace(p);
                    if (peek(p) == ',') {
                        p->pos++;
                        skip_whitespace(p);
                        continue;
                    }
                    if (consume(p, '}')) break;
                    break;
                }
            }
        }
    } else if (c == '[') {
        p->pos++;
        result = value_new(AL_JSON_ARRAY);
        if (result == NULL) {
            fail(p, AL_ERR_OUT_OF_MEMORY);
        } else {
            skip_whitespace(p);
            if (peek(p) == ']') {
                p->pos++;
            } else {
                for (;;) {
                    al_json_value *child = parse_value(p);
                    if (child == NULL ||
                        array_append(result, NULL, child) != AL_OK) {
                        break;
                    }
                    skip_whitespace(p);
                    if (peek(p) == ',') {
                        p->pos++;
                        skip_whitespace(p);
                        continue;
                    }
                    if (consume(p, ']')) break;
                    break;
                }
            }
        }
    } else if (c == '"') {
        char *text = parse_string_raw(p);
        if (text != NULL) {
            result = value_new(AL_JSON_STRING);
            if (result == NULL) {
                free(text);
                fail(p, AL_ERR_OUT_OF_MEMORY);
            } else {
                result->string = text;
            }
        }
    } else if (c == 't') {
        p->pos += 3u;
        if (consume(p, 'e')) {
            result = value_new(AL_JSON_TRUE);
        }
    } else if (c == 'f') {
        p->pos += 4u;
        if (consume(p, 'e')) {
            result = value_new(AL_JSON_FALSE);
        }
    } else if (c == 'n') {
        p->pos += 3u;
        if (consume(p, 'l')) {
            result = value_new(AL_JSON_NULL);
        }
    } else if (c == '-' || (c >= '0' && c <= '9')) {
        result = parse_number(p);
    } else {
        fail(p, AL_ERR_MALFORMED);
    }

    p->depth--;
    return result;
}

al_status al_json_parse(const char *text, al_json_value **out) {
    if (text == NULL || out == NULL) return AL_ERR_INVALID_ARG;
    *out = NULL;
    json_parser parser = { text, 0u, 0u, AL_OK };
    al_json_value *value = parse_value(&parser);
    if (parser.status != AL_OK) {
        al_json_free(value);
        return parser.status;
    }
    skip_whitespace(&parser);
    if (parser.text[parser.pos] != '\0') {
        al_json_free(value);
        return AL_ERR_TRAILING_BYTES;
    }
    *out = value;
    return AL_OK;
}

void al_json_free(al_json_value *value) {
    if (value == NULL) return;
    for (al_size i = 0u; i < value->count; ++i) {
        al_json_free(value->children[i]);
        if (value->keys != NULL) free(value->keys[i]);
    }
    free(value->children);
    free(value->keys);
    free(value->string);
    free(value);
}

const al_json_value *al_json_get(const al_json_value *object,
                                 const char *key) {
    if (object == NULL || object->kind != AL_JSON_OBJECT || key == NULL) {
        return NULL;
    }
    for (al_size i = 0u; i < object->count; ++i) {
        if (strcmp(object->keys[i], key) == 0) return object->children[i];
    }
    return NULL;
}

al_bool al_json_as_u64(const al_json_value *value, al_u64 *out) {
    if (value == NULL || out == NULL) return AL_FALSE;
    if (value->kind == AL_JSON_U64) {
        *out = value->u64_value;
        return AL_TRUE;
    }
    if (value->kind == AL_JSON_I64 && value->i64_value >= 0) {
        *out = (al_u64)value->i64_value;
        return AL_TRUE;
    }
    return AL_FALSE;
}

const char *al_json_as_string(const al_json_value *value) {
    if (value == NULL || value->kind != AL_JSON_STRING) return NULL;
    return value->string;
}

/* --- Writer ------------------------------------------------------------------- */

static void writer_reserve(al_json_writer *writer, al_size extra) {
    if (writer->status != AL_OK) return;
    if (writer->len + extra + 1u <= writer->cap) return;
    al_size cap = writer->cap != 0u ? writer->cap : 256u;
    while (cap < writer->len + extra + 1u) cap *= 2u;
    char *grown = (char *)realloc(writer->data, cap);
    if (grown == NULL) {
        writer->status = AL_ERR_OUT_OF_MEMORY;
        return;
    }
    /* Fresh memory is not terminated; guarantee the invariant here so an
     * empty writer is always a valid empty C string. */
    if (writer->data == NULL) grown[0] = '\0';
    writer->data = grown;
    writer->cap = cap;
}

static void writer_append(al_json_writer *writer, const char *text,
                          al_size len) {
    writer_reserve(writer, len);
    if (writer->status != AL_OK) return;
    memcpy(writer->data + writer->len, text, len);
    writer->len += len;
    writer->data[writer->len] = '\0';
}

void al_json_writer_init(al_json_writer *writer) {
    al_memzero(writer, sizeof(*writer));
    writer_reserve(writer, 0u); /* establish the NUL terminator early */
}

void al_json_writer_free(al_json_writer *writer) {
    if (writer == NULL) return;
    free(writer->data);
    al_memzero(writer, sizeof(*writer));
}

void al_json_writer_raw(al_json_writer *writer, const char *text) {
    writer_append(writer, text, strlen(text));
}

void al_json_writer_u64(al_json_writer *writer, al_u64 value) {
    char buffer[24];
    (void)snprintf(buffer, sizeof(buffer), "%llu", (unsigned long long)value);
    writer_append(writer, buffer, strlen(buffer));
}

void al_json_writer_i64(al_json_writer *writer, al_i64 value) {
    char buffer[24];
    (void)snprintf(buffer, sizeof(buffer), "%lld", (long long)value);
    writer_append(writer, buffer, strlen(buffer));
}

void al_json_writer_string(al_json_writer *writer, const char *text) {
    writer_append(writer, "\"", 1u);
    for (const char *p = text; *p != '\0'; ++p) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
        case '"': writer_append(writer, "\\\"", 2u); break;
        case '\\': writer_append(writer, "\\\\", 2u); break;
        case '\b': writer_append(writer, "\\b", 2u); break;
        case '\f': writer_append(writer, "\\f", 2u); break;
        case '\n': writer_append(writer, "\\n", 2u); break;
        case '\r': writer_append(writer, "\\r", 2u); break;
        case '\t': writer_append(writer, "\\t", 2u); break;
        default:
            if (c < 0x20u) {
                char escape[8];
                (void)snprintf(escape, sizeof(escape), "\\u%04x", (unsigned)c);
                writer_append(writer, escape, strlen(escape));
            } else {
                writer_append(writer, p, 1u);
            }
            break;
        }
    }
    writer_append(writer, "\"", 1u);
}

void al_json_writer_hex(al_json_writer *writer, al_bytes data) {
    writer_append(writer, "\"0x", 3u);
    static const char digits[] = "0123456789abcdef";
    for (al_size i = 0u; i < data.len; ++i) {
        char pair[2] = { digits[data.data[i] >> 4], digits[data.data[i] & 15u] };
        writer_append(writer, pair, 2u);
    }
    writer_append(writer, "\"", 1u);
}

al_status al_json_writer_finish(const al_json_writer *writer) {
    return writer->status;
}

const char *al_json_writer_text(const al_json_writer *writer) {
    return writer->data != NULL ? writer->data : "";
}
