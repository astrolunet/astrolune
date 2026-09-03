/* Minimal TOML parser. See toml.h for design notes. */

#include "astrolune/toml.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Arena-style bump allocator for parse results                        */
/* ------------------------------------------------------------------ */

typedef struct toml_alloc {
    void   *blocks[256];
    al_size count;
} toml_alloc;

static void *toml_alloc_pick(toml_alloc *a, al_size size, al_size align) {
    /* Simple: just use malloc for each allocation. */
    (void)align;
    void *p = malloc(size);
    if (p) memset(p, 0, size);
    if (p && a->count < 256) a->blocks[a->count++] = p;
    return p;
}

static char *toml_alloc_str(toml_alloc *a, const char *start, al_size len) {
    char *s = (char *)toml_alloc_pick(a, len + 1u, 1);
    if (s) {
        memcpy(s, start, len);
        s[len] = '\0';
    }
    return s;
}

static char *toml_strdup(toml_alloc *a, const char *s) {
    return toml_alloc_str(a, s, strlen(s));
}

/* ------------------------------------------------------------------ */
/* Tokenizer                                                           */
/* ------------------------------------------------------------------ */

typedef enum toml_token_kind {
    TOK_KEY,
    TOK_STRING,
    TOK_INTEGER,
    TOK_TRUE,
    TOK_FALSE,
    TOK_LBRACKET,   /* [ */
    TOK_RBRACKET,   /* ] */
    TOK_LBRACE,     /* { */
    TOK_RBRACE,     /* } */
    TOK_EQUALS,     /* = */
    TOK_COMMA,      /* , */
    TOK_DOT,        /* . */
    TOK_EOF,
    TOK_ERROR
} toml_token_kind;

typedef struct toml_token {
    toml_token_kind kind;
    const char     *start;
    al_size         len;
} toml_token;

typedef struct toml_lexer {
    const char *pos;
    const char *end;
} toml_lexer;

static void lexer_skip_whitespace_and_comments(toml_lexer *lex) {
    while (lex->pos < lex->end) {
        char c = *lex->pos;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            lex->pos++;
        } else if (c == '#') {
            /* skip comment to end of line */
            while (lex->pos < lex->end && *lex->pos != '\n')
                lex->pos++;
        } else {
            break;
        }
    }
}

static toml_token lexer_next(toml_lexer *lex) {
    toml_token tok = { TOK_ERROR, NULL, 0 };
    lexer_skip_whitespace_and_comments(lex);
    if (lex->pos >= lex->end) {
        tok.kind = TOK_EOF;
        return tok;
    }
    char c = *lex->pos;
    switch (c) {
    case '[': tok.kind = TOK_LBRACKET; tok.start = lex->pos; tok.len = 1; lex->pos++; return tok;
    case ']': tok.kind = TOK_RBRACKET; tok.start = lex->pos; tok.len = 1; lex->pos++; return tok;
    case '{': tok.kind = TOK_LBRACE;   tok.start = lex->pos; tok.len = 1; lex->pos++; return tok;
    case '}': tok.kind = TOK_RBRACE;   tok.start = lex->pos; tok.len = 1; lex->pos++; return tok;
    case '=': tok.kind = TOK_EQUALS;   tok.start = lex->pos; tok.len = 1; lex->pos++; return tok;
    case ',': tok.kind = TOK_COMMA;    tok.start = lex->pos; tok.len = 1; lex->pos++; return tok;
    case '.': tok.kind = TOK_DOT;      tok.start = lex->pos; tok.len = 1; lex->pos++; return tok;
    case '"': {
        /* quoted string */
        lex->pos++;
        const char *str_start = lex->pos;
        while (lex->pos < lex->end && *lex->pos != '"') {
            if (*lex->pos == '\\') lex->pos++; /* skip escaped char */
            lex->pos++;
        }
        tok.kind = TOK_STRING;
        tok.start = str_start;
        tok.len = (al_size)(lex->pos - str_start);
        if (lex->pos < lex->end) lex->pos++; /* skip closing " */
        return tok;
    }
    default: {
        if (c == '-' || (c >= '0' && c <= '9')) {
            /* integer (possibly negative) */
            const char *num_start = lex->pos;
            if (c == '-') lex->pos++;
            while (lex->pos < lex->end && *lex->pos >= '0' && *lex->pos <= '9')
                lex->pos++;
            tok.kind = TOK_INTEGER;
            tok.start = num_start;
            tok.len = (al_size)(lex->pos - num_start);
            return tok;
        }
        if (isalpha((unsigned char)c) || c == '_' || c == '-') {
            /* bare key or boolean */
            const char *id_start = lex->pos;
            while (lex->pos < lex->end &&
                   (isalnum((unsigned char)*lex->pos) || *lex->pos == '_' || *lex->pos == '-'))
                lex->pos++;
            tok.start = id_start;
            tok.len = (al_size)(lex->pos - id_start);
            if (tok.len == 4 && memcmp(id_start, "true", 4) == 0) {
                tok.kind = TOK_TRUE;
            } else if (tok.len == 5 && memcmp(id_start, "false", 5) == 0) {
                tok.kind = TOK_FALSE;
            } else {
                tok.kind = TOK_KEY;
            }
            return tok;
        }
        /* unknown character — skip it */
        lex->pos++;
        tok.kind = TOK_ERROR;
        tok.start = lex->pos - 1;
        tok.len = 1;
        return tok;
    }
    }
}

/* ------------------------------------------------------------------ */
/* Parser                                                              */
/* ------------------------------------------------------------------ */

typedef struct toml_parser {
    toml_lexer  lex;
    toml_token  cur;
    toml_alloc *alloc;
    al_status   status;
} toml_parser;

static void parser_advance(toml_parser *p) {
    p->cur = lexer_next(&p->lex);
}

static al_bool parser_match(toml_parser *p, toml_token_kind kind) {
    if (p->cur.kind == kind) {
        parser_advance(p);
        return AL_TRUE;
    }
    return AL_FALSE;
}

static al_bool parser_expect(toml_parser *p, toml_token_kind kind) {
    if (p->cur.kind == kind) {
        parser_advance(p);
        return AL_TRUE;
    }
    p->status = AL_ERR_MALFORMED;
    return AL_FALSE;
}

/* Create a new TOML value node. */
static al_toml_value *toml_new_value(toml_parser *p, al_toml_kind kind) {
    al_toml_value *v = (al_toml_value *)toml_alloc_pick(p->alloc, sizeof(al_toml_value), 8);
    if (v) v->kind = kind;
    return v;
}

/* Parse a string literal (already tokenized). Handles escape sequences. */
static char *toml_parse_string_value(toml_parser *p, const toml_token *tok) {
    /* Allocate worst-case (same length + room for escapes). */
    char *buf = (char *)toml_alloc_pick(p->alloc, tok->len + 1u, 1);
    if (!buf) { p->status = AL_ERR_OUT_OF_MEMORY; return NULL; }
    al_size out = 0;
    const char *s = tok->start;
    const char *end = tok->start + tok->len;
    while (s < end) {
        if (*s == '\\' && s + 1 < end) {
            s++;
            switch (*s) {
            case 'n':  buf[out++] = '\n'; break;
            case 't':  buf[out++] = '\t'; break;
            case 'r':  buf[out++] = '\r'; break;
            case '\\': buf[out++] = '\\'; break;
            case '"':  buf[out++] = '"';  break;
            default:   buf[out++] = *s;   break;
            }
            s++;
        } else {
            buf[out++] = *s++;
        }
    }
    buf[out] = '\0';
    return buf;
}

/* Forward declarations. */
static al_toml_value *parse_value(toml_parser *p);
static al_toml_value *parse_inline_table(toml_parser *p);

/* Parse an array: [ v1, v2, ... ] */
static al_toml_value *parse_array(toml_parser *p) {
    al_toml_value *arr = toml_new_value(p, AL_TOML_ARRAY);
    if (!arr) return NULL;
    parser_advance(p); /* consume [ */
    /* allocate items array (growable) */
    al_size cap = 8;
    arr->items = (al_toml_value **)toml_alloc_pick(p->alloc, cap * sizeof(al_toml_value *), 8);
    arr->count = 0;
    if (!arr->items) { p->status = AL_ERR_OUT_OF_MEMORY; return NULL; }

    while (p->cur.kind != TOK_RBRACKET && p->cur.kind != TOK_EOF) {
        al_toml_value *item = parse_value(p);
        if (!item || p->status != AL_OK) return NULL;
        if (arr->count >= cap) {
            cap *= 2;
            /* Can't realloc in bump alloc; just report error. */
            p->status = AL_ERR_OUT_OF_MEMORY;
            return NULL;
        }
        arr->items[arr->count++] = item;
        parser_match(p, TOK_COMMA); /* optional trailing comma */
    }
    parser_expect(p, TOK_RBRACKET);
    return arr;
}

/* Parse a value: string, integer, boolean, array, or inline table. */
static al_toml_value *parse_value(toml_parser *p) {
    switch (p->cur.kind) {
    case TOK_STRING: {
        al_toml_value *v = toml_new_value(p, AL_TOML_STRING);
        if (v) v->string = toml_parse_string_value(p, &p->cur);
        parser_advance(p);
        return v;
    }
    case TOK_INTEGER: {
        al_toml_value *v = toml_new_value(p, AL_TOML_INTEGER);
        if (v) {
            v->integer = 0;
            const char *s = p->cur.start;
            al_bool negative = AL_FALSE;
            if (*s == '-') { negative = AL_TRUE; s++; }
            while (s < p->cur.start + p->cur.len) {
                v->integer = v->integer * 10 + (*s - '0');
                s++;
            }
            if (negative) v->integer = -v->integer;
        }
        parser_advance(p);
        return v;
    }
    case TOK_TRUE: {
        al_toml_value *v = toml_new_value(p, AL_TOML_BOOLEAN);
        if (v) v->boolean = AL_TRUE;
        parser_advance(p);
        return v;
    }
    case TOK_FALSE: {
        al_toml_value *v = toml_new_value(p, AL_TOML_BOOLEAN);
        if (v) v->boolean = AL_FALSE;
        parser_advance(p);
        return v;
    }
    case TOK_LBRACKET:
        return parse_array(p);
    case TOK_LBRACE:
        return parse_inline_table(p);
    case TOK_KEY:
    case TOK_RBRACKET:
    case TOK_RBRACE:
    case TOK_EQUALS:
    case TOK_COMMA:
    case TOK_DOT:
    case TOK_EOF:
    case TOK_ERROR:
        p->status = AL_ERR_MALFORMED;
        return NULL;
    }
    return NULL;
}

/* Parse inline table: { key = val, key2 = val2 } */
static al_toml_value *parse_inline_table(toml_parser *p) {
    al_toml_value *tbl = toml_new_value(p, AL_TOML_TABLE);
    if (!tbl) return NULL;
    parser_advance(p); /* consume { */

    al_size cap = 8;
    tbl->keys = (char **)toml_alloc_pick(p->alloc, cap * sizeof(char *), 8);
    tbl->values = (al_toml_value **)toml_alloc_pick(p->alloc, cap * sizeof(al_toml_value *), 8);
    tbl->length = 0;
    if (!tbl->keys || !tbl->values) { p->status = AL_ERR_OUT_OF_MEMORY; return NULL; }

    while (p->cur.kind != TOK_RBRACE && p->cur.kind != TOK_EOF) {
        if (p->cur.kind != TOK_KEY && p->cur.kind != TOK_STRING) {
            p->status = AL_ERR_MALFORMED;
            return NULL;
        }
        char *key = toml_alloc_str(p->alloc, p->cur.start, p->cur.len);
        parser_advance(p);
        if (!parser_expect(p, TOK_EQUALS)) return NULL;
        al_toml_value *val = parse_value(p);
        if (!val || p->status != AL_OK) return NULL;
        if (tbl->length >= cap) {
            cap *= 2;
            p->status = AL_ERR_OUT_OF_MEMORY;
            return NULL;
        }
        tbl->keys[tbl->length] = key;
        tbl->values[tbl->length] = val;
        tbl->length++;
        parser_match(p, TOK_COMMA);
    }
    parser_expect(p, TOK_RBRACE);
    return tbl;
}

/* Ensure a table value has allocated key/value arrays. */
static void ensure_table(toml_parser *p, al_toml_value *tbl) {
    if (tbl->keys == NULL) {
        al_size cap = 16;
        tbl->keys = (char **)toml_alloc_pick(p->alloc, cap * sizeof(char *), 8);
        tbl->values = (al_toml_value **)toml_alloc_pick(p->alloc, cap * sizeof(al_toml_value *), 8);
        tbl->length = 0;
    }
}

/* Add a key-value pair to a table. */
static al_bool table_add(toml_parser *p, al_toml_value *tbl,
                         const char *key, al_toml_value *val) {
    ensure_table(p, tbl);
    if (tbl->length >= 16) { p->status = AL_ERR_OUT_OF_MEMORY; return AL_FALSE; }
    tbl->keys[tbl->length] = toml_strdup(p->alloc, key);
    tbl->values[tbl->length] = val;
    tbl->length++;
    return AL_TRUE;
}

/* Find or create a sub-table within a table for dotted keys / sections. */
static al_toml_value *table_get_or_create(toml_parser *p, al_toml_value *tbl,
                                          const char *key) {
    for (al_size i = 0; i < tbl->length; i++) {
        if (tbl->keys[i] && strcmp(tbl->keys[i], key) == 0 &&
            tbl->values[i]->kind == AL_TOML_TABLE)
            return tbl->values[i];
    }
    al_toml_value *sub = toml_new_value(p, AL_TOML_TABLE);
    if (!sub) return NULL;
    table_add(p, tbl, key, sub);
    return sub;
}

/* Parse a dotted key path like "a.b.c" and return the deepest table. */
static al_toml_value *resolve_dotted_path(toml_parser *p, al_toml_value *root,
                                          const char *key, al_size key_len) {
    al_toml_value *cur = root;
    const char *cursor = key;
    const char *end = key + key_len;
    while (cursor < end) {
        while (cursor < end && (*cursor == ' ' || *cursor == '\t')) cursor++;
        const char *segment_end = cursor;
        while (segment_end < end && *segment_end != '.') segment_end++;
        const char *trimmed_end = segment_end;
        while (trimmed_end > cursor &&
               (trimmed_end[-1] == ' ' || trimmed_end[-1] == '\t')) {
            trimmed_end--;
        }
        al_size segment_len = (al_size)(trimmed_end - cursor);
        if (segment_len == 0u || segment_len >= 256u) {
            p->status = AL_ERR_MALFORMED;
            return NULL;
        }
        char segment[256];
        memcpy(segment, cursor, segment_len);
        segment[segment_len] = '\0';
        cur = table_get_or_create(p, cur, segment);
        if (cur == NULL) return NULL;
        cursor = segment_end < end ? segment_end + 1 : end;
    }
    return cur;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

al_status al_toml_parse(const char *text, al_toml_value **out) {
    if (!text || !out) return AL_ERR_INVALID_ARG;
    *out = NULL;

    toml_alloc alloc = { { NULL }, 0 };
    toml_parser parser;
    parser.lex.pos = text;
    parser.lex.end = text + strlen(text);
    parser.alloc = &alloc;
    parser.status = AL_OK;

    al_toml_value *root = toml_new_value(&parser, AL_TOML_TABLE);
    if (!root) return AL_ERR_OUT_OF_MEMORY;
    ensure_table(&parser, root);

    /* Current section context (starts at root). */
    al_toml_value *section = root;

    parser_advance(&parser); /* prime the lexer */

    while (parser.cur.kind != TOK_EOF && parser.status == AL_OK) {
        if (parser.cur.kind == TOK_LBRACKET) {
            /* [section] or [section.subsection] */
            parser_advance(&parser); /* consume [ */

            /* Read the full section path (may contain dots). */
            const char *path_start = parser.cur.start;
            while (parser.cur.kind != TOK_RBRACKET && parser.cur.kind != TOK_EOF)
                parser_advance(&parser);

            al_size path_len = (al_size)(parser.cur.start - path_start);
            /* Strip trailing whitespace before ']'. */
            while (path_len > 0 &&
                   (path_start[path_len - 1] == ' ' ||
                    path_start[path_len - 1] == '\t'))
                path_len--;
            if (path_len == 0) { parser.status = AL_ERR_MALFORMED; break; }

            /* Resolve the path: create intermediate tables as needed. */
            section = resolve_dotted_path(&parser, root, path_start, path_len);

            parser_expect(&parser, TOK_RBRACKET);
            continue;
        }

        if (parser.cur.kind == TOK_KEY || parser.cur.kind == TOK_STRING) {
            /* key = value */
            const char *key_start = parser.cur.start;

            /* Handle dotted keys within a line: a.b.c = value */
            while (parser.cur.kind == TOK_KEY || parser.cur.kind == TOK_STRING ||
                   parser.cur.kind == TOK_DOT) {
                parser_advance(&parser);
            }

            al_size full_key_len = (al_size)(parser.cur.start - key_start);
            /* Strip trailing whitespace / dot (space before '=' is allowed in
             * TOML: `key = value`). */
            while (full_key_len > 0 &&
                   (key_start[full_key_len - 1] == ' ' ||
                    key_start[full_key_len - 1] == '\t' ||
                    key_start[full_key_len - 1] == '.'))
                full_key_len--;

            if (!parser_expect(&parser, TOK_EQUALS)) break;
            al_toml_value *val = parse_value(&parser);
            if (!val || parser.status != AL_OK) break;

            /* Check if key contains dots (dotted assignment). */
            al_bool has_dot = AL_FALSE;
            for (al_size i = 0; i < full_key_len; i++) {
                if (key_start[i] == '.') { has_dot = AL_TRUE; break; }
            }

            if (has_dot) {
                /* Split at last dot: parent.subkey = value */
                const char *last_dot = NULL;
                for (al_size i = full_key_len; i > 0; i--) {
                    if (key_start[i - 1] == '.') { last_dot = key_start + i - 1; break; }
                }
                al_size parent_len = (al_size)(last_dot - key_start);
                const char *leaf_key = last_dot + 1;
                al_size leaf_len = full_key_len - parent_len - 1;

                al_toml_value *parent = resolve_dotted_path(&parser, root,
                                                            key_start, parent_len);
                if (parent) {
                    char leaf[256];
                    if (leaf_len >= sizeof(leaf)) {
                        parser.status = AL_ERR_MALFORMED;
                        break;
                    }
                    memcpy(leaf, leaf_key, leaf_len);
                    leaf[leaf_len] = '\0';
                    table_add(&parser, parent, leaf, val);
                }
            } else {
                /* table_add duplicates the key into the parse result.  Pass
                 * the source slice directly so we do not leak a temporary
                 * allocation for every ordinary assignment. */
                char key[256];
                if (full_key_len >= sizeof(key)) {
                    parser.status = AL_ERR_MALFORMED;
                    break;
                }
                memcpy(key, key_start, full_key_len);
                key[full_key_len] = '\0';
                table_add(&parser, section, key, val);
            }
            continue;
        }

        /* Unexpected token — skip. */
        parser_advance(&parser);
    }

    if (parser.status != AL_OK) {
        al_toml_free(root);
        return parser.status;
    }
    *out = root;
    return AL_OK;
}

void al_toml_free(al_toml_value *value) {
    if (value == NULL) return;

    if (value->kind == AL_TOML_ARRAY) {
        for (al_size i = 0u; i < value->count; ++i) {
            al_toml_free(value->items[i]);
        }
        free(value->items);
    } else if (value->kind == AL_TOML_TABLE) {
        for (al_size i = 0u; i < value->length; ++i) {
            free(value->keys[i]);
            al_toml_free(value->values[i]);
        }
        free(value->keys);
        free(value->values);
    } else if (value->kind == AL_TOML_STRING) {
        free(value->string);
    }

    free(value);
}

const al_toml_value *al_toml_get(const al_toml_value *table, const char *key) {
    if (!table || table->kind != AL_TOML_TABLE) return NULL;
    for (al_size i = 0; i < table->length; i++) {
        if (table->keys[i] && strcmp(table->keys[i], key) == 0)
            return table->values[i];
    }
    return NULL;
}

const al_toml_value *al_toml_get_path(const al_toml_value *root,
                                      const char *path) {
    if (!root || !path) return NULL;
    const al_toml_value *cur = root;
    const char *cursor = path;
    while (*cursor != '\0' && cur != NULL) {
        const char *dot = strchr(cursor, '.');
        al_size segment_len = dot != NULL
                                  ? (al_size)(dot - cursor)
                                  : (al_size)strlen(cursor);
        if (segment_len == 0u || segment_len >= 256u) return NULL;
        char segment[256];
        memcpy(segment, cursor, segment_len);
        segment[segment_len] = '\0';
        cur = al_toml_get(cur, segment);
        cursor = dot != NULL ? dot + 1 : cursor + segment_len;
    }
    return cur;
}

al_bool al_toml_as_string(const al_toml_value *value, const char **out) {
    if (!value || value->kind != AL_TOML_STRING || !out) return AL_FALSE;
    *out = value->string;
    return AL_TRUE;
}

al_bool al_toml_as_i64(const al_toml_value *value, al_i64 *out) {
    if (!value || value->kind != AL_TOML_INTEGER || !out) return AL_FALSE;
    *out = value->integer;
    return AL_TRUE;
}

al_bool al_toml_as_bool(const al_toml_value *value, al_bool *out) {
    if (!value || value->kind != AL_TOML_BOOLEAN || !out) return AL_FALSE;
    *out = value->boolean;
    return AL_TRUE;
}

al_bool al_toml_string(const al_toml_value *table, const char *key,
                       const char **out) {
    return al_toml_as_string(al_toml_get(table, key), out);
}

al_bool al_toml_i64(const al_toml_value *table, const char *key,
                    al_i64 *out) {
    return al_toml_as_i64(al_toml_get(table, key), out);
}

al_bool al_toml_bool(const al_toml_value *table, const char *key,
                     al_bool *out) {
    return al_toml_as_bool(al_toml_get(table, key), out);
}
