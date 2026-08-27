/*
 * Byte views, the bounds-checked reader/writer pair, and hex.
 *
 * The reader and writer both latch their first error and then become inert.
 * That turns a decoder into a straight run of field reads with one status check
 * at the end, instead of an error branch after every field - which is how
 * parsers acquire the untested paths that malformed network input finds.
 */

#include "astrolune/bytes.h"

#include "internal/common.h"

/* --------------------------------------------------------------------------
 * Views
 * -------------------------------------------------------------------------- */

al_bytes al_bytes_make(const void *data, al_size len) {
    al_bytes b;
    b.data = (const al_u8 *)data;
    b.len  = (data != NULL) ? len : 0u;
    return b;
}

al_bytes al_bytes_empty(void) {
    al_bytes b;
    b.data = NULL;
    b.len  = 0u;
    return b;
}

al_bytes al_bytes_from_cstr(const char *s) {
    return al_bytes_make(s, (s != NULL) ? strlen(s) : 0u);
}

al_bool al_bytes_eq(al_bytes a, al_bytes b) {
    if (a.len != b.len) {
        return AL_FALSE;
    }
    if (a.len == 0u) {
        return AL_TRUE;
    }
    return (memcmp(a.data, b.data, a.len) == 0) ? AL_TRUE : AL_FALSE;
}

al_bool al_bytes_eq_ct(al_bytes a, al_bytes b) {
    /* The length is treated as public - it is visible from the wire format
     * anyway - but the contents are compared without an early exit, so the
     * timing does not reveal the length of the matching prefix. */
    if (a.len != b.len) {
        return AL_FALSE;
    }
    al_u8 diff = 0u;
    for (al_size i = 0u; i < a.len; ++i) {
        diff |= (al_u8)(a.data[i] ^ b.data[i]);
    }
    return (diff == 0u) ? AL_TRUE : AL_FALSE;
}

al_bytes al_bytes_slice(al_bytes b, al_size offset, al_size len) {
    if (offset > b.len || len > b.len - offset) {
        return al_bytes_empty();
    }
    if (len == 0u) return al_bytes_empty();
    return al_bytes_make(b.data + offset, len);
}

/* --------------------------------------------------------------------------
 * Reader
 * -------------------------------------------------------------------------- */

void al_reader_init(al_reader *r, al_bytes src) {
    r->data   = src.data;
    r->len    = src.len;
    r->pos    = 0u;
    r->status = AL_OK;
}

al_size al_reader_remaining(const al_reader *r) {
    return (r->pos <= r->len) ? (r->len - r->pos) : 0u;
}

al_status al_reader_status(const al_reader *r) {
    return r->status;
}

void al_reader_fail(al_reader *r, al_status status) {
    if (r->status == AL_OK) {
        r->status = status;
    }
}

/* Reserve `n` bytes, or latch AL_ERR_TRUNCATED and return NULL. */
static const al_u8 *al_reader_advance(al_reader *r, al_size n) {
    if (r->status != AL_OK) {
        return NULL;
    }
    if (n > al_reader_remaining(r)) {
        r->status = AL_ERR_TRUNCATED;
        return NULL;
    }
    const al_u8 *p = r->data + r->pos;
    r->pos += n;
    return p;
}

al_u8 al_reader_u8(al_reader *r) {
    const al_u8 *p = al_reader_advance(r, 1u);
    return (p != NULL) ? p[0] : 0u;
}

al_u16 al_reader_u16(al_reader *r) {
    const al_u8 *p = al_reader_advance(r, 2u);
    return (p != NULL) ? al_load_le16(p) : 0u;
}

al_u32 al_reader_u32(al_reader *r) {
    const al_u8 *p = al_reader_advance(r, 4u);
    return (p != NULL) ? al_load_le32(p) : 0u;
}

al_u64 al_reader_u64(al_reader *r) {
    const al_u8 *p = al_reader_advance(r, 8u);
    return (p != NULL) ? al_load_le64(p) : 0u;
}

al_u64 al_reader_varint(al_reader *r) {
    if (r->status != AL_OK) {
        return 0u;
    }

    al_u64   value = 0u;
    unsigned shift = 0u;

    for (;;) {
        const al_u8 *p = al_reader_advance(r, 1u);
        if (p == NULL) {
            return 0u;
        }
        al_u8 byte = p[0];

        /* 10 groups of 7 bits cover 64 bits (the tenth carries a single bit). */
        if (shift >= 64u) {
            r->status = AL_ERR_MALFORMED;
            return 0u;
        }
        al_u64 chunk = (al_u64)(byte & 0x7fu);
        if (shift == 63u && chunk > 1u) {
            r->status = AL_ERR_OUT_OF_RANGE;   /* would exceed 64 bits */
            return 0u;
        }
        value |= chunk << shift;

        if ((byte & 0x80u) == 0u) {
            /*
             * Reject non-minimal encodings.
             *
             * A trailing zero group encodes the same value in more bytes. Two
             * valid encodings of one transaction field means two valid byte
             * strings for one transaction, which means two hashes - transaction
             * malleability. Canonical form is mandatory, not preferred.
             */
            if (byte == 0u && shift != 0u) {
                r->status = AL_ERR_NOT_CANONICAL;
                return 0u;
            }
            break;
        }
        shift += 7u;
    }
    return value;
}

al_bytes al_reader_take(al_reader *r, al_size len) {
    const al_u8 *p = al_reader_advance(r, len);
    if (p == NULL) {
        return al_bytes_empty();
    }
    return al_bytes_make(p, len);
}

void al_reader_bytes(al_reader *r, void *dst, al_size len) {
    const al_u8 *p = al_reader_advance(r, len);
    if (p != NULL) {
        al_memcpy(dst, p, len);
    } else {
        /* Zero the destination on failure so a caller that ignores the status
         * sees a defined value rather than stack garbage. */
        al_memzero(dst, len);
    }
}

void al_reader_hash(al_reader *r, al_hash256 *out) {
    al_reader_bytes(r, out->bytes, AL_HASH_SIZE);
}

void al_reader_address(al_reader *r, al_address *out) {
    al_reader_bytes(r, out->bytes, AL_ADDRESS_SIZE);
}

al_status al_reader_finish(const al_reader *r) {
    if (r->status != AL_OK) {
        return r->status;
    }
    if (r->pos != r->len) {
        /* Unconsumed input is rejected. Ignoring it would let an attacker append
         * arbitrary bytes to a valid message and obtain a distinct encoding that
         * still verifies. */
        return AL_ERR_TRAILING_BYTES;
    }
    return AL_OK;
}

/* --------------------------------------------------------------------------
 * Writer
 * -------------------------------------------------------------------------- */

void al_writer_init(al_writer *w, void *buf, al_size cap) {
    w->data   = (al_u8 *)buf;
    w->cap    = (buf != NULL) ? cap : 0u;
    w->pos    = 0u;
    w->status = AL_OK;
}

al_size al_writer_len(const al_writer *w) {
    return w->pos;
}

al_bytes al_writer_bytes(const al_writer *w) {
    return al_bytes_make(w->data, w->pos);
}

static al_u8 *al_writer_reserve(al_writer *w, al_size n) {
    if (w->status != AL_OK) {
        return NULL;
    }
    if (n > w->cap - w->pos) {
        w->status = AL_ERR_BUFFER_TOO_SMALL;
        return NULL;
    }
    al_u8 *p = w->data + w->pos;
    w->pos += n;
    return p;
}

void al_writer_u8(al_writer *w, al_u8 v) {
    al_u8 *p = al_writer_reserve(w, 1u);
    if (p != NULL) {
        p[0] = v;
    }
}

void al_writer_u16(al_writer *w, al_u16 v) {
    al_u8 *p = al_writer_reserve(w, 2u);
    if (p != NULL) {
        al_store_le16(p, v);
    }
}

void al_writer_u32(al_writer *w, al_u32 v) {
    al_u8 *p = al_writer_reserve(w, 4u);
    if (p != NULL) {
        al_store_le32(p, v);
    }
}

void al_writer_u64(al_writer *w, al_u64 v) {
    al_u8 *p = al_writer_reserve(w, 8u);
    if (p != NULL) {
        al_store_le64(p, v);
    }
}

void al_writer_varint(al_writer *w, al_u64 v) {
    /* Minimal encoding: emit 7 bits at a time, continuation bit set while more
     * remain. Matches what al_reader_varint accepts. */
    for (;;) {
        al_u8 byte = (al_u8)(v & 0x7fu);
        v >>= 7;
        if (v != 0u) {
            byte |= 0x80u;
        }
        al_writer_u8(w, byte);
        if (v == 0u) {
            break;
        }
    }
}

void al_writer_raw(al_writer *w, const void *src, al_size len) {
    al_u8 *p = al_writer_reserve(w, len);
    if (p != NULL) {
        al_memcpy(p, src, len);
    }
}

void al_writer_hash(al_writer *w, const al_hash256 *h) {
    al_writer_raw(w, h->bytes, AL_HASH_SIZE);
}

void al_writer_address(al_writer *w, const al_address *a) {
    al_writer_raw(w, a->bytes, AL_ADDRESS_SIZE);
}

al_status al_writer_finish(const al_writer *w) {
    return w->status;
}

al_size al_varint_size(al_u64 v) {
    al_size n = 1u;
    while (v >= 0x80u) {
        v >>= 7;
        ++n;
    }
    return n;
}

/* --------------------------------------------------------------------------
 * Hex
 * -------------------------------------------------------------------------- */

static const char al_hex_digits[] = "0123456789abcdef";

al_status al_hex_encode(al_bytes in, char *out, al_size out_cap) {
    if (out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    if (in.len > (SIZE_MAX - 1u) / 2u) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (out_cap < in.len * 2u + 1u) {
        return AL_ERR_BUFFER_TOO_SMALL;
    }
    for (al_size i = 0u; i < in.len; ++i) {
        out[i * 2u]      = al_hex_digits[in.data[i] >> 4];
        out[i * 2u + 1u] = al_hex_digits[in.data[i] & 0x0fu];
    }
    out[in.len * 2u] = '\0';
    return AL_OK;
}

/* Nibble value of a hex character, or 0xff if it is not one. */
static al_u8 al_hex_nibble(char c) {
    if (c >= '0' && c <= '9') { return (al_u8)(c - '0'); }
    if (c >= 'a' && c <= 'f') { return (al_u8)(c - 'a' + 10); }
    if (c >= 'A' && c <= 'F') { return (al_u8)(c - 'A' + 10); }
    return 0xffu;
}

al_status al_hex_decode(const char *in, void *out, al_size out_cap,
                        al_size *out_len) {
    if (in == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }

    /* Tolerate a 0x prefix: it is what users paste. */
    if (in[0] == '0' && (in[1] == 'x' || in[1] == 'X')) {
        in += 2;
    }

    al_size n = strlen(in);
    if ((n % 2u) != 0u) {
        return AL_ERR_MALFORMED;
    }
    al_size bytes = n / 2u;
    if (bytes > out_cap) {
        return AL_ERR_BUFFER_TOO_SMALL;
    }

    al_u8 *dst = (al_u8 *)out;
    for (al_size i = 0u; i < bytes; ++i) {
        al_u8 hi = al_hex_nibble(in[i * 2u]);
        al_u8 lo = al_hex_nibble(in[i * 2u + 1u]);
        if (hi == 0xffu || lo == 0xffu) {
            return AL_ERR_MALFORMED;
        }
        dst[i] = (al_u8)((hi << 4) | lo);
    }
    if (out_len != NULL) {
        *out_len = bytes;
    }
    return AL_OK;
}

void al_hash_to_hex(const al_hash256 *h, char out[AL_HASH_HEX_SIZE]) {
    al_status status = al_hex_encode(al_bytes_make(h->bytes, AL_HASH_SIZE), out,
                                     AL_HASH_HEX_SIZE);
    AL_ASSERT(status == AL_OK);
    (void)status;
}

void al_address_to_hex(const al_address *a, char out[AL_ADDRESS_HEX_SIZE]) {
    al_status status = al_hex_encode(
        al_bytes_make(a->bytes, AL_ADDRESS_SIZE), out, AL_ADDRESS_HEX_SIZE);
    AL_ASSERT(status == AL_OK);
    (void)status;
}
