/*
 * astrolune/bytes.h - non-owning byte views and a bounds-checked cursor.
 *
 * Every parser in the core reads through al_reader and every serialiser writes
 * through al_writer. Neither ever advances past its end, so a malformed block
 * from the network produces AL_ERR_TRUNCATED rather than a read out of bounds.
 * That property is what lets the decoders be simple.
 */

#ifndef ASTROLUNE_BYTES_H
#define ASTROLUNE_BYTES_H

#include "astrolune/base.h"

AL_EXTERN_C_BEGIN

/* --------------------------------------------------------------------------
 * Views
 * -------------------------------------------------------------------------- */

/* Immutable view over borrowed bytes. Does not own its storage. */
typedef struct al_bytes {
    const al_u8 *data;
    al_size      len;
} al_bytes;

/* Mutable view over borrowed bytes. */
typedef struct al_bytes_mut {
    al_u8  *data;
    al_size len;
} al_bytes_mut;

AL_PUBLIC al_bytes al_bytes_make(const void *data, al_size len);
AL_PUBLIC al_bytes al_bytes_empty(void);

/* Borrow a NUL-terminated string as bytes, excluding the terminator. */
AL_PUBLIC al_bytes al_bytes_from_cstr(const char *s);

AL_PUBLIC AL_NODISCARD al_bool al_bytes_eq(al_bytes a, al_bytes b);

/*
 * Constant-time equality, for comparing secrets, MACs and signatures.
 *
 * al_bytes_eq short-circuits on the first differing byte and therefore leaks
 * the length of the common prefix through timing. Use this whenever the
 * comparison result is not already public.
 */
AL_PUBLIC AL_NODISCARD al_bool al_bytes_eq_ct(al_bytes a, al_bytes b);

/* Subrange [offset, offset+len). Returns an empty view if out of range. */
AL_PUBLIC al_bytes al_bytes_slice(al_bytes b, al_size offset, al_size len);

/* --------------------------------------------------------------------------
 * Reader
 *
 * A cursor over an al_bytes. Once an error is latched the reader stays in the
 * failed state, so a decoder may perform a run of reads and check the status
 * once at the end instead of after every field.
 * -------------------------------------------------------------------------- */

typedef struct al_reader {
    const al_u8 *data;
    al_size      len;
    al_size      pos;
    al_status    status;   /* sticky: first error is preserved */
} al_reader;

AL_PUBLIC void al_reader_init(al_reader *r, al_bytes src);

AL_PUBLIC al_size   al_reader_remaining(const al_reader *r);
AL_PUBLIC al_status al_reader_status(const al_reader *r);

/* All integer reads are little-endian, which is the canonical Astrolune
 * encoding. See docs/04-state/transactions.md. */
AL_PUBLIC al_u8  al_reader_u8(al_reader *r);
AL_PUBLIC al_u16 al_reader_u16(al_reader *r);
AL_PUBLIC al_u32 al_reader_u32(al_reader *r);
AL_PUBLIC al_u64 al_reader_u64(al_reader *r);

/* LEB128-style unsigned varint. Rejects non-minimal encodings with
 * AL_ERR_NOT_CANONICAL: two encodings of one value would give two valid
 * serialisations of one transaction, and therefore two different hashes. */
AL_PUBLIC al_u64 al_reader_varint(al_reader *r);

/* Borrowed view of the next `len` bytes. Empty view on underflow. */
AL_PUBLIC al_bytes al_reader_take(al_reader *r, al_size len);

/* Copy the next `len` bytes into `dst`. */
AL_PUBLIC void al_reader_bytes(al_reader *r, void *dst, al_size len);

AL_PUBLIC void al_reader_hash(al_reader *r, al_hash256 *out);
AL_PUBLIC void al_reader_address(al_reader *r, al_address *out);

/* Latch an error explicitly, for semantic failures the reader cannot see. */
AL_PUBLIC void al_reader_fail(al_reader *r, al_status status);

/* AL_OK only if every read succeeded and the input was fully consumed.
 * Trailing bytes are rejected: they are a canonicalisation hole and a classic
 * transaction-malleability vector. */
AL_PUBLIC AL_NODISCARD al_status al_reader_finish(const al_reader *r);

/* --------------------------------------------------------------------------
 * Writer
 *
 * Writes into a caller-supplied buffer. Overflow latches
 * AL_ERR_BUFFER_TOO_SMALL rather than growing, because the core's hot paths
 * size their buffers up front and must not allocate mid-serialisation.
 * -------------------------------------------------------------------------- */

typedef struct al_writer {
    al_u8    *data;
    al_size   cap;
    al_size   pos;
    al_status status;   /* sticky */
} al_writer;

AL_PUBLIC void al_writer_init(al_writer *w, void *buf, al_size cap);

AL_PUBLIC al_size al_writer_len(const al_writer *w);
AL_PUBLIC al_bytes al_writer_bytes(const al_writer *w);

AL_PUBLIC void al_writer_u8(al_writer *w, al_u8 v);
AL_PUBLIC void al_writer_u16(al_writer *w, al_u16 v);
AL_PUBLIC void al_writer_u32(al_writer *w, al_u32 v);
AL_PUBLIC void al_writer_u64(al_writer *w, al_u64 v);
AL_PUBLIC void al_writer_varint(al_writer *w, al_u64 v);
AL_PUBLIC void al_writer_raw(al_writer *w, const void *src, al_size len);
AL_PUBLIC void al_writer_hash(al_writer *w, const al_hash256 *h);
AL_PUBLIC void al_writer_address(al_writer *w, const al_address *a);

AL_PUBLIC AL_NODISCARD al_status al_writer_finish(const al_writer *w);

/* Bytes a varint will occupy. Lets callers size a buffer exactly. */
AL_PUBLIC al_size al_varint_size(al_u64 v);

/* --------------------------------------------------------------------------
 * Hex
 * -------------------------------------------------------------------------- */

/* Lowercase hex. Needs 2*len+1 bytes in `out`, including the terminator. */
AL_PUBLIC AL_NODISCARD al_status al_hex_encode(al_bytes in, char *out, al_size out_cap);

/* Accepts both cases, rejects odd length and non-hex characters. */
AL_PUBLIC AL_NODISCARD al_status al_hex_decode(const char *in, void *out, al_size out_cap,
                                     al_size *out_len);

/* Convenience wrappers for the two types that get printed constantly.
 * `out` needs AL_HASH_HEX_SIZE / AL_ADDRESS_HEX_SIZE bytes. */
#define AL_HASH_HEX_SIZE    (AL_HASH_SIZE * 2 + 1)
#define AL_ADDRESS_HEX_SIZE (AL_ADDRESS_SIZE * 2 + 1)

AL_PUBLIC void al_hash_to_hex(const al_hash256 *h, char out[AL_HASH_HEX_SIZE]);
AL_PUBLIC void al_address_to_hex(const al_address *a, char out[AL_ADDRESS_HEX_SIZE]);

AL_EXTERN_C_END

#endif /* ASTROLUNE_BYTES_H */
