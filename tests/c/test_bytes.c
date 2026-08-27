/*
 * Byte views, the reader/writer pair, varint and hex.
 *
 * Expectations here are exact byte strings, not approximations. `al_bytes` sits
 * on the block-decoding path, so its rules are consensus rules rather than
 * library conveniences: a varint with two accepted encodings gives one
 * transaction two hashes, and a decoder that ignores trailing bytes lets an
 * attacker append padding to a signed message and obtain a distinct encoding
 * that still verifies. Both are tested as canonicalisation properties, not as
 * "does it parse".
 *
 * Two of the cases are exhaustive rather than sampled. The one- and two-byte
 * varint spaces are small enough to enumerate completely, and enumerating them
 * proves something sampling cannot: that the accepted subset is exactly the
 * image of the encoder, i.e. that encoding is injective over that domain. Those
 * two cases tally their classifications and assert the tallies, so 65,792
 * decoded inputs cost a handful of counted checks instead of drowning the
 * suite's totals.
 */

#include "astrolune/bytes.h"

#include "altest.h"

#define AL_TEST_SUITE_NAME "bytes"

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

/*
 * Round-trip one value through the writer and back, asserting minimality.
 *
 * Three properties at once: al_varint_size predicts the encoded length exactly
 * (callers size buffers with it, so a disagreement is a buffer overrun waiting
 * to happen), the writer's output decodes back to the same value, and the reader
 * consumes precisely what the writer produced - al_reader_finish returning AL_OK
 * means no short read and no leftover byte.
 *
 * Failures inside a helper report the helper's line rather than the caller's,
 * which is why every check here prints the value it saw.
 */
static void al_test_varint_roundtrip(al_u64 v, al_size expect_len) {
    al_u8    buf[16];
    al_writer w;

    al_writer_init(&w, buf, sizeof(buf));
    al_writer_varint(&w, v);
    AL_CHECK_EQ_STATUS(al_writer_finish(&w), AL_OK);
    AL_CHECK_EQ_U64(al_writer_len(&w), expect_len);
    AL_CHECK_EQ_U64(al_varint_size(v), expect_len);

    al_reader r;
    al_reader_init(&r, al_writer_bytes(&w));
    AL_CHECK_EQ_U64(al_reader_varint(&r), v);
    AL_CHECK_EQ_STATUS(al_reader_finish(&r), AL_OK);
}

/* Decode a hand-built byte string and assert the exact rejection. The status is
 * checked twice on purpose: once as latched, and once through al_reader_finish,
 * which must report the original failure rather than the trailing bytes the
 * abandoned read left behind. */
static void al_test_varint_rejects(const char *hex, al_status expect) {
    al_u8   buf[32];
    al_size len = al_test_unhex(hex, buf, sizeof(buf));

    al_reader r;
    al_reader_init(&r, al_bytes_make(buf, len));
    AL_CHECK_EQ_U64(al_reader_varint(&r), 0u);
    AL_CHECK_EQ_STATUS(al_reader_status(&r), expect);
    AL_CHECK_EQ_STATUS(al_reader_finish(&r), expect);
}

/* --------------------------------------------------------------------------
 * Views
 * -------------------------------------------------------------------------- */

AL_TEST(views_make_and_eq) {
    static const al_u8 abc[3] = {'a', 'b', 'c'};
    static const al_u8 abd[3] = {'a', 'b', 'd'};

    al_bytes v = al_bytes_make(abc, 3u);
    AL_CHECK(v.data == abc);
    AL_CHECK_EQ_U64(v.len, 3u);

    /* A NULL pointer forces the length to zero rather than trusting the caller.
     * Without this, `al_bytes_make(NULL, n)` would produce a view that every
     * bounds check believes is readable. */
    al_bytes null_view = al_bytes_make(NULL, 5u);
    AL_CHECK(null_view.data == NULL);
    AL_CHECK_EQ_U64(null_view.len, 0u);

    al_bytes e = al_bytes_empty();
    AL_CHECK(e.data == NULL);
    AL_CHECK_EQ_U64(e.len, 0u);

    AL_CHECK_EQ_U64(al_bytes_from_cstr("abc").len, 3u);
    AL_CHECK_EQ_U64(al_bytes_from_cstr("").len, 0u);
    AL_CHECK(al_bytes_from_cstr("").data != NULL);   /* points at the NUL */
    AL_CHECK_EQ_U64(al_bytes_from_cstr(NULL).len, 0u);
    AL_CHECK(al_bytes_from_cstr(NULL).data == NULL);

    /* The terminator is excluded, so a view of "abc" equals a view of the raw
     * three bytes. */
    AL_CHECK(al_bytes_eq(al_bytes_from_cstr("abc"), v) == AL_TRUE);

    AL_CHECK(al_bytes_eq(v, al_bytes_make(abd, 3u)) == AL_FALSE);
    AL_CHECK(al_bytes_eq(v, al_bytes_make(abc, 2u)) == AL_FALSE);

    /* Two empty views are equal whether or not either has a pointer. Callers
     * therefore compare with al_bytes_eq and never with `data == NULL`. */
    AL_CHECK(al_bytes_eq(e, al_bytes_empty()) == AL_TRUE);
    AL_CHECK(al_bytes_eq(e, al_bytes_from_cstr("")) == AL_TRUE);
    AL_CHECK(al_bytes_eq(e, v) == AL_FALSE);
}

AL_TEST(views_eq_ct_agrees_with_eq) {
    /* al_bytes_eq_ct exists for secrets, MACs and epoch-seed reveals, so its
     * result must be indistinguishable from al_bytes_eq on every input - the
     * only difference being that it does not stop at the first mismatch. A
     * divergence here would mean one of the two is used in the wrong place. */
    static const al_u8 a[4]     = {0x00u, 0x11u, 0x22u, 0x33u};
    static const al_u8 same[4]  = {0x00u, 0x11u, 0x22u, 0x33u};
    static const al_u8 first[4] = {0xffu, 0x11u, 0x22u, 0x33u};
    static const al_u8 last[4]  = {0x00u, 0x11u, 0x22u, 0xffu};

    al_bytes va = al_bytes_make(a, 4u);

    AL_CHECK(al_bytes_eq_ct(va, al_bytes_make(same, 4u)) == AL_TRUE);
    AL_CHECK(al_bytes_eq_ct(va, al_bytes_make(first, 4u)) == AL_FALSE);
    AL_CHECK(al_bytes_eq_ct(va, al_bytes_make(last, 4u)) == AL_FALSE);
    AL_CHECK(al_bytes_eq_ct(va, al_bytes_make(a, 3u)) == AL_FALSE);
    AL_CHECK(al_bytes_eq_ct(al_bytes_empty(), al_bytes_empty()) == AL_TRUE);
    AL_CHECK(al_bytes_eq_ct(al_bytes_empty(), va) == AL_FALSE);

    /* Every difference is ORed in, so a mismatch in any single position is
     * caught. Walk one flipped bit across all four bytes. */
    for (al_size i = 0u; i < 4u; ++i) {
        al_u8 tweaked[4];
        for (al_size j = 0u; j < 4u; ++j) { tweaked[j] = a[j]; }
        tweaked[i] ^= 0x80u;
        AL_CHECK(al_bytes_eq_ct(va, al_bytes_make(tweaked, 4u)) == AL_FALSE);
        AL_CHECK(al_bytes_eq(va, al_bytes_make(tweaked, 4u)) == AL_FALSE);
    }
}

AL_TEST(views_slice_bounds) {
    static const al_u8 src[8] = {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u};
    al_bytes b = al_bytes_make(src, 8u);

    al_bytes whole = al_bytes_slice(b, 0u, 8u);
    AL_CHECK(whole.data == src);
    AL_CHECK_EQ_U64(whole.len, 8u);

    al_bytes mid = al_bytes_slice(b, 2u, 3u);
    AL_CHECK(mid.data == src + 2);
    AL_CHECK_EQ_U64(mid.len, 3u);
    AL_CHECK_EQ_U64(mid.data[0], 2u);

    /* offset == len with length 0 is in range: it is the empty tail, which a
     * loop over a sequence of fields reaches naturally on its last step. The
     * pointer is one past the end rather than NULL, so callers must test `len`
     * and not `data` - al_bytes_eq does exactly that, which is why the
     * comparison against an empty view still holds. */
    al_bytes tail = al_bytes_slice(b, 8u, 0u);
    AL_CHECK_EQ_U64(tail.len, 0u);
    AL_CHECK(al_bytes_eq(tail, al_bytes_empty()) == AL_TRUE);

    /* Out of range in each of the two ways. */
    AL_CHECK_EQ_U64(al_bytes_slice(b, 9u, 0u).len, 0u);
    AL_CHECK(al_bytes_slice(b, 9u, 0u).data == NULL);
    AL_CHECK_EQ_U64(al_bytes_slice(b, 2u, 7u).len, 0u);
    AL_CHECK_EQ_U64(al_bytes_slice(b, 0u, 9u).len, 0u);

    /*
     * The bound is written `len > b.len - offset`, not `offset + len > b.len`,
     * so a length near the top of the range cannot wrap past the check. This is
     * the form of overflow a length field taken straight off the wire produces,
     * so it is the one that matters.
     */
    AL_CHECK_EQ_U64(al_bytes_slice(b, 0u, SIZE_MAX).len, 0u);
    AL_CHECK_EQ_U64(al_bytes_slice(b, 4u, SIZE_MAX - 3u).len, 0u);
    AL_CHECK_EQ_U64(al_bytes_slice(b, SIZE_MAX, 1u).len, 0u);

    /* Slicing an empty view yields an empty view rather than reading through a
     * NULL pointer. */
    AL_CHECK_EQ_U64(al_bytes_slice(al_bytes_empty(), 0u, 0u).len, 0u);
    AL_CHECK_EQ_U64(al_bytes_slice(al_bytes_empty(), 0u, 1u).len, 0u);
}

/* --------------------------------------------------------------------------
 * Reader
 * -------------------------------------------------------------------------- */

AL_TEST(reader_integers_are_little_endian) {
    /*
     * Little-endian is the canonical Astrolune encoding, and these helpers are
     * the only place the core converts. Asserting the byte order explicitly is
     * what makes the suite meaningful on a big-endian host: a native-load
     * shortcut would pass every round-trip test and still produce a different
     * block hash.
     */
    static const al_u8 src[15] = {
        0xaau,                                     /* u8  */
        0x34u, 0x12u,                              /* u16 = 0x1234 */
        0x78u, 0x56u, 0x34u, 0x12u,                /* u32 = 0x12345678 */
        0xf0u, 0xdeu, 0xbcu, 0x9au,
        0x78u, 0x56u, 0x34u, 0x12u                 /* u64 = 0x123456789abcdef0 */
    };

    al_reader r;
    al_reader_init(&r, al_bytes_make(src, sizeof(src)));
    AL_CHECK_EQ_U64(r.pos, 0u);
    AL_CHECK_EQ_STATUS(al_reader_status(&r), AL_OK);
    AL_CHECK_EQ_U64(al_reader_remaining(&r), 15u);

    AL_CHECK_EQ_U64(al_reader_u8(&r), 0xaau);
    AL_CHECK_EQ_U64(al_reader_remaining(&r), 14u);
    AL_CHECK_EQ_U64(al_reader_u16(&r), 0x1234u);
    AL_CHECK_EQ_U64(al_reader_remaining(&r), 12u);
    AL_CHECK_EQ_U64(al_reader_u32(&r), 0x12345678u);
    AL_CHECK_EQ_U64(al_reader_remaining(&r), 8u);
    AL_CHECK_EQ_U64(al_reader_u64(&r), UINT64_C(0x123456789abcdef0));
    AL_CHECK_EQ_U64(al_reader_remaining(&r), 0u);

    AL_CHECK_EQ_STATUS(al_reader_finish(&r), AL_OK);

    /* An empty source is a valid, fully-consumed reader, not an error. */
    al_reader empty;
    al_reader_init(&empty, al_bytes_empty());
    AL_CHECK_EQ_U64(al_reader_remaining(&empty), 0u);
    AL_CHECK_EQ_STATUS(al_reader_finish(&empty), AL_OK);

    /* al_reader_remaining guards against pos > len. Unreachable through the API,
     * because advance never overshoots - but the reader struct is public, so a
     * caller that rewinds by hand can produce it, and the guard is what stops
     * that becoming an unsigned underflow into a huge remaining count. */
    al_reader poked;
    al_reader_init(&poked, al_bytes_make(src, 4u));
    poked.pos = 100u;
    AL_CHECK_EQ_U64(al_reader_remaining(&poked), 0u);
}

AL_TEST(reader_truncation_is_sticky) {
    static const al_u8 src[3] = {0x01u, 0x02u, 0x03u};

    al_reader r;
    al_reader_init(&r, al_bytes_make(src, sizeof(src)));

    /* A short read consumes nothing: the reservation is checked before pos
     * moves, so a decoder that recovers can still see where it was. */
    AL_CHECK_EQ_U64(al_reader_u32(&r), 0u);
    AL_CHECK_EQ_STATUS(al_reader_status(&r), AL_ERR_TRUNCATED);
    AL_CHECK_EQ_U64(r.pos, 0u);
    AL_CHECK_EQ_U64(al_reader_remaining(&r), 3u);

    /* Inert thereafter. A read that would have succeeded still returns zero, so
     * a decoder cannot accidentally proceed on half-parsed input. */
    AL_CHECK_EQ_U64(al_reader_u8(&r), 0u);
    AL_CHECK_EQ_U64(r.pos, 0u);
    AL_CHECK_EQ_STATUS(al_reader_status(&r), AL_ERR_TRUNCATED);

    /* First error wins. al_reader_fail cannot overwrite a latched status, which
     * is what makes the one status check at the end of a decoder report the
     * root cause rather than the last symptom. */
    al_reader_fail(&r, AL_ERR_MALFORMED);
    AL_CHECK_EQ_STATUS(al_reader_status(&r), AL_ERR_TRUNCATED);

    /* al_reader_finish reports the latched failure, not AL_ERR_TRAILING_BYTES,
     * even though three bytes are unconsumed. The precedence matters: a
     * truncated message must not be diagnosed as a padded one. */
    AL_CHECK_EQ_STATUS(al_reader_finish(&r), AL_ERR_TRUNCATED);

    /* Explicit failure on a clean reader, for the semantic errors the reader
     * cannot see itself. */
    al_reader s;
    al_reader_init(&s, al_bytes_make(src, sizeof(src)));
    al_reader_fail(&s, AL_ERR_CONSENSUS_VIOLATION);
    AL_CHECK_EQ_STATUS(al_reader_status(&s), AL_ERR_CONSENSUS_VIOLATION);
    AL_CHECK_EQ_U64(al_reader_u8(&s), 0u);
    AL_CHECK_EQ_STATUS(al_reader_finish(&s), AL_ERR_CONSENSUS_VIOLATION);

    /* Failing with AL_OK is a no-op rather than a way to clear an error. */
    al_reader t;
    al_reader_init(&t, al_bytes_make(src, sizeof(src)));
    al_reader_fail(&t, AL_OK);
    AL_CHECK_EQ_STATUS(al_reader_status(&t), AL_OK);
    AL_CHECK_EQ_U64(al_reader_u8(&t), 0x01u);
}

AL_TEST(reader_take_and_copy) {
    static const al_u8 src[8] = {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u};

    al_reader r;
    al_reader_init(&r, al_bytes_make(src, sizeof(src)));

    al_bytes head = al_reader_take(&r, 3u);
    AL_CHECK(head.data == src);
    AL_CHECK_EQ_U64(head.len, 3u);
    AL_CHECK_EQ_U64(r.pos, 3u);

    /* The view borrows the source; it is not a copy. */
    al_bytes next = al_reader_take(&r, 2u);
    AL_CHECK(next.data == src + 3);
    AL_CHECK_EQ_U64(next.len, 2u);

    /* A zero-length take at a valid position yields a zero-length view. Taken
     * here from a non-empty reader deliberately: on a reader whose source is
     * empty the same call forms `NULL + 0`, which C23 defines but clang's
     * pointer-overflow check still reports, so that input is left untested
     * rather than pinned. Noted in implementation-status.md. */
    al_bytes none = al_reader_take(&r, 0u);
    AL_CHECK_EQ_U64(none.len, 0u);
    AL_CHECK_EQ_U64(r.pos, 5u);

    /* Overrun yields an empty view and latches, so a caller that forgets to
     * check the status still gets a view it cannot read out of bounds. */
    al_bytes over = al_reader_take(&r, 4u);
    AL_CHECK_EQ_U64(over.len, 0u);
    AL_CHECK(over.data == NULL);
    AL_CHECK_EQ_STATUS(al_reader_status(&r), AL_ERR_TRUNCATED);

    /* al_reader_bytes copies out, and zeroes the destination when it cannot -
     * the same reasoning as the empty view above, applied to a buffer. */
    al_reader c;
    al_reader_init(&c, al_bytes_make(src, sizeof(src)));
    al_u8 dst[8];
    memset(dst, 0xffu, sizeof(dst));
    al_reader_bytes(&c, dst, 4u);
    AL_CHECK_EQ_STATUS(al_reader_status(&c), AL_OK);
    AL_CHECK_HEX(dst, 4u, "00010203");
    AL_CHECK_EQ_U64(dst[4], 0xffu);              /* nothing written past len */

    memset(dst, 0xffu, sizeof(dst));
    al_reader_bytes(&c, dst, 8u);                /* only 4 remain */
    AL_CHECK_EQ_STATUS(al_reader_status(&c), AL_ERR_TRUNCATED);
    AL_CHECK_HEX(dst, 8u, "0000000000000000");
}

AL_TEST(reader_hash_and_address) {
    al_u8 src[AL_HASH_SIZE + AL_ADDRESS_SIZE];
    for (al_size i = 0u; i < sizeof(src); ++i) {
        src[i] = (al_u8)(i + 1u);
    }

    al_reader r;
    al_reader_init(&r, al_bytes_make(src, sizeof(src)));

    al_hash256 h;
    al_address a;
    memset(&h, 0xffu, sizeof(h));
    memset(&a, 0xffu, sizeof(a));
    al_reader_hash(&r, &h);
    al_reader_address(&r, &a);
    AL_CHECK_EQ_STATUS(al_reader_finish(&r), AL_OK);
    AL_CHECK_HASH_HEX(h,
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    AL_CHECK_HEX(a.bytes, AL_ADDRESS_SIZE,
        "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");

    /* A hash read that does not fit is zeroed rather than left half-written.
     * A partially-copied hash that a caller then compared would be a genuine
     * consensus hazard, so this is the one guarantee worth stating twice. */
    al_reader s;
    al_reader_init(&s, al_bytes_make(src, 10u));
    memset(&h, 0xffu, sizeof(h));
    al_reader_hash(&s, &h);
    AL_CHECK_EQ_STATUS(al_reader_status(&s), AL_ERR_TRUNCATED);
    AL_CHECK_HASH_HEX(h,
        "0000000000000000000000000000000000000000000000000000000000000000");

    memset(&a, 0xffu, sizeof(a));
    al_reader t;
    al_reader_init(&t, al_bytes_make(src, 31u));
    al_reader_address(&t, &a);
    AL_CHECK_EQ_STATUS(al_reader_status(&t), AL_ERR_TRUNCATED);
    AL_CHECK_HEX(a.bytes, AL_ADDRESS_SIZE,
        "0000000000000000000000000000000000000000000000000000000000000000");
}

AL_TEST(reader_finish_rejects_trailing_bytes) {
    static const al_u8 src[4] = {0x01u, 0x02u, 0x03u, 0x04u};

    /* Unconsumed input is a canonicalisation hole: without this rejection an
     * attacker appends arbitrary bytes to a valid signed message and obtains a
     * second encoding that still verifies. */
    al_reader r;
    al_reader_init(&r, al_bytes_make(src, sizeof(src)));
    AL_CHECK_EQ_U64(al_reader_u16(&r), 0x0201u);
    AL_CHECK_EQ_STATUS(al_reader_finish(&r), AL_ERR_TRAILING_BYTES);

    /* One byte is enough to reject. */
    AL_CHECK_EQ_U64(al_reader_u8(&r), 0x03u);
    AL_CHECK_EQ_STATUS(al_reader_finish(&r), AL_ERR_TRAILING_BYTES);

    AL_CHECK_EQ_U64(al_reader_u8(&r), 0x04u);
    AL_CHECK_EQ_STATUS(al_reader_finish(&r), AL_OK);

    /* Reading nothing at all from a non-empty source is the same hole. */
    al_reader s;
    al_reader_init(&s, al_bytes_make(src, sizeof(src)));
    AL_CHECK_EQ_STATUS(al_reader_finish(&s), AL_ERR_TRAILING_BYTES);
}

/* --------------------------------------------------------------------------
 * Varint
 * -------------------------------------------------------------------------- */

AL_TEST(varint_roundtrip_at_every_width) {
    /* One value per encoded length, at both ends of each group's range. The
     * group boundaries are where an off-by-one in the shift loop shows up. */
    al_test_varint_roundtrip(0u, 1u);
    al_test_varint_roundtrip(1u, 1u);
    al_test_varint_roundtrip(0x7fu, 1u);
    al_test_varint_roundtrip(0x80u, 2u);
    al_test_varint_roundtrip(0x3fffu, 2u);
    al_test_varint_roundtrip(0x4000u, 3u);
    al_test_varint_roundtrip(0x1fffffu, 3u);
    al_test_varint_roundtrip(0x200000u, 4u);
    al_test_varint_roundtrip(0xfffffffu, 4u);
    al_test_varint_roundtrip(0x10000000u, 5u);
    al_test_varint_roundtrip(UINT64_C(0x7ffffffff), 5u);
    al_test_varint_roundtrip(UINT64_C(0x800000000), 6u);
    al_test_varint_roundtrip(UINT64_C(0x3ffffffffff), 6u);
    al_test_varint_roundtrip(UINT64_C(0x40000000000), 7u);
    al_test_varint_roundtrip(UINT64_C(0x1ffffffffffff), 7u);
    al_test_varint_roundtrip(UINT64_C(0x2000000000000), 8u);
    al_test_varint_roundtrip(UINT64_C(0xffffffffffffff), 8u);
    al_test_varint_roundtrip(UINT64_C(0x100000000000000), 9u);
    al_test_varint_roundtrip(UINT64_C(0x7fffffffffffffff), 9u);
    al_test_varint_roundtrip(UINT64_C(0x8000000000000000), 10u);
    al_test_varint_roundtrip(UINT64_MAX, 10u);

    /* A sweep either side of every bit position, which catches a shift that
     * loses or duplicates a group without needing one literal per case. */
    for (unsigned bit = 0u; bit < 64u; ++bit) {
        al_u64 v = UINT64_C(1) << bit;
        al_test_varint_roundtrip(v, al_varint_size(v));
        al_test_varint_roundtrip(v - 1u, al_varint_size(v - 1u));
        if (v != UINT64_C(0x8000000000000000)) {
            al_test_varint_roundtrip(v + 1u, al_varint_size(v + 1u));
        }
    }

    /* Golden encodings, so a change to the group order or the continuation bit
     * is caught as a byte string rather than only as a round-trip. */
    al_u8    buf[16];
    al_writer w;

    al_writer_init(&w, buf, sizeof(buf));
    al_writer_varint(&w, 0u);
    AL_CHECK_HEX(buf, al_writer_len(&w), "00");

    al_writer_init(&w, buf, sizeof(buf));
    al_writer_varint(&w, 300u);
    AL_CHECK_HEX(buf, al_writer_len(&w), "ac02");

    al_writer_init(&w, buf, sizeof(buf));
    al_writer_varint(&w, 0x3fffu);
    AL_CHECK_HEX(buf, al_writer_len(&w), "ff7f");

    al_writer_init(&w, buf, sizeof(buf));
    al_writer_varint(&w, UINT64_MAX);
    AL_CHECK_HEX(buf, al_writer_len(&w), "ffffffffffffffffff01");
}

AL_TEST(varint_rejects_non_canonical) {
    /*
     * Three distinct rejections, hand-encoded, because each is a different
     * failure mode and conflating them would hide a regression in one behind
     * the other two.
     */

    /* A trailing zero group encodes the same value in more bytes. Two encodings
     * of one field means two encodings of one transaction, and therefore two
     * hashes - this is the malleability rejection, and it is the reason the
     * status has its own name. */
    al_test_varint_rejects("8000", AL_ERR_NOT_CANONICAL);     /* long form of 0 */
    al_test_varint_rejects("ff8000", AL_ERR_NOT_CANONICAL);   /* long form of 0x7f */
    al_test_varint_rejects("818000", AL_ERR_NOT_CANONICAL);   /* long form of 1 */

    /* The tenth group carries one usable bit. A tenth group above 1 describes a
     * value that does not fit in 64 bits, which is out of range rather than
     * malformed - the shape is legal, the magnitude is not. */
    al_test_varint_rejects("ffffffffffffffffff02", AL_ERR_OUT_OF_RANGE);
    al_test_varint_rejects("ffffffffffffffffff7f", AL_ERR_OUT_OF_RANGE);

    /* An eleventh group cannot contribute any bits at all, so the encoding is
     * structurally wrong. Note the loop reads before it checks the shift, so
     * the eleventh byte must actually be present to reach this - one byte
     * shorter is a truncation, below. */
    al_test_varint_rejects("ffffffffffffffffff8100", AL_ERR_MALFORMED);

    /* Truncation: a continuation bit with nothing following it. */
    al_test_varint_rejects("80", AL_ERR_TRUNCATED);
    al_test_varint_rejects("ffffffffffffffffff81", AL_ERR_TRUNCATED);

    /* An empty input is a truncated varint, not a zero. */
    al_reader r;
    al_reader_init(&r, al_bytes_empty());
    AL_CHECK_EQ_U64(al_reader_varint(&r), 0u);
    AL_CHECK_EQ_STATUS(al_reader_status(&r), AL_ERR_TRUNCATED);

    /* A varint read on an already-failed reader returns 0 without consuming,
     * and does not replace the latched status. */
    al_u8 canonical[2] = {0xacu, 0x02u};
    al_reader s;
    al_reader_init(&s, al_bytes_make(canonical, sizeof(canonical)));
    al_reader_fail(&s, AL_ERR_BAD_SIGNATURE);
    AL_CHECK_EQ_U64(al_reader_varint(&s), 0u);
    AL_CHECK_EQ_U64(s.pos, 0u);
    AL_CHECK_EQ_STATUS(al_reader_status(&s), AL_ERR_BAD_SIGNATURE);
}

AL_TEST(varint_one_byte_space_is_exhaustive) {
    /*
     * All 256 one-byte inputs. Tallied rather than checked individually so the
     * suite's check count stays meaningful; an anomaly is reported with the
     * offending byte and then counted, so a failure is still diagnosable.
     */
    al_size accepted  = 0u;
    al_size truncated = 0u;
    al_size anomalies = 0u;

    for (al_u32 b = 0u; b < 256u; ++b) {
        al_u8 in = (al_u8)b;

        al_reader r;
        al_reader_init(&r, al_bytes_make(&in, 1u));
        al_u64    got = al_reader_varint(&r);
        al_status st  = al_reader_status(&r);

        if (b < 0x80u) {
            /* Single group, minimal by construction, fully consumed. */
            if (st != AL_OK || got != (al_u64)b ||
                al_reader_finish(&r) != AL_OK) {
                ++anomalies;
                (void)fprintf(stderr, "      byte %02x: st=%s got=%llu\n",
                              (unsigned)b, al_status_str(st),
                              (unsigned long long)got);
            }
            ++accepted;
        } else {
            /* Continuation bit set with nothing after it. */
            if (st != AL_ERR_TRUNCATED || got != 0u) {
                ++anomalies;
                (void)fprintf(stderr, "      byte %02x: st=%s got=%llu\n",
                              (unsigned)b, al_status_str(st),
                              (unsigned long long)got);
            }
            ++truncated;
        }
    }

    AL_CHECK_EQ_U64(anomalies, 0u);
    AL_CHECK_EQ_U64(accepted, 128u);
    AL_CHECK_EQ_U64(truncated, 128u);
}

AL_TEST(varint_two_byte_space_is_injective) {
    /*
     * All 65,536 two-byte inputs, classified.
     *
     * This is the property that matters for consensus, and it is stronger than
     * any round-trip test: the set of two-byte strings the reader accepts is
     * exactly the set the writer can produce. Every accepted input is
     * re-encoded and compared byte for byte, so an encoding the reader tolerates
     * but the writer would never emit - a second spelling of some value - shows
     * up here as an anomaly. Sampling cannot establish that; enumeration can,
     * and at this width enumeration is free.
     */
    al_size single    = 0u;   /* first byte terminates; second is trailing  */
    al_size accepted  = 0u;   /* genuine two-byte value                     */
    al_size noncanon  = 0u;   /* second group is a trailing zero            */
    al_size truncated = 0u;   /* second byte continues, nothing follows     */
    al_size anomalies = 0u;

    for (al_u32 hi = 0u; hi < 256u; ++hi) {
        for (al_u32 lo = 0u; lo < 256u; ++lo) {
            al_u8 in[2];
            in[0] = (al_u8)hi;
            in[1] = (al_u8)lo;

            al_reader r;
            al_reader_init(&r, al_bytes_make(in, 2u));
            al_u64    got = al_reader_varint(&r);
            al_status st  = al_reader_status(&r);

            al_bool bad = AL_FALSE;

            if (hi < 0x80u) {
                /* One group only. The second byte is unconsumed, which
                 * al_reader_finish must reject. */
                if (st != AL_OK || got != (al_u64)hi || r.pos != 1u ||
                    al_reader_finish(&r) != AL_ERR_TRAILING_BYTES) {
                    bad = AL_TRUE;
                }
                ++single;
            } else if (lo == 0u) {
                if (st != AL_ERR_NOT_CANONICAL || got != 0u) { bad = AL_TRUE; }
                ++noncanon;
            } else if (lo >= 0x80u) {
                if (st != AL_ERR_TRUNCATED || got != 0u) { bad = AL_TRUE; }
                ++truncated;
            } else {
                al_u64 want = (al_u64)(hi & 0x7fu) | ((al_u64)lo << 7);
                if (st != AL_OK || got != want ||
                    al_reader_finish(&r) != AL_OK) {
                    bad = AL_TRUE;
                } else {
                    /* Injectivity: the writer's encoding of the decoded value
                     * must be this exact two-byte string. */
                    al_u8    back[16];
                    al_writer w;
                    al_writer_init(&w, back, sizeof(back));
                    al_writer_varint(&w, got);
                    if (al_writer_finish(&w) != AL_OK ||
                        al_writer_len(&w) != 2u ||
                        back[0] != in[0] || back[1] != in[1]) {
                        bad = AL_TRUE;
                    }
                }
                ++accepted;
            }

            if (bad) {
                ++anomalies;
                if (anomalies <= 8u) {
                    (void)fprintf(stderr,
                                  "      %02x %02x: st=%s got=%llu pos=%llu\n",
                                  (unsigned)hi, (unsigned)lo,
                                  al_status_str(st), (unsigned long long)got,
                                  (unsigned long long)r.pos);
                }
            }
        }
    }

    AL_CHECK_EQ_U64(anomalies, 0u);
    AL_CHECK_EQ_U64(single, 128u * 256u);
    AL_CHECK_EQ_U64(noncanon, 128u);
    AL_CHECK_EQ_U64(truncated, 128u * 128u);
    AL_CHECK_EQ_U64(accepted, 128u * 127u);
    AL_CHECK_EQ_U64(single + noncanon + truncated + accepted, 65536u);
}

/* --------------------------------------------------------------------------
 * Writer
 * -------------------------------------------------------------------------- */

AL_TEST(writer_byte_order_and_length) {
    al_u8    buf[32];
    al_writer w;

    memset(buf, 0u, sizeof(buf));
    al_writer_init(&w, buf, sizeof(buf));
    AL_CHECK_EQ_U64(al_writer_len(&w), 0u);
    AL_CHECK_EQ_U64(al_writer_bytes(&w).len, 0u);

    al_writer_u8(&w, 0xaau);
    al_writer_u16(&w, 0x1234u);
    al_writer_u32(&w, 0x12345678u);
    al_writer_u64(&w, UINT64_C(0x123456789abcdef0));
    AL_CHECK_EQ_STATUS(al_writer_finish(&w), AL_OK);
    AL_CHECK_EQ_U64(al_writer_len(&w), 15u);
    AL_CHECK_HEX(buf, 15u, "aa341278563412f0debc9a78563412");

    /* al_writer_bytes is a view of exactly what has been written, not of the
     * whole buffer. */
    al_bytes out = al_writer_bytes(&w);
    AL_CHECK(out.data == buf);
    AL_CHECK_EQ_U64(out.len, 15u);
}

AL_TEST(writer_overflow_latches) {
    al_u8    buf[8];
    al_writer w;

    memset(buf, 0u, sizeof(buf));
    al_writer_init(&w, buf, sizeof(buf));
    al_writer_u8(&w, 0x11u);
    al_writer_u16(&w, 0x2222u);
    al_writer_u32(&w, 0x33333333u);
    AL_CHECK_EQ_U64(al_writer_len(&w), 7u);
    AL_CHECK_EQ_STATUS(al_writer_finish(&w), AL_OK);

    /* Two bytes needed, one left. The core's hot paths size their buffers up
     * front, so overflow is a caller bug reported by status rather than a
     * reallocation mid-serialisation. */
    al_writer_u16(&w, 0x4444u);
    AL_CHECK_EQ_STATUS(al_writer_finish(&w), AL_ERR_BUFFER_TOO_SMALL);
    AL_CHECK_EQ_U64(al_writer_len(&w), 7u);   /* nothing partially written */
    AL_CHECK_EQ_U64(buf[7], 0u);

    /* Inert thereafter: a write that would have fitted is still dropped, so a
     * caller cannot end up with a buffer holding fields 1-3 and 5. */
    al_writer_u8(&w, 0x55u);
    AL_CHECK_EQ_U64(al_writer_len(&w), 7u);
    AL_CHECK_EQ_U64(buf[7], 0u);
    AL_CHECK_EQ_STATUS(al_writer_finish(&w), AL_ERR_BUFFER_TOO_SMALL);

    /* Exactly filling the buffer is not an overflow. */
    al_writer x;
    al_writer_init(&x, buf, sizeof(buf));
    al_writer_u64(&x, 0u);
    AL_CHECK_EQ_U64(al_writer_len(&x), 8u);
    AL_CHECK_EQ_STATUS(al_writer_finish(&x), AL_OK);
    al_writer_u8(&x, 1u);
    AL_CHECK_EQ_STATUS(al_writer_finish(&x), AL_ERR_BUFFER_TOO_SMALL);

    /* A NULL buffer is a zero-capacity writer, not a crash and not an
     * unchecked write. Useful for sizing a buffer by dry run - though
     * al_varint_size is the intended way. */
    al_writer n;
    al_writer_init(&n, NULL, 100u);
    AL_CHECK_EQ_U64(n.cap, 0u);
    al_writer_u8(&n, 1u);
    AL_CHECK_EQ_STATUS(al_writer_finish(&n), AL_ERR_BUFFER_TOO_SMALL);
    AL_CHECK_EQ_U64(al_writer_len(&n), 0u);
    AL_CHECK_EQ_U64(al_writer_bytes(&n).len, 0u);
    AL_CHECK(al_writer_bytes(&n).data == NULL);

    /*
     * A varint that runs out of room mid-encoding leaves its leading groups in
     * the buffer. That is not a defect - the writer promises nothing about the
     * buffer's contents once the status is latched - but it is worth pinning,
     * because it is the one case where a failed write is visibly partial and a
     * caller who checks only the length would ship a truncated field.
     */
    al_u8    tiny[1];
    al_writer v;
    al_writer_init(&v, tiny, sizeof(tiny));
    al_writer_varint(&v, 300u);                  /* wants two bytes */
    AL_CHECK_EQ_STATUS(al_writer_finish(&v), AL_ERR_BUFFER_TOO_SMALL);
    AL_CHECK_EQ_U64(al_writer_len(&v), 1u);
    AL_CHECK_EQ_U64(tiny[0], 0xacu);             /* first group, orphaned */
}

AL_TEST(writer_reader_roundtrip_compound) {
    /*
     * The shape a block or transaction decoder actually has: a tag, two
     * fixed-width digests, a length-prefixed field, three integers and a raw
     * payload. Round-tripping the whole record is what proves the reader and
     * writer agree on field widths - a disagreement in either would be invisible
     * when each primitive is tested alone.
     */
    al_hash256 h;
    al_address a;
    for (al_size i = 0u; i < AL_HASH_SIZE; ++i)    { h.bytes[i] = (al_u8)(0x10u + i); }
    for (al_size i = 0u; i < AL_ADDRESS_SIZE; ++i) { a.bytes[i] = (al_u8)(0xf0u - i); }

    static const al_u8 payload[3] = {0xcau, 0xfeu, 0xbau};

    al_u8    buf[128];
    al_writer w;
    al_writer_init(&w, buf, sizeof(buf));
    al_writer_u8(&w, 0x02u);
    al_writer_hash(&w, &h);
    al_writer_address(&w, &a);
    al_writer_varint(&w, 300u);
    al_writer_u32(&w, 0xdeadbeefu);
    al_writer_u64(&w, UINT64_C(0x0123456789abcdef));
    al_writer_raw(&w, payload, sizeof(payload));
    AL_CHECK_EQ_STATUS(al_writer_finish(&w), AL_OK);
    AL_CHECK_EQ_U64(al_writer_len(&w), 1u + 32u + 32u + 2u + 4u + 8u + 3u);

    al_reader r;
    al_reader_init(&r, al_writer_bytes(&w));
    al_hash256 h2;
    al_address a2;
    al_u8      tail[3];
    AL_CHECK_EQ_U64(al_reader_u8(&r), 0x02u);
    al_reader_hash(&r, &h2);
    al_reader_address(&r, &a2);
    AL_CHECK_EQ_U64(al_reader_varint(&r), 300u);
    AL_CHECK_EQ_U64(al_reader_u32(&r), 0xdeadbeefu);
    AL_CHECK_EQ_U64(al_reader_u64(&r), UINT64_C(0x0123456789abcdef));
    al_reader_bytes(&r, tail, sizeof(tail));

    /* One status check at the end of a run of reads - the property the sticky
     * status exists to provide. */
    AL_CHECK_EQ_STATUS(al_reader_finish(&r), AL_OK);
    AL_CHECK(al_bytes_eq(al_bytes_make(h2.bytes, AL_HASH_SIZE),
                         al_bytes_make(h.bytes, AL_HASH_SIZE)) == AL_TRUE);
    AL_CHECK(al_bytes_eq(al_bytes_make(a2.bytes, AL_ADDRESS_SIZE),
                         al_bytes_make(a.bytes, AL_ADDRESS_SIZE)) == AL_TRUE);
    AL_CHECK_HEX(tail, sizeof(tail), "cafeba");

    /*
     * The same record, truncated to 40 bytes. Every read after the first
     * failure returns a defined zero value and the final status names the
     * original truncation - so a decoder written as a straight run of reads
     * cannot be tricked into acting on a short message.
     */
    al_reader s;
    al_reader_init(&s, al_bytes_slice(al_writer_bytes(&w), 0u, 40u));
    memset(&h2, 0xffu, sizeof(h2));
    memset(&a2, 0xffu, sizeof(a2));
    AL_CHECK_EQ_U64(al_reader_u8(&s), 0x02u);
    al_reader_hash(&s, &h2);                     /* fits: 1 + 32 <= 40 */
    AL_CHECK_EQ_STATUS(al_reader_status(&s), AL_OK);
    al_reader_address(&s, &a2);                  /* needs 32, 7 remain */
    AL_CHECK_EQ_STATUS(al_reader_status(&s), AL_ERR_TRUNCATED);
    AL_CHECK_EQ_U64(al_reader_varint(&s), 0u);
    AL_CHECK_EQ_U64(al_reader_u32(&s), 0u);
    AL_CHECK_EQ_U64(al_reader_u64(&s), 0u);
    AL_CHECK_EQ_STATUS(al_reader_finish(&s), AL_ERR_TRUNCATED);

    /* The field read before the failure is intact; the one that failed is
     * zeroed. */
    AL_CHECK(al_bytes_eq(al_bytes_make(h2.bytes, AL_HASH_SIZE),
                         al_bytes_make(h.bytes, AL_HASH_SIZE)) == AL_TRUE);
    AL_CHECK_HEX(a2.bytes, AL_ADDRESS_SIZE,
        "0000000000000000000000000000000000000000000000000000000000000000");
}

/* --------------------------------------------------------------------------
 * Hex
 * -------------------------------------------------------------------------- */

AL_TEST(hex_encode_contract) {
    static const al_u8 src[4] = {0x00u, 0x0fu, 0xf0u, 0xffu};
    char out[16];

    memset(out, 0x7fu, sizeof(out));
    AL_CHECK_EQ_STATUS(al_hex_encode(al_bytes_make(src, 4u), out, sizeof(out)),
                       AL_OK);
    AL_CHECK_EQ_STR(out, "000ff0ff");            /* lowercase, NUL-terminated */

    /* Exactly 2*len+1 is enough; one less is not. The boundary is where a
     * caller sizing a buffer from AL_HASH_HEX_SIZE would get it wrong. */
    AL_CHECK_EQ_STATUS(al_hex_encode(al_bytes_make(src, 4u), out, 9u), AL_OK);
    AL_CHECK_EQ_STR(out, "000ff0ff");
    AL_CHECK_EQ_STATUS(al_hex_encode(al_bytes_make(src, 4u), out, 8u),
                       AL_ERR_BUFFER_TOO_SMALL);

    /* An empty input still writes the terminator, so the result is a valid
     * empty string rather than whatever was in the buffer. */
    memset(out, 0x7fu, sizeof(out));
    AL_CHECK_EQ_STATUS(al_hex_encode(al_bytes_empty(), out, 1u), AL_OK);
    AL_CHECK_EQ_STR(out, "");
    AL_CHECK_EQ_STATUS(al_hex_encode(al_bytes_empty(), out, 0u),
                       AL_ERR_BUFFER_TOO_SMALL);

    AL_CHECK_EQ_STATUS(al_hex_encode(al_bytes_make(src, 4u), NULL, 100u),
                       AL_ERR_INVALID_ARG);

    /*
     * A length whose doubling would wrap is rejected before the capacity check,
     * so `in.len * 2 + 1` cannot overflow into a small number that a small
     * buffer then satisfies. The view is never dereferenced on this path, which
     * is why a bogus length over a real pointer is safe to pass.
     */
    AL_CHECK_EQ_STATUS(al_hex_encode(al_bytes_make(src, SIZE_MAX), out,
                                     sizeof(out)),
                       AL_ERR_OUT_OF_RANGE);
    AL_CHECK_EQ_STATUS(al_hex_encode(al_bytes_make(src, (SIZE_MAX - 1u) / 2u + 1u),
                                     out, sizeof(out)),
                       AL_ERR_OUT_OF_RANGE);
}

AL_TEST(hex_decode_contract) {
    al_u8   out[8];
    al_size len;

    memset(out, 0u, sizeof(out));
    len = 0u;
    AL_CHECK_EQ_STATUS(al_hex_decode("000ff0ff", out, sizeof(out), &len), AL_OK);
    AL_CHECK_EQ_U64(len, 4u);
    AL_CHECK_HEX(out, 4u, "000ff0ff");

    /* Both cases accepted, mixed within one string. */
    AL_CHECK_EQ_STATUS(al_hex_decode("AABBccDd", out, sizeof(out), &len), AL_OK);
    AL_CHECK_EQ_U64(len, 4u);
    AL_CHECK_HEX(out, 4u, "aabbccdd");

    /* A 0x prefix is tolerated because it is what users paste. Both spellings. */
    AL_CHECK_EQ_STATUS(al_hex_decode("0x1234", out, sizeof(out), &len), AL_OK);
    AL_CHECK_EQ_U64(len, 2u);
    AL_CHECK_HEX(out, 2u, "1234");
    AL_CHECK_EQ_STATUS(al_hex_decode("0X1234", out, sizeof(out), &len), AL_OK);
    AL_CHECK_HEX(out, 2u, "1234");

    /* The prefix is skipped, not treated as data: a bare "0x" is zero bytes,
     * and "0x00" is one. */
    len = 99u;
    AL_CHECK_EQ_STATUS(al_hex_decode("0x", out, sizeof(out), &len), AL_OK);
    AL_CHECK_EQ_U64(len, 0u);
    AL_CHECK_EQ_STATUS(al_hex_decode("0x00", out, sizeof(out), &len), AL_OK);
    AL_CHECK_EQ_U64(len, 1u);

    /* An empty string is zero bytes, not an error. */
    len = 99u;
    AL_CHECK_EQ_STATUS(al_hex_decode("", out, sizeof(out), &len), AL_OK);
    AL_CHECK_EQ_U64(len, 0u);

    /* out_len is optional. */
    AL_CHECK_EQ_STATUS(al_hex_decode("1234", out, sizeof(out), NULL), AL_OK);

    /* Odd length cannot be a byte string. */
    AL_CHECK_EQ_STATUS(al_hex_decode("abc", out, sizeof(out), &len),
                       AL_ERR_MALFORMED);
    AL_CHECK_EQ_STATUS(al_hex_decode("0x123", out, sizeof(out), &len),
                       AL_ERR_MALFORMED);

    /* Non-hex characters, in either nibble. */
    AL_CHECK_EQ_STATUS(al_hex_decode("zz", out, sizeof(out), &len),
                       AL_ERR_MALFORMED);
    AL_CHECK_EQ_STATUS(al_hex_decode("0g", out, sizeof(out), &len),
                       AL_ERR_MALFORMED);
    AL_CHECK_EQ_STATUS(al_hex_decode("g0", out, sizeof(out), &len),
                       AL_ERR_MALFORMED);
    AL_CHECK_EQ_STATUS(al_hex_decode("00 11", out, sizeof(out), &len),
                       AL_ERR_MALFORMED);
    /*
     * The characters immediately either side of each accepted range, so the six
     * comparisons in al_hex_nibble cannot be off by one. Each is tried in both
     * nibble positions, because the two are separate calls and only one of them
     * would catch a bound applied to just the high nibble.
     *
     * Written as characters rather than as their hex codes: "2f" is the two
     * digits '2' and 'f' and decodes fine, which is a mistake worth naming
     * here since it is invisible on inspection.
     */
    static const char boundary[] = {
        '/',   /* '0' - 1 */
        ':',   /* '9' + 1 */
        '`',   /* 'a' - 1 */
        'g',   /* 'f' + 1 */
        '@',   /* 'A' - 1 */
        'G'    /* 'F' + 1 */
    };
    for (al_size i = 0u; i < sizeof(boundary); ++i) {
        char hi_bad[3];
        char lo_bad[3];
        hi_bad[0] = boundary[i]; hi_bad[1] = '0'; hi_bad[2] = '\0';
        lo_bad[0] = '0'; lo_bad[1] = boundary[i]; lo_bad[2] = '\0';
        AL_CHECK_EQ_STATUS(al_hex_decode(hi_bad, out, sizeof(out), &len),
                           AL_ERR_MALFORMED);
        AL_CHECK_EQ_STATUS(al_hex_decode(lo_bad, out, sizeof(out), &len),
                           AL_ERR_MALFORMED);
    }

    /* And the first character of each accepted range, which must be accepted -
     * a bound tightened by one would reject these. */
    AL_CHECK_EQ_STATUS(al_hex_decode("09", out, sizeof(out), &len), AL_OK);
    AL_CHECK_HEX(out, 1u, "09");
    AL_CHECK_EQ_STATUS(al_hex_decode("af", out, sizeof(out), &len), AL_OK);
    AL_CHECK_HEX(out, 1u, "af");
    AL_CHECK_EQ_STATUS(al_hex_decode("AF", out, sizeof(out), &len), AL_OK);
    AL_CHECK_HEX(out, 1u, "af");

    /* Capacity is checked as `bytes > out_cap`, so a buffer of exactly the
     * decoded size is accepted - unlike al_hex_encode, no terminator is
     * written to `out`. */
    AL_CHECK_EQ_STATUS(al_hex_decode("00112233", out, 4u, &len), AL_OK);
    AL_CHECK_EQ_U64(len, 4u);
    AL_CHECK_EQ_STATUS(al_hex_decode("00112233", out, 3u, &len),
                       AL_ERR_BUFFER_TOO_SMALL);

    AL_CHECK_EQ_STATUS(al_hex_decode(NULL, out, sizeof(out), &len),
                       AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_hex_decode("1234", NULL, sizeof(out), &len),
                       AL_ERR_INVALID_ARG);

    /*
     * On a malformed character the bytes decoded before it are already in the
     * destination: al_hex_decode does not zero its output on failure, unlike
     * al_reader_bytes, which does. Pinned rather than corrected because the two
     * have different callers - the reader's output is consumed by decoders that
     * check the status once at the end, while hex decoding is a boundary
     * conversion whose status is checked immediately. A caller that ignores it
     * gets a partial value either way; only the reader promises otherwise.
     */
    memset(out, 0xeeu, sizeof(out));
    len = 99u;
    AL_CHECK_EQ_STATUS(al_hex_decode("aabbZZ", out, sizeof(out), &len),
                       AL_ERR_MALFORMED);
    AL_CHECK_EQ_U64(out[0], 0xaau);
    AL_CHECK_EQ_U64(out[1], 0xbbu);
    AL_CHECK_EQ_U64(out[2], 0xeeu);              /* never reached */
    AL_CHECK_EQ_U64(len, 99u);                   /* not written on failure */
}

AL_TEST(hex_roundtrip_and_wrappers) {
    AL_CHECK_EQ_U64(AL_HASH_HEX_SIZE, 65u);
    AL_CHECK_EQ_U64(AL_ADDRESS_HEX_SIZE, 65u);

    /* Round-trip every byte value, so no nibble maps to the wrong character in
     * either direction. */
    al_u8 all[256];
    for (al_size i = 0u; i < sizeof(all); ++i) { all[i] = (al_u8)i; }

    char text[513];
    AL_CHECK_EQ_STATUS(al_hex_encode(al_bytes_make(all, sizeof(all)), text,
                                     sizeof(text)),
                       AL_OK);
    AL_CHECK_EQ_U64(strlen(text), 512u);

    al_u8   back[256];
    al_size len = 0u;
    AL_CHECK_EQ_STATUS(al_hex_decode(text, back, sizeof(back), &len), AL_OK);
    AL_CHECK_EQ_U64(len, 256u);
    AL_CHECK(al_bytes_eq(al_bytes_make(all, sizeof(all)),
                         al_bytes_make(back, len)) == AL_TRUE);

    /* The two convenience wrappers, which discard the status because their
     * capacity is fixed by the macro and therefore cannot be wrong. */
    al_hash256 h;
    al_address a;
    for (al_size i = 0u; i < AL_HASH_SIZE; ++i)    { h.bytes[i] = (al_u8)i; }
    for (al_size i = 0u; i < AL_ADDRESS_SIZE; ++i) { a.bytes[i] = (al_u8)(0xffu - i); }

    char hhex[AL_HASH_HEX_SIZE];
    char ahex[AL_ADDRESS_HEX_SIZE];
    al_hash_to_hex(&h, hhex);
    al_address_to_hex(&a, ahex);
    AL_CHECK_EQ_STR(hhex,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    AL_CHECK_EQ_STR(ahex,
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0");
    AL_CHECK_EQ_U64(strlen(hhex), 64u);
    AL_CHECK_EQ_U64(strlen(ahex), 64u);
}

/* -------------------------------------------------------------------------- */

AL_TEST_MAIN {
    AL_RUN(views_make_and_eq);
    AL_RUN(views_eq_ct_agrees_with_eq);
    AL_RUN(views_slice_bounds);
    AL_RUN(reader_integers_are_little_endian);
    AL_RUN(reader_truncation_is_sticky);
    AL_RUN(reader_take_and_copy);
    AL_RUN(reader_hash_and_address);
    AL_RUN(reader_finish_rejects_trailing_bytes);
    AL_RUN(varint_roundtrip_at_every_width);
    AL_RUN(varint_rejects_non_canonical);
    AL_RUN(varint_one_byte_space_is_exhaustive);
    AL_RUN(varint_two_byte_space_is_injective);
    AL_RUN(writer_byte_order_and_length);
    AL_RUN(writer_overflow_latches);
    AL_RUN(writer_reader_roundtrip_compound);
    AL_RUN(hex_encode_contract);
    AL_RUN(hex_decode_contract);
    AL_RUN(hex_roundtrip_and_wrappers);
}
