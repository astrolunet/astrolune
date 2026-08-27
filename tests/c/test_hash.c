/*
 * SHA-256, HMAC, HKDF and the domain-separated hashing built on them.
 *
 * The primitive vectors come from the published sources - FIPS 180-4 for
 * SHA-256, RFC 4231 for HMAC, RFC 5869 for HKDF - so a mistake in the
 * implementation cannot be papered over by a self-consistent expectation.
 *
 * The tagged-hash vectors are Astrolune's own and were computed independently
 * with Python's hashlib. They pin the wire format: changing any of them changes
 * every hash in the protocol, which is a hard fork. Treat a failure here as a
 * consensus change until proven otherwise.
 */

#include "astrolune/hash.h"

#include "altest.h"

#define AL_TEST_SUITE_NAME "hash"

AL_TEST(sha256_nist_vectors) {
    al_hash256 h;

    al_sha256("", 0u, &h);
    AL_CHECK_HASH_HEX(h,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    al_sha256("abc", 3u, &h);
    AL_CHECK_HASH_HEX(h,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    /* 56 bytes: the length that forces padding into a second block. */
    const char *s448 =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    al_sha256(s448, strlen(s448), &h);
    AL_CHECK_HASH_HEX(h,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* 112 bytes. */
    const char *s896 =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    al_sha256(s896, strlen(s896), &h);
    AL_CHECK_HASH_HEX(h,
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
}

AL_TEST(sha256_streaming_matches_oneshot) {
    /* A million 'a's, fed in awkward chunk sizes. This is the vector that
     * catches a broken buffer-carry path, and the odd chunk lengths make sure
     * the partial-block handling is exercised at every offset. */
    al_sha256_ctx ctx;
    al_sha256_init(&ctx);

    char chunk[64];
    memset(chunk, 'a', sizeof(chunk));

    al_size remaining = 1000000u;
    al_size step      = 1u;
    while (remaining != 0u) {
        al_size take = (step <= remaining) ? step : remaining;
        if (take > sizeof(chunk)) {
            take = sizeof(chunk);
        }
        al_sha256_update(&ctx, chunk, take);
        remaining -= take;
        step = (step % 63u) + 1u;
    }

    al_hash256 h;
    al_sha256_final(&ctx, &h);
    AL_CHECK_HASH_HEX(h,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

AL_TEST(sha256_block_boundaries) {
    /* Lengths around the block size and around the padding threshold, compared
     * against a single-shot call over the same bytes. Any off-by-one in
     * al_sha256_final's padding shows up here. */
    al_u8 data[200];
    for (al_size i = 0u; i < sizeof(data); ++i) {
        data[i] = (al_u8)(i * 7u + 3u);
    }

    static const al_size lengths[] = {0, 1, 54, 55, 56, 57, 63, 64, 65,
                                      119, 120, 127, 128, 129, 200};
    for (al_size i = 0u; i < AL_COUNTOF(lengths); ++i) {
        al_size len = lengths[i];

        al_hash256 one_shot;
        al_sha256(data, len, &one_shot);

        /* Same input split at every possible point. */
        for (al_size cut = 0u; cut <= len; ++cut) {
            al_sha256_ctx ctx;
            al_sha256_init(&ctx);
            al_sha256_update(&ctx, data, cut);
            al_sha256_update(&ctx, data + cut, len - cut);

            al_hash256 split;
            al_sha256_final(&ctx, &split);
            AL_CHECK(al_hash_eq(&one_shot, &split));
        }
    }
}

AL_TEST(sha256d) {
    al_hash256 h;
    al_sha256d("abc", 3u, &h);
    /* SHA256(SHA256("abc")) */
    AL_CHECK_HASH_HEX(h,
        "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358");
}

AL_TEST(hmac_rfc4231) {
    al_hash256 mac;

    /* Test case 1: 20-byte key of 0x0b, data "Hi There". */
    al_u8 key1[20];
    memset(key1, 0x0b, sizeof(key1));
    al_hmac_sha256(key1, sizeof(key1), "Hi There", 8u, &mac);
    AL_CHECK_HASH_HEX(mac,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /* Test case 2: short key, exercises the zero-padding path. */
    al_hmac_sha256("Jefe", 4u, "what do ya want for nothing?", 28u, &mac);
    AL_CHECK_HASH_HEX(mac,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    /* Test case 3: 20-byte key of 0xaa, 50 bytes of 0xdd. */
    al_u8 key3[20], data3[50];
    memset(key3, 0xaa, sizeof(key3));
    memset(data3, 0xdd, sizeof(data3));
    al_hmac_sha256(key3, sizeof(key3), data3, sizeof(data3), &mac);
    AL_CHECK_HASH_HEX(mac,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /* Test case 6: 131-byte key, which is longer than the block size and must
     * therefore be replaced by its own digest. */
    al_u8 key6[131];
    memset(key6, 0xaa, sizeof(key6));
    al_hmac_sha256(key6, sizeof(key6),
                   "Test Using Larger Than Block-Size Key - Hash Key First",
                   54u, &mac);
    AL_CHECK_HASH_HEX(mac,
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

AL_TEST(hkdf_rfc5869) {
    /* RFC 5869 test case 1. */
    al_u8 ikm[22], salt[13], info[10];
    memset(ikm, 0x0b, sizeof(ikm));
    for (al_size i = 0u; i < sizeof(salt); ++i) {
        salt[i] = (al_u8)i;
    }
    for (al_size i = 0u; i < sizeof(info); ++i) {
        info[i] = (al_u8)(0xf0u + i);
    }

    al_hash256 prk;
    al_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), &prk);
    AL_CHECK_HASH_HEX(prk,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

    al_u8 okm[42];
    AL_CHECK_EQ_STATUS(al_hkdf_expand(&prk, info, sizeof(info), okm, sizeof(okm)),
                       AL_OK);
    AL_CHECK_HEX(okm, sizeof(okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865");

    /* RFC 5869 test case 3: empty salt and empty info. The absent salt must be
     * treated as 32 zero bytes, not skipped. */
    al_hash256 prk3;
    al_hkdf_extract(NULL, 0u, ikm, sizeof(ikm), &prk3);
    AL_CHECK_HASH_HEX(prk3,
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");

    al_u8 okm3[42];
    AL_CHECK_EQ_STATUS(al_hkdf_expand(&prk3, NULL, 0u, okm3, sizeof(okm3)),
                       AL_OK);
    AL_CHECK_HEX(okm3, sizeof(okm3),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8");

    /* The one-byte counter caps the output at 255 blocks. */
    al_u8 too_much[1];
    AL_CHECK_EQ_STATUS(al_hkdf_expand(&prk, info, sizeof(info), too_much,
                                      255u * AL_HASH_SIZE + 1u),
                       AL_ERR_OUT_OF_RANGE);
}

AL_TEST(tagged_hashing) {
    al_hash256 a, b;

    /* Golden values - these define the protocol's hashing. */
    al_hash_tagged(AL_TAG_TX, "", 0u, &a);
    AL_CHECK_HASH_HEX(a,
        "3922e2d0ac632767642c7b111fda161ccbacc2b7a8b3ad4064032b94896ba7c8");

    al_hash_tagged(AL_TAG_TX, "abc", 3u, &a);
    AL_CHECK_HASH_HEX(a,
        "c4ac5c66c834fdf45b4ac9bf1fd353e4c11b24fcf50b941435e8901bb8a6ab5d");

    /* Same data, different tag, different digest. This is the whole point of
     * domain separation: a transaction's bytes must not be reinterpretable as a
     * block header. */
    al_hash_tagged(AL_TAG_BLOCK, "abc", 3u, &b);
    AL_CHECK_HASH_HEX(b,
        "56ecdd8b74a02d32b53b1e28b7c79342941c2f8cf467122e4866f53107112174");
    AL_CHECK(!al_hash_eq(&a, &b));

    /* A tagged hash must also differ from the untagged hash of the same data. */
    al_hash256 plain;
    al_sha256("abc", 3u, &plain);
    AL_CHECK(!al_hash_eq(&a, &plain));

    /* al_hash_tagged_bytes is the same function through a view. */
    al_hash256 via_bytes;
    al_hash_tagged_bytes(AL_TAG_TX, al_bytes_from_cstr("abc"), &via_bytes);
    AL_CHECK(al_hash_eq(&a, &via_bytes));

    /* Because the tag is absorbed as its fixed-width digest, a tag/data split
     * cannot be shifted. If tags were prefixed raw, these two would collide. */
    al_hash256 shift_a, shift_b;
    al_hash_tagged("astrolune.x", "yz", 2u, &shift_a);
    al_hash_tagged("astrolune.xy", "z", 1u, &shift_b);
    AL_CHECK(!al_hash_eq(&shift_a, &shift_b));
}

AL_TEST(tagged_pair_is_order_sensitive) {
    al_hash256 l, r, lr, rl;
    al_sha256("left", 4u, &l);
    al_sha256("right", 5u, &r);

    al_hash_tagged_pair(AL_TAG_MERKLE_NODE, &l, &r, &lr);
    al_hash_tagged_pair(AL_TAG_MERKLE_NODE, &r, &l, &rl);
    AL_CHECK(!al_hash_eq(&lr, &rl));

    /* Aliasing the output with an input is used by the Merkle verifier's fold,
     * so it has to be safe. */
    al_hash256 acc = l;
    al_hash_tagged_pair(AL_TAG_MERKLE_NODE, &acc, &r, &acc);
    AL_CHECK(al_hash_eq(&acc, &lr));
}

AL_TEST(hash_utilities) {
    al_hash256 zero = al_hash_zero();
    AL_CHECK(al_hash_is_zero(&zero));

    al_hash256 h;
    al_sha256("x", 1u, &h);
    AL_CHECK(!al_hash_is_zero(&h));
    AL_CHECK(al_hash_eq(&h, &h));

    /* Ordering must be a total order with a normalised sign, because sets sorted
     * by it are serialised into blocks. */
    al_hash256 lo = al_hash_zero(), hi = al_hash_zero();
    hi.bytes[0] = 1u;
    AL_CHECK_EQ_I64(al_hash_cmp(&lo, &hi), -1);
    AL_CHECK_EQ_I64(al_hash_cmp(&hi, &lo), 1);
    AL_CHECK_EQ_I64(al_hash_cmp(&lo, &lo), 0);

    /* Ordering is by byte 0 first, so a difference late in the digest must not
     * outrank one at the start. */
    al_hash256 late = al_hash_zero();
    late.bytes[31] = 0xffu;
    AL_CHECK_EQ_I64(al_hash_cmp(&late, &hi), -1);

    /* Bit 0 is the most significant bit of byte 0. */
    al_hash256 bits = al_hash_zero();
    bits.bytes[0] = 0x80u;
    AL_CHECK(al_hash_bit(&bits, 0u));
    AL_CHECK(!al_hash_bit(&bits, 1u));

    bits.bytes[0] = 0x01u;
    AL_CHECK(!al_hash_bit(&bits, 0u));
    AL_CHECK(al_hash_bit(&bits, 7u));

    bits.bytes[31] = 0x01u;
    AL_CHECK(al_hash_bit(&bits, 255u));

    /* Out of range reads AL_FALSE rather than running off the end. */
    AL_CHECK(!al_hash_bit(&bits, 256u));
    AL_CHECK(!al_hash_bit(&bits, (al_size)-1));
}

AL_TEST_MAIN {
    AL_RUN(sha256_nist_vectors);
    AL_RUN(sha256_streaming_matches_oneshot);
    AL_RUN(sha256_block_boundaries);
    AL_RUN(sha256d);
    AL_RUN(hmac_rfc4231);
    AL_RUN(hkdf_rfc5869);
    AL_RUN(tagged_hashing);
    AL_RUN(tagged_pair_is_order_sensitive);
    AL_RUN(hash_utilities);
}
