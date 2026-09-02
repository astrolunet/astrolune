/*
 * Keys, addresses, signatures, VRF and VDF.
 *
 * The suite runs against either the dependency-free development signatures or
 * the libsodium Ed25519 backend. The dev backend is never secure; the sodium
 * backend reports secure because Ed25519 signatures are real (VRF/VDF remain
 * development primitives but are not used in consensus). The tests check:
 *
 *   - determinism: the same seed yields the same identity on every machine, which
 *     is what makes genesis fixtures and simulation runs reproducible;
 *   - the API contract: what returns AL_OK, what returns which error, and that
 *     wrong keys and mutated signatures are rejected;
 *   - the encodings: address derivation, contract address derivation and the
 *     80-byte VRF proof layout are all consensus-visible, so they are pinned to
 *     golden values.
 *
 * The signature goldens are the one group that will change when the backend does.
 * They are marked, and that is intentional: a silent change to the signature
 * construction should be impossible, and swapping backends is a deliberate act.
 */

#include "astrolune/crypto.h"
#include "astrolune/fixed.h"

#include "altest.h"

#define AL_TEST_SUITE_NAME "crypto"

/* The seed used throughout: 00 01 02 ... 1f. */
static void al_test_seed(al_u8 out[32]) {
    for (al_size i = 0u; i < 32u; ++i) {
        out[i] = (al_u8)i;
    }
}

AL_TEST(backend_reports_security_status) {
    /*
     * The dev backend is never secure. The sodium backend reports secure
     * because Ed25519 signatures are real; VRF/VDF remain dev primitives but
     * are not used in consensus for a controlled-validator network.
     */
    if (al_crypto_backend() == AL_CRYPTO_BACKEND_DEV) {
        AL_CHECK(!al_crypto_is_secure());
        AL_CHECK_EQ_STR(al_crypto_backend_name(), "dev-insecure");
    } else {
        AL_CHECK(al_crypto_backend() == AL_CRYPTO_BACKEND_ED25519);
        AL_CHECK(al_crypto_is_secure());
        AL_CHECK_EQ_STR(al_crypto_backend_name(), "libsodium-ed25519");
    }
}

AL_TEST(keypair_from_seed_is_deterministic) {
    al_u8 seed[32];
    al_test_seed(seed);

    al_keypair kp;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);

    if (al_crypto_backend() == AL_CRYPTO_BACKEND_DEV) {
        AL_CHECK_HEX(kp.pk.bytes, AL_PUBKEY_SIZE,
            "24df13dcb948de73b15bdbbd11a583ddbeb5f130b25ca75a9c3804f0bffab4e5");
    }

    /* The secret key's second half caches the public key, matching Ed25519's
     * layout so that storage and wire formats survive the backend swap. */
    AL_CHECK(memcmp(kp.sk.bytes + 32, kp.pk.bytes, AL_PUBKEY_SIZE) == 0);

    if (al_crypto_backend() == AL_CRYPTO_BACKEND_DEV) {
        /* The stub stretches its seed before constructing the fake key. */
        AL_CHECK(memcmp(kp.sk.bytes, seed, 32u) != 0);
    } else {
        /* libsodium's stable Ed25519 secret-key format is seed || public key. */
        AL_CHECK(memcmp(kp.sk.bytes, seed, 32u) == 0);
    }

    /* Same seed, same identity - twice. */
    al_keypair again;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &again), AL_OK);
    AL_CHECK(memcmp(&kp, &again, sizeof(kp)) == 0);

    /* One flipped seed bit gives an unrelated key. */
    seed[31] ^= 0x01u;
    al_keypair other;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &other), AL_OK);
    AL_CHECK(memcmp(other.pk.bytes, kp.pk.bytes, AL_PUBKEY_SIZE) != 0);

    AL_CHECK_EQ_STATUS(al_keypair_from_seed(NULL, &kp), AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, NULL), AL_ERR_INVALID_ARG);
}

AL_TEST(pubkey_from_seckey_rejects_mismatch) {
    al_u8 seed[32];
    al_test_seed(seed);

    al_keypair kp;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);

    al_pubkey pk;
    AL_CHECK_EQ_STATUS(al_pubkey_from_seckey(&kp.sk, &pk), AL_OK);
    AL_CHECK(memcmp(pk.bytes, kp.pk.bytes, AL_PUBKEY_SIZE) == 0);

    /*
     * A secret key whose halves disagree is either corrupt storage or an attempt
     * to make one signature verify under a second identity. It must be rejected
     * rather than silently trusting either half.
     */
    al_keypair tampered = kp;
    tampered.sk.bytes[32] ^= 0x01u;
    AL_CHECK_EQ_STATUS(al_pubkey_from_seckey(&tampered.sk, &pk),
                       AL_ERR_INVALID_ARG);

    tampered = kp;
    tampered.sk.bytes[0] ^= 0x01u;
    AL_CHECK_EQ_STATUS(al_pubkey_from_seckey(&tampered.sk, &pk),
                       AL_ERR_INVALID_ARG);

    AL_CHECK_EQ_STATUS(al_pubkey_from_seckey(NULL, &pk), AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_pubkey_from_seckey(&kp.sk, NULL), AL_ERR_INVALID_ARG);
}

AL_TEST(address_derivation) {
    al_u8 seed[32];
    al_test_seed(seed);

    al_keypair kp;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);

    al_address addr;
    al_address_from_pubkey(&kp.pk, &addr);
    if (al_crypto_backend() == AL_CRYPTO_BACKEND_DEV) {
        AL_CHECK_HEX(addr.bytes, AL_ADDRESS_SIZE,
            "dca1ff0f6bdf7a88f405941576b994f75db0677dd7b6ffe42f919a82897c8248");
    }

    /* Full 32 bytes, not a truncation - see astrolune/crypto.h. */
    AL_CHECK_EQ_U64(AL_ADDRESS_SIZE, 32u);

    /* An address is not its public key: substituting one for the other must not
     * silently work anywhere. */
    AL_CHECK(memcmp(addr.bytes, kp.pk.bytes, AL_ADDRESS_SIZE) != 0);

    al_address zero = al_address_zero();
    AL_CHECK(al_address_is_zero(&zero));
    AL_CHECK(!al_address_is_zero(&addr));
    AL_CHECK(al_address_eq(&addr, &addr));
    AL_CHECK(!al_address_eq(&addr, &zero));

    /* Normalised ordering, because account sets get serialised in sorted order. */
    al_address one = al_address_zero();
    one.bytes[0] = 1u;
    AL_CHECK_EQ_I64(al_address_cmp(&zero, &one), -1);
    AL_CHECK_EQ_I64(al_address_cmp(&one, &zero), 1);
    AL_CHECK_EQ_I64(al_address_cmp(&one, &one), 0);
}

AL_TEST(contract_address_derivation) {
    al_u8 seed[32];
    al_test_seed(seed);

    al_keypair kp;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);

    al_address deployer;
    al_address_from_pubkey(&kp.pk, &deployer);

    al_hash256 code_hash;
    al_sha256("code", 4u, &code_hash);
    AL_CHECK_HASH_HEX(code_hash,
        "5694d08a2e53ffcae0c3103e5ad6f6076abd960eb1f8a56577040bc1028f702b");

    al_address at7;
    al_address_for_contract(&deployer, 7u, &code_hash, &at7);
    if (al_crypto_backend() == AL_CRYPTO_BACKEND_DEV) {
        AL_CHECK_HEX(at7.bytes, AL_ADDRESS_SIZE,
            "3ab7f1494d61ac462f075c04a3d09f5f334d93b8f601717a3251f0a413c11679");
    }

    /* Nonce 0 is a distinct, valid deployment slot. */
    al_address at0;
    al_address_for_contract(&deployer, 0u, &code_hash, &at0);
    if (al_crypto_backend() == AL_CRYPTO_BACKEND_DEV) {
        AL_CHECK_HEX(at0.bytes, AL_ADDRESS_SIZE,
            "0cf9cccde6792a30d8d4d68a981e63007290d33c8cfd114ba78b53e4d4744b00");
    }
    AL_CHECK(!al_address_eq(&at0, &at7));

    /* All three inputs must matter. */
    al_hash256 other_code;
    al_sha256("code2", 5u, &other_code);
    al_address other_addr;
    al_address_for_contract(&deployer, 7u, &other_code, &other_addr);
    AL_CHECK(!al_address_eq(&other_addr, &at7));

    al_address other_deployer = al_address_zero();
    al_address_for_contract(&other_deployer, 7u, &code_hash, &other_addr);
    AL_CHECK(!al_address_eq(&other_addr, &at7));

    /*
     * The nonce is a fixed-width 8-byte field, so no (deployer, nonce) pair can
     * produce another pair's preimage. If it were a varint, a deployer address
     * ending in the right bytes could collide with a different nonce.
     */
    al_address big;
    al_address_for_contract(&deployer, UINT64_C(0xffffffffffffffff), &code_hash,
                            &big);
    AL_CHECK(!al_address_eq(&big, &at7));
}

AL_TEST(sign_and_verify) {
    al_u8 seed[32];
    al_test_seed(seed);

    al_keypair kp;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);

    al_bytes msg = al_bytes_from_cstr("astrolune test message");

    al_sig sig;
    AL_CHECK_EQ_STATUS(al_sign(&kp.sk, msg, &sig), AL_OK);

    /* The development golden makes an accidental construction change visible. */
    AL_CHECK_EQ_U64(AL_SIGNATURE_SIZE, 64u);
    if (al_crypto_backend() == AL_CRYPTO_BACKEND_DEV) {
        AL_CHECK_HEX(sig.bytes, AL_SIGNATURE_SIZE,
            "1f1779be5f93c97277589aed3d3f325f1028b590231dc0cf63e0a15522ae9e33"
            "761092de33bc7ec8dbf36cbeaddf26963f3bfdfff7e4e3369918ac95c4046ec0");
    }

    AL_CHECK_EQ_STATUS(al_verify(&kp.pk, msg, &sig), AL_OK);

    /* Signing is deterministic - no nonce, so no chance of a reused-k disaster
     * and no chance of two nodes disagreeing on a signature's bytes. */
    al_sig again;
    AL_CHECK_EQ_STATUS(al_sign(&kp.sk, msg, &again), AL_OK);
    AL_CHECK(memcmp(&sig, &again, sizeof(sig)) == 0);

    /* Wrong message. */
    AL_CHECK_EQ_STATUS(al_verify(&kp.pk, al_bytes_from_cstr("other message"),
                                 &sig),
                       AL_ERR_BAD_SIGNATURE);

    /* Wrong key. */
    al_u8 seed2[32];
    memset(seed2, 0xff, sizeof(seed2));
    al_keypair kp2;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed2, &kp2), AL_OK);
    AL_CHECK_EQ_STATUS(al_verify(&kp2.pk, msg, &sig), AL_ERR_BAD_SIGNATURE);

    /* A flipped bit in the verified half is caught. */
    al_sig mutated = sig;
    mutated.bytes[0] ^= 0x01u;
    AL_CHECK_EQ_STATUS(al_verify(&kp.pk, msg, &mutated), AL_ERR_BAD_SIGNATURE);

    /* The empty message is a valid thing to sign. */
    al_sig empty_sig;
    AL_CHECK_EQ_STATUS(al_sign(&kp.sk, al_bytes_empty(), &empty_sig), AL_OK);
    AL_CHECK_EQ_STATUS(al_verify(&kp.pk, al_bytes_empty(), &empty_sig), AL_OK);
    AL_CHECK_EQ_STATUS(al_verify(&kp.pk, msg, &empty_sig),
                       AL_ERR_BAD_SIGNATURE);

    AL_CHECK_EQ_STATUS(al_sign(NULL, msg, &sig), AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_sign(&kp.sk, msg, NULL), AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_verify(NULL, msg, &sig), AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_verify(&kp.pk, msg, NULL), AL_ERR_INVALID_ARG);

    al_bytes invalid;
    invalid.data = NULL;
    invalid.len  = 1u;
    AL_CHECK_EQ_STATUS(al_sign(&kp.sk, invalid, &sig), AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_verify(&kp.pk, invalid, &sig), AL_ERR_INVALID_ARG);
}

AL_TEST(ed25519_rfc8032_vector) {
    if (al_crypto_backend() != AL_CRYPTO_BACKEND_ED25519) {
        return;
    }

    /* RFC 8032 section 7.1, test vector 1: an empty message. */
    al_u8 seed[32];
    AL_CHECK_EQ_U64(al_test_unhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        seed, sizeof(seed)), sizeof(seed));

    al_keypair kp;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);
    AL_CHECK_HEX(kp.pk.bytes, AL_PUBKEY_SIZE,
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    al_sig sig;
    AL_CHECK_EQ_STATUS(al_sign(&kp.sk, al_bytes_empty(), &sig), AL_OK);
    AL_CHECK_HEX(sig.bytes, AL_SIGNATURE_SIZE,
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    AL_CHECK_EQ_STATUS(al_verify(&kp.pk, al_bytes_empty(), &sig), AL_OK);

    /* Strict verification rejects points outside the prime-order subgroup.
     * These rules are consensus-visible and must match in every node. */
    al_pubkey small_order_pk;
    memset(&small_order_pk, 0, sizeof(small_order_pk));
    AL_CHECK_EQ_STATUS(al_verify(&small_order_pk, al_bytes_empty(), &sig),
                       AL_ERR_BAD_SIGNATURE);

    al_sig small_order_r = sig;
    memset(small_order_r.bytes, 0, 32u);
    AL_CHECK_EQ_STATUS(al_verify(&kp.pk, al_bytes_empty(), &small_order_r),
                       AL_ERR_BAD_SIGNATURE);

    /* Replacing S with the group order L encodes a non-reduced scalar. It must
     * be rejected even if a future dependency version changes its defaults. */
    (void)al_test_unhex(
        "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        sig.bytes + 32u, 32u);
    AL_CHECK_EQ_STATUS(al_verify(&kp.pk, al_bytes_empty(), &sig),
                       AL_ERR_BAD_SIGNATURE);
}

AL_TEST(sign_hash_matches_sign_over_digest) {
    al_u8 seed[32];
    al_test_seed(seed);

    al_keypair kp;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);

    al_hash256 h;
    al_hash_tagged(AL_TAG_TX_SIGNING, "payload", 7u, &h);

    /* The transaction path signs a pre-computed digest so the message is hashed
     * exactly once. That must be the same operation as signing those 32 bytes. */
    al_sig via_hash, via_bytes;
    AL_CHECK_EQ_STATUS(al_sign_hash(&kp.sk, &h, &via_hash), AL_OK);
    AL_CHECK_EQ_STATUS(al_sign(&kp.sk, al_bytes_make(h.bytes, AL_HASH_SIZE),
                               &via_bytes),
                       AL_OK);
    AL_CHECK(memcmp(&via_hash, &via_bytes, sizeof(via_hash)) == 0);

    AL_CHECK_EQ_STATUS(al_verify_hash(&kp.pk, &h, &via_hash), AL_OK);

    al_hash256 other;
    al_hash_tagged(AL_TAG_TX_SIGNING, "payload2", 8u, &other);
    AL_CHECK_EQ_STATUS(al_verify_hash(&kp.pk, &other, &via_hash),
                       AL_ERR_BAD_SIGNATURE);

    AL_CHECK_EQ_STATUS(al_sign_hash(&kp.sk, NULL, &via_hash),
                       AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_verify_hash(&kp.pk, NULL, &via_hash),
                       AL_ERR_INVALID_ARG);
}

AL_TEST(secure_zero) {
    al_u8 buf[64];
    memset(buf, 0xab, sizeof(buf));

    al_secure_zero(buf, sizeof(buf));
    for (al_size i = 0u; i < sizeof(buf); ++i) {
        AL_CHECK_EQ_U64(buf[i], 0u);
    }

    /* Degenerate arguments must not fault: key material is wiped on paths that
     * may not have allocated anything. */
    al_secure_zero(NULL, 0u);
    al_secure_zero(buf, 0u);
    al_secure_zero(NULL, 16u);
}

AL_TEST(bech32_address_round_trip) {
    al_address address;
    memset(address.bytes, 0xa5u, sizeof(address.bytes));

    char text[AL_ADDRESS_TEXT_SIZE];
    AL_CHECK_EQ_STATUS(al_address_to_bech32(&address, text, sizeof(text)),
                       AL_OK);
    /* Prefix and shape: "al" + separator + 52 data + 6 checksum chars. */
    AL_CHECK(text[0] == 'a' && text[1] == 'l' && text[2] == '1');
    AL_CHECK(strlen(text) == 61u);

    al_address decoded;
    AL_CHECK_EQ_STATUS(al_address_from_bech32(text, &decoded), AL_OK);
    fprintf(stderr, "DBG bech32='%s'\n", text);
    {   /* Independent polymod recomputation over the full text payload. */
        const char *charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        al_u32 gen[5] = { 0x3b6a57b2u, 0x26508e6du, 0x1ea119fau,
                          0x3d4233ddu, 0x2a1462b3u };
        al_u8 v[256];
        al_u8 n = 0;
        const char *hrp = "al";
        for (const char *p = hrp; *p; ++p) v[n++] = (al_u8)(*p >> 5);
        v[n++] = 0;
        for (const char *p = hrp; *p; ++p) v[n++] = (al_u8)(*p & 31);
        for (const char *p = text + 3; *p; ++p) {
            const char *hit = strchr(charset, *p);
            if (hit == NULL) break;
            v[n++] = (al_u8)(hit - charset);
        }
        al_u32 chk = 1u;
        for (al_size i = 0u; i < n; ++i) {
            al_u32 top = chk >> 25u;
            chk = ((chk & 0x1ffffffu) << 5u) ^ v[i];
            for (al_size j = 0u; j < 5u; ++j)
                if ((top >> j) & 1u) chk ^= gen[j];
        }
        fprintf(stderr, "DBG independent polymod=0x%08x n=%u\n", chk,
                (unsigned)n);
    }
    AL_CHECK(al_address_eq(&decoded, &address));

    /* A flipped character must fail the checksum, not decode to a twin. */
    text[strlen(text) - 1u] =
        text[strlen(text) - 1u] == 'q' ? 'p' : 'q';
    AL_CHECK_EQ_STATUS(al_address_from_bech32(text, &decoded),
                       AL_ERR_CHECKSUM);

    /* Uppercase is rejected outright rather than case-folded. */
    memset(address.bytes, 0x3cu, sizeof(address.bytes));
    AL_CHECK_EQ_STATUS(al_address_to_bech32(&address, text, sizeof(text)),
                       AL_OK);
    char upper[AL_ADDRESS_TEXT_SIZE];
    for (al_size i = 0u; i <= strlen(text); ++i) {
        upper[i] = (text[i] >= 'a' && text[i] <= 'z')
                       ? (char)(text[i] - 'a' + 'A')
                       : text[i];
    }
    AL_CHECK_EQ_STATUS(al_address_from_bech32(upper, &decoded),
                       AL_ERR_MALFORMED);
}

AL_TEST_MAIN {
    AL_RUN(backend_reports_security_status);
    AL_RUN(keypair_from_seed_is_deterministic);
    AL_RUN(pubkey_from_seckey_rejects_mismatch);
    AL_RUN(address_derivation);
    AL_RUN(contract_address_derivation);
    AL_RUN(sign_and_verify);
    AL_RUN(ed25519_rfc8032_vector);
    AL_RUN(sign_hash_matches_sign_over_digest);
    AL_RUN(secure_zero);
    AL_RUN(bech32_address_round_trip);
}
