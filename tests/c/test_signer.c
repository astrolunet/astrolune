/*
 * Signer interface tests.
 */

#include "astrolune/signer.h"
#include "astrolune/crypto.h"

#include "altest.h"

#define AL_TEST_SUITE_NAME "signer"

AL_TEST(signer_new_from_keypair) {
    al_keypair kp;
    al_u8 seed[32];
    memset(seed, 0x42, sizeof(seed));
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);
    al_secure_zero(seed, sizeof(seed));

    al_signer *signer = NULL;
    AL_CHECK_EQ_STATUS(al_signer_new_from_keypair(&kp, &signer), AL_OK);
    AL_CHECK(signer != NULL);

    al_pubkey pk;
    AL_CHECK_EQ_STATUS(al_signer_pubkey(signer, &pk), AL_OK);
    AL_CHECK(memcmp(pk.bytes, kp.pk.bytes, AL_PUBKEY_SIZE) == 0);

    al_signer_destroy(signer);
}

AL_TEST(signer_new_from_hex) {
    al_keypair kp;
    al_u8 seed[32];
    memset(seed, 0xAB, sizeof(seed));
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);
    
    char hex[65];
    AL_CHECK_EQ_STATUS(al_hex_encode(al_bytes_make(seed, 32), hex, sizeof(hex)), AL_OK);
    al_secure_zero(seed, sizeof(seed));

    al_signer *signer = NULL;
    AL_CHECK_EQ_STATUS(al_signer_new_from_hex(hex, &signer), AL_OK);
    AL_CHECK(signer != NULL);

    al_pubkey pk;
    AL_CHECK_EQ_STATUS(al_signer_pubkey(signer, &pk), AL_OK);
    AL_CHECK(memcmp(pk.bytes, kp.pk.bytes, AL_PUBKEY_SIZE) == 0);

    al_signer_destroy(signer);
}

AL_TEST(signer_sign_and_verify) {
    al_keypair kp;
    al_u8 seed[32];
    memset(seed, 0x55, sizeof(seed));
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);
    al_secure_zero(seed, sizeof(seed));

    al_signer *signer = NULL;
    AL_CHECK_EQ_STATUS(al_signer_new_from_keypair(&kp, &signer), AL_OK);

    al_hash256 hash;
    memset(hash.bytes, 0xBE, sizeof(hash.bytes));

    al_sig sig;
    AL_CHECK_EQ_STATUS(al_signer_sign(signer, &hash, &sig), AL_OK);

    /* Verify the signature using the public key. */
    AL_CHECK_EQ_STATUS(al_verify_hash(&kp.pk, &hash, &sig), AL_OK);

    al_signer_destroy(signer);
}

AL_TEST(signer_encrypt_decrypt_seed) {
    /* Test that encrypt then decrypt recovers the original seed.
     * This test requires the sodium backend with crypto_pwhash support. */
    if (al_crypto_backend() != AL_CRYPTO_BACKEND_ED25519) {
        /* Skip test on dev backend - encrypted-at-rest not supported. */
        return;
    }
    
    al_u8 seed[32];
    memset(seed, 0x77, sizeof(seed));
    al_u8 decrypted[32];
    const char *passphrase = "test-passphrase-123";

    al_u8 encrypted[AL_SIGNER_ENCRYPTED_SIZE];
    AL_CHECK_EQ_STATUS(al_signer_encrypt_seed(seed, passphrase, encrypted), AL_OK);
    AL_CHECK_EQ_STATUS(al_signer_decrypt_seed(encrypted, passphrase, decrypted), AL_OK);
    AL_CHECK(memcmp(seed, decrypted, 32) == 0);
    
    al_secure_zero(seed, sizeof(seed));
    al_secure_zero(decrypted, sizeof(decrypted));
    al_secure_zero(encrypted, sizeof(encrypted));
}

AL_TEST(signer_wrong_passphrase_fails) {
    /* Test that wrong passphrase fails.
     * This test requires the sodium backend with crypto_pwhash support. */
    if (al_crypto_backend() != AL_CRYPTO_BACKEND_ED25519) {
        /* Skip test on dev backend - encrypted-at-rest not supported. */
        return;
    }
    
    al_u8 seed[32];
    memset(seed, 0x88, sizeof(seed));
    const char *passphrase = "correct-passphrase";
    const char *wrong_passphrase = "wrong-passphrase";

    al_u8 encrypted[AL_SIGNER_ENCRYPTED_SIZE];
    AL_CHECK_EQ_STATUS(al_signer_encrypt_seed(seed, passphrase, encrypted), AL_OK);

    al_u8 decrypted[32];
    al_status status = al_signer_decrypt_seed(encrypted, wrong_passphrase, decrypted);
    AL_CHECK_EQ_STATUS(status, AL_ERR_BAD_PROOF);

    al_secure_zero(seed, sizeof(seed));
    al_secure_zero(encrypted, sizeof(encrypted));
}

AL_TEST(signer_deterministic) {
    /* Two signers with the same keypair should produce the same signature. */
    al_keypair kp;
    al_u8 seed[32];
    memset(seed, 0x99, sizeof(seed));
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &kp), AL_OK);
    al_secure_zero(seed, sizeof(seed));

    al_signer *signer1 = NULL;
    al_signer *signer2 = NULL;
    AL_CHECK_EQ_STATUS(al_signer_new_from_keypair(&kp, &signer1), AL_OK);
    AL_CHECK_EQ_STATUS(al_signer_new_from_keypair(&kp, &signer2), AL_OK);

    al_hash256 hash;
    memset(hash.bytes, 0xCC, sizeof(hash.bytes));

    al_sig sig1, sig2;
    AL_CHECK_EQ_STATUS(al_signer_sign(signer1, &hash, &sig1), AL_OK);
    AL_CHECK_EQ_STATUS(al_signer_sign(signer2, &hash, &sig2), AL_OK);
    AL_CHECK(memcmp(sig1.bytes, sig2.bytes, AL_SIGNATURE_SIZE) == 0);

    al_signer_destroy(signer1);
    al_signer_destroy(signer2);
}

AL_TEST(signer_null_checks) {
    al_signer *signer = NULL;
    al_keypair kp;
    memset(&kp, 0, sizeof(kp));
    
    AL_CHECK_EQ_STATUS(al_signer_new_from_keypair(NULL, &signer), AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_signer_new_from_keypair(&kp, NULL), AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_signer_new_from_hex(NULL, &signer), AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_signer_new_from_hex("00", NULL), AL_ERR_INVALID_ARG);
    
    al_hash256 hash;
    al_sig sig;
    AL_CHECK_EQ_STATUS(al_signer_sign(NULL, &hash, &sig), AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_signer_pubkey(NULL, &kp.pk), AL_ERR_INVALID_ARG);
}

AL_TEST_MAIN {
    AL_RUN(signer_new_from_keypair);
    AL_RUN(signer_new_from_hex);
    AL_RUN(signer_sign_and_verify);
    AL_RUN(signer_encrypt_decrypt_seed);
    AL_RUN(signer_wrong_passphrase_fails);
    AL_RUN(signer_deterministic);
    AL_RUN(signer_null_checks);
}
