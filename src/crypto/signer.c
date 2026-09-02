/*
 * Signer interface implementation.
 *
 * The file-based signer is the default. Encrypted-at-rest uses libsodium's
 * crypto_pwhash for key derivation and crypto_secretbox for encryption.
 * These features are only available when building with the sodium backend.
 */

#include "astrolune/signer.h"

#include "internal/common.h"

#include <stdlib.h>
#include <string.h>

/* Include sodium header conditionally. */
#if defined(ASTROLUNE_HAS_SODIUM)
#  include <sodium.h>
#endif

/* --------------------------------------------------------------------------
 * Signer structure
 * -------------------------------------------------------------------------- */

struct al_signer {
    al_keypair keypair;
};

/* --------------------------------------------------------------------------
 * Constructors
 * -------------------------------------------------------------------------- */

al_status al_signer_new_from_keypair(const al_keypair *kp, al_signer **out) {
    if (kp == NULL || out == NULL) return AL_ERR_INVALID_ARG;
    
    al_signer *signer = (al_signer *)malloc(sizeof(al_signer));
    if (signer == NULL) return AL_ERR_OUT_OF_MEMORY;
    
    signer->keypair = *kp;
    *out = signer;
    return AL_OK;
}

al_status al_signer_new_from_hex(const char *hex, al_signer **out) {
    if (hex == NULL || out == NULL) return AL_ERR_INVALID_ARG;
    
    al_u8 seed[32];
    al_status status = al_hex_decode(hex, seed, sizeof(seed), NULL);
    if (status != AL_OK) return AL_ERR_MALFORMED;
    
    al_keypair kp;
    status = al_keypair_from_seed(seed, &kp);
    al_secure_zero(seed, sizeof(seed));
    if (status != AL_OK) return status;
    
    return al_signer_new_from_keypair(&kp, out);
}

/* --------------------------------------------------------------------------
 * Interface methods
 * -------------------------------------------------------------------------- */

al_status al_signer_sign(al_signer *signer, const al_hash256 *hash,
                         al_sig *sig_out) {
    if (signer == NULL || hash == NULL || sig_out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    return al_sign_hash(&signer->keypair.sk, hash, sig_out);
}

al_status al_signer_pubkey(const al_signer *signer, al_pubkey *pk_out) {
    if (signer == NULL || pk_out == NULL) return AL_ERR_INVALID_ARG;
    *pk_out = signer->keypair.pk;
    return AL_OK;
}

void al_signer_destroy(al_signer *signer) {
    if (signer == NULL) return;
    al_wipe(&signer->keypair, sizeof(signer->keypair));
    free(signer);
}

/* --------------------------------------------------------------------------
 * Encrypted seed storage helpers
 * -------------------------------------------------------------------------- */

#if defined(ASTROLUNE_HAS_SODIUM)

al_status al_signer_encrypt_seed(const al_u8 seed[AL_SIGNER_SEED_SIZE],
                                 const char *passphrase,
                                 al_u8 out[AL_SIGNER_ENCRYPTED_SIZE]) {
    if (seed == NULL || passphrase == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    
    /* Generate salt and nonce using libsodium. */
    al_u8 *salt = out;
    al_u8 *nonce = out + AL_SIGNER_SALT_SIZE;
    al_u8 *ciphertext = out + AL_SIGNER_SALT_SIZE + AL_SIGNER_NONCE_SIZE;
    
    randombytes_buf(salt, AL_SIGNER_SALT_SIZE);
    randombytes_buf(nonce, AL_SIGNER_NONCE_SIZE);
    
    /* Derive key from passphrase. */
    al_u8 key[32];
    if (crypto_pwhash(key, sizeof(key),
                      passphrase, strlen(passphrase),
                      salt, crypto_pwhash_OPSLIMIT_SENSITIVE,
                      crypto_pwhash_MEMLIMIT_SENSITIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return AL_ERR_UNSUPPORTED;
    }
    
    /* Encrypt. */
    crypto_secretbox_easy(ciphertext, seed, AL_SIGNER_SEED_SIZE, nonce, key);
    al_secure_zero(key, sizeof(key));
    
    return AL_OK;
}

al_status al_signer_decrypt_seed(const al_u8 encrypted[AL_SIGNER_ENCRYPTED_SIZE],
                                 const char *passphrase,
                                 al_u8 seed_out[AL_SIGNER_SEED_SIZE]) {
    if (encrypted == NULL || passphrase == NULL || seed_out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    
    const al_u8 *salt = encrypted;
    const al_u8 *nonce = encrypted + AL_SIGNER_SALT_SIZE;
    const al_u8 *ciphertext = encrypted + AL_SIGNER_SALT_SIZE + AL_SIGNER_NONCE_SIZE;
    
    /* Derive key from passphrase. */
    al_u8 key[32];
    if (crypto_pwhash(key, sizeof(key),
                      passphrase, strlen(passphrase),
                      salt, crypto_pwhash_OPSLIMIT_SENSITIVE,
                      crypto_pwhash_MEMLIMIT_SENSITIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return AL_ERR_UNSUPPORTED;
    }
    
    /* Decrypt. */
    if (crypto_secretbox_open_easy(seed_out, ciphertext,
                                   AL_SIGNER_SEED_SIZE + AL_SIGNER_MAC_SIZE,
                                   nonce, key) != 0) {
        al_secure_zero(key, sizeof(key));
        return AL_ERR_BAD_PROOF; /* Wrong passphrase */
    }
    
    al_secure_zero(key, sizeof(key));
    return AL_OK;
}

#else /* dev backend - encrypted-at-rest not supported */

al_status al_signer_encrypt_seed(const al_u8 seed[AL_SIGNER_SEED_SIZE],
                                 const char *passphrase,
                                 al_u8 out[AL_SIGNER_ENCRYPTED_SIZE]) {
    (void)seed;
    (void)passphrase;
    (void)out;
    return AL_ERR_UNSUPPORTED;
}

al_status al_signer_decrypt_seed(const al_u8 encrypted[AL_SIGNER_ENCRYPTED_SIZE],
                                 const char *passphrase,
                                 al_u8 seed_out[AL_SIGNER_SEED_SIZE]) {
    (void)encrypted;
    (void)passphrase;
    (void)seed_out;
    return AL_ERR_UNSUPPORTED;
}

#endif /* ASTROLUNE_HAS_SODIUM */
