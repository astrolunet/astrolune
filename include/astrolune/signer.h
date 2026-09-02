/*
 * astrolune/signer.h - signer interface abstraction.
 *
 * The daemon signs blocks and transactions through this interface without
 * knowing whether the key lives in a local file, an OS keystore, or a remote
 * signer process.
 *
 * SECURITY MODEL:
 *   - The seed file is stored in the node's data directory.
 *   - Optional encrypted-at-rest via passphrase-derived key (crypto_pwhash +
 *     crypto_secretbox). Enabled by setting a passphrase in config or CLI.
 *   - Operators are responsible for data-directory protection and backups.
 */

#ifndef ASTROLUNE_SIGNER_H
#define ASTROLUNE_SIGNER_H

#include "astrolune/base.h"
#include "astrolune/crypto.h"

AL_EXTERN_C_BEGIN

/* --------------------------------------------------------------------------
 * Signer interface (opaque)
 * -------------------------------------------------------------------------- */

typedef struct al_signer al_signer;

/* Sign a message hash using the signer's key. */
AL_PUBLIC AL_NODISCARD al_status al_signer_sign(al_signer *signer,
                                                const al_hash256 *hash,
                                                al_sig *sig_out);

/* Get the signer's public key. */
AL_PUBLIC AL_NODISCARD al_status al_signer_pubkey(const al_signer *signer,
                                                  al_pubkey *pk_out);

/* Destroy the signer and release resources. */
AL_PUBLIC void al_signer_destroy(al_signer *signer);

/* --------------------------------------------------------------------------
 * Constructors
 * -------------------------------------------------------------------------- */

/* Create a signer from an existing keypair (takes ownership of copy). */
AL_PUBLIC AL_NODISCARD al_status al_signer_new_from_keypair(
    const al_keypair *kp, al_signer **out);

/* Create a signer from a hex-encoded secret key / seed. */
AL_PUBLIC AL_NODISCARD al_status al_signer_new_from_hex(
    const char *hex, al_signer **out);

/* --------------------------------------------------------------------------
 * Encrypted seed storage helpers
 *
 * These helpers encrypt/decrypt a 32-byte seed using a passphrase. They do
 * NOT perform file I/O; the caller is responsible for persisting the result.
 *
 * Encrypted format: salt(32) || nonce(24) || ciphertext(48)
 * -------------------------------------------------------------------------- */

#define AL_SIGNER_SEED_SIZE    32u
#define AL_SIGNER_SALT_SIZE    32u
#define AL_SIGNER_NONCE_SIZE   24u
#define AL_SIGNER_MAC_SIZE     16u
#define AL_SIGNER_ENCRYPTED_SIZE (AL_SIGNER_SALT_SIZE + AL_SIGNER_NONCE_SIZE + AL_SIGNER_SEED_SIZE + AL_SIGNER_MAC_SIZE)

/* Encrypt a seed with a passphrase. Writes AL_SIGNER_ENCRYPTED_SIZE bytes to
 * `out`. The salt and nonce are generated from OS randomness. */
AL_PUBLIC AL_NODISCARD al_status al_signer_encrypt_seed(
    const al_u8 seed[AL_SIGNER_SEED_SIZE],
    const char *passphrase,
    al_u8 out[AL_SIGNER_ENCRYPTED_SIZE]);

/* Decrypt a seed with a passphrase. Returns AL_ERR_BAD_PROOF on wrong
 * passphrase. */
AL_PUBLIC AL_NODISCARD al_status al_signer_decrypt_seed(
    const al_u8 encrypted[AL_SIGNER_ENCRYPTED_SIZE],
    const char *passphrase,
    al_u8 seed_out[AL_SIGNER_SEED_SIZE]);

AL_EXTERN_C_END

#endif /* ASTROLUNE_SIGNER_H */
