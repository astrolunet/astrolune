/*
 * astrolune/tools/ecosystem/share/content_encryptor.hpp
 *
 * Client-side content encryption for Astrolune Share paid content.
 *
 * Encrypts file content with a random symmetric key (XChaCha20-Poly1305 via
 * the core library's al_aead_* primitives) and wraps that key with the
 * buyer's X25519 public key so that only the buyer can decrypt.
 *
 * Features:
 *   - Whole-file and per-chunk encryption (chunks use deterministic nonces
 *     derived from a base nonce + chunk index, guaranteeing uniqueness).
 *   - Key wrapping via X25519 ECDH + HKDF + AEAD.
 *   - Per-recipient key derivation via HKDF for multiple buyers.
 *   - Threshold key sharing stub (future Shamir-style secret sharing).
 *
 * Design constraints:
 *   - No exceptions across ABI boundaries; errors return std::expected.
 *   - RAII throughout; no manual resource management.
 *   - Uses the core library's al_aead_*, al_kx_*, al_hkdf_*, al_secure_zero.
 */

#ifndef ASTROLUNE_SHARE_CONTENT_ENCRYPTOR_HPP
#define ASTROLUNE_SHARE_CONTENT_ENCRYPTOR_HPP

#include "astrolune/base.h"
#include "astrolune/crypto.h"
#include "astrolune/hash.h"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace astrolune::share {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr uint32_t kContentKeyVersion    = 1;
constexpr size_t   kContentKeySize       = AL_AEAD_KEY_SIZE;   // 32 bytes
constexpr size_t   kContentNonceSize     = AL_AEAD_NONCE_SIZE; // 24 bytes
constexpr size_t   kContentTagSize       = AL_AEAD_TAG_SIZE;   // 16 bytes
constexpr size_t   kMaxWrappedKeySize    = 256;                 // overhead for key envelope

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

enum class EncryptErrorCode {
    FileNotFound,
    FileOpenFailed,
    FileReadError,
    FileWriteError,
    FileEmpty,
    KeyGenerationFailed,
    KeyExchangeFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidCiphertext,
    HkdfDerivationFailed,
    ThresholdNotSupported,
    ChunkIndexOutOfRange,
    InternalError,
};

struct EncryptError {
    EncryptErrorCode code = EncryptErrorCode::InternalError;
    std::string message;

    static EncryptError make(EncryptErrorCode c, std::string msg) {
        return EncryptError{c, std::move(msg)};
    }
};

// ---------------------------------------------------------------------------
// ContentKey — symmetric key + nonce for AEAD
// ---------------------------------------------------------------------------

struct ContentKey {
    al_u8 key[kContentKeySize]{};
    al_u8 nonce[kContentNonceSize]{};

    // Generate a fresh random key and nonce.
    static ContentKey generate();

    // Derive a per-chunk nonce from the base nonce and chunk index.
    // Ensures nonce uniqueness across chunks without storing per-chunk values.
    void chunk_nonce(uint32_t index, al_u8 out[kContentNonceSize]) const;

    // Securely zero key material on destruction.
    ~ContentKey();
    ContentKey() = default;
    ContentKey(const ContentKey&);
    ContentKey& operator=(const ContentKey&);
    ContentKey(ContentKey&&) noexcept;
    ContentKey& operator=(ContentKey&&) noexcept;
};

// ---------------------------------------------------------------------------
// EncryptedChunk — a single encrypted chunk
// ---------------------------------------------------------------------------

struct EncryptedChunk {
    uint32_t index = 0;
    std::vector<uint8_t> ciphertext;  // includes AEAD tag
    al_u8 nonce[kContentNonceSize]{};

    // Original plaintext size = ciphertext.size() - kContentTagSize
    size_t plaintext_size() const;
};

// ---------------------------------------------------------------------------
// EncryptedContent — result of encrypting a file or buffer
// ---------------------------------------------------------------------------

struct EncryptedContent {
    uint32_t version = kContentKeyVersion;
    std::vector<uint8_t> encrypted_data;   // AEAD-encrypted content (whole-file mode)
    std::vector<EncryptedChunk> chunks;    // per-chunk encrypted data (chunk mode)
    std::vector<uint8_t> wrapped_key;      // content key encrypted for the buyer
    al_u8 content_nonce[kContentNonceSize]{};
    uint32_t chunk_count = 0;
    uint64_t plaintext_size = 0;

    bool is_chunked() const { return !chunks.empty(); }
};

// ---------------------------------------------------------------------------
// RecipientPublicKey — buyer's X25519 public key
// ---------------------------------------------------------------------------

struct RecipientPublicKey {
    al_u8 bytes[AL_KX_PUBLIC_KEY_SIZE]{};

    static RecipientPublicKey from_raw(const al_u8 pk[AL_KX_PUBLIC_KEY_SIZE]);
};

// ---------------------------------------------------------------------------
// RecipientKeyPair — buyer's full X25519 keypair (for decryption)
// ---------------------------------------------------------------------------

struct RecipientKeyPair {
    al_u8 pk[AL_KX_PUBLIC_KEY_SIZE]{};
    al_u8 sk[AL_KX_SECRET_KEY_SIZE]{};

    // Generate a fresh keypair.
    static std::expected<RecipientKeyPair, EncryptError> generate();

    RecipientPublicKey public_key() const;
};

// ---------------------------------------------------------------------------
// ContentEncryptorConfig — immutable encryption parameters
// ---------------------------------------------------------------------------

struct ContentEncryptorConfig {
    // Chunk size for per-chunk encryption (0 = whole-file mode).
    uint32_t chunk_size = 0;

    // HKDF info string for key derivation context.
    std::string derivation_info = "astrolune.share.content.v1";
};

// ---------------------------------------------------------------------------
// ContentEncryptor — the encryption engine
// ---------------------------------------------------------------------------

class ContentEncryptor {
public:
    ContentEncryptor();
    explicit ContentEncryptor(ContentEncryptorConfig config);
    ~ContentEncryptor();

    ContentEncryptor(const ContentEncryptor&) = delete;
    ContentEncryptor& operator=(const ContentEncryptor&) = delete;
    ContentEncryptor(ContentEncryptor&&) noexcept;
    ContentEncryptor& operator=(ContentEncryptor&&) noexcept;

    // --- File encryption ---------------------------------------------------

    // Encrypt a whole file. Returns the encrypted content envelope.
    std::expected<EncryptedContent, EncryptError> encrypt_file(
        const std::filesystem::path& path,
        const RecipientPublicKey& recipient);

    // Encrypt a file with per-chunk encryption for streaming/seekable access.
    std::expected<EncryptedContent, EncryptError> encrypt_file_chunked(
        const std::filesystem::path& path,
        const RecipientPublicKey& recipient);

    // Decrypt a whole-file encrypted envelope back to plaintext.
    std::expected<std::vector<uint8_t>, EncryptError> decrypt_file(
        const EncryptedContent& encrypted,
        const RecipientKeyPair& recipient);

    // Decrypt a single chunk from a chunked envelope.
    std::expected<std::vector<uint8_t>, EncryptError> decrypt_chunk(
        const EncryptedContent& encrypted,
        uint32_t chunk_index,
        const RecipientKeyPair& recipient);

    // --- Buffer encryption -------------------------------------------------

    // Encrypt an in-memory buffer (whole-buffer mode).
    std::expected<EncryptedContent, EncryptError> encrypt_buffer(
        std::span<const uint8_t> data,
        const RecipientPublicKey& recipient);

    // --- Key wrapping ------------------------------------------------------

    // Encrypt (wrap) a content key with the recipient's X25519 public key.
    // Uses ECDH + HKDF + AEAD internally.
    std::expected<std::vector<uint8_t>, EncryptError> encrypt_key(
        const ContentKey& content_key,
        const RecipientPublicKey& recipient);

    // Decrypt (unwrap) a content key with the recipient's X25519 keypair.
    std::expected<ContentKey, EncryptError> decrypt_key(
        std::span<const uint8_t> wrapped_key,
        const RecipientKeyPair& recipient);

    // --- Key derivation ----------------------------------------------------

    // Derive a per-recipient content key from a master key and recipient
    // identifier. Uses HKDF with the configured derivation info.
    std::expected<ContentKey, EncryptError> derive_key(
        const ContentKey& master_key,
        std::string_view recipient_id);

    // --- Threshold (future) ------------------------------------------------

    // Split a content key into `threshold` shares such that any `threshold`
    // shares can reconstruct the key. Stub — returns ThresholdNotSupported.
    std::expected<std::vector<std::vector<uint8_t>>, EncryptError> threshold_split(
        const ContentKey& key,
        uint32_t threshold,
        uint32_t total_shares);

    // Reconstruct a content key from shares. Stub — returns ThresholdNotSupported.
    std::expected<ContentKey, EncryptError> threshold_reconstruct(
        std::span<const std::vector<uint8_t>> shares);

    // --- Configuration -----------------------------------------------------

    void set_config(ContentEncryptorConfig config);
    const ContentEncryptorConfig& config() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace astrolune::share

#endif  // ASTROLUNE_SHARE_CONTENT_ENCRYPTOR_HPP
