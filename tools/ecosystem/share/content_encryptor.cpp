/*
 * astrolune/tools/ecosystem/share/content_encryptor.cpp
 *
 * Implementation of client-side content encryption for Astrolune Share.
 *
 * Encryption protocol:
 *   1. Generate a random ContentKey (32-byte XChaCha20 key + 24-byte nonce).
 *   2. Encrypt file content with al_aead_encrypt using the content key.
 *      For chunked mode, each chunk gets a deterministic nonce derived from
 *      the base nonce via HKDF(base_nonce || chunk_index), ensuring uniqueness.
 *   3. Wrap the content key for the recipient:
 *      a. Generate an ephemeral X25519 keypair.
 *      b. Compute ECDH(shared_secret, recipient_pk).
 *      c. HKDF-derive a wrapping key from the shared secret.
 *      d. AEAD-encrypt the content key with the wrapping key.
 *      e. The wrapped_key = ephemeral_pk || encrypted_key || tag.
 *
 * Decryption reverses the process: unwrap the content key via ECDH, then
 * decrypt the content.
 *
 * All key material is securely zeroed via al_secure_zero when it goes out
 * of scope.
 */

#include "content_encryptor.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <fstream>

#include <sodium.h>

namespace astrolune::share {

// ---------------------------------------------------------------------------
// HKDF info strings for key derivation
// ---------------------------------------------------------------------------

namespace {

constexpr const char* kHkdfInfoKeyWrap    = "astrolune.share.keywrap.v1";
constexpr const char* kHkdfInfoKeyDerive  = "astrolune.share.derive.v1";
constexpr const char* kHkdfInfoNonce      = "astrolune.share.nonce.v1";
constexpr const char* kHkdfInfoThreshold  = "astrolune.share.threshold.v1";

// ---------------------------------------------------------------------------
// Secure RAII wrapper for raw byte arrays
// ---------------------------------------------------------------------------

struct SecureBytes {
    al_u8* data;
    al_size len;

    explicit SecureBytes(al_size n) : len(n) {
        data = static_cast<al_u8*>(std::malloc(n));
        if (data) std::memset(data, 0, n);
    }

    ~SecureBytes() {
        if (data) {
            al_secure_zero(data, len);
            std::free(data);
        }
    }

    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;
    SecureBytes(SecureBytes&& o) noexcept : data(o.data), len(o.len) {
        o.data = nullptr;
        o.len = 0;
    }
    SecureBytes& operator=(SecureBytes&& o) noexcept {
        if (this != &o) {
            if (data) { al_secure_zero(data, len); std::free(data); }
            data = o.data; len = o.len;
            o.data = nullptr; o.len = 0;
        }
        return *this;
    }

    al_u8* get() { return data; }
    const al_u8* get() const { return data; }
    bool valid() const { return data != nullptr; }
};

// ---------------------------------------------------------------------------
// Derive a wrapping key from an ECDH shared secret
// ---------------------------------------------------------------------------

std::expected<SecureBytes, EncryptError> derive_wrapping_key(
    const al_u8 shared_secret[AL_KX_SHARED_KEY_SIZE],
    const al_u8 remote_pk[AL_KX_PUBLIC_KEY_SIZE]) {

    // HKDF-Extract: salt = remote_pk, IKM = shared_secret
    al_hash256 prk{};
    al_hkdf_extract(remote_pk, AL_KX_PUBLIC_KEY_SIZE,
                    shared_secret, AL_KX_SHARED_KEY_SIZE, &prk);

    // HKDF-Expand: derive AL_AEAD_KEY_SIZE bytes
    SecureBytes wrapping_key(AL_AEAD_KEY_SIZE);
    if (!wrapping_key.valid()) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::InternalError, "allocation failed"));
    }

    auto status = al_hkdf_expand(&prk, kHkdfInfoKeyWrap,
                                  std::strlen(kHkdfInfoKeyWrap),
                                  wrapping_key.get(), AL_AEAD_KEY_SIZE);
    al_secure_zero(&prk, sizeof(prk));

    if (status != AL_OK) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::HkdfDerivationFailed,
            "HKDF-Expand failed for wrapping key"));
    }

    return wrapping_key;
}

// ---------------------------------------------------------------------------
// Derive a per-chunk nonce from a base nonce
// ---------------------------------------------------------------------------

void derive_chunk_nonce(const al_u8 base_nonce[kContentNonceSize],
                        uint32_t chunk_index,
                        al_u8 out[kContentNonceSize]) {
    // HKDF-Extract: salt = base_nonce, IKM = index_bytes
    al_u8 index_buf[4];
    index_buf[0] = static_cast<al_u8>((chunk_index >> 24) & 0xFF);
    index_buf[1] = static_cast<al_u8>((chunk_index >> 16) & 0xFF);
    index_buf[2] = static_cast<al_u8>((chunk_index >> 8)  & 0xFF);
    index_buf[3] = static_cast<al_u8>((chunk_index)       & 0xFF);

    al_hash256 prk{};
    al_hkdf_extract(base_nonce, kContentNonceSize, index_buf, 4, &prk);

    // Expand to nonce size
    al_hkdf_expand(&prk, kHkdfInfoNonce, std::strlen(kHkdfInfoNonce),
                    out, kContentNonceSize);
    al_secure_zero(&prk, sizeof(prk));
}

// ---------------------------------------------------------------------------
// ContentEncryptor::Impl
// ---------------------------------------------------------------------------

struct ContentEncryptor::Impl {
    ContentEncryptorConfig cfg;

    explicit Impl(ContentEncryptorConfig c) : cfg(std::move(c)) {}

    // --- Key wrapping (encrypt content key for a recipient) -----------------

    std::expected<std::vector<uint8_t>, EncryptError> wrap_key(
        const ContentKey& content_key,
        const RecipientPublicKey& recipient) {

        // 1. Generate ephemeral X25519 keypair
        al_kx_keypair ephemeral{};
        if (al_kx_keygen(&ephemeral) != AL_OK) {
            return std::unexpected(EncryptError::make(
                EncryptErrorCode::KeyGenerationFailed,
                "ephemeral keypair generation failed"));
        }

        // 2. Compute ECDH shared secret
        al_u8 shared_secret[AL_KX_SHARED_KEY_SIZE]{};
        if (al_kx_shared(&ephemeral, recipient.bytes, shared_secret) != AL_OK) {
            al_secure_zero(shared_secret, sizeof(shared_secret));
            return std::unexpected(EncryptError::make(
                EncryptErrorCode::KeyExchangeFailed,
                "X25519 ECDH failed"));
        }

        // 3. Derive wrapping key via HKDF
        auto wk_result = derive_wrapping_key(shared_secret, recipient.bytes);
        al_secure_zero(shared_secret, sizeof(shared_secret));
        if (!wk_result) return std::unexpected(std::move(wk_result.error()));

        // 4. Build plaintext = key || nonce
        std::vector<uint8_t> key_plaintext;
        key_plaintext.reserve(kContentKeySize + kContentNonceSize);
        key_plaintext.insert(key_plaintext.end(),
                             content_key.key, content_key.key + kContentKeySize);
        key_plaintext.insert(key_plaintext.end(),
                             content_key.nonce, content_key.nonce + kContentNonceSize);

        // 5. AEAD-encrypt the content key
        // Use a deterministic nonce derived from the wrapping key for key-wrapping.
        al_u8 wrap_nonce[kContentNonceSize]{};
        al_hash256 nonce_hash{};
        al_sha256(wk_result->get(), AL_AEAD_KEY_SIZE, &nonce_hash);
        std::memcpy(wrap_nonce, nonce_hash.bytes, kContentNonceSize);
        al_secure_zero(&nonce_hash, sizeof(nonce_hash));

        size_t ciphertext_len = key_plaintext.size() + kContentTagSize;
        std::vector<uint8_t> wrapped(ciphertext_len);

        auto status = al_aead_encrypt(
            wk_result->get(), wrap_nonce,
            nullptr, 0,
            key_plaintext.data(), key_plaintext.size(),
            wrapped.data(), &ciphertext_len);

        wrapped.resize(ciphertext_len);

        // 6. Build envelope: ephemeral_pk || wrapped_ciphertext
        std::vector<uint8_t> envelope;
        envelope.reserve(AL_KX_PUBLIC_KEY_SIZE + ciphertext_len);
        envelope.insert(envelope.end(),
                        ephemeral.pk, ephemeral.pk + AL_KX_PUBLIC_KEY_SIZE);
        envelope.insert(envelope.end(), wrapped.begin(), wrapped.end());

        al_secure_zero(&ephemeral, sizeof(ephemeral));
        return envelope;
    }

    // --- Key unwrapping (decrypt content key with recipient's keypair) ------

    std::expected<ContentKey, EncryptError> unwrap_key(
        std::span<const uint8_t> wrapped_key,
        const RecipientKeyPair& recipient) {

        if (wrapped_key.size() < AL_KX_PUBLIC_KEY_SIZE + kContentTagSize) {
            return std::unexpected(EncryptError::make(
                EncryptErrorCode::InvalidCiphertext,
                "wrapped key too short"));
        }

        // 1. Extract ephemeral public key
        al_u8 ephemeral_pk[AL_KX_PUBLIC_KEY_SIZE];
        std::memcpy(ephemeral_pk, wrapped_key.data(), AL_KX_PUBLIC_KEY_SIZE);

        // 2. Compute ECDH shared secret
        al_kx_keypair local_kx{};
        std::memcpy(local_kx.pk, recipient.pk, AL_KX_PUBLIC_KEY_SIZE);
        std::memcpy(local_kx.sk, recipient.sk, AL_KX_SECRET_KEY_SIZE);

        al_u8 shared_secret[AL_KX_SHARED_KEY_SIZE]{};
        if (al_kx_shared(&local_kx, ephemeral_pk, shared_secret) != AL_OK) {
            al_secure_zero(shared_secret, sizeof(shared_secret));
            return std::unexpected(EncryptError::make(
                EncryptErrorCode::KeyExchangeFailed,
                "X25519 ECDH failed during unwrap"));
        }

        // 3. Derive wrapping key
        auto wk_result = derive_wrapping_key(shared_secret, ephemeral_pk);
        al_secure_zero(shared_secret, sizeof(shared_secret));
        if (!wk_result) return std::unexpected(std::move(wk_result.error()));

        // 4. Decrypt the content key
        al_u8 wrap_nonce[kContentNonceSize]{};
        al_hash256 nonce_hash{};
        al_sha256(wk_result->get(), AL_AEAD_KEY_SIZE, &nonce_hash);
        std::memcpy(wrap_nonce, nonce_hash.bytes, kContentNonceSize);
        al_secure_zero(&nonce_hash, sizeof(nonce_hash));

        auto ciphertext = wrapped_key.subspan(AL_KX_PUBLIC_KEY_SIZE);
        std::vector<uint8_t> plaintext(ciphertext.size() - kContentTagSize);

        size_t plaintext_len = plaintext.size();
        auto status = al_aead_decrypt(
            wk_result->get(), wrap_nonce,
            nullptr, 0,
            ciphertext.data(), ciphertext.size(),
            plaintext.data(), &plaintext_len);

        if (status != AL_OK) {
            return std::unexpected(EncryptError::make(
                EncryptErrorCode::DecryptionFailed,
                "AEAD decryption of content key failed (wrong key or tampered data)"));
        }

        if (plaintext_len != kContentKeySize + kContentNonceSize) {
            return std::unexpected(EncryptError::make(
                EncryptErrorCode::InvalidCiphertext,
                "decrypted key material has unexpected length"));
        }

        // 5. Parse key + nonce
        ContentKey ck{};
        std::memcpy(ck.key, plaintext.data(), kContentKeySize);
        std::memcpy(ck.nonce, plaintext.data() + kContentKeySize, kContentNonceSize);
        return ck;
    }

    // --- Whole-file encryption ---------------------------------------------

    std::expected<EncryptedContent, EncryptError> encrypt_whole(
        std::span<const uint8_t> plaintext,
        const RecipientPublicKey& recipient) {

        // 1. Generate random content key
        ContentKey content_key = ContentKey::generate();

        // 2. Encrypt content
        size_t ciphertext_len = plaintext.size() + kContentTagSize;
        std::vector<uint8_t> ciphertext(ciphertext_len);

        auto status = al_aead_encrypt(
            content_key.key, content_key.nonce,
            nullptr, 0,
            plaintext.data(), plaintext.size(),
            ciphertext.data(), &ciphertext_len);

        if (status != AL_OK) {
            return std::unexpected(EncryptError::make(
                EncryptErrorCode::EncryptionFailed,
                "AEAD encryption failed"));
        }
        ciphertext.resize(ciphertext_len);

        // 3. Wrap key for recipient
        auto wrapped = wrap_key(content_key, recipient);
        if (!wrapped) return std::unexpected(std::move(wrapped.error()));

        EncryptedContent result;
        result.encrypted_data = std::move(ciphertext);
        result.wrapped_key = std::move(*wrapped);
        std::memcpy(result.content_nonce, content_key.nonce, kContentNonceSize);
        result.plaintext_size = plaintext.size();
        return result;
    }

    // --- Chunked encryption ------------------------------------------------

    std::expected<EncryptedContent, EncryptError> encrypt_chunked(
        std::span<const uint8_t> plaintext,
        const RecipientPublicKey& recipient) {

        if (cfg.chunk_size == 0) {
            return std::unexpected(EncryptError::make(
                EncryptErrorCode::InternalError,
                "chunk_size must be > 0 for chunked encryption"));
        }

        // 1. Generate random content key
        ContentKey content_key = ContentKey::generate();

        // 2. Encrypt each chunk with a deterministic nonce
        EncryptedContent result;
        result.plaintext_size = plaintext.size();

        uint32_t index = 0;
        size_t offset = 0;

        while (offset < plaintext.size()) {
            size_t chunk_len = std::min<size_t>(cfg.chunk_size, plaintext.size() - offset);

            // Derive per-chunk nonce
            al_u8 chunk_nonce[kContentNonceSize]{};
            derive_chunk_nonce(content_key.nonce, index, chunk_nonce);

            // Encrypt chunk
            size_t ct_len = chunk_len + kContentTagSize;
            std::vector<uint8_t> ct(ct_len);

            auto status = al_aead_encrypt(
                content_key.key, chunk_nonce,
                nullptr, 0,
                plaintext.data() + offset, chunk_len,
                ct.data(), &ct_len);

            if (status != AL_OK) {
                return std::unexpected(EncryptError::make(
                    EncryptErrorCode::EncryptionFailed,
                    "AEAD encryption failed on chunk " + std::to_string(index)));
            }
            ct.resize(ct_len);

            EncryptedChunk ec;
            ec.index = index;
            ec.ciphertext = std::move(ct);
            std::memcpy(ec.nonce, chunk_nonce, kContentNonceSize);
            result.chunks.push_back(std::move(ec));

            offset += chunk_len;
            ++index;
        }

        result.chunk_count = index;

        // 3. Wrap key for recipient
        auto wrapped = wrap_key(content_key, recipient);
        if (!wrapped) return std::unexpected(std::move(wrapped.error()));
        result.wrapped_key = std::move(*wrapped);
        std::memcpy(result.content_nonce, content_key.nonce, kContentNonceSize);

        return result;
    }

    // --- Decryption --------------------------------------------------------

    std::expected<ContentKey, EncryptError> unwrap_for_recipient(
        const EncryptedContent& encrypted,
        const RecipientKeyPair& recipient) {

        return unwrap_key(encrypted.wrapped_key, recipient);
    }
};

// ---------------------------------------------------------------------------
// ContentKey
// ---------------------------------------------------------------------------

ContentKey ContentKey::generate() {
    ContentKey ck{};
    randombytes_buf(ck.key, kContentKeySize);
    randombytes_buf(ck.nonce, kContentNonceSize);
    return ck;
}

void ContentKey::chunk_nonce(uint32_t index, al_u8 out[kContentNonceSize]) const {
    derive_chunk_nonce(nonce, index, out);
}

ContentKey::~ContentKey() {
    al_secure_zero(key, kContentKeySize);
    al_secure_zero(nonce, kContentNonceSize);
}

ContentKey::ContentKey(const ContentKey& o) {
    std::memcpy(key, o.key, kContentKeySize);
    std::memcpy(nonce, o.nonce, kContentNonceSize);
}

ContentKey& ContentKey::operator=(const ContentKey& o) {
    if (this != &o) {
        std::memcpy(key, o.key, kContentKeySize);
        std::memcpy(nonce, o.nonce, kContentNonceSize);
    }
    return *this;
}

ContentKey::ContentKey(ContentKey&& o) noexcept {
    std::memcpy(key, o.key, kContentKeySize);
    std::memcpy(nonce, o.nonce, kContentNonceSize);
    al_secure_zero(o.key, kContentKeySize);
    al_secure_zero(o.nonce, kContentNonceSize);
}

ContentKey& ContentKey::operator=(ContentKey&& o) noexcept {
    if (this != &o) {
        std::memcpy(key, o.key, kContentKeySize);
        std::memcpy(nonce, o.nonce, kContentNonceSize);
        al_secure_zero(o.key, kContentKeySize);
        al_secure_zero(o.nonce, kContentNonceSize);
    }
    return *this;
}

// ---------------------------------------------------------------------------
// EncryptedChunk
// ---------------------------------------------------------------------------

size_t EncryptedChunk::plaintext_size() const {
    return ciphertext.size() > kContentTagSize
        ? ciphertext.size() - kContentTagSize
        : 0;
}

// ---------------------------------------------------------------------------
// RecipientPublicKey
// ---------------------------------------------------------------------------

RecipientPublicKey RecipientPublicKey::from_raw(const al_u8 pk[AL_KX_PUBLIC_KEY_SIZE]) {
    RecipientPublicKey rp{};
    std::memcpy(rp.bytes, pk, AL_KX_PUBLIC_KEY_SIZE);
    return rp;
}

// ---------------------------------------------------------------------------
// RecipientKeyPair
// ---------------------------------------------------------------------------

std::expected<RecipientKeyPair, EncryptError> RecipientKeyPair::generate() {
    al_kx_keypair kp{};
    if (al_kx_keygen(&kp) != AL_OK) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::KeyGenerationFailed,
            "X25519 keypair generation failed"));
    }

    RecipientKeyPair result{};
    std::memcpy(result.pk, kp.pk, AL_KX_PUBLIC_KEY_SIZE);
    std::memcpy(result.sk, kp.sk, AL_KX_SECRET_KEY_SIZE);
    al_secure_zero(&kp, sizeof(kp));
    return result;
}

RecipientPublicKey RecipientKeyPair::public_key() const {
    return RecipientPublicKey::from_raw(pk);
}

// ---------------------------------------------------------------------------
// ContentEncryptor
// ---------------------------------------------------------------------------

ContentEncryptor::ContentEncryptor()
    : impl_(std::make_unique<Impl>(ContentEncryptorConfig{})) {}

ContentEncryptor::ContentEncryptor(ContentEncryptorConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

ContentEncryptor::~ContentEncryptor() = default;

ContentEncryptor::ContentEncryptor(ContentEncryptor&&) noexcept = default;
ContentEncryptor& ContentEncryptor::operator=(ContentEncryptor&&) noexcept = default;

// --- File encryption -------------------------------------------------------

std::expected<EncryptedContent, EncryptError> ContentEncryptor::encrypt_file(
    const std::filesystem::path& path,
    const RecipientPublicKey& recipient) {

    std::error_code ec;
    auto file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::FileNotFound,
            "cannot stat file: " + path.string() + " (" + ec.message() + ")"));
    }

    if (file_size == 0) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::FileEmpty, "file is empty: " + path.string()));
    }

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::FileOpenFailed,
            "failed to open: " + path.string()));
    }

    std::vector<uint8_t> buffer(static_cast<size_t>(file_size));
    ifs.read(reinterpret_cast<char*>(buffer.data()),
             static_cast<std::streamsize>(file_size));
    if (!ifs) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::FileReadError,
            "read failed: " + path.string()));
    }

    return impl_->encrypt_whole(buffer, recipient);
}

std::expected<EncryptedContent, EncryptError> ContentEncryptor::encrypt_file_chunked(
    const std::filesystem::path& path,
    const RecipientPublicKey& recipient) {

    std::error_code ec;
    auto file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::FileNotFound,
            "cannot stat file: " + path.string() + " (" + ec.message() + ")"));
    }

    if (file_size == 0) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::FileEmpty, "file is empty: " + path.string()));
    }

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::FileOpenFailed,
            "failed to open: " + path.string()));
    }

    std::vector<uint8_t> buffer(static_cast<size_t>(file_size));
    ifs.read(reinterpret_cast<char*>(buffer.data()),
             static_cast<std::streamsize>(file_size));
    if (!ifs) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::FileReadError,
            "read failed: " + path.string()));
    }

    return impl_->encrypt_chunked(buffer, recipient);
}

std::expected<std::vector<uint8_t>, EncryptError> ContentEncryptor::decrypt_file(
    const EncryptedContent& encrypted,
    const RecipientKeyPair& recipient) {

    if (encrypted.is_chunked()) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::InternalError,
            "use decrypt_chunk() for chunked content"));
    }

    // 1. Unwrap content key
    auto key_result = impl_->unwrap_for_recipient(encrypted, recipient);
    if (!key_result) return std::unexpected(std::move(key_result.error()));

    // 2. Decrypt content
    std::vector<uint8_t> plaintext(encrypted.encrypted_data.size() - kContentTagSize);
    size_t plaintext_len = plaintext.size();

    auto status = al_aead_decrypt(
        key_result->key, key_result->nonce,
        nullptr, 0,
        encrypted.encrypted_data.data(), encrypted.encrypted_data.size(),
        plaintext.data(), &plaintext_len);

    if (status != AL_OK) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::DecryptionFailed,
            "AEAD decryption failed (wrong key or tampered data)"));
    }

    plaintext.resize(plaintext_len);
    return plaintext;
}

std::expected<std::vector<uint8_t>, EncryptError> ContentEncryptor::decrypt_chunk(
    const EncryptedContent& encrypted,
    uint32_t chunk_index,
    const RecipientKeyPair& recipient) {

    if (!encrypted.is_chunked()) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::InternalError,
            "content is not chunked; use decrypt_file() instead"));
    }

    if (chunk_index >= encrypted.chunks.size()) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::ChunkIndexOutOfRange,
            "chunk index " + std::to_string(chunk_index) + " out of range [0, " +
            std::to_string(encrypted.chunks.size()) + ")"));
    }

    // 1. Unwrap content key
    auto key_result = impl_->unwrap_for_recipient(encrypted, recipient);
    if (!key_result) return std::unexpected(std::move(key_result.error()));

    // 2. Derive the per-chunk nonce
    const auto& chunk = encrypted.chunks[chunk_index];
    al_u8 chunk_nonce[kContentNonceSize]{};
    derive_chunk_nonce(key_result->nonce, chunk_index, chunk_nonce);

    // 3. Decrypt chunk
    std::vector<uint8_t> plaintext(chunk.ciphertext.size() - kContentTagSize);
    size_t plaintext_len = plaintext.size();

    auto status = al_aead_decrypt(
        key_result->key, chunk_nonce,
        nullptr, 0,
        chunk.ciphertext.data(), chunk.ciphertext.size(),
        plaintext.data(), &plaintext_len);

    if (status != AL_OK) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::DecryptionFailed,
            "AEAD decryption failed on chunk " + std::to_string(chunk_index)));
    }

    plaintext.resize(plaintext_len);
    return plaintext;
}

// --- Buffer encryption -----------------------------------------------------

std::expected<EncryptedContent, EncryptError> ContentEncryptor::encrypt_buffer(
    std::span<const uint8_t> data,
    const RecipientPublicKey& recipient) {

    if (data.empty()) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::FileEmpty, "empty buffer"));
    }

    return impl_->encrypt_whole(data, recipient);
}

// --- Key wrapping ----------------------------------------------------------

std::expected<std::vector<uint8_t>, EncryptError> ContentEncryptor::encrypt_key(
    const ContentKey& content_key,
    const RecipientPublicKey& recipient) {

    return impl_->wrap_key(content_key, recipient);
}

std::expected<ContentKey, EncryptError> ContentEncryptor::decrypt_key(
    std::span<const uint8_t> wrapped_key,
    const RecipientKeyPair& recipient) {

    return impl_->unwrap_key(wrapped_key, recipient);
}

// --- Key derivation --------------------------------------------------------

std::expected<ContentKey, EncryptError> ContentEncryptor::derive_key(
    const ContentKey& master_key,
    std::string_view recipient_id) {

    // HKDF-Extract: salt = master nonce, IKM = master key
    al_hash256 prk{};
    al_hkdf_extract(master_key.nonce, kContentNonceSize,
                    master_key.key, kContentKeySize, &prk);

    // Combine derivation info with recipient ID for domain separation
    std::string info_str = cfg.derivation_info;
    info_str.push_back('\0');
    info_str.append(recipient_id);

    // Derive new key material: key || nonce
    constexpr size_t derived_len = kContentKeySize + kContentNonceSize;
    SecureBytes derived(derived_len);
    if (!derived.valid()) {
        al_secure_zero(&prk, sizeof(prk));
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::InternalError, "allocation failed"));
    }

    auto status = al_hkdf_expand(&prk, info_str.data(), info_str.size(),
                                  derived.get(), derived_len);
    al_secure_zero(&prk, sizeof(prk));

    if (status != AL_OK) {
        return std::unexpected(EncryptError::make(
            EncryptErrorCode::HkdfDerivationFailed,
            "HKDF-Expand failed for key derivation"));
    }

    ContentKey dk{};
    std::memcpy(dk.key, derived.get(), kContentKeySize);
    std::memcpy(dk.nonce, derived.get() + kContentKeySize, kContentNonceSize);
    return dk;
}

// --- Threshold (future) ----------------------------------------------------

std::expected<std::vector<std::vector<uint8_t>>, EncryptError>
ContentEncryptor::threshold_split(
    const ContentKey& /*key*/,
    uint32_t /*threshold*/,
    uint32_t /*total_shares*/) {

    return std::unexpected(EncryptError::make(
        EncryptErrorCode::ThresholdNotSupported,
        "threshold key sharing not yet implemented"));
}

std::expected<ContentKey, EncryptError>
ContentEncryptor::threshold_reconstruct(
    std::span<const std::vector<uint8_t>> /*shares*/) {

    return std::unexpected(EncryptError::make(
        EncryptErrorCode::ThresholdNotSupported,
        "threshold key sharing not yet implemented"));
}

// --- Configuration ---------------------------------------------------------

void ContentEncryptor::set_config(ContentEncryptorConfig config) {
    impl_->cfg = std::move(config);
}

const ContentEncryptorConfig& ContentEncryptor::config() const {
    return impl_->cfg;
}

}  // namespace astrolune::share
