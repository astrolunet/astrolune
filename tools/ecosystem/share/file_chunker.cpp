/*
 * astrolune/tools/ecosystem/share/file_chunker.cpp
 *
 * Implementation of the file chunking engine for Astrolune Share.
 *
 * Supports two modes:
 *   1. Fixed-size chunking — straightforward slicing at configurable boundaries.
 *   2. Content-defined chunking (FastCDC) — finds natural boundaries in the
 *      data stream so that insertions/deletions only affect nearby chunks.
 *
 * All hashing uses the core library's al_sha256.
 */

#include "file_chunker.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <fstream>

namespace astrolune::share {

// ---------------------------------------------------------------------------
// Gear table generation
//
// FastCDC uses a pseudo-random mapping from byte values to 64-bit fingerprints.
// Rather than shipping a 2 KiB static table, we derive it deterministically
// from SHA-256.  The result is identical across runs and platforms.
// ---------------------------------------------------------------------------

namespace {

bool g_gear_table_initialized = false;
uint64_t g_gear_table[256];

void init_gear_table() {
    if (g_gear_table_initialized) return;
    // Fill the table by hashing index bytes through SHA-256 and extracting
    // 8 bytes at a time from the digest.
    for (unsigned i = 0; i < 256; ++i) {
        al_u8 buf = static_cast<al_u8>(i);
        al_hash256 h{};
        al_sha256(&buf, 1, &h);
        // Take the first 8 bytes as a little-endian u64.
        uint64_t v = 0;
        std::memcpy(&v, h.bytes, sizeof(v));
        g_gear_table[i] = v;
    }
    g_gear_table_initialized = true;
}

}  // namespace

const uint64_t (&fastcdc_gear_table())[256] {
    init_gear_table();
    return g_gear_table;
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

namespace {

std::string to_hex(const uint8_t* data, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(kHex[data[i] >> 4]);
        result.push_back(kHex[data[i] & 0x0F]);
    }
    return result;
}

std::expected<al_hash256, ChunkError> parse_hex_hash(std::string_view hex) {
    if (hex.size() != AL_HASH_SIZE * 2) {
        return std::unexpected(ChunkError::make(
            ChunkErrorCode::InvalidChunkSize,
            "hex hash must be 64 characters"));
    }
    al_hash256 h{};
    for (size_t i = 0; i < AL_HASH_SIZE; ++i) {
        uint8_t hi = 0, lo = 0;
        auto hc = hex[i * 2];
        auto lc = hex[i * 2 + 1];
        if (hc >= '0' && hc <= '9') hi = hc - '0';
        else if (hc >= 'a' && hc <= 'f') hi = 10 + hc - 'a';
        else if (hc >= 'A' && hc <= 'F') hi = 10 + hc - 'A';
        else return std::unexpected(ChunkError::make(
            ChunkErrorCode::InvalidChunkSize, "invalid hex character"));
        if (lc >= '0' && lc <= '9') lo = lc - '0';
        else if (lc >= 'a' && lc <= 'f') lo = 10 + lc - 'a';
        else if (lc >= 'A' && lc <= 'F') lo = 10 + lc - 'A';
        else return std::unexpected(ChunkError::make(
            ChunkErrorCode::InvalidChunkSize, "invalid hex character"));
        h.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return h;
}

}  // namespace

// ---------------------------------------------------------------------------
// ChunkInfo
// ---------------------------------------------------------------------------

std::string ChunkInfo::hash_string() const {
    return "sha256:" + to_hex(hash.bytes, AL_HASH_SIZE);
}

std::expected<al_hash256, ChunkError> ChunkInfo::parse_hash(std::string_view hex) {
    // Strip "sha256:" prefix if present
    if (hex.starts_with("sha256:")) {
        hex = hex.substr(7);
    }
    return parse_hex_hash(hex);
}

// ---------------------------------------------------------------------------
// ChunkedFile
// ---------------------------------------------------------------------------

uint64_t ChunkedFile::total_chunk_bytes() const {
    uint64_t total = 0;
    for (auto& c : chunks) total += c.size;
    return total;
}

size_t ChunkedFile::uploaded_count() const {
    return static_cast<size_t>(
        std::count_if(chunks.begin(), chunks.end(),
                      [](auto& c) { return c.uploaded; }));
}

bool ChunkedFile::is_complete() const {
    return !chunks.empty() &&
           uploaded_count() == chunks.size();
}

std::expected<void, ChunkError> ChunkedFile::mark_uploaded(uint32_t index) {
    if (index >= chunks.size()) {
        return std::unexpected(ChunkError::make(
            ChunkErrorCode::ChunkIndexOutOfRange,
            "chunk index " + std::to_string(index) + " out of range [0, " +
            std::to_string(chunks.size()) + ")"));
    }
    chunks[index].uploaded = true;
    return {};
}

std::string ChunkedFile::serialize_upload_state() const {
    // Bitfield: one bit per chunk, '1' = uploaded.
    std::string result;
    result.reserve((chunks.size() + 7) / 8);
    uint8_t byte = 0;
    for (size_t i = 0; i < chunks.size(); ++i) {
        if (chunks[i].uploaded) {
            byte |= static_cast<uint8_t>(1u << (i % 8));
        }
        if (i % 8 == 7 || i + 1 == chunks.size()) {
            result.push_back(static_cast<char>(byte));
            byte = 0;
        }
    }
    return result;
}

std::expected<void, ChunkError> ChunkedFile::restore_upload_state(
    std::string_view state) {
    size_t byte_count = (chunks.size() + 7) / 8;
    if (state.size() < byte_count) {
        return std::unexpected(ChunkError::make(
            ChunkErrorCode::InvalidChunkSize,
            "upload state too short for chunk count"));
    }
    for (size_t i = 0; i < chunks.size(); ++i) {
        uint8_t byte = static_cast<uint8_t>(state[i / 8]);
        chunks[i].uploaded = ((byte >> (i % 8)) & 1u) != 0;
    }
    return {};
}

// ---------------------------------------------------------------------------
// FileChunker — internals
// ---------------------------------------------------------------------------

struct FileChunker::Impl {
    FileChunkerConfig config;

    explicit Impl(FileChunkerConfig cfg) : config(std::move(cfg)) {}

    // Compute SHA-256 over a contiguous buffer.
    al_hash256 hash_data(const void* data, size_t len) {
        al_hash256 h{};
        al_sha256(data, len, &h);
        return h;
    }

    // Chunk a contiguous in-memory buffer with fixed-size chunking.
    ChunkedFile chunk_fixed(std::span<const uint8_t> data,
                            std::string_view name) {
        ChunkedFile result;
        result.file_size = data.size();
        result.file_hash = hash_data(data.data(), data.size());
        result.mode = ChunkingMode::Fixed;
        result.source_path = std::string(name);

        const uint32_t chunk_size = config.fixed_chunk_size;
        uint32_t index = 0;
        uint64_t offset = 0;

        while (offset < data.size()) {
            uint32_t len = static_cast<uint32_t>(
                std::min<uint64_t>(chunk_size, data.size() - offset));

            ChunkInfo ci;
            ci.index = index;
            ci.offset = offset;
            ci.size = len;
            ci.hash = hash_data(data.data() + offset, len);
            ci.uploaded = false;

            result.chunks.push_back(ci);
            offset += len;
            ++index;
        }

        return result;
    }

    // Content-defined chunking using FastCDC.
    //
    // FastCDC (Liu et al., FAST 2020) computes a rolling fingerprint over the
    // data stream. A chunk boundary is placed when the fingerprint matches a
    // normalized mask. This yields chunks whose sizes depend on content
    // patterns rather than absolute positions, so inserting or deleting a few
    // bytes only affects the chunk at that location.
    ChunkedFile chunk_fastcdc(std::span<const uint8_t> data,
                              std::string_view name) {
        ChunkedFile result;
        result.file_size = data.size();
        result.file_hash = hash_data(data.data(), data.size());
        result.mode = ChunkingMode::ContentDefined;
        result.source_path = std::string(name);

        const uint32_t min_size = config.content_min_size;
        const uint32_t avg_size = config.content_avg_size;
        const uint32_t max_size = config.content_max_size;

        // Mask: cut when (fingerprint & mask) == 0.  Higher mask bits mean
        // larger average chunks.  We want avg_size, so mask = 2^(bits) - 1
        // where bits is chosen so that 2^bits ≈ avg_size.
        const uint64_t mask = static_cast<uint64_t>(avg_size) - 1;

        init_gear_table();
        uint64_t fingerprint = 0;
        uint32_t index = 0;
        uint64_t offset = 0;
        uint32_t current_chunk_start = 0;

        for (uint64_t pos = 0; pos < data.size(); ++pos) {
            uint8_t b = data[pos];
            fingerprint = (fingerprint << 1) + g_gear_table[b];

            uint32_t chunk_len = static_cast<uint32_t>(pos - offset) + 1;

            // Only consider a cut after the minimum size and before the max.
            if (chunk_len >= min_size && chunk_len <= max_size) {
                // Normalized cut: fingerprint bits match the mask.
                if ((fingerprint & mask) == 0 || chunk_len == max_size) {
                    ChunkInfo ci;
                    ci.index = index;
                    ci.offset = offset;
                    ci.size = chunk_len;
                    ci.hash = hash_data(data.data() + offset, chunk_len);
                    ci.uploaded = false;
                    result.chunks.push_back(ci);

                    offset += chunk_len;
                    ++index;
                    fingerprint = 0;
                }
            }
        }

        // Flush any remaining bytes as the final chunk.
        if (offset < data.size()) {
            uint32_t tail = static_cast<uint32_t>(data.size() - offset);
            ChunkInfo ci;
            ci.index = index;
            ci.offset = offset;
            ci.size = tail;
            ci.hash = hash_data(data.data() + offset, tail);
            ci.uploaded = false;
            result.chunks.push_back(ci);
        }

        return result;
    }

    // Core chunking dispatch.
    std::expected<ChunkedFile, ChunkError> do_chunk(
        std::span<const uint8_t> data, std::string_view name) {

        if (data.empty()) {
            return std::unexpected(ChunkError::make(
                ChunkErrorCode::InvalidChunkSize, "empty input data"));
        }

        if (config.mode == ChunkingMode::Fixed) {
            return chunk_fixed(data, name);
        } else {
            return chunk_fastcdc(data, name);
        }
    }
};

// ---------------------------------------------------------------------------
// FileChunker — public API
// ---------------------------------------------------------------------------

FileChunker::FileChunker()
    : impl_(std::make_unique<Impl>(FileChunkerConfig{})) {}

FileChunker::FileChunker(FileChunkerConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

FileChunker::~FileChunker() = default;

FileChunker::FileChunker(FileChunker&&) noexcept = default;
FileChunker& FileChunker::operator=(FileChunker&&) noexcept = default;

std::expected<ChunkedFile, ChunkError> FileChunker::chunk_file(
    const std::filesystem::path& path) {
    // Check file exists and get size.
    std::error_code ec;
    auto file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(ChunkError::make(
            ChunkErrorCode::FileNotFound,
            "cannot stat file: " + path.string() + " (" + ec.message() + ")"));
    }

    // Read entire file into memory.  For very large files a streaming
    // approach would be more appropriate, but chunking requires random
    // access for content-defined boundaries.
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        return std::unexpected(ChunkError::make(
            ChunkErrorCode::FileOpenFailed,
            "failed to open: " + path.string()));
    }

    std::vector<uint8_t> buffer(static_cast<size_t>(file_size));
    ifs.read(reinterpret_cast<char*>(buffer.data()),
             static_cast<std::streamsize>(file_size));
    if (!ifs) {
        return std::unexpected(ChunkError::make(
            ChunkErrorCode::FileReadError,
            "read failed: " + path.string()));
    }

    auto result = impl_->do_chunk(
        std::span<const uint8_t>(buffer.data(), buffer.size()),
        path.string());
    if (result) {
        result->source_path = path;
    }
    return result;
}

std::expected<ChunkedFile, ChunkError> FileChunker::chunk_buffer(
    std::span<const uint8_t> data, std::string_view name) {
    return impl_->do_chunk(data, name);
}

std::expected<al_hash256, ChunkError> FileChunker::hash_chunk(
    std::span<const uint8_t> data) {
    if (data.empty()) {
        return std::unexpected(ChunkError::make(
            ChunkErrorCode::InvalidChunkSize, "empty chunk data"));
    }
    al_hash256 h{};
    al_sha256(data.data(), data.size(), &h);
    return h;
}

void FileChunker::set_config(FileChunkerConfig config) {
    impl_->config = std::move(config);
}

const FileChunkerConfig& FileChunker::config() const {
    return impl_->config;
}

}  // namespace astrolune::share
