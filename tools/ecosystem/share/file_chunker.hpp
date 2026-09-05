/*
 * astrolune/tools/ecosystem/share/file_chunker.hpp
 *
 * File chunking engine for Astrolune Share. Splits files into fixed-size or
 * content-defined chunks (FastCDC), computes SHA-256 hashes for each chunk,
 * and tracks upload state for resumable transfers.
 *
 * Design constraints:
 *   - No exceptions across ABI boundaries; errors return std::expected.
 *   - RAII throughout; no manual resource management.
 *   - Uses the core library's al_sha256 for all hashing.
 */

#ifndef ASTROLUNE_SHARE_FILE_CHUNKER_HPP
#define ASTROLUNE_SHARE_FILE_CHUNKER_HPP

#include "astrolune/base.h"
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

constexpr uint32_t kDefaultChunkSize   = 256 * 1024;  // 256 KiB
constexpr uint32_t kMinChunkSize       = 64 * 1024;   // 64 KiB
constexpr uint32_t kMaxChunkSize       = 1024 * 1024;  // 1 MiB
constexpr uint32_t kFastCDCMinSize     = 32 * 1024;   // 32 KiB
constexpr uint32_t kFastCDCMaxSize     = 1024 * 1024;  // 1 MiB
constexpr uint32_t kFastCDCAvgSize     = 256 * 1024;  // 256 KiB

// ---------------------------------------------------------------------------
// Chunking mode
// ---------------------------------------------------------------------------

enum class ChunkingMode {
    Fixed,        // Fixed-size chunks (default 256 KiB)
    ContentDefined,  // FastCDC content-defined chunking
};

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

enum class ChunkErrorCode {
    FileNotFound,
    FileOpenFailed,
    FileReadError,
    FileTooLarge,
    ChunkIndexOutOfRange,
    InvalidChunkSize,
    InternalError,
};

struct ChunkError {
    ChunkErrorCode code = ChunkErrorCode::InternalError;
    std::string message;

    static ChunkError make(ChunkErrorCode c, std::string msg) {
        return ChunkError{c, std::move(msg)};
    }
};

// ---------------------------------------------------------------------------
// ChunkInfo — metadata for a single chunk
// ---------------------------------------------------------------------------

struct ChunkInfo {
    uint32_t index = 0;          // 0-based chunk index
    uint64_t offset = 0;         // byte offset within the file
    uint32_t size = 0;           // chunk size in bytes
    al_hash256 hash{};           // SHA-256 of the chunk contents
    bool uploaded = false;       // upload tracking for resumable transfers

    // Hex-encoded hash string (e.g. "sha256:abcdef...").
    std::string hash_string() const;

    // Parse a hex-encoded hash string back into al_hash256.
    static std::expected<al_hash256, ChunkError> parse_hash(std::string_view hex);
};

// ---------------------------------------------------------------------------
// FileChunkerConfig — immutable chunking parameters
// ---------------------------------------------------------------------------

struct FileChunkerConfig {
    ChunkingMode mode = ChunkingMode::Fixed;
    uint32_t fixed_chunk_size = kDefaultChunkSize;     // used when mode == Fixed
    uint32_t content_min_size = kFastCDCMinSize;       // used when mode == ContentDefined
    uint32_t content_avg_size = kFastCDCAvgSize;       // used when mode == ContentDefined
    uint32_t content_max_size = kFastCDCMaxSize;       // used when mode == ContentDefined
};

// ---------------------------------------------------------------------------
// ChunkedFile — result of chunking a file
// ---------------------------------------------------------------------------

struct ChunkedFile {
    std::filesystem::path source_path;
    uint64_t file_size = 0;
    al_hash256 file_hash{};              // SHA-256 of the whole file
    ChunkingMode mode = ChunkingMode::Fixed;
    std::vector<ChunkInfo> chunks;

    // Total bytes across all chunks (should equal file_size).
    uint64_t total_chunk_bytes() const;

    // Number of chunks that have been marked as uploaded.
    size_t uploaded_count() const;

    // True when every chunk is marked as uploaded.
    bool is_complete() const;

    // Set the uploaded flag on a specific chunk by index.
    std::expected<void, ChunkError> mark_uploaded(uint32_t index);

    // Serialize upload state to a compact string for persistence.
    std::string serialize_upload_state() const;

    // Restore upload state from a previously serialized string.
    std::expected<void, ChunkError> restore_upload_state(std::string_view state);
};

// ---------------------------------------------------------------------------
// FileChunker — the chunking engine
// ---------------------------------------------------------------------------

class FileChunker {
public:
    FileChunker();
    explicit FileChunker(FileChunkerConfig config);
    ~FileChunker();

    FileChunker(const FileChunker&) = delete;
    FileChunker& operator=(const FileChunker&) = delete;
    FileChunker(FileChunker&&) noexcept;
    FileChunker& operator=(FileChunker&&) noexcept;

    // --- Core operations ---------------------------------------------------

    // Chunk a file on disk. Reads the file, splits into chunks, hashes each
    // chunk, and computes the overall file hash.
    std::expected<ChunkedFile, ChunkError> chunk_file(
        const std::filesystem::path& path);

    // Chunk a buffer already in memory.
    std::expected<ChunkedFile, ChunkError> chunk_buffer(
        std::span<const uint8_t> data,
        std::string_view name = {});

    // --- Individual chunk access -------------------------------------------

    // Compute the SHA-256 hash of a specific chunk's data.
    std::expected<al_hash256, ChunkError> hash_chunk(
        std::span<const uint8_t> data);

    // --- Configuration -----------------------------------------------------

    void set_config(FileChunkerConfig config);
    const FileChunkerConfig& config() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// FastCDC gear table access
// ---------------------------------------------------------------------------

// Returns a reference to the precomputed pseudo-random 64-bit gear table used
// by FastCDC for content-defined chunk boundary detection. The table is
// computed once on first call and cached.
const uint64_t (&fastcdc_gear_table())[256];

}  // namespace astrolune::share

#endif  // ASTROLUNE_SHARE_FILE_CHUNKER_HPP
