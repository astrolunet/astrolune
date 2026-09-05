/*
 * astrolune/tools/ecosystem/share/merkle_manifest.hpp
 *
 * Merkle tree manifest for Astrolune Share. Builds a binary Merkle tree from
 * file chunk hashes, stores the Merkle root as the content identifier (CID),
 * and generates inclusion proofs for individual chunks.
 *
 * A single manifest may describe multiple files. Each file is independently
 * chunked and its chunks form a sub-tree. The per-file Merkle roots are then
 * combined into a single root that covers the entire manifest.
 *
 * Design constraints:
 *   - No exceptions across ABI boundaries; errors return std::expected.
 *   - Uses the core library's al_merkle_root / al_merkle_prove / al_merkle_verify.
 *   - JSON serialisation uses a minimal self-contained parser (no dependencies).
 */

#ifndef ASTROLUNE_SHARE_MERKLE_MANIFEST_HPP
#define ASTROLUNE_SHARE_MERKLE_MANIFEST_HPP

#include "astrolune/base.h"
#include "astrolune/hash.h"
#include "file_chunker.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace astrolune::share {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr uint32_t kManifestVersion = 1;
constexpr size_t   kMaxManifestSize = 4 * 1024 * 1024;  // 4 MiB

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

enum class ManifestErrorCode {
    JsonParseError,
    JsonFieldMissing,
    JsonFieldInvalid,
    VersionUnsupported,
    RootCidMismatch,
    ChunkHashMismatch,
    ProofInvalid,
    FileNotFound,
    FileReadError,
    FileDuplicatePath,
    FileEmpty,
    TooManyFiles,
    TooManyChunks,
    InternalError,
};

struct ManifestError {
    ManifestErrorCode code = ManifestErrorCode::InternalError;
    std::string message;

    static ManifestError make(ManifestErrorCode c, std::string msg) {
        return ManifestError{c, std::move(msg)};
    }
};

// ---------------------------------------------------------------------------
// ChunkRecord — per-chunk entry in the manifest
// ---------------------------------------------------------------------------

struct ChunkRecord {
    uint32_t index = 0;          // 0-based chunk index within the file
    uint64_t offset = 0;         // byte offset within the file
    uint32_t size = 0;           // chunk size in bytes
    al_hash256 hash{};           // SHA-256 of the chunk contents

    std::string hash_hex() const;
};

// ---------------------------------------------------------------------------
// FileRecord — per-file entry in the manifest
// ---------------------------------------------------------------------------

struct FileRecord {
    std::string path;            // logical path (e.g. "/video.mp4")
    std::string mime;            // MIME type
    uint64_t size = 0;          // total file size in bytes
    al_hash256 file_hash{};     // SHA-256 of the entire file
    al_hash256 merkle_root{};   // Merkle root of this file's chunks
    uint32_t chunk_count = 0;
    std::vector<ChunkRecord> chunks;
};

// ---------------------------------------------------------------------------
// InclusionProof — proof that a chunk belongs to a file's Merkle tree
// ---------------------------------------------------------------------------

struct InclusionProof {
    uint32_t chunk_index = 0;         // which chunk this proof covers
    uint32_t leaf_count = 0;          // total chunks in the file
    al_hash256 leaf_hash{};           // hash of the chunk itself
    std::vector<al_hash256> siblings; // sibling hashes from leaf to root

    // Verify this proof against the expected Merkle root.
    bool verify(const al_hash256& expected_root) const;
};

// ---------------------------------------------------------------------------
// ShareManifest — full manifest covering one or more files
// ---------------------------------------------------------------------------

struct ShareManifest {
    uint32_t version = kManifestVersion;

    // Merkle root over all file-level Merkle roots, serving as the CID
    // for the entire manifest.
    al_hash256 root_cid{};

    // All files described by this manifest, sorted by path.
    std::vector<FileRecord> files;

    // --- Serialisation -----------------------------------------------------

    // Serialise to canonical JSON (sorted keys, no whitespace).
    std::string to_json() const;

    // Parse from JSON.
    static std::expected<ShareManifest, ManifestError> from_json(
        std::string_view json);

    // --- CID computation ---------------------------------------------------

    // Compute the root CID from the file list.  Each file contributes its
    // Merkle root; the overall root is SHA-256 of the concatenated roots
    // (sorted by path).
    std::expected<al_hash256, ManifestError> compute_root_cid() const;

    // Verify that the stored root_cid matches the computed one.
    std::expected<void, ManifestError> verify_root_cid() const;

    // --- Proofs ------------------------------------------------------------

    // Generate an inclusion proof for a specific chunk within a file.
    std::expected<InclusionProof, ManifestError> prove_chunk(
        std::string_view file_path, uint32_t chunk_index) const;

    // Verify an inclusion proof against this manifest's root CID.
    std::expected<void, ManifestError> verify_proof(
        std::string_view file_path, const InclusionProof& proof) const;

    // --- Validation --------------------------------------------------------

    // Full validation: version, structure, root CID, chunk hashes.
    std::expected<void, ManifestError> validate() const;
};

// ---------------------------------------------------------------------------
// MerkleManifestBuilder — high-level API for building manifests
// ---------------------------------------------------------------------------

class MerkleManifestBuilder {
public:
    MerkleManifestBuilder();
    explicit MerkleManifestBuilder(FileChunkerConfig chunker_config);
    ~MerkleManifestBuilder();

    MerkleManifestBuilder(const MerkleManifestBuilder&) = delete;
    MerkleManifestBuilder& operator=(const MerkleManifestBuilder&) = delete;
    MerkleManifestBuilder(MerkleManifestBuilder&&) noexcept;
    MerkleManifestBuilder& operator=(MerkleManifestBuilder&&) noexcept;

    // --- Add files ---------------------------------------------------------

    // Add a file from disk. Chunks it, builds a sub-Merkle-tree, and stores
    // the record. MIME type is auto-detected from the extension.
    std::expected<void, ManifestError> add_file(
        const std::filesystem::path& path);

    // Add a file with an explicit logical path and MIME type.
    std::expected<void, ManifestError> add_file(
        const std::filesystem::path& path,
        std::string_view logical_path,
        std::string_view mime_type);

    // Add a buffer already in memory.
    std::expected<void, ManifestError> add_buffer(
        std::span<const uint8_t> data,
        std::string_view logical_path,
        std::string_view mime_type);

    // --- Build -------------------------------------------------------------

    // Finalise the manifest: compute the root CID over all files.
    std::expected<ShareManifest, ManifestError> build() const;

    // --- Serialisation (convenience) ---------------------------------------

    // Build and serialise to JSON in one step.
    std::expected<std::string, ManifestError> build_json() const;

    // --- Query -------------------------------------------------------------

    size_t file_count() const;
    uint64_t total_bytes() const;

    // --- Static helpers ----------------------------------------------------

    // Build a manifest from a directory tree.
    static std::expected<ShareManifest, ManifestError> from_directory(
        const std::filesystem::path& root_dir,
        FileChunkerConfig config = {});

    // Load a manifest from a JSON file on disk.
    static std::expected<ShareManifest, ManifestError> load(
        const std::filesystem::path& path);

    // Save a manifest to a JSON file on disk.
    static std::expected<void, ManifestError> save(
        const ShareManifest& manifest,
        const std::filesystem::path& path);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Proof helpers (standalone, no builder needed)
// ---------------------------------------------------------------------------

// Compute the Merkle root of a list of chunk hashes using the core library.
al_hash256 compute_merkle_root(const std::vector<al_hash256>& leaves);

// Generate an inclusion proof for `index` within `leaves`.
std::expected<InclusionProof, ManifestError> generate_proof(
    const std::vector<al_hash256>& leaves, uint32_t index);

// Verify an inclusion proof.
bool verify_proof(const InclusionProof& proof, const al_hash256& root);

}  // namespace astrolune::share

#endif  // ASTROLUNE_SHARE_MERKLE_MANIFEST_HPP
