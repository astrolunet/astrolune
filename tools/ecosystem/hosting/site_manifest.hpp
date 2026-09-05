/*
 * astrolune/tools/ecosystem/hosting/site_manifest.hpp
 *
 * Content-addressed manifest format for static .lune website hosting.
 *
 * A manifest describes every file in a static website deployment, its MIME
 * type, content hash, optional per-file cache headers, and the merkle root
 * CID of the entire file set.  Manifests are signed by the domain owner and
 * verified by the gateway before content is served.
 *
 * No exceptions across ABI boundaries; errors are returned via
 * std::expected.
 */

#ifndef ASTROLUNE_HOSTING_SITE_MANIFEST_HPP
#define ASTROLUNE_HOSTING_SITE_MANIFEST_HPP

#include "astrolune/base.h"
#include "astrolune/hash.h"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace astrolune::hosting {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr uint32_t kManifestVersion = 1;
constexpr size_t   kMaxManifestSize = 4 * 1024 * 1024;  // 4 MiB

// ---------------------------------------------------------------------------
// Manifest error codes
// ---------------------------------------------------------------------------

enum class ManifestErrorCode {
    JsonParseError,
    JsonFieldMissing,
    JsonFieldInvalid,
    VersionUnsupported,
    RootCidMismatch,
    SignatureInvalid,
    SignatureVerifyFailed,
    FileDuplicatePath,
    FileHashInvalid,
    FileSizeMismatch,
    ManifestTooLarge,
    FileReadError,
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
// ManifestFile — metadata for a single file in the deployment
// ---------------------------------------------------------------------------

struct ManifestFile {
    // URL path, e.g. "/index.html".  Always starts with '/'.
    std::string path;

    // MIME content type, e.g. "text/html".
    std::string mime;

    // Uncompressed file size in bytes.
    uint64_t size = 0;

    // Content hash, e.g. "sha256:abcdef...".
    std::string hash;

    // Optional per-file response headers (cache-control, etc.).
    std::map<std::string, std::string> headers;

    // Serialise this entry to a JSON object.
    std::string to_json() const;

    // Parse a JSON object into this struct.
    static std::expected<ManifestFile, ManifestError> from_json(
        std::string_view json);
};

// ---------------------------------------------------------------------------
// SiteManifest — full deployment manifest
// ---------------------------------------------------------------------------

struct SiteManifest {
    // Manifest format version (currently 1).
    uint32_t version = kManifestVersion;

    // Deployment mode.  Only "static" is supported today.
    std::string mode = "static";

    // Merkle root CID of the file set, e.g. "sha256:abcdef...".
    std::string root_cid;

    // All files in this deployment, sorted by path.
    std::vector<ManifestFile> files;

    // When true the gateway serves /index.html for unknown paths (SPA).
    bool spa_fallback = true;

    // Default cache headers applied to files without per-file overrides.
    // Keys are header names, values are header values.
    std::map<std::string, std::string> cache_headers;

    // Hex-encoded public key of the domain owner, e.g. "0x...".
    std::string owner;

    // Hex-encoded signature over the canonical manifest bytes.
    std::string signature;

    // CID of the previous version, or null for the first deployment.
    std::optional<std::string> previous_version;

    // Optional mirror URLs for redundancy.
    std::vector<std::string> mirrors;

    // --- Serialisation -----------------------------------------------------

    // Serialise the manifest to a canonical JSON string (fields sorted,
    // whitespace removed).  This is the bytes that get signed.
    std::string to_json() const;

    // Serialise with the signature field included.
    std::string to_json_signed() const;

    // Parse a JSON string into a manifest.  Does NOT verify the signature.
    static std::expected<SiteManifest, ManifestError> from_json(
        std::string_view json);

    // --- CID computation ---------------------------------------------------

    // Compute the root CID from the sorted file list.
    // Each file's contribution is:  path + "\0" + hash.
    // The root is SHA-256 of the concatenation of all contributions.
    std::expected<std::string, ManifestError> compute_root_cid() const;

    // Verify that the stored root_cid matches the computed one.
    std::expected<void, ManifestError> verify_root_cid() const;

    // --- Signature ---------------------------------------------------------

    // Verify the signature over the canonical manifest bytes (without the
    // signature field).  `public_key` is the hex-encoded secp256k1 public
    // key of the domain owner.
    std::expected<void, ManifestError> verify_signature(
        std::string_view public_key) const;

    // --- Validation --------------------------------------------------------

    // Full validation: version, structure, root CID, and optionally signature.
    std::expected<void, ManifestError> validate() const;
};

// ---------------------------------------------------------------------------
// MIME type detection
// ---------------------------------------------------------------------------

// Map a file path (or extension) to a MIME content-type string.
// Returns "application/octet-stream" for unknown extensions.
std::string_view mime_type_for(std::string_view path);

// --- File I/O helpers ------------------------------------------------------

// Read a manifest from a JSON file on disk.
std::expected<SiteManifest, ManifestError> load_manifest(
    const std::filesystem::path& path);

// Write a manifest to a JSON file on disk.
std::expected<void, ManifestError> save_manifest(
    const SiteManifest& manifest,
    const std::filesystem::path& path);

// Build a manifest from a directory tree.  Computes hashes, sizes, MIME
// types, and the root CID.  The manifest is NOT signed.
std::expected<SiteManifest, ManifestError> build_manifest(
    const std::filesystem::path& root_dir,
    bool spa_fallback = true);

}  // namespace astrolune::hosting

#endif  // ASTROLUNE_HOSTING_SITE_MANIFEST_HPP
