/*
 * astrolune/tools/ecosystem/hosting/host_node.hpp
 *
 * Content-addressed file store and HTTP server for the Astrolune network.
 * The HostNode stores files on disk keyed by their SHA-256 hash and serves
 * them over HTTP.  It supports multiple sites (multiple root CIDs), enforces
 * storage quotas, and responds to requests from the LuneGateway or directly.
 *
 * Design constraints:
 *   - No exceptions across ABI boundaries; errors return std::expected.
 *   - Thread-safe; the accept loop runs on its own thread.
 *   - Lifetime managed through RAII and pImpl for ABI stability.
 */

#ifndef ASTROLUNE_HOSTING_HOST_NODE_HPP
#define ASTROLUNE_HOSTING_HOST_NODE_HPP

#include "astrolune/base.h"
#include "astrolune/hash.h"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace astrolune::hosting {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr uint16_t kDefaultHostPort = 8081;
constexpr size_t   kDefaultMaxStorageBytes = 1ULL << 30;  // 1 GiB
constexpr size_t   kMaxHostRequestBytes    = 8192;
constexpr size_t   kMaxHostHeaderBytes     = 8192;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

enum class HostErrorCode {
    SocketCreateFailed,
    SocketBindFailed,
    SocketListenFailed,
    SocketAcceptFailed,
    SocketSendFailed,
    SocketRecvFailed,
    HttpMalformedRequest,
    HttpHeaderTooLarge,
    HttpBodyTooLarge,
    HostHeaderMissing,
    FileNotFound,
    FileHashMismatch,
    FileStoreFailed,
    FileReadFailed,
    QuotaExceeded,
    SiteNotFound,
    SiteAlreadyExists,
    AlreadyRunning,
    NotRunning,
    InternalError,
};

struct HostError {
    HostErrorCode code = HostErrorCode::InternalError;
    std::string message;

    static HostError make(HostErrorCode c, std::string msg) {
        return HostError{c, std::move(msg)};
    }
};

// ---------------------------------------------------------------------------
// ContentFile — metadata for a single stored file
// ---------------------------------------------------------------------------

struct ContentFile {
    al_hash256 hash{};        // SHA-256 of the file contents
    std::filesystem::path path;  // on-disk path under the data directory
    std::vector<uint8_t> data;   // in-memory copy (populated on store)
    size_t size = 0;             // file size in bytes
};

// ---------------------------------------------------------------------------
// SiteInfo — maps a site identifier to its root content hash
// ---------------------------------------------------------------------------

struct SiteInfo {
    std::string site_id;         // unique site identifier (e.g. domain name)
    al_hash256 root_hash{};     // root CID / content hash for this site
    size_t file_count = 0;      // number of files belonging to this site
    size_t total_bytes = 0;     // total bytes stored for this site
};

// ---------------------------------------------------------------------------
// HostConfig — immutable after construction
// ---------------------------------------------------------------------------

struct HostConfig {
    // Directory where content-addressed files are stored on disk.
    std::filesystem::path data_dir = "host_store";

    // Maximum total storage in bytes (0 = unlimited).
    size_t max_storage = kDefaultMaxStorageBytes;

    // HTTP listen port.
    uint16_t listen_port = kDefaultHostPort;

    // Bind address.  "0.0.0.0" for all interfaces, "127.0.0.1" for loopback.
    std::string bind_address = "127.0.0.1";

    // Enable CORS headers for development.
    bool cors_enabled = true;
    std::string cors_origin = "*";

    // Maximum concurrent connections (0 = unlimited).
    size_t max_connections = 0;

    // Request read timeout in milliseconds.
    uint32_t request_timeout_ms = 10000;
};

// ---------------------------------------------------------------------------
// HostNode — the main storage and HTTP server
// ---------------------------------------------------------------------------

class HostNode {
public:
    HostNode();
    explicit HostNode(HostConfig config);
    ~HostNode();

    HostNode(const HostNode&) = delete;
    HostNode& operator=(const HostNode&) = delete;
    HostNode(HostNode&&) noexcept;
    HostNode& operator=(HostNode&&) noexcept;

    // --- Lifecycle --------------------------------------------------------

    // Start listening.  Spawns the accept thread.
    std::expected<void, HostError> start();

    // Stop the host node and close all active connections.
    void stop();

    // True when the accept loop is running.
    bool is_running() const;

    // --- File operations --------------------------------------------------

    // Store a file by its content hash.  Returns an error if the hash does
    // not match the data, or if the storage quota would be exceeded.
    std::expected<ContentFile, HostError> store_file(
        const al_hash256& hash,
        std::span<const uint8_t> data,
        std::string_view site_id = {});

    // Retrieve a file by its content hash.
    std::expected<ContentFile, HostError> get_file(const al_hash256& hash);

    // Verify that the stored file matches its content hash.
    std::expected<bool, HostError> verify_integrity(const al_hash256& hash);

    // --- Site management --------------------------------------------------

    // Register a new site with a root content hash.
    std::expected<void, HostError> register_site(
        std::string site_id,
        const al_hash256& root_hash);

    // Remove a site and all its files.
    std::expected<void, HostError> remove_site(std::string_view site_id);

    // Look up a site by its identifier.
    std::expected<SiteInfo, HostError> get_site(std::string_view site_id) const;

    // List all registered sites.
    std::vector<SiteInfo> list_sites() const;

    // --- Storage ----------------------------------------------------------

    // Return the total bytes currently stored on disk.
    size_t get_storage_usage() const;

    // Return the number of files currently stored.
    size_t file_count() const;

    // --- Configuration (must be set before start()) -----------------------

    void set_config(HostConfig config);
    const HostConfig& config() const;

    // --- Connection tracking -----------------------------------------------

    size_t connection_count() const;

    // --- Static helpers ---------------------------------------------------

    // Map a file extension to a MIME content-type string.
    static std::string_view content_type_for(std::string_view path);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace astrolune::hosting

#endif  // ASTROLUNE_HOSTING_HOST_NODE_HPP
