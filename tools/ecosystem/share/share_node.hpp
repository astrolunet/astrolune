/*
 * astrolune/tools/ecosystem/share/share_node.hpp
 *
 * Content-addressed chunk store and TCP server for the Astrolune network.
 * The ShareNode stores fixed-size file chunks on disk keyed by their SHA-256
 * hash and serves them to requesting peers over a custom binary protocol.
 * It tracks inventory (which chunks are available), enforces storage quotas,
 * and supports seeding (passively serving stored chunks to the network).
 *
 * Design constraints:
 *   - No exceptions across ABI boundaries; errors return std::expected.
 *   - Thread-safe; the accept loop runs on its own thread.
 *   - Lifetime managed through RAII and pImpl for ABI stability.
 */

#ifndef ASTROLUNE_SHARE_SHARE_NODE_HPP
#define ASTROLUNE_SHARE_SHARE_NODE_HPP

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

constexpr uint16_t kDefaultSharePort   = 8082;
constexpr size_t   kDefaultMaxStorage  = 1ULL << 30;  // 1 GiB
constexpr size_t   kDefaultChunkSize   = 1ULL << 18;  // 256 KiB
constexpr size_t   kMaxShareRequest    = 8192;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

enum class ShareErrorCode {
    SocketCreateFailed,
    SocketBindFailed,
    SocketListenFailed,
    SocketAcceptFailed,
    SocketSendFailed,
    SocketRecvFailed,
    MalformedRequest,
    RequestTooLarge,
    ChunkNotFound,
    ChunkHashMismatch,
    ChunkStoreFailed,
    ChunkReadFailed,
    ChunkTooLarge,
    QuotaExceeded,
    SeedingDisabled,
    AlreadyRunning,
    NotRunning,
    InternalError,
};

struct ShareError {
    ShareErrorCode code = ShareErrorCode::InternalError;
    std::string message;

    static ShareError make(ShareErrorCode c, std::string msg) {
        return ShareError{c, std::move(msg)};
    }
};

// ---------------------------------------------------------------------------
// ChunkInfo — metadata and data for a single stored chunk
// ---------------------------------------------------------------------------

struct ChunkInfo {
    al_hash256 hash{};              // SHA-256 of the chunk contents
    std::filesystem::path path;     // on-disk path under the data directory
    std::vector<uint8_t> data;      // in-memory copy (populated on store/get)
    size_t size = 0;                // chunk size in bytes
    bool verified = false;          // true if hash has been verified against data
};

// ---------------------------------------------------------------------------
// InventoryEntry — summary of a stored chunk for inventory reporting
// ---------------------------------------------------------------------------

struct InventoryEntry {
    al_hash256 hash{};
    size_t size = 0;
};

// ---------------------------------------------------------------------------
// ShareConfig — immutable after construction
// ---------------------------------------------------------------------------

struct ShareConfig {
    // Directory where content-addressed chunks are stored on disk.
    std::filesystem::path data_dir = "share_store";

    // Maximum total storage in bytes (0 = unlimited).
    size_t max_storage = kDefaultMaxStorage;

    // TCP listen port.
    uint16_t listen_port = kDefaultSharePort;

    // Bind address.  "0.0.0.0" for all interfaces, "127.0.0.1" for loopback.
    std::string bind_address = "0.0.0.0";

    // Enable seeding (serving stored chunks to requesting peers).
    bool seed_enabled = true;

    // Maximum concurrent connections (0 = unlimited).
    size_t max_connections = 0;

    // Request read timeout in milliseconds.
    uint32_t request_timeout_ms = 10000;

    // Chunk size used for content addressing (must match network protocol).
    size_t chunk_size = kDefaultChunkSize;
};

// ---------------------------------------------------------------------------
// ShareNode — the main chunk store and TCP server
// ---------------------------------------------------------------------------

class ShareNode {
public:
    ShareNode();
    explicit ShareNode(ShareConfig config);
    ~ShareNode();

    ShareNode(const ShareNode&) = delete;
    ShareNode& operator=(const ShareNode&) = delete;
    ShareNode(ShareNode&&) noexcept;
    ShareNode& operator=(ShareNode&&) noexcept;

    // --- Lifecycle --------------------------------------------------------

    // Start listening.  Spawns the accept thread.
    std::expected<void, ShareError> start();

    // Stop the share node and close all active connections.
    void stop();

    // True when the accept loop is running.
    bool is_running() const;

    // --- Chunk operations -------------------------------------------------

    // Store a chunk by its content hash.  Returns an error if the hash does
    // not match the data, or if the storage quota would be exceeded.
    std::expected<ChunkInfo, ShareError> store_chunk(
        const al_hash256& hash,
        std::span<const uint8_t> data);

    // Retrieve a chunk by its content hash.
    std::expected<ChunkInfo, ShareError> get_chunk(const al_hash256& hash);

    // Check whether a chunk with the given hash is stored locally.
    bool has_chunk(const al_hash256& hash) const;

    // Verify that the stored chunk matches its content hash.
    std::expected<bool, ShareError> verify_chunk(const al_hash256& hash);

    // Remove a stored chunk and free its storage.
    std::expected<void, ShareError> remove_chunk(const al_hash256& hash);

    // --- Inventory --------------------------------------------------------

    // Return a list of all stored chunks (hash + size).
    std::vector<InventoryEntry> get_inventory() const;

    // Return the number of chunks currently stored.
    size_t chunk_count() const;

    // --- Storage ----------------------------------------------------------

    // Return the total bytes currently stored on disk.
    size_t get_storage_usage() const;

    // --- Seeding ----------------------------------------------------------

    // Enable or disable seeding at runtime.
    void set_seed_enabled(bool enabled);

    // True if the node is actively seeding to the network.
    bool is_seeding() const;

    // --- Configuration (must be set before start()) -----------------------

    void set_config(ShareConfig config);
    const ShareConfig& config() const;

    // --- Connection tracking -----------------------------------------------

    size_t connection_count() const;

    // --- Static helpers ---------------------------------------------------

    // Compute SHA-256 of a buffer.
    static std::expected<al_hash256, ShareError> compute_hash(
        const uint8_t* data, size_t len);

    // Convert a hash to its hex representation.
    static std::string to_hex(const al_hash256& h);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace astrolune::share

#endif  // ASTROLUNE_SHARE_SHARE_NODE_HPP
