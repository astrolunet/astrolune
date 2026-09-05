/*
 * astrolune/tools/ecosystem/share/share_node.cpp
 *
 * Implementation of the content-addressed chunk store and TCP server.
 * Thread-per-connection model: the accept loop spawns a detached thread
 * for each incoming peer.  The thread reads a binary chunk request, looks
 * up the content hash, fetches the chunk from disk, and writes the response.
 *
 * Wire protocol (all integers are big-endian):
 *
 *   Request:
 *     u8   method   (0x01 = HAVE, 0x02 = GET, 0x03 = PUT)
 *     u8[32] hash   (SHA-256 of the chunk)
 *     u64  size     (only for PUT, otherwise ignored)
 *     u8[size] data (only for PUT)
 *
 *   Response:
 *     u8   status   (0x00 = OK, 0x01 = NOT_FOUND, 0x02 = HASH_MISMATCH,
 *                     0x03 = QUOTA_FULL, 0x04 = ERROR)
 *     u64  size     (only for GET/HAVE)
 *     u8[size] data (only for GET)
 */

#include "share_node.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  using sock_t = SOCKET;
  constexpr sock_t kInvalidSock = INVALID_SOCKET;
  constexpr int kSockError = SOCKET_ERROR;
  #define CLOSE_SOCKET closesocket
#else
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <poll.h>
  #include <sys/socket.h>
  #include <unistd.h>
  using sock_t = int;
  constexpr sock_t kInvalidSock = -1;
  constexpr int kSockError = -1;
  #define CLOSE_SOCKET ::close
#endif

namespace astrolune::share {

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

namespace {

enum class Method : uint8_t {
    HAVE = 0x01,
    GET  = 0x02,
    PUT  = 0x03,
};

enum class StatusCode : uint8_t {
    OK            = 0x00,
    NOT_FOUND     = 0x01,
    HASH_MISMATCH = 0x02,
    QUOTA_FULL    = 0x03,
    ERROR         = 0x04,
};

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

std::expected<size_t, ShareError> read_exact(sock_t fd, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        auto got = ::recv(fd, reinterpret_cast<char*>(buf + total),
                          static_cast<int>(n - total), 0);
        if (got <= 0) {
            return std::unexpected(ShareError::make(
                ShareErrorCode::SocketRecvFailed,
                got == 0 ? "connection closed" : std::strerror(errno)));
        }
        total += static_cast<size_t>(got);
    }
    return total;
}

std::expected<size_t, ShareError> write_exact(sock_t fd, const uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        auto sent = ::send(fd, reinterpret_cast<const char*>(buf + total),
                           static_cast<int>(n - total), 0);
        if (sent <= 0) {
            return std::unexpected(ShareError::make(
                ShareErrorCode::SocketSendFailed,
                sent == 0 ? "connection closed" : std::strerror(errno)));
        }
        total += static_cast<size_t>(sent);
    }
    return total;
}

std::expected<uint64_t, ShareError> read_u64(sock_t fd) {
    uint8_t buf[8];
    auto result = read_exact(fd, buf, 8);
    if (!result) return std::unexpected(std::move(result.error()));
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | buf[i];
    }
    return val;
}

std::expected<void, ShareError> write_u64(sock_t fd, uint64_t val) {
    uint8_t buf[8];
    for (int i = 7; i >= 0; --i) {
        buf[i] = static_cast<uint8_t>(val & 0xFF);
        val >>= 8;
    }
    return write_exact(fd, buf, 8);
}

bool hashes_equal(const al_hash256& a, const al_hash256& b) {
    return std::memcmp(a.bytes, b.bytes, AL_HASH_SIZE) == 0;
}

}  // namespace

// ---------------------------------------------------------------------------
// ShareNode static helpers
// ---------------------------------------------------------------------------

std::string ShareNode::to_hex(const al_hash256& h) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(AL_HASH_SIZE * 2);
    for (size_t i = 0; i < AL_HASH_SIZE; ++i) {
        result.push_back(kHex[h.bytes[i] >> 4]);
        result.push_back(kHex[h.bytes[i] & 0x0F]);
    }
    return result;
}

std::expected<al_hash256, ShareError> ShareNode::compute_hash(
    const uint8_t* data, size_t len) {
    al_hash256 hash{};
    al_sha256(data, len, &hash);
    return hash;
}

// ---------------------------------------------------------------------------
// ShareNode::Impl
// ---------------------------------------------------------------------------

struct ShareNode::Impl {
    ShareConfig cfg;
    std::atomic<bool> running{false};
    std::atomic<bool> seeding{false};
    sock_t listen_fd = kInvalidSock;
    std::thread accept_thread;
    std::atomic<size_t> active_conns{0};

    mutable std::mutex mu;

    // --- Content store: hex(hash) -> StoredChunk --------------------------
    struct StoredChunk {
        std::filesystem::path path;
        size_t size = 0;
    };
    std::unordered_map<std::string, StoredChunk> chunks;

    // --- Storage tracking ------------------------------------------------
    size_t total_stored_bytes = 0;

    // --- Path helpers ----------------------------------------------------

    std::filesystem::path data_root() const {
        return cfg.data_dir;
    }

    std::filesystem::path path_for_hash(const al_hash256& h) const {
        auto hex = to_hex(h);
        auto dir1 = data_root() / hex.substr(0, 2);
        auto dir2 = dir1 / hex.substr(2, 2);
        auto file = dir2 / hex.substr(4);
        return file;
    }

    std::string key_for_hash(const al_hash256& h) const {
        return to_hex(h);
    }

    // --- Storage accounting -----------------------------------------------

    bool check_quota(size_t additional_bytes) const {
        if (cfg.max_storage == 0) return true;  // unlimited
        return (total_stored_bytes + additional_bytes) <= cfg.max_storage;
    }

    // --- Read stored chunk from disk --------------------------------------

    std::expected<std::vector<uint8_t>, ShareError> read_stored_chunk(
        const std::filesystem::path& path) {
        std::error_code ec;
        auto file_size = std::filesystem::file_size(path, ec);
        if (ec) {
            return std::unexpected(ShareError::make(
                ShareErrorCode::ChunkReadFailed,
                "file size query failed: " + path.string()));
        }

        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) {
            return std::unexpected(ShareError::make(
                ShareErrorCode::ChunkReadFailed,
                "failed to open: " + path.string()));
        }

        std::vector<uint8_t> data(static_cast<size_t>(file_size));
        ifs.read(reinterpret_cast<char*>(data.data()),
                 static_cast<std::streamsize>(file_size));

        if (!ifs) {
            return std::unexpected(ShareError::make(
                ShareErrorCode::ChunkReadFailed,
                "read failed: " + path.string()));
        }

        return data;
    }

    // --- Accept loop ------------------------------------------------------

    void accept_loop() {
        while (running.load(std::memory_order_relaxed)) {
            sockaddr_storage client_addr{};
            socklen_t addr_len = sizeof(client_addr);

            sock_t client_fd = ::accept(listen_fd,
                reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
            if (client_fd == kInvalidSock) {
                if (!running.load(std::memory_order_relaxed)) break;
                continue;
            }

            if (cfg.max_connections > 0 &&
                active_conns.load(std::memory_order_relaxed) >= cfg.max_connections) {
                // Reject with ERROR status
                uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::ERROR) };
                write_exact(client_fd, resp, 1);
                CLOSE_SOCKET(client_fd);
                continue;
            }

            active_conns.fetch_add(1, std::memory_order_relaxed);
            std::thread(&Impl::handle_client, this, client_fd).detach();
        }
    }

    // --- Client handler ---------------------------------------------------

    void handle_client(sock_t client_fd) {
        auto guard = [this](int) {
            active_conns.fetch_sub(1, std::memory_order_relaxed);
        };

        // Read method byte
        uint8_t method_byte;
        auto method_result = read_exact(client_fd, &method_byte, 1);
        if (!method_result) {
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        auto method = static_cast<Method>(method_byte);

        // Read hash (32 bytes)
        uint8_t hash_buf[AL_HASH_SIZE];
        auto hash_result = read_exact(client_fd, hash_buf, AL_HASH_SIZE);
        if (!hash_result) {
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        al_hash256 requested_hash{};
        std::memcpy(requested_hash.bytes, hash_buf, AL_HASH_SIZE);

        switch (method) {
            case Method::HAVE:
                handle_have(client_fd, requested_hash);
                break;
            case Method::GET:
                handle_get(client_fd, requested_hash);
                break;
            case Method::PUT:
                handle_put(client_fd, requested_hash);
                break;
            default: {
                uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::ERROR) };
                write_exact(client_fd, resp, 1);
                break;
            }
        }

        CLOSE_SOCKET(client_fd);
        guard(0);
    }

    // --- Method handlers --------------------------------------------------

    void handle_have(sock_t fd, const al_hash256& hash) {
        uint8_t status;
        {
            std::lock_guard lock(mu);
            auto key = key_for_hash(hash);
            status = chunks.contains(key)
                ? static_cast<uint8_t>(StatusCode::OK)
                : static_cast<uint8_t>(StatusCode::NOT_FOUND);
        }
        write_exact(fd, &status, 1);
    }

    void handle_get(sock_t fd, const al_hash256& hash) {
        std::lock_guard lock(mu);
        auto key = key_for_hash(hash);
        auto it = chunks.find(key);

        if (it == chunks.end()) {
            uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::NOT_FOUND) };
            write_exact(fd, resp, 1);
            return;
        }

        // Read chunk from disk
        auto read_result = read_stored_chunk(it->second.path);
        if (!read_result) {
            uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::ERROR) };
            write_exact(fd, resp, 1);
            return;
        }

        // Send OK status
        uint8_t status = static_cast<uint8_t>(StatusCode::OK);
        write_exact(fd, &status, 1);

        // Send size (big-endian u64)
        if (!write_u64(fd, read_result->size())) {
            return;
        }

        // Send data
        if (!read_result->empty()) {
            write_exact(fd, read_result->data(), read_result->size());
        }
    }

    void handle_put(sock_t fd, const al_hash256& hash) {
        // Read chunk size
        auto size_result = read_u64(fd);
        if (!size_result) {
            uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::ERROR) };
            write_exact(fd, resp, 1);
            return;
        }

        uint64_t chunk_size = *size_result;

        // Enforce maximum chunk size
        if (chunk_size > cfg.chunk_size * 4) {
            uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::ERROR) };
            write_exact(fd, resp, 1);
            return;
        }

        // Read chunk data
        std::vector<uint8_t> data(static_cast<size_t>(chunk_size));
        auto read_result = read_exact(fd, data.data(), data.size());
        if (!read_result) {
            uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::ERROR) };
            write_exact(fd, resp, 1);
            return;
        }

        // Verify hash
        auto computed = compute_hash(data.data(), data.size());
        if (!computed || !hashes_equal(hash, *computed)) {
            uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::HASH_MISMATCH) };
            write_exact(fd, resp, 1);
            return;
        }

        // Store the chunk
        std::lock_guard lock(mu);
        auto key = key_for_hash(hash);

        // Already stored
        if (chunks.contains(key)) {
            uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::OK) };
            write_exact(fd, resp, 1);
            return;
        }

        // Check quota
        if (!check_quota(data.size())) {
            uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::QUOTA_FULL) };
            write_exact(fd, resp, 1);
            return;
        }

        // Compute on-disk path and create directories
        auto file_path = path_for_hash(hash);
        std::error_code ec;
        std::filesystem::create_directories(file_path.parent_path(), ec);
        if (ec) {
            uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::ERROR) };
            write_exact(fd, resp, 1);
            return;
        }

        // Write the file
        std::ofstream ofs(file_path, std::ios::binary);
        if (!ofs.is_open()) {
            uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::ERROR) };
            write_exact(fd, resp, 1);
            return;
        }

        ofs.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
        if (!ofs) {
            std::filesystem::remove(file_path, ec);
            uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::ERROR) };
            write_exact(fd, resp, 1);
            return;
        }

        // Record in index
        StoredChunk stored;
        stored.path = file_path;
        stored.size = data.size();
        chunks[key] = std::move(stored);
        total_stored_bytes += data.size();

        uint8_t resp[1] = { static_cast<uint8_t>(StatusCode::OK) };
        write_exact(fd, resp, 1);
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

ShareNode::ShareNode()
    : impl_(std::make_unique<Impl>()) {}

ShareNode::ShareNode(ShareConfig config)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(config);
}

ShareNode::~ShareNode() {
    stop();
}

ShareNode::ShareNode(ShareNode&&) noexcept = default;
ShareNode& ShareNode::operator=(ShareNode&&) noexcept = default;

std::expected<void, ShareError> ShareNode::start() {
    if (impl_->running.load(std::memory_order_relaxed)) {
        return std::unexpected(ShareError::make(
            ShareErrorCode::AlreadyRunning, "share node already running"));
    }

    // Ensure data directory exists
    std::error_code ec;
    std::filesystem::create_directories(impl_->data_root(), ec);
    if (ec) {
        return std::unexpected(ShareError::make(
            ShareErrorCode::ChunkStoreFailed,
            "failed to create data directory: " + impl_->data_root().string()));
    }

    // Create listening socket
    impl_->listen_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (impl_->listen_fd == kInvalidSock) {
        return std::unexpected(ShareError::make(
            ShareErrorCode::SocketCreateFailed,
            "socket() failed: " + std::string(std::strerror(errno))));
    }

    int reuse = 1;
    ::setsockopt(impl_->listen_fd, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(impl_->cfg.listen_port);

    if (impl_->cfg.bind_address == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (impl_->cfg.bind_address == "127.0.0.1" ||
               impl_->cfg.bind_address == "localhost") {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        ::inet_pton(AF_INET, impl_->cfg.bind_address.c_str(),
                    &addr.sin_addr);
    }

    if (::bind(impl_->listen_fd, reinterpret_cast<sockaddr*>(&addr),
               sizeof(addr)) < 0) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
        return std::unexpected(ShareError::make(
            ShareErrorCode::SocketBindFailed,
            "bind() failed on " + impl_->cfg.bind_address + ":" +
                std::to_string(impl_->cfg.listen_port) + ": " +
                std::strerror(errno)));
    }

    if (::listen(impl_->listen_fd, 16) < 0) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
        return std::unexpected(ShareError::make(
            ShareErrorCode::SocketListenFailed,
            "listen() failed: " + std::string(std::strerror(errno))));
    }

    impl_->running.store(true, std::memory_order_release);
    impl_->seeding.store(impl_->cfg.seed_enabled, std::memory_order_release);
    impl_->accept_thread = std::thread(&Impl::accept_loop, impl_.get());

    return {};
}

void ShareNode::stop() {
    impl_->running.store(false, std::memory_order_release);
    impl_->seeding.store(false, std::memory_order_release);

    if (impl_->listen_fd != kInvalidSock) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
    }

    if (impl_->accept_thread.joinable()) {
        impl_->accept_thread.join();
    }
}

bool ShareNode::is_running() const {
    return impl_->running.load(std::memory_order_acquire);
}

// ---------------------------------------------------------------------------
// Chunk operations
// ---------------------------------------------------------------------------

std::expected<ChunkInfo, ShareError> ShareNode::store_chunk(
    const al_hash256& hash,
    std::span<const uint8_t> data) {

    // Verify the hash matches the data
    auto computed = compute_hash(data.data(), data.size());
    if (!computed) {
        return std::unexpected(std::move(computed.error()));
    }
    if (!hashes_equal(hash, *computed)) {
        return std::unexpected(ShareError::make(
            ShareErrorCode::ChunkHashMismatch,
            "provided hash does not match computed SHA-256"));
    }

    std::lock_guard lock(impl_->mu);

    auto key = impl_->key_for_hash(hash);

    // Check if already stored
    if (impl_->chunks.contains(key)) {
        ChunkInfo result;
        result.hash = hash;
        result.path = impl_->chunks[key].path;
        result.size = impl_->chunks[key].size;
        result.verified = true;
        return result;
    }

    // Check quota
    if (!impl_->check_quota(data.size())) {
        return std::unexpected(ShareError::make(
            ShareErrorCode::QuotaExceeded,
            "storage quota exceeded: " + std::to_string(impl_->total_stored_bytes) +
            " + " + std::to_string(data.size()) + " > " +
            std::to_string(impl_->cfg.max_storage)));
    }

    // Compute on-disk path and create directories
    auto file_path = impl_->path_for_hash(hash);
    std::error_code ec;
    std::filesystem::create_directories(file_path.parent_path(), ec);
    if (ec) {
        return std::unexpected(ShareError::make(
            ShareErrorCode::ChunkStoreFailed,
            "failed to create directory: " + file_path.parent_path().string()));
    }

    // Write the file
    std::ofstream ofs(file_path, std::ios::binary);
    if (!ofs.is_open()) {
        return std::unexpected(ShareError::make(
            ShareErrorCode::ChunkStoreFailed,
            "failed to open file for writing: " + file_path.string()));
    }

    ofs.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    if (!ofs) {
        std::filesystem::remove(file_path, ec);
        return std::unexpected(ShareError::make(
            ShareErrorCode::ChunkStoreFailed,
            "write failed: " + file_path.string()));
    }

    // Record in index
    Impl::StoredChunk stored;
    stored.path = file_path;
    stored.size = data.size();
    impl_->chunks[key] = std::move(stored);
    impl_->total_stored_bytes += data.size();

    ChunkInfo result;
    result.hash = hash;
    result.path = file_path;
    result.size = data.size();
    result.verified = true;
    return result;
}

std::expected<ChunkInfo, ShareError> ShareNode::get_chunk(
    const al_hash256& hash) {
    std::lock_guard lock(impl_->mu);

    auto key = impl_->key_for_hash(hash);
    auto it = impl_->chunks.find(key);
    if (it == impl_->chunks.end()) {
        return std::unexpected(ShareError::make(
            ShareErrorCode::ChunkNotFound,
            "chunk not found: " + to_hex(hash)));
    }

    ChunkInfo result;
    result.hash = hash;
    result.path = it->second.path;
    result.size = it->second.size;
    return result;
}

bool ShareNode::has_chunk(const al_hash256& hash) const {
    std::lock_guard lock(impl_->mu);
    auto key = impl_->key_for_hash(hash);
    return impl_->chunks.contains(key);
}

std::expected<bool, ShareError> ShareNode::verify_chunk(
    const al_hash256& hash) {
    std::lock_guard lock(impl_->mu);

    auto key = impl_->key_for_hash(hash);
    auto it = impl_->chunks.find(key);
    if (it == impl_->chunks.end()) {
        return std::unexpected(ShareError::make(
            ShareErrorCode::ChunkNotFound,
            "chunk not found: " + to_hex(hash)));
    }

    // Read the chunk and recompute the hash
    auto read_result = impl_->read_stored_chunk(it->second.path);
    if (!read_result) {
        return std::unexpected(std::move(read_result.error()));
    }

    auto computed = compute_hash(read_result->data(), read_result->size());
    if (!computed) {
        return std::unexpected(std::move(computed.error()));
    }

    return hashes_equal(hash, *computed);
}

std::expected<void, ShareError> ShareNode::remove_chunk(
    const al_hash256& hash) {
    std::lock_guard lock(impl_->mu);

    auto key = impl_->key_for_hash(hash);
    auto it = impl_->chunks.find(key);
    if (it == impl_->chunks.end()) {
        return std::unexpected(ShareError::make(
            ShareErrorCode::ChunkNotFound,
            "chunk not found: " + to_hex(hash)));
    }

    // Remove from disk
    std::error_code ec;
    std::filesystem::remove(it->second.path, ec);

    impl_->total_stored_bytes -= it->second.size;
    impl_->chunks.erase(it);

    return {};
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

std::vector<InventoryEntry> ShareNode::get_inventory() const {
    std::lock_guard lock(impl_->mu);

    std::vector<InventoryEntry> result;
    result.reserve(impl_->chunks.size());
    for (auto& [hex, stored] : impl_->chunks) {
        InventoryEntry entry;
        entry.size = stored.size;

        // Convert hex back to hash
        for (size_t i = 0; i < AL_HASH_SIZE; ++i) {
            auto hi = hex[i * 2];
            auto lo = hex[i * 2 + 1];
            auto nibble = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
                return static_cast<uint8_t>(c - 'a' + 10);
            };
            entry.hash.bytes[i] = static_cast<uint8_t>(
                (nibble(hi) << 4) | nibble(lo));
        }

        result.push_back(entry);
    }
    return result;
}

size_t ShareNode::chunk_count() const {
    return impl_->chunks.size();
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

size_t ShareNode::get_storage_usage() const {
    return impl_->total_stored_bytes;
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

void ShareNode::set_seed_enabled(bool enabled) {
    impl_->seeding.store(enabled, std::memory_order_release);
}

bool ShareNode::is_seeding() const {
    return impl_->seeding.load(std::memory_order_acquire);
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

void ShareNode::set_config(ShareConfig config) {
    impl_->cfg = std::move(config);
}

const ShareConfig& ShareNode::config() const {
    return impl_->cfg;
}

size_t ShareNode::connection_count() const {
    return impl_->active_conns.load(std::memory_order_relaxed);
}

}  // namespace astrolune::share
