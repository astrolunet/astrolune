/*
 * astrolune/tools/ecosystem/hosting/host_node.cpp
 *
 * Implementation of the content-addressed file store and HTTP server.
 * Thread-per-connection model: the accept loop spawns a detached thread
 * for each incoming client.  The thread reads the HTTP request, resolves
 * the content hash, fetches the file from disk, and writes the response.
 */

#include "host_node.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

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

namespace astrolune::hosting {

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

namespace {

std::expected<size_t, HostError> read_exact(sock_t fd, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        auto got = ::recv(fd, reinterpret_cast<char*>(buf + total),
                          static_cast<int>(n - total), 0);
        if (got <= 0) {
            return std::unexpected(HostError::make(
                HostErrorCode::SocketRecvFailed,
                got == 0 ? "connection closed" : std::strerror(errno)));
        }
        total += static_cast<size_t>(got);
    }
    return total;
}

std::expected<size_t, HostError> write_exact(sock_t fd, const uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        auto sent = ::send(fd, reinterpret_cast<const char*>(buf + total),
                           static_cast<int>(n - total), 0);
        if (sent <= 0) {
            return std::unexpected(HostError::make(
                HostErrorCode::SocketSendFailed,
                sent == 0 ? "connection closed" : std::strerror(errno)));
        }
        total += static_cast<size_t>(sent);
    }
    return total;
}

std::string to_hex(const al_hash256& h) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(AL_HASH_SIZE * 2);
    for (size_t i = 0; i < AL_HASH_SIZE; ++i) {
        result.push_back(kHex[h.bytes[i] >> 4]);
        result.push_back(kHex[h.bytes[i] & 0x0F]);
    }
    return result;
}

std::expected<al_hash256, HostError> compute_sha256(
    const uint8_t* data, size_t len) {
    al_hash256 hash{};
    al_sha256(data, len, &hash);
    return hash;
}

bool hashes_equal(const al_hash256& a, const al_hash256& b) {
    return std::memcmp(a.bytes, b.bytes, AL_HASH_SIZE) == 0;
}

}  // namespace

// ---------------------------------------------------------------------------
// HostNode::Impl
// ---------------------------------------------------------------------------

struct HostNode::Impl {
    HostConfig cfg;
    std::atomic<bool> running{false};
    sock_t listen_fd = kInvalidSock;
    std::thread accept_thread;
    std::atomic<size_t> active_conns{0};

    mutable std::mutex mu;

    // --- Content store: hash -> on-disk path -----------------------------
    // Files are stored in a content-addressed layout:
    //   <data_dir>/<hex[0:2]>/<hex[2:4]>/<hex[4]>
    struct StoredFile {
        std::filesystem::path path;
        size_t size = 0;
        std::string site_id;  // owning site (empty = unowned)
    };
    std::unordered_map<std::string, StoredFile> files;  // hex(hash) -> StoredFile

    // --- Site registry ---------------------------------------------------
    std::unordered_map<std::string, SiteInfo> sites;  // site_id -> SiteInfo

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
                std::string resp =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Connection: close\r\n"
                    "Content-Length: 0\r\n\r\n";
                write_exact(client_fd,
                            reinterpret_cast<const uint8_t*>(resp.data()),
                            resp.size());
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

        // Read the full HTTP request until \r\n\r\n
        std::string request_data;
        request_data.reserve(4096);

        char buf[4096];
        while (request_data.size() < kMaxHostRequestBytes) {
            auto n = ::recv(client_fd, buf, sizeof(buf), 0);
            if (n <= 0) {
                CLOSE_SOCKET(client_fd);
                guard(0);
                return;
            }
            request_data.append(buf, static_cast<size_t>(n));
            if (request_data.find("\r\n\r\n") != std::string::npos) break;
        }

        if (request_data.size() >= kMaxHostRequestBytes &&
            request_data.find("\r\n\r\n") == std::string::npos) {
            std::string resp =
                "HTTP/1.1 413 Request Entity Too Large\r\n"
                "Connection: close\r\n\r\n";
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        // Parse the request line: METHOD /path HTTP/1.1
        auto first_crlf = request_data.find("\r\n");
        std::string request_line = request_data.substr(0, first_crlf);

        // Extract method
        auto sp1 = request_line.find(' ');
        if (sp1 == std::string::npos) {
            send_error(client_fd, 400, "Bad Request");
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }
        std::string method = request_line.substr(0, sp1);

        // Extract path
        auto sp2 = request_line.find(' ', sp1 + 1);
        if (sp2 == std::string::npos) {
            send_error(client_fd, 400, "Bad Request");
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }
        std::string path = request_line.substr(sp1 + 1, sp2 - sp1 - 1);

        // Handle OPTIONS for CORS preflight
        if (method == "OPTIONS") {
            std::string resp = build_response_head(204, "No Content", "text/plain", 0, false);
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        // Only GET and HEAD are supported
        bool is_head = (method == "HEAD");
        if (method != "GET" && !is_head) {
            send_error(client_fd, 405, "Method Not Allowed");
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        // Normalise path
        if (path.empty() || path[0] != '/') {
            path = "/" + path;
        }

        // Strip query string
        auto qpos = path.find('?');
        if (qpos != std::string::npos) {
            path = path.substr(0, qpos);
        }

        // Prevent directory traversal
        if (path.find("..") != std::string::npos) {
            send_error(client_fd, 403, "Forbidden");
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        // Route: /__host/site/<site_id>/<path>   — serve a site file
        //        /__host/file/<hex_hash>          — serve a raw content file
        //        /__host/status                   — storage status JSON
        constexpr std::string_view kSitePrefix = "/__host/site/";
        constexpr std::string_view kFilePrefix = "/__host/file/";
        constexpr std::string_view kStatusPath = "/__host/status";

        if (path.starts_with(kSitePrefix)) {
            // Extract site_id and file path
            auto rest = path.substr(kSitePrefix.size());
            auto slash = rest.find('/');
            std::string site_id;
            std::string file_path;
            if (slash != std::string::npos) {
                site_id = std::string(rest.substr(0, slash));
                file_path = std::string(rest.substr(slash + 1));
            } else {
                site_id = std::string(rest);
                file_path = "index.html";
            }

            std::lock_guard lock(mu);
            auto it = sites.find(site_id);
            if (it == sites.end()) {
                send_error(client_fd, 404, "Site Not Found");
                CLOSE_SOCKET(client_fd);
                guard(0);
                return;
            }

            // For a real implementation, we'd walk a Merkle tree here.
            // For now we treat root_hash as the index.html hash,
            // and look up files by their direct hash.
            // This is a simplified model.
            auto file_it = files.find(to_hex(it->second.root_hash));
            if (file_it == files.end()) {
                send_error(client_fd, 404, "Content Not Found");
                CLOSE_SOCKET(client_fd);
                guard(0);
                return;
            }

            auto& stored = file_it->second;
            auto read_result = read_stored_file(stored.path);
            if (!read_result) {
                send_error(client_fd, 500, "Internal Server Error");
                CLOSE_SOCKET(client_fd);
                guard(0);
                return;
            }

            auto ct = content_type_for(path);
            auto resp = build_response_head(200, "OK", ct, read_result->size(), false);
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            if (!is_head && !read_result->empty()) {
                write_exact(client_fd, read_result->data(), read_result->size());
            }

            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        if (path.starts_with(kFilePrefix)) {
            // Extract hex hash from path
            auto hex_hash = path.substr(kFilePrefix.size());

            // Validate hex string
            if (hex_hash.size() != AL_HASH_SIZE * 2) {
                send_error(client_fd, 400, "Invalid Hash Length");
                CLOSE_SOCKET(client_fd);
                guard(0);
                return;
            }
            for (char c : hex_hash) {
                if (!std::isxdigit(static_cast<unsigned char>(c))) {
                    send_error(client_fd, 400, "Invalid Hex Characters");
                    CLOSE_SOCKET(client_fd);
                    guard(0);
                    return;
                }
            }

            std::lock_guard lock(mu);
            auto it = files.find(std::string(hex_hash));
            if (it == files.end()) {
                send_error(client_fd, 404, "File Not Found");
                CLOSE_SOCKET(client_fd);
                guard(0);
                return;
            }

            auto& stored = it->second;
            auto read_result = read_stored_file(stored.path);
            if (!read_result) {
                send_error(client_fd, 500, "Internal Server Error");
                CLOSE_SOCKET(client_fd);
                guard(0);
                return;
            }

            auto ct = content_type_for(path);
            auto resp = build_response_head(200, "OK", ct, read_result->size(), false);
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            if (!is_head && !read_result->empty()) {
                write_exact(client_fd, read_result->data(), read_result->size());
            }

            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        if (path == kStatusPath) {
            // Return storage status as JSON
            std::ostringstream json;
            json << "{"
                 << "\"total_bytes\":" << total_stored_bytes << ","
                 << "\"max_bytes\":" << cfg.max_storage << ","
                 << "\"file_count\":" << files.size() << ","
                 << "\"site_count\":" << sites.size() << ","
                 << "\"running\":" << (running.load() ? "true" : "false")
                 << "}";

            auto body = json.str();
            auto resp = build_response_head(200, "OK", "application/json",
                                            body.size(), false);
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            if (!is_head) {
                write_exact(client_fd,
                            reinterpret_cast<const uint8_t*>(body.data()),
                            body.size());
            }

            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        // Default: 404
        send_error(client_fd, 404, "Not Found");
        CLOSE_SOCKET(client_fd);
        guard(0);
    }

    // --- Helpers -----------------------------------------------------------

    void send_error(sock_t fd, int code, std::string_view text) {
        std::string resp = build_response_head(code, text, "text/plain", 0, false);
        write_exact(fd,
                    reinterpret_cast<const uint8_t*>(resp.data()),
                    resp.size());
    }

    std::string build_response_head(
        int status_code,
        std::string_view status_text,
        std::string_view content_type,
        size_t content_length,
        bool keep_alive)
    {
        std::ostringstream ss;
        ss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";

        if (cfg.cors_enabled) {
            ss << "Access-Control-Allow-Origin: " << cfg.cors_origin << "\r\n";
            ss << "Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n";
            ss << "Access-Control-Allow-Headers: Content-Type, Range\r\n";
            ss << "Access-Control-Expose-Headers: Content-Length, Content-Range\r\n";
        }

        ss << "Content-Type: " << content_type << "\r\n";
        ss << "Content-Length: " << content_length << "\r\n";
        ss << "Connection: " << (keep_alive ? "keep-alive" : "close") << "\r\n";
        ss << "Cache-Control: public, max-age=3600\r\n";
        ss << "X-Content-Type-Options: nosniff\r\n";
        ss << "\r\n";

        return ss.str();
    }

    std::expected<std::vector<uint8_t>, HostError> read_stored_file(
        const std::filesystem::path& path) {
        std::error_code ec;
        auto file_size = std::filesystem::file_size(path, ec);
        if (ec) {
            return std::unexpected(HostError::make(
                HostErrorCode::FileReadFailed,
                "file size query failed: " + path.string()));
        }

        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) {
            return std::unexpected(HostError::make(
                HostErrorCode::FileReadFailed,
                "failed to open: " + path.string()));
        }

        std::vector<uint8_t> data(static_cast<size_t>(file_size));
        ifs.read(reinterpret_cast<char*>(data.data()),
                 static_cast<std::streamsize>(file_size));

        if (!ifs) {
            return std::unexpected(HostError::make(
                HostErrorCode::FileReadFailed,
                "read failed: " + path.string()));
        }

        return data;
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

HostNode::HostNode()
    : impl_(std::make_unique<Impl>()) {}

HostNode::HostNode(HostConfig config)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(config);
}

HostNode::~HostNode() {
    stop();
}

HostNode::HostNode(HostNode&&) noexcept = default;
HostNode& HostNode::operator=(HostNode&&) noexcept = default;

std::expected<void, HostError> HostNode::start() {
    if (impl_->running.load(std::memory_order_relaxed)) {
        return std::unexpected(HostError::make(
            HostErrorCode::AlreadyRunning, "host node already running"));
    }

    // Ensure data directory exists
    std::error_code ec;
    std::filesystem::create_directories(impl_->data_root(), ec);
    if (ec) {
        return std::unexpected(HostError::make(
            HostErrorCode::FileStoreFailed,
            "failed to create data directory: " + impl_->data_root().string()));
    }

    // Create listening socket
    impl_->listen_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (impl_->listen_fd == kInvalidSock) {
        return std::unexpected(HostError::make(
            HostErrorCode::SocketCreateFailed,
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
        return std::unexpected(HostError::make(
            HostErrorCode::SocketBindFailed,
            "bind() failed on " + impl_->cfg.bind_address + ":" +
                std::to_string(impl_->cfg.listen_port) + ": " +
                std::strerror(errno)));
    }

    if (::listen(impl_->listen_fd, 16) < 0) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
        return std::unexpected(HostError::make(
            HostErrorCode::SocketListenFailed,
            "listen() failed: " + std::string(std::strerror(errno))));
    }

    impl_->running.store(true, std::memory_order_release);
    impl_->accept_thread = std::thread(&Impl::accept_loop, impl_.get());

    return {};
}

void HostNode::stop() {
    impl_->running.store(false, std::memory_order_release);

    if (impl_->listen_fd != kInvalidSock) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
    }

    if (impl_->accept_thread.joinable()) {
        impl_->accept_thread.join();
    }
}

bool HostNode::is_running() const {
    return impl_->running.load(std::memory_order_acquire);
}

// ---------------------------------------------------------------------------
// File operations
// ---------------------------------------------------------------------------

std::expected<ContentFile, HostError> HostNode::store_file(
    const al_hash256& hash,
    std::span<const uint8_t> data,
    std::string_view site_id) {

    // Verify the hash matches the data
    auto computed = compute_sha256(data.data(), data.size());
    if (!computed) {
        return std::unexpected(std::move(computed.error()));
    }
    if (!hashes_equal(hash, *computed)) {
        return std::unexpected(HostError::make(
            HostErrorCode::FileHashMismatch,
            "provided hash does not match computed SHA-256"));
    }

    std::lock_guard lock(impl_->mu);

    auto key = impl_->key_for_hash(hash);

    // Check if already stored
    if (impl_->files.contains(key)) {
        // Already stored, update site ownership if needed
        if (!site_id.empty()) {
            auto& stored = impl_->files[key];
            if (stored.site_id.empty()) {
                stored.site_id = std::string(site_id);
            }
        }
        ContentFile result;
        result.hash = hash;
        result.path = impl_->files[key].path;
        result.size = impl_->files[key].size;
        return result;
    }

    // Check quota
    if (!impl_->check_quota(data.size())) {
        return std::unexpected(HostError::make(
            HostErrorCode::QuotaExceeded,
            "storage quota exceeded: " + std::to_string(impl_->total_stored_bytes) +
            " + " + std::to_string(data.size()) + " > " +
            std::to_string(impl_->cfg.max_storage)));
    }

    // Compute on-disk path and create directories
    auto file_path = impl_->path_for_hash(hash);
    std::error_code ec;
    std::filesystem::create_directories(file_path.parent_path(), ec);
    if (ec) {
        return std::unexpected(HostError::make(
            HostErrorCode::FileStoreFailed,
            "failed to create directory: " + file_path.parent_path().string()));
    }

    // Write the file
    std::ofstream ofs(file_path, std::ios::binary);
    if (!ofs.is_open()) {
        return std::unexpected(HostError::make(
            HostErrorCode::FileStoreFailed,
            "failed to open file for writing: " + file_path.string()));
    }

    ofs.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    if (!ofs) {
        std::filesystem::remove(file_path, ec);
        return std::unexpected(HostError::make(
            HostErrorCode::FileStoreFailed,
            "write failed: " + file_path.string()));
    }

    // Record in index
    Impl::StoredFile stored;
    stored.path = file_path;
    stored.size = data.size();
    stored.site_id = std::string(site_id);
    impl_->files[key] = std::move(stored);
    impl_->total_stored_bytes += data.size();

    // Update site stats if applicable
    if (!site_id.empty()) {
        auto site_it = impl_->sites.find(std::string(site_id));
        if (site_it != impl_->sites.end()) {
            site_it->second.file_count += 1;
            site_it->second.total_bytes += data.size();
        }
    }

    ContentFile result;
    result.hash = hash;
    result.path = file_path;
    result.size = data.size();
    return result;
}

std::expected<ContentFile, HostError> HostNode::get_file(
    const al_hash256& hash) {
    std::lock_guard lock(impl_->mu);

    auto key = impl_->key_for_hash(hash);
    auto it = impl_->files.find(key);
    if (it == impl_->files.end()) {
        return std::unexpected(HostError::make(
            HostErrorCode::FileNotFound,
            "file not found: " + to_hex(hash)));
    }

    ContentFile result;
    result.hash = hash;
    result.path = it->second.path;
    result.size = it->second.size;
    return result;
}

std::expected<bool, HostError> HostNode::verify_integrity(
    const al_hash256& hash) {
    std::lock_guard lock(impl_->mu);

    auto key = impl_->key_for_hash(hash);
    auto it = impl_->files.find(key);
    if (it == impl_->files.end()) {
        return std::unexpected(HostError::make(
            HostErrorCode::FileNotFound,
            "file not found: " + to_hex(hash)));
    }

    // Read the file and recompute the hash
    auto read_result = read_stored_file(it->second.path);
    if (!read_result) {
        return std::unexpected(std::move(read_result.error()));
    }

    auto computed = compute_sha256(read_result->data(), read_result->size());
    if (!computed) {
        return std::unexpected(std::move(computed.error()));
    }

    return hashes_equal(hash, *computed);
}

// ---------------------------------------------------------------------------
// Site management
// ---------------------------------------------------------------------------

std::expected<void, HostError> HostNode::register_site(
    std::string site_id,
    const al_hash256& root_hash) {
    std::lock_guard lock(impl_->mu);

    if (impl_->sites.contains(site_id)) {
        return std::unexpected(HostError::make(
            HostErrorCode::SiteAlreadyExists,
            "site already registered: " + site_id));
    }

    SiteInfo info;
    info.site_id = std::move(site_id);
    info.root_hash = root_hash;
    impl_->sites[info.site_id] = std::move(info);

    return {};
}

std::expected<void, HostError> HostNode::remove_site(std::string_view site_id) {
    std::lock_guard lock(impl_->mu);

    auto it = impl_->sites.find(std::string(site_id));
    if (it == impl_->sites.end()) {
        return std::unexpected(HostError::make(
            HostErrorCode::SiteNotFound,
            "site not found: " + std::string(site_id)));
    }

    // Remove all files belonging to this site
    std::string sid(it->second.site_id);
    size_t removed_bytes = 0;
    for (auto fit = impl_->files.begin(); fit != impl_->files.end(); ) {
        if (fit->second.site_id == sid) {
            std::error_code ec;
            std::filesystem::remove(fit->second.path, ec);
            removed_bytes += fit->second.size;
            fit = impl_->files.erase(fit);
        } else {
            ++fit;
        }
    }

    impl_->total_stored_bytes -= removed_bytes;
    impl_->sites.erase(it);

    return {};
}

std::expected<SiteInfo, HostError> HostNode::get_site(
    std::string_view site_id) const {
    std::lock_guard lock(impl_->mu);

    auto it = impl_->sites.find(std::string(site_id));
    if (it == impl_->sites.end()) {
        return std::unexpected(HostError::make(
            HostErrorCode::SiteNotFound,
            "site not found: " + std::string(site_id)));
    }

    return it->second;
}

std::vector<SiteInfo> HostNode::list_sites() const {
    std::lock_guard lock(impl_->mu);

    std::vector<SiteInfo> result;
    result.reserve(impl_->sites.size());
    for (auto& [_, info] : impl_->sites) {
        result.push_back(info);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

size_t HostNode::get_storage_usage() const {
    return impl_->total_stored_bytes;
}

size_t HostNode::file_count() const {
    return impl_->files.size();
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

void HostNode::set_config(HostConfig config) {
    impl_->cfg = std::move(config);
}

const HostConfig& HostNode::config() const {
    return impl_->cfg;
}

size_t HostNode::connection_count() const {
    return impl_->active_conns.load(std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

std::string_view HostNode::content_type_for(std::string_view path) {
    auto dot = path.rfind('.');
    if (dot == std::string_view::npos) {
        return "application/octet-stream";
    }

    auto ext = path.substr(dot + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (ext == "html" || ext == "htm")  return "text/html; charset=utf-8";
    if (ext == "css")                   return "text/css; charset=utf-8";
    if (ext == "js" || ext == "mjs")   return "application/javascript; charset=utf-8";
    if (ext == "json")                  return "application/json; charset=utf-8";
    if (ext == "png")                   return "image/png";
    if (ext == "jpg" || ext == "jpeg")  return "image/jpeg";
    if (ext == "gif")                   return "image/gif";
    if (ext == "svg")                   return "image/svg+xml";
    if (ext == "ico")                   return "image/x-icon";
    if (ext == "woff")                  return "font/woff";
    if (ext == "woff2")                 return "font/woff2";
    if (ext == "ttf")                   return "font/ttf";
    if (ext == "otf")                   return "font/otf";
    if (ext == "webp")                  return "image/webp";
    if (ext == "avif")                  return "image/avif";
    if (ext == "mp4")                   return "video/mp4";
    if (ext == "webm")                  return "video/webm";
    if (ext == "txt")                   return "text/plain; charset=utf-8";
    if (ext == "xml")                   return "application/xml; charset=utf-8";
    if (ext == "pdf")                   return "application/pdf";
    if (ext == "wasm")                  return "application/wasm";
    if (ext == "map")                   return "application/json; charset=utf-8";
    if (ext == "ts" || ext == "tsx")    return "application/javascript; charset=utf-8";
    if (ext == "jsx")                   return "application/javascript; charset=utf-8";

    return "application/octet-stream";
}

}  // namespace astrolune::hosting
