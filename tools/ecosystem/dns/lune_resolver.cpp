// Local DNS resolver for .lune domains.
//
// Implementation notes:
//   - UDP-only, single-threaded receive loop with select()-based polling.
//   - Responses are served from cache when possible; upstream queries
//     use non-blocking UDP sockets with a per-upstream timeout.
//   - The pImpl pattern keeps the ABI stable as internal details evolve.
//   - No exceptions; all errors flow through std::expected.

#include "lune_resolver.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

// --- Platform socket headers ------------------------------------------------

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
#  include <arpa/inet.h>
#  include <cerrno>
#  include <fcntl.h>
#  include <netdb.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
#endif

namespace astrolune::dns {
namespace {

// --- Monotonic clock --------------------------------------------------------

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

uint64_t now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now().time_since_epoch()).count());
}

// --- Platform helpers -------------------------------------------------------

void close_socket(socket_t s) {
#if defined(_WIN32)
    closesocket(s);
#else
    close(s);
#endif
}

void set_nonblocking(socket_t s) {
#if defined(_WIN32)
    unsigned long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
}

bool init_sockets() {
#if defined(_WIN32)
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    return true;
#endif
}

// --- DNS wire helpers -------------------------------------------------------

// Encode a single DNS label: length byte + label bytes. Input is the raw
// label text (no trailing dot).
std::vector<uint8_t> encode_label(std::string_view label) {
    std::vector<uint8_t> out;
    if (label.size() > 63) label = label.substr(0, 63);
    out.push_back(static_cast<uint8_t>(label.size()));
    out.insert(out.end(), label.begin(), label.end());
    return out;
}

// Write a 16-bit value in network byte order.
void push_u16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v >> 8));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

// Write a 32-bit value in network byte order.
void push_u32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint32_t read_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

}  // namespace

// ===========================================================================
// DnsCache
// ===========================================================================

bool DnsCache::Key::operator==(const Key& o) const noexcept {
    return name == o.name && type == o.type;
}

size_t DnsCache::KeyHash::operator()(const Key& k) const noexcept {
    size_t h1 = std::hash<std::string>{}(k.name);
    size_t h2 = std::hash<uint16_t>{}(static_cast<uint16_t>(k.type));
    return h1 ^ (h2 * 0x9E3779B97F4A7C15ULL);
}

DnsCache::DnsCache() = default;

void DnsCache::set_max_entries(size_t max) {
    std::lock_guard lock(mu_);
    max_entries_ = max;
}

std::optional<DnsRecord> DnsCache::lookup(std::string_view name, RecordType type) {
    std::lock_guard lock(mu_);
    Key key{std::string(name), type};
    auto it = entries_.find(key);
    if (it == entries_.end()) return std::nullopt;

    if (now_ms() > it->second.expires_at) {
        entries_.erase(it);
        return std::nullopt;
    }
    return it->second.record;
}

void DnsCache::store(DnsRecord record) {
    std::lock_guard lock(mu_);
    Key key{record.name, record.type};
    uint64_t expires = now_ms() + static_cast<uint64_t>(record.ttl) * 1000ULL;
    entries_[key] = CacheEntry{std::move(record), expires};
    evict_if_needed();
}

void DnsCache::clear() {
    std::lock_guard lock(mu_);
    entries_.clear();
}

size_t DnsCache::size() const {
    std::lock_guard lock(mu_);
    return entries_.size();
}

void DnsCache::evict_if_needed() {
    if (entries_.size() <= max_entries_) return;
    size_t target = max_entries_ * 3 / 4;
    // Evict oldest entries (earliest expires_at).
    std::vector<Key> candidates;
    candidates.reserve(entries_.size());
    for (auto& [k, v] : entries_) candidates.push_back(k);
    std::sort(candidates.begin(), candidates.end(),
              [this](const Key& a, const Key& b) {
                  return entries_.at(a).expires_at < entries_.at(b).expires_at;
              });
    for (size_t i = 0; i < candidates.size() && entries_.size() > target; ++i) {
        entries_.erase(candidates[i]);
    }
}

// ===========================================================================
// LuneResolver::Impl — private implementation
// ===========================================================================

struct LuneResolver::Impl {
    socket_t sock = kInvalidSocket;
    uint16_t port = kLuneDnsPort;
    std::atomic<bool> running{false};
    std::thread recv_thread;

    DnsCache cache;

    std::vector<SplitZone> zones;
    std::string default_upstream_host;
    uint16_t default_upstream_port = 53;
    uint16_t default_timeout_ms = 2000;

    // Parse "host:port" or just "host" (port defaults to 53).
    bool parse_upstream(std::string_view addr, std::string& host, uint16_t& port_out) {
        auto colon = addr.find(':');
        if (colon != std::string_view::npos) {
            host = std::string(addr.substr(0, colon));
            auto port_str = addr.substr(colon + 1);
            int p = 0;
            for (char c : port_str) {
                if (c < '0' || c > '9') return false;
                p = p * 10 + (c - '0');
            }
            if (p <= 0 || p > 65535) return false;
            port_out = static_cast<uint16_t>(p);
        } else {
            host = std::string(addr);
            port_out = 53;
        }
        return true;
    }

    // Find the best matching zone for a query name (longest suffix match).
    const SplitZone* find_zone(std::string_view qname) const {
        const SplitZone* best = nullptr;
        size_t best_len = 0;
        for (const auto& z : zones) {
            if (qname.size() >= z.suffix.size() &&
                qname.compare(qname.size() - z.suffix.size(),
                             z.suffix.size(), z.suffix) == 0) {
                if (z.suffix.size() > best_len) {
                    best_len = z.suffix.size();
                    best = &z;
                }
            }
        }
        return best;
    }

    // Send a DNS query to an upstream and receive the response.
    std::expected<std::vector<DnsRecord>, DnsError> query_upstream(
        std::string_view upstream_addr, const std::vector<uint8_t>& query,
        uint16_t timeout_ms) {

        std::string host;
        uint16_t up_port = 53;
        if (!parse_upstream(upstream_addr, host, up_port)) {
            return std::unexpected(DnsError{
                DnsErrorCode::UpstreamConnectFailed,
                "bad upstream address: " + std::string(upstream_addr)});
        }

        socket_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == kInvalidSocket) {
            return std::unexpected(DnsError{
                DnsErrorCode::SocketCreateFailed,
                "upstream socket creation failed"});
        }

        set_nonblocking(s);

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(up_port);
        if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
            // Try getaddrinfo for hostname resolution.
            struct addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            struct addrinfo* result = nullptr;
            if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 ||
                !result) {
                close_socket(s);
                return std::unexpected(DnsError{
                    DnsErrorCode::UpstreamConnectFailed,
                    "cannot resolve upstream: " + host});
            }
            addr = *reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
            freeaddrinfo(result);
        }

        // Send query.
        auto sent = sendto(s, reinterpret_cast<const char*>(query.data()),
                           static_cast<int>(query.size()), 0,
                           reinterpret_cast<struct sockaddr*>(&addr),
                           sizeof(addr));
        if (sent < 0) {
            close_socket(s);
            return std::unexpected(DnsError{
                DnsErrorCode::SocketSendFailed,
                "upstream send failed"});
        }

        // Wait for response with timeout.
        fd_set read_set;
        FD_ZERO(&read_set);
#if defined(_WIN32)
        FD_SET(s, &read_set);
#else
        FD_SET(s, &read_set);
#endif

        struct timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int ready = select(static_cast<int>(s) + 1, &read_set,
                           nullptr, nullptr, &tv);
        if (ready <= 0) {
            close_socket(s);
            return std::unexpected(DnsError{
                DnsErrorCode::UpstreamTimeout,
                "upstream timeout: " + std::string(upstream_addr)});
        }

        // Receive response.
        std::vector<uint8_t> resp_buf(512);
        auto recvd = recvfrom(s, reinterpret_cast<char*>(resp_buf.data()),
                              static_cast<int>(resp_buf.size()), 0, nullptr, nullptr);
        close_socket(s);

        if (recvd < 0) {
            return std::unexpected(DnsError{
                DnsErrorCode::SocketRecvFailed,
                "upstream recv failed"});
        }
        if (recvd < 12) {
            return std::unexpected(DnsError{
                DnsErrorCode::PacketTooShort,
                "upstream response too short"});
        }

        resp_buf.resize(static_cast<size_t>(recvd));
        return parse_response(resp_buf.data(), resp_buf.size());
    }

    // Try each upstream in order until one succeeds.
    std::expected<std::vector<DnsRecord>, DnsError> query_upstreams(
        const std::vector<uint8_t>& query, const SplitZone* zone) {

        uint16_t timeout = zone ? zone->timeout_ms : default_timeout_ms;

        if (zone && !zone->upstreams.empty()) {
            for (const auto& up : zone->upstreams) {
                auto result = query_upstream(up, query, timeout);
                if (result) return result;
            }
            return std::unexpected(DnsError{
                DnsErrorCode::UpstreamTimeout,
                "all zone upstreams exhausted"});
        }

        // Use default upstream.
        if (!default_upstream_host.empty()) {
            std::string addr = default_upstream_host + ":" +
                               std::to_string(default_upstream_port);
            return query_upstream(addr, query, timeout);
        }

        return std::unexpected(DnsError{
            DnsErrorCode::UpstreamConnectFailed,
            "no upstream configured"});
    }
};

// ===========================================================================
// LuneResolver — public API
// ===========================================================================

LuneResolver::LuneResolver() : impl_(std::make_unique<Impl>()) {}
LuneResolver::~LuneResolver() { stop(); }

LuneResolver::LuneResolver(LuneResolver&&) noexcept = default;
LuneResolver& LuneResolver::operator=(LuneResolver&&) noexcept = default;

std::expected<void, DnsError> LuneResolver::start() {
    if (impl_->running.load()) {
        return std::unexpected(DnsError{
            DnsErrorCode::AlreadyRunning, "resolver already running"});
    }

    if (!init_sockets()) {
        return std::unexpected(DnsError{
            DnsErrorCode::SocketCreateFailed, "socket init failed"});
    }

    impl_->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (impl_->sock == kInvalidSocket) {
        return std::unexpected(DnsError{
            DnsErrorCode::SocketCreateFailed, "UDP socket creation failed"});
    }

    // Allow address reuse for quick restart.
    int reuse = 1;
    setsockopt(impl_->sock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    struct sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(impl_->port);

    if (bind(impl_->sock,
             reinterpret_cast<struct sockaddr*>(&bind_addr),
             sizeof(bind_addr)) < 0) {
        close_socket(impl_->sock);
        impl_->sock = kInvalidSocket;
        return std::unexpected(DnsError{
            DnsErrorCode::SocketBindFailed,
            "bind failed on port " + std::to_string(impl_->port)});
    }

    set_nonblocking(impl_->sock);
    impl_->running.store(true);

    // Spawn receive thread.
    impl_->recv_thread = std::thread([this]() {
        std::vector<uint8_t> buf(512);
        while (impl_->running.load()) {
            fd_set read_set;
            FD_ZERO(&read_set);
#if defined(_WIN32)
            FD_SET(impl_->sock, &read_set);
#else
            FD_SET(impl_->sock, &read_set);
#endif
            struct timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 100'000;  // 100ms poll interval

            int ready = select(static_cast<int>(impl_->sock) + 1,
                               &read_set, nullptr, nullptr, &tv);
            if (ready <= 0 || !FD_ISSET(impl_->sock, &read_set)) continue;

            struct sockaddr_in from{};
#if defined(_WIN32)
            int from_len = sizeof(from);
#else
            socklen_t from_len = sizeof(from);
#endif
            auto n = recvfrom(impl_->sock,
                              reinterpret_cast<char*>(buf.data()),
                              static_cast<int>(buf.size()), 0,
                              reinterpret_cast<struct sockaddr*>(&from),
                              &from_len);
            if (n < 12) continue;

            size_t pkt_len = static_cast<size_t>(n);
            auto result = parse_response(buf.data(), pkt_len);
            if (!result) continue;

            // Cache each record from the response.
            for (auto& rec : *result) {
                impl_->cache.store(std::move(rec));
            }
        }
    });

    return {};
}

void LuneResolver::stop() {
    if (!impl_->running.exchange(false)) return;
    if (impl_->sock != kInvalidSocket) {
        close_socket(impl_->sock);
        impl_->sock = kInvalidSocket;
    }
    if (impl_->recv_thread.joinable()) {
        impl_->recv_thread.join();
    }
}

bool LuneResolver::is_running() const {
    return impl_->running.load();
}

void LuneResolver::set_port(uint16_t port) { impl_->port = port; }
uint16_t LuneResolver::port() const { return impl_->port; }

void LuneResolver::add_zone(SplitZone zone) {
    impl_->zones.push_back(std::move(zone));
}

void LuneResolver::remove_zone(std::string_view suffix) {
    impl_->zones.erase(
        std::remove_if(impl_->zones.begin(), impl_->zones.end(),
                        [suffix](const SplitZone& z) {
                            return z.suffix == suffix;
                        }),
        impl_->zones.end());
}

void LuneResolver::set_default_upstream(std::string upstream, uint16_t timeout_ms) {
    uint16_t port = 53;
    std::string host;
    if (impl_->parse_upstream(upstream, host, port)) {
        impl_->default_upstream_host = std::move(host);
        impl_->default_upstream_port = port;
        impl_->default_timeout_ms = timeout_ms;
    }
}

std::expected<std::vector<DnsRecord>, DnsError> LuneResolver::resolve(
    std::string_view name, RecordType type, DnsClass cls) {

    // Check cache first.
    auto cached = impl_->cache.lookup(name, type);
    if (cached) {
        return std::vector<DnsRecord>{std::move(*cached)};
    }

    // Build query and forward to upstream(s).
    auto query = build_query(name, type, cls);
    const SplitZone* zone = impl_->find_zone(name);
    return impl_->query_upstreams(query, zone);
}

DnsCache& LuneResolver::cache() { return impl_->cache; }
const DnsCache& LuneResolver::cache() const { return impl_->cache; }

std::optional<DnsRecord> LuneResolver::cache_lookup(
    std::string_view name, RecordType type) {
    return impl_->cache.lookup(name, type);
}

void LuneResolver::cache_store(DnsRecord record) {
    impl_->cache.store(std::move(record));
}

// ===========================================================================
// Wire protocol — static methods
// ===========================================================================

std::vector<uint8_t> LuneResolver::name_to_wire(std::string_view name) {
    std::vector<uint8_t> out;
    size_t start = 0;
    while (start < name.size()) {
        auto dot = name.find('.', start);
        if (dot == std::string_view::npos) dot = name.size();
        auto label = name.substr(start, dot - start);
        auto encoded = encode_label(label);
        out.insert(out.end(), encoded.begin(), encoded.end());
        start = dot + 1;
    }
    out.push_back(0);  // root label
    return out;
}

std::expected<std::pair<std::string, size_t>, DnsError> LuneResolver::name_from_wire(
    const uint8_t* data, size_t len, size_t offset) {

    std::string name;
    size_t pos = offset;
    int jump_count = 0;

    while (pos < len) {
        uint8_t label_len = data[pos];
        if (label_len == 0) {
            ++pos;
            break;
        }

        // Compression pointer: top two bits set.
        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= len) {
                return std::unexpected(DnsError{
                    DnsErrorCode::PacketMalformed,
                    "truncated compression pointer"});
            }
            if (++jump_count > 128) {
                return std::unexpected(DnsError{
                    DnsErrorCode::PacketMalformed,
                    "compression pointer loop"});
            }
            uint16_t ptr = static_cast<uint16_t>(
                ((label_len & 0x3F) << 8) | data[pos + 1]);
            if (ptr >= len) {
                return std::unexpected(DnsError{
                    DnsErrorCode::PacketMalformed,
                    "compression pointer out of bounds"});
            }
            pos = ptr;
            continue;
        }

        if (label_len > 63 || pos + 1 + label_len > len) {
            return std::unexpected(DnsError{
                DnsErrorCode::PacketMalformed,
                "invalid label length"});
        }
        if (!name.empty()) name.push_back('.');
        name.append(reinterpret_cast<const char*>(&data[pos + 1]), label_len);
        pos += 1 + label_len;
    }

    return std::pair{std::move(name), pos};
}

std::vector<uint8_t> LuneResolver::build_query(
    std::string_view name, RecordType type, DnsClass cls) {

    std::vector<uint8_t> pkt;

    // Header: ID=0x0000, flags=0x0100 (standard query, recursion desired),
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0.
    push_u16(pkt, 0x0000);  // ID
    push_u16(pkt, 0x0100);  // Flags: RD=1
    push_u16(pkt, 1);       // QDCOUNT
    push_u16(pkt, 0);       // ANCOUNT
    push_u16(pkt, 0);       // NSCOUNT
    push_u16(pkt, 0);       // ARCOUNT

    // Question section.
    auto wire_name = name_to_wire(name);
    pkt.insert(pkt.end(), wire_name.begin(), wire_name.end());
    push_u16(pkt, static_cast<uint16_t>(type));
    push_u16(pkt, static_cast<uint16_t>(cls));

    return pkt;
}

std::expected<std::vector<DnsRecord>, DnsError> LuneResolver::parse_response(
    const uint8_t* data, size_t len) {

    if (len < 12) {
        return std::unexpected(DnsError{
            DnsErrorCode::PacketTooShort, "packet too short for DNS header"});
    }

    // Parse header.
    // uint16_t id       = read_u16(data + 0);
    uint16_t flags     = read_u16(data + 2);
    uint16_t qdcount   = read_u16(data + 4);
    uint16_t ancount   = read_u16(data + 6);
    // uint16_t nscount = read_u16(data + 8);
    // uint16_t arcount = read_u16(data + 10);

    // Check for response bit (QR=1).
    if (!(flags & 0x8000)) {
        return std::unexpected(DnsError{
            DnsErrorCode::PacketMalformed, "not a response (QR=0)"});
    }

    size_t pos = 12;

    // Skip question section.
    for (uint16_t i = 0; i < qdcount; ++i) {
        auto name_result = name_from_wire(data, len, pos);
        if (!name_result) return std::unexpected(name_result.error());
        pos = name_result->second;
        if (pos + 4 > len) {
            return std::unexpected(DnsError{
                DnsErrorCode::PacketMalformed, "truncated question"});
        }
        pos += 4;  // QTYPE + QCLASS
    }

    // Parse answer section.
    std::vector<DnsRecord> records;
    records.reserve(ancount);

    for (uint16_t i = 0; i < ancount; ++i) {
        auto name_result = name_from_wire(data, len, pos);
        if (!name_result) return std::unexpected(name_result.error());
        pos = name_result->second;

        if (pos + 10 > len) {
            return std::unexpected(DnsError{
                DnsErrorCode::PacketMalformed, "truncated answer RR"});
        }

        uint16_t rr_type  = read_u16(data + pos);
        uint16_t rr_class = read_u16(data + pos + 2);
        uint32_t rr_ttl   = read_u32(data + pos + 4);
        uint16_t rdlen    = read_u16(data + pos + 8);
        pos += 10;

        if (pos + rdlen > len) {
            return std::unexpected(DnsError{
                DnsErrorCode::PacketMalformed, "truncated RDATA"});
        }

        DnsRecord rec;
        rec.name = std::move(name_result->first);
        rec.type = static_cast<RecordType>(rr_type);
        rec.cls = static_cast<DnsClass>(rr_class);
        rec.ttl = rr_ttl;
        rec.rdata.assign(data + pos, data + pos + rdlen);
        rec.received_at = now_ms();

        pos += rdlen;
        records.push_back(std::move(rec));
    }

    return records;
}

}  // namespace astrolune::dns
