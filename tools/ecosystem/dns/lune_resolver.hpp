// Local DNS resolver for the .lune domain.
//
// Listens on UDP port 5335 (non-privileged) for DNS queries targeting
// .lune domains. Handles A, AAAA, CONTENT, and SERVICE record types.
// Serves cached responses with TTL and supports split-DNS zones that
// forward to different upstream resolvers.
//
// This is a stub resolver, not a recursive nameserver. It resolves
// .lune names by querying the configured upstream(s) and caches the
// results for subsequent local queries.

#ifndef ASTROLUNE_DNS_LUNE_RESOLVER_HPP
#define ASTROLUNE_DNS_LUNE_RESOLVER_HPP

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace astrolune::dns {

// ---------------------------------------------------------------------------
// Wire-level constants
// ---------------------------------------------------------------------------

constexpr uint16_t kLuneDnsPort = 5335;
constexpr std::string_view kLuneDomain = ".lune";
constexpr std::string_view kLuneDomainBare = "lune";

// ---------------------------------------------------------------------------
// DNS record types (beyond the standard A/AAAA/CNAME/MX/TXT)
// ---------------------------------------------------------------------------

enum class RecordType : uint16_t {
    A     = 1,
    AAAA  = 28,
    CNAME = 5,
    MX    = 15,
    TXT   = 16,
    // Astrolune-specific record types (private-use range 65280-65534)
    CONTENT  = 65280,   // arbitrary content payload (JSON, CBOR, etc.)
    SERVICE  = 65281,   // service endpoint descriptor
};

enum class DnsClass : uint16_t {
    IN = 1,   // Internet
};

// ---------------------------------------------------------------------------
// DnsRecord — a single resolved RR
// ---------------------------------------------------------------------------

struct DnsRecord {
    std::string name;            // fully-qualified, e.g. "alice.lune."
    RecordType type = RecordType::A;
    DnsClass cls = DnsClass::IN;
    uint32_t ttl = 0;            // seconds
    std::vector<uint8_t> rdata;  // type-specific binary payload
    uint64_t received_at = 0;    // monotonic clock timestamp at store
};

// ---------------------------------------------------------------------------
// Split-DNS zone mapping
// ---------------------------------------------------------------------------

struct SplitZone {
    std::string suffix;                   // e.g. ".lune" or ".dev.lune"
    std::vector<std::string> upstreams;   // e.g. {"127.0.0.1:5353"}
    uint16_t timeout_ms = 2000;           // per-upstream timeout
};

// ---------------------------------------------------------------------------
// DnsCache — TTL-based record cache, thread-safe
// ---------------------------------------------------------------------------

class DnsCache {
public:
    struct CacheEntry {
        DnsRecord record;
        uint64_t expires_at = 0;  // monotonic clock deadline
    };

    DnsCache();

    // Maximum number of entries. Exceeding this evicts the oldest 25%.
    void set_max_entries(size_t max);

    // Look up a record by (name, type). Returns std::nullopt on miss or
    // expiry. Expired entries are removed on access.
    std::optional<DnsRecord> lookup(std::string_view name, RecordType type);

    // Store a record. TTL is taken from the record's ttl field.
    void store(DnsRecord record);

    // Remove all entries.
    void clear();

    // Current entry count (approximate, under lock).
    size_t size() const;

private:
    struct Key {
        std::string name;
        RecordType type;
        bool operator==(const Key& o) const noexcept;
    };
    struct KeyHash {
        size_t operator()(const Key& k) const noexcept;
    };

    mutable std::mutex mu_;
    std::unordered_map<Key, CacheEntry, KeyHash> entries_;
    size_t max_entries_ = 4096;

    void evict_if_needed();
};

// ---------------------------------------------------------------------------
// DnsError — non-exception error for ABI-safe propagation
// ---------------------------------------------------------------------------

enum class DnsErrorCode {
    SocketCreateFailed,
    SocketBindFailed,
    SocketSendFailed,
    SocketRecvFailed,
    PacketTooShort,
    PacketMalformed,
    UnsupportedRecordType,
    UpstreamTimeout,
    UpstreamConnectFailed,
    CacheFull,
    AlreadyRunning,
    NotRunning,
};

struct DnsError {
    DnsErrorCode code = DnsErrorCode::PacketMalformed;
    std::string message;
};

// ---------------------------------------------------------------------------
// LuneResolver — the main resolver
// ---------------------------------------------------------------------------

class LuneResolver {
public:
    LuneResolver();
    ~LuneResolver();

    LuneResolver(const LuneResolver&) = delete;
    LuneResolver& operator=(const LuneResolver&) = delete;
    LuneResolver(LuneResolver&&) noexcept;
    LuneResolver& operator=(LuneResolver&&) noexcept;

    // --- Lifecycle --------------------------------------------------------

    // Start listening on the configured port. Returns an error if the
    // socket cannot be created or bound.
    std::expected<void, DnsError> start();

    // Stop listening and release the socket. Safe to call multiple times.
    void stop();

    // True if the resolver is actively listening.
    bool is_running() const;

    // --- Configuration ----------------------------------------------------

    // Port to listen on (default 5335). Must be set before start().
    void set_port(uint16_t port);
    uint16_t port() const;

    // Add a split-DNS zone. Zones are matched longest-suffix-first.
    void add_zone(SplitZone zone);

    // Remove a zone by suffix.
    void remove_zone(std::string_view suffix);

    // Set the default upstream (used when no zone matches).
    void set_default_upstream(std::string upstream, uint16_t timeout_ms = 2000);

    // --- Resolution -------------------------------------------------------

    // Resolve a single question. This queries upstream(s) and caches
    // the result. Returns an error on network failure or malformed response.
    std::expected<std::vector<DnsRecord>, DnsError> resolve(
        std::string_view name, RecordType type, DnsClass cls = DnsClass::IN);

    // --- Cache ------------------------------------------------------------

    DnsCache& cache();
    const DnsCache& cache() const;

    // Direct cache lookup (bypasses upstream).
    std::optional<DnsRecord> cache_lookup(std::string_view name, RecordType type);

    // Store a record directly in the cache.
    void cache_store(DnsRecord record);

    // --- Wire protocol helpers (public for testability) --------------------

    // Build a DNS query packet for (name, type, class).
    static std::vector<uint8_t> build_query(std::string_view name,
                                            RecordType type,
                                            DnsClass cls = DnsClass::IN);

    // Parse a DNS response packet into records. Returns an error if the
    // packet is malformed or truncated.
    static std::expected<std::vector<DnsRecord>, DnsError> parse_response(
        const uint8_t* data, size_t len);

    // --- Static DNS name helpers -------------------------------------------

    // Convert "alice.lune" to wire format labels: \x05alice\x04lune\x00
    static std::vector<uint8_t> name_to_wire(std::string_view name);

    // Read a DNS name from wire format starting at offset. Returns the
    // name and the offset past the name (handling compression pointers).
    static std::expected<std::pair<std::string, size_t>, DnsError> name_from_wire(
        const uint8_t* data, size_t len, size_t offset);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace astrolune::dns

#endif  // ASTROLUNE_DNS_LUNE_RESOLVER_HPP
