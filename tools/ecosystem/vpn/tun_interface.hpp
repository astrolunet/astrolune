#pragma once

#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace astrolune::vpn {

/// @brief Network route definition
struct Route {
    std::string destination;   // CIDR notation (e.g., "10.0.0.0/8")
    std::string gateway;       // Gateway IP (optional for directly connected)
    uint32_t metric{0};        // Route metric for priority
    bool is_default{false};    // Whether this is a default route
};

/// @brief IPv4/IPv6 packet representation
struct Packet {
    std::vector<uint8_t> data;
    size_t length{0};
    enum class Protocol : uint8_t {
        Unknown = 0,
        IPv4 = 4,
        IPv6 = 6,
        ICMP = 1,
        TCP = 6,
        UDP = 17
    } protocol{Protocol::Unknown};

    [[nodiscard]] bool is_valid() const noexcept { return length > 0 && !data.empty(); }
    [[nodiscard]] uint8_t version() const noexcept {
        if (data.empty()) return 0;
        return (data[0] >> 4) & 0x0F;
    }
};

/// @brief DNS query information for interception
struct DnsQuery {
    std::string domain;
    std::vector<uint8_t> raw_query;
    uint16_t transaction_id{0};
    bool intercepted{false};
};

/// @brief Kill switch configuration
struct KillSwitchConfig {
    bool enabled{false};
    std::vector<std::string> allowed_apps;      // Bypass rules for specific apps
    std::vector<std::string> allowed_ips;       // Bypass rules for specific IPs
    std::vector<std::string> allowed_networks;  // Bypass rules for local networks
};

/// @brief TUN interface configuration
struct TunConfig {
    std::string interface_name{"astrolune_tun"};
    uint32_t mtu{1500};
    std::vector<Route> routes;
    std::string ipv4_address;
    std::string ipv4_netmask{"255.255.255.0"};
    std::string ipv6_address;
    int ipv6_prefix_length{64};
    KillSwitchConfig kill_switch;
    bool auto_dns{true};                      // Enable DNS interception
    std::string dns_server{"1.1.1.1"};        // Upstream DNS server
};

/// @brief Error codes for TUN operations
enum class TunError : uint8_t {
    None = 0,
    DeviceNotFound,
    PermissionDenied,
    InvalidConfig,
    AlreadyOpen,
    NotOpen,
    ReadFailed,
    WriteFailed,
    RouteFailed,
    DnsInterceptionFailed,
    KillSwitchFailed,
    PlatformError
};

/// @brief Result type using std::expected
template <typename T>
using TunResult = std::expected<T, TunError>;

/// @brief Cross-platform TUN interface implementation
class TunInterface {
public:
    TunInterface();
    ~TunInterface();

    TunInterface(const TunInterface&) = delete;
    TunInterface& operator=(const TunInterface&) = delete;
    TunInterface(TunInterface&&) noexcept;
    TunInterface& operator=(TunInterface&&) noexcept;

    /// @brief Open and initialize the TUN interface
    [[nodiscard]] TunResult<void> open(const TunConfig& config);

    /// @brief Close the TUN interface
    void close() noexcept;

    /// @brief Check if interface is open
    [[nodiscard]] bool is_open() const noexcept;

    /// @brief Read a packet from the TUN interface
    [[nodiscard]] TunResult<Packet> read_packet();

    /// @brief Write a packet to the TUN interface
    [[nodiscard]] TunResult<void> write_packet(const Packet& packet);

    /// @brief Add a route to the routing table
    [[nodiscard]] TunResult<void> add_route(const Route& route);

    /// @brief Remove a route from the routing table
    [[nodiscard]] TunResult<void> remove_route(const Route& route);

    /// @brief Enable DNS query interception
    [[nodiscard]] TunResult<void> enable_dns_interception(bool enable);

    /// @brief Set DNS interception callback
    void set_dns_callback(std::function<void(DnsQuery&)> callback);

    /// @brief Enable or disable kill switch
    [[nodiscard]] TunResult<void> set_kill_switch(bool enable);

    /// @brief Update kill switch configuration
    [[nodiscard]] TunResult<void> update_kill_switch_config(const KillSwitchConfig& config);

    /// @brief Check if traffic is allowed (kill switch check)
    [[nodiscard]] bool is_traffic_allowed(const Packet& packet) const noexcept;

    /// @brief Get current interface configuration
    [[nodiscard]] const TunConfig& config() const noexcept;

    /// @brief Get platform-specific file descriptor (Linux/macOS) or handle (Windows)
    [[nodiscard]] int native_handle() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace astrolune::vpn
