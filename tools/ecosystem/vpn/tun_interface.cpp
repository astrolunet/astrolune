#include "tun_interface.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <mutex>
#include <thread>

// Platform-specific includes
#if defined(_WIN32)
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "ws2_32.lib")
#elif defined(__linux__)
    #include <fcntl.h>
    #include <sys/ioctl.h>
    #include <sys/socket.h>
    #include <linux/if.h>
    #include <linux/if_tun.h>
    #include <arpa/inet.h>
    #include <net/route.h>
    #include <unistd.h>
#elif defined(__APPLE__)
    #include <fcntl.h>
    #include <sys/ioctl.h>
    #include <sys/socket.h>
    #include <sys/kern_control.h>
    #include <sys/sys_domain.h>
    #include <net/if.h>
    #include <net/if_utun.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <unistd.h>
#endif

namespace astrolune::vpn {

namespace {

// IPv4 header parsing utilities
[[nodiscard]] bool is_ipv4_packet(const uint8_t* data, size_t length) noexcept {
    if (length < 20) return false;
    const uint8_t version = (data[0] >> 4) & 0x0F;
    return version == 4;
}

[[nodiscard]] bool is_ipv6_packet(const uint8_t* data, size_t length) noexcept {
    if (length < 40) return false;
    const uint8_t version = (data[0] >> 4) & 0x0F;
    return version == 6;
}

[[nodiscard]] Packet::Protocol detect_protocol(const uint8_t* data, size_t length) noexcept {
    if (!is_ipv4_packet(data, length)) {
        return is_ipv6_packet(data, length) ? Packet::Protocol::IPv6
                                            : Packet::Protocol::Unknown;
    }
    const uint8_t proto = data[9];
    switch (proto) {
        case 1:  return Packet::Protocol::ICMP;
        case 6:  return Packet::Protocol::TCP;
        case 17: return Packet::Protocol::UDP;
        default: return Packet::Protocol::IPv4;
    }
}

[[nodiscard]] std::string extract_dns_domain(const uint8_t* udp_payload, size_t length) {
    if (length < 12) return {}; // DNS header minimum

    std::string domain;
    size_t offset = 12; // Skip DNS header

    while (offset < length) {
        const uint8_t label_len = udp_payload[offset++];
        if (label_len == 0) break;
        if (offset + label_len > length) return {};

        if (!domain.empty()) domain += '.';
        domain.append(reinterpret_cast<const char*>(&udp_payload[offset]), label_len);
        offset += label_len;
    }

    return domain;
}

} // anonymous namespace

// ============================================================================
// Platform-specific implementation
// ============================================================================

struct TunInterface::Impl {
    TunConfig config;
    bool open{false};
    std::mutex read_mutex;
    std::mutex write_mutex;
    std::function<void(DnsQuery&)> dns_callback;
    bool dns_interception_enabled{false};

#if defined(_WIN32)
    HANDLE tun_handle{INVALID_HANDLE_VALUE};
    std::wstring device_path;
#elif defined(__linux__)
    int tun_fd{-1};
    char ifname[IFNAMSIZ]{};
#elif defined(__APPLE__)
    int utun_fd{-1};
    int utun_unit{-1};
#endif

    std::vector<Route> active_routes;
    KillSwitchConfig kill_switch_config;

    ~Impl() {
        if (open) {
            close_interface();
        }
    }

    [[nodiscard]] TunResult<void> open_interface(const TunConfig& cfg) {
        if (open) {
            return std::unexpected(TunError::AlreadyOpen);
        }

        config = cfg;

#if defined(_WIN32)
        return open_windows();
#elif defined(__linux__)
        return open_linux();
#elif defined(__APPLE__)
        return open_macos();
#else
        return std::unexpected(TunError::PlatformError);
#endif
    }

    void close_interface() noexcept {
#if defined(_WIN32)
        if (tun_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(tun_handle);
            tun_handle = INVALID_HANDLE_VALUE;
        }
#elif defined(__linux__)
        if (tun_fd >= 0) {
            close(tun_fd);
            tun_fd = -1;
        }
#elif defined(__APPLE__)
        if (utun_fd >= 0) {
            close(utun_fd);
            utun_fd = -1;
        }
#endif
        active_routes.clear();
        open = false;
    }

    [[nodiscard]] TunResult<Packet> read_packet_impl() {
        if (!open) return std::unexpected(TunError::NotOpen);

        std::lock_guard lock(read_mutex);
        Packet packet;
        packet.data.resize(config.mtu + 64); // Extra space for headers

#if defined(_WIN32)
        DWORD bytes_read{0};
        if (!ReadFile(tun_handle, packet.data.data(),
                      static_cast<DWORD>(packet.data.size()),
                      &bytes_read, nullptr)) {
            return std::unexpected(TunError::ReadFailed);
        }
        packet.length = bytes_read;
#elif defined(__linux__)
        const ssize_t bytes_read = read(tun_fd, packet.data.data(), packet.data.size());
        if (bytes_read < 0) {
            return std::unexpected(TunError::ReadFailed);
        }
        packet.length = static_cast<size_t>(bytes_read);
#elif defined(__APPLE__)
        // utun prepends a 4-byte address family header
        uint32_t af_header{0};
        const ssize_t total_read = read(utun_fd, &af_header, sizeof(af_header));
        if (total_read < 0) {
            return std::unexpected(TunError::ReadFailed);
        }

        const ssize_t payload_read = read(utun_fd, packet.data.data(), packet.data.size());
        if (payload_read < 0) {
            return std::unexpected(TunError::ReadFailed);
        }
        packet.length = static_cast<size_t>(payload_read);
#endif

        if (packet.length == 0) {
            return std::unexpected(TunError::ReadFailed);
        }

        packet.protocol = detect_protocol(packet.data.data(), packet.length);

        // DNS interception
        if (dns_interception_enabled && packet.protocol == Packet::Protocol::UDP) {
            try_intercept_dns(packet);
        }

        // Kill switch check
        if (kill_switch_config.enabled && !is_traffic_allowed(packet)) {
            return std::unexpected(TunError::KillSwitchFailed);
        }

        return packet;
    }

    [[nodiscard]] TunResult<void> write_packet_impl(const Packet& packet) {
        if (!open) return std::unexpected(TunError::NotOpen);
        if (!packet.is_valid()) return std::unexpected(TunError::InvalidConfig);

        std::lock_guard lock(write_mutex);

#if defined(_WIN32)
        DWORD bytes_written{0};
        if (!WriteFile(tun_handle, packet.data.data(),
                       static_cast<DWORD>(packet.length),
                       &bytes_written, nullptr)) {
            return std::unexpected(TunError::WriteFailed);
        }
#elif defined(__linux__)
        const ssize_t bytes_written = write(tun_fd, packet.data.data(), packet.length);
        if (bytes_written < 0) {
            return std::unexpected(TunError::WriteFailed);
        }
#elif defined(__APPLE__)
        // utun expects a 4-byte address family header
        uint32_t af_header = (packet.version() == 6) ? AF_INET6 : AF_INET;
        af_header = htonl(af_header); // Network byte order

        if (write(utun_fd, &af_header, sizeof(af_header)) < 0) {
            return std::unexpected(TunError::WriteFailed);
        }

        const ssize_t bytes_written = write(utun_fd, packet.data.data(), packet.length);
        if (bytes_written < 0) {
            return std::unexpected(TunError::WriteFailed);
        }
#endif

        return {};
    }

private:
#if defined(_WIN32)
    [[nodiscard]] TunResult<void> open_windows() {
        tun_handle = CreateFileW(
            L"\\\\.\\Global\\" L"astrolune_tun",
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
            nullptr);

        if (tun_handle == INVALID_HANDLE_VALUE) {
            // Fallback: try loading WinTun driver dynamically
            const auto wintun_module = LoadLibraryW(L"wintun.dll");
            if (!wintun_module) {
                return std::unexpected(TunError::DeviceNotFound);
            }

            using WintunCreateAdapter = HANDLE(WINAPI*)(const wchar_t*, const wchar_t*, BOOL*);
            const auto create_adapter = reinterpret_cast<WintunCreateAdapter>(
                GetProcAddress(wintun_module, "WintunCreateAdapter"));

            if (!create_adapter) {
                FreeLibrary(wintun_module);
                return std::unexpected(TunError::PlatformError);
            }

            const std::wstring name(config.interface_name.begin(),
                                    config.interface_name.end());
            tun_handle = create_adapter(name.c_str(), L"Astrolune TUN", FALSE);

            if (tun_handle == INVALID_HANDLE_VALUE) {
                FreeLibrary(wintun_module);
                return std::unexpected(TunError::DeviceNotFound);
            }
        }

        // Configure interface IP
        if (!config.ipv4_address.empty()) {
            if (!set_windows_ip_address(config.ipv4_address, config.ipv4_netmask)) {
                close_interface();
                return std::unexpected(TunError::PlatformError);
            }
        }

        open = true;
        return {};
    }

    [[nodiscard]] bool set_windows_ip_address(const std::string& ip, const std::string& mask) {
        // Use netsh to configure the interface
        std::string cmd = "netsh interface ip set address name=\"" +
                          config.interface_name + "\" source=static addr=" +
                          ip + " mask=" + mask;
        return system(cmd.c_str()) == 0;
    }
#elif defined(__linux__)
    [[nodiscard]] TunResult<void> open_linux() {
        tun_fd = open("/dev/net/tun", O_RDWR);
        if (tun_fd < 0) {
            return std::unexpected(TunError::DeviceNotFound);
        }

        struct ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN mode, no packet info

        const std::string name = config.interface_name.substr(0, IFNAMSIZ - 1);
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);

        if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
            close(tun_fd);
            tun_fd = -1;
            return std::unexpected(TunError::PlatformError);
        }

        std::strncpy(ifname, ifr.ifr_name, IFNAMSIZ);

        // Set MTU
        if (!set_linux_mtu()) {
            close_interface();
            return std::unexpected(TunError::PlatformError);
        }

        // Configure IP
        if (!config.ipv4_address.empty()) {
            if (!set_linux_ip_address()) {
                close_interface();
                return std::unexpected(TunError::PlatformError);
            }
        }

        // Bring interface up
        if (!bring_interface_up()) {
            close_interface();
            return std::unexpected(TunError::PlatformError);
        }

        open = true;
        return {};
    }

    [[nodiscard]] bool set_linux_mtu() {
        const int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;

        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
        ifr.ifr_mtu = static_cast<int>(config.mtu);

        const bool success = (ioctl(sock, SIOCSIFMTU, &ifr) == 0);
        close(sock);
        return success;
    }

    [[nodiscard]] bool set_linux_ip_address() {
        const int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;

        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

        struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
        addr->sin_family = AF_INET;
        inet_pton(AF_INET, config.ipv4_address.c_str(), &addr->sin_addr);

        bool success = (ioctl(sock, SIOCSIFADDR, &ifr) == 0);

        if (success) {
            addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_dstaddr);
            inet_pton(AF_INET, config.ipv4_netmask.c_str(), &addr->sin_addr);
            success = (ioctl(sock, SIOCSIFNETMASK, &ifr) == 0);
        }

        close(sock);
        return success;
    }

    [[nodiscard]] bool bring_interface_up() {
        const int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;

        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            close(sock);
            return false;
        }

        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        const bool success = (ioctl(sock, SIOCSIFFLAGS, &ifr) == 0);
        close(sock);
        return success;
    }
#elif defined(__APPLE__)
    [[nodiscard]] TunResult<void> open_macos() {
        utun_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (utun_fd < 0) {
            return std::unexpected(TunError::DeviceNotFound);
        }

        struct ctl_info ctl_info{};
        std::strncpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(ctl_info.ctl_name) - 1);

        if (ioctl(utun_fd, CTLIOCGINFO, &ctl_info) < 0) {
            close(utun_fd);
            utun_fd = -1;
            return std::unexpected(TunError::PlatformError);
        }

        struct sockaddr_sc addr{};
        addr.sc_len = sizeof(addr);
        addr.sc_family = AF_SYSTEM;
        addr.ss_sysaddr = AF_SYS_CONTROL;
        addr.sc_id = ctl_info.ctl_id;
        addr.sc_unit = 0; // Let system assign unit number

        if (connect(utun_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(utun_fd);
            utun_fd = -1;
            return std::unexpected(TunError::PlatformError);
        }

        // Get assigned utun unit
        int unit = 0;
        socklen_t unit_len = sizeof(unit);
        if (getsockopt(utun_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &unit, &unit_len) < 0) {
            close_interface();
            return std::unexpected(TunError::PlatformError);
        }
        utun_unit = unit;

        // Configure IP
        if (!config.ipv4_address.empty()) {
            if (!set_macos_ip_address()) {
                close_interface();
                return std::unexpected(TunError::PlatformError);
            }
        }

        open = true;
        return {};
    }

    [[nodiscard]] bool set_macos_ip_address() {
        std::string ifname = "utun" + std::to_string(utun_unit);

        // Configure IPv4 address
        std::string cmd = "ifconfig " + ifname + " " + config.ipv4_address +
                          " " + config.ipv4_address + " netmask " +
                          config.ipv4_netmask;
        if (system(cmd.c_str()) != 0) return false;

        // Bring interface up
        cmd = "ifconfig " + ifname + " up";
        return system(cmd.c_str()) == 0;
    }
#endif

    void try_intercept_dns(const Packet& packet) {
        if (!dns_callback) return;

        // Extract UDP payload for DNS analysis
        size_t ip_header_len = 0;
        if (packet.protocol == Packet::Protocol::IPv4) {
            ip_header_len = (packet.data[0] & 0x0F) * 4;
        } else if (packet.protocol == Packet::Protocol::IPv6) {
            ip_header_len = 40; // IPv6 base header
        }

        if (ip_header_len + 8 >= packet.length) return; // No UDP header

        const uint8_t* udp_header = packet.data.data() + ip_header_len;
        const uint16_t src_port = (udp_header[0] << 8) | udp_header[1];
        const uint16_t dst_port = (udp_header[2] << 8) | udp_header[3];

        // DNS is typically on port 53
        if (dst_port != 53 && src_port != 53) return;

        const uint8_t* udp_payload = udp_header + 8;
        const size_t payload_len = packet.length - ip_header_len - 8;

        DnsQuery query;
        query.raw_query.assign(udp_payload, udp_payload + payload_len);
        query.domain = extract_dns_domain(udp_payload, payload_len);

        // Parse transaction ID from DNS header
        if (payload_len >= 2) {
            query.transaction_id = (udp_payload[0] << 8) | udp_payload[1];
        }

        dns_callback(query);
        query.intercepted = true;
    }
};

// ============================================================================
// TunInterface public API implementation
// ============================================================================

TunInterface::TunInterface() : impl_(std::make_unique<Impl>()) {}
TunInterface::~TunInterface() = default;

TunInterface::TunInterface(TunInterface&&) noexcept = default;
TunInterface& TunInterface::operator=(TunInterface&&) noexcept = default;

TunResult<void> TunInterface::open(const TunConfig& config) {
    return impl_->open_interface(config);
}

void TunInterface::close() noexcept {
    impl_->close_interface();
}

bool TunInterface::is_open() const noexcept {
    return impl_->open;
}

TunResult<Packet> TunInterface::read_packet() {
    return impl_->read_packet_impl();
}

TunResult<void> TunInterface::write_packet(const Packet& packet) {
    return impl_->write_packet_impl(packet);
}

TunResult<void> TunInterface::add_route(const Route& route) {
    if (!impl_->open) return std::unexpected(TunError::NotOpen);

#if defined(_WIN32)
    MIB_IPFORWARDROW row{};
    row.dwForwardIfIndex = 1; // Interface index would need to be looked up
    row.dwForwardMetric1 = route.metric;

    // Parse destination
    IPADDR prefix;
    inet_pton(AF_INET, route.destination.c_str(), &prefix);
    row.dwForwardDest = ntohl(prefix);
    row.dwForwardMask = 0xFFFFFFFF; // Would need proper CIDR calculation

    if (route.gateway.empty()) {
        row.dwForwardType = 3; // MIB_IPPROTO_NETMGMT
    } else {
        inet_pton(AF_INET, route.gateway.c_str(), &prefix);
        row.dwForwardNextHop = ntohl(prefix);
        row.dwForwardType = 4; // MIB_IPPROTO_BOOTP
    }

    const DWORD result = CreateIpForwardEntry(&row);
    if (result != NO_ERROR) {
        return std::unexpected(TunError::RouteFailed);
    }
#elif defined(__linux__)
    const int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return std::unexpected(TunError::RouteFailed);

    struct rtentry rt{};
    rt.rt_flags = RTF_UP | RTF_GATEWAY;

    // Parse gateway
    struct sockaddr_in* gate = reinterpret_cast<struct sockaddr_in*>(&rt.rt_gateway);
    gate->sin_family = AF_INET;
    inet_pton(AF_INET, route.gateway.c_str(), &gate->sin_addr);

    // Parse destination
    struct sockaddr_in* dst = reinterpret_cast<struct sockaddr_in*>(&rt.rt_dst);
    dst->sin_family = AF_INET;
    inet_pton(AF_INET, route.destination.c_str(), &dst->sin_addr);

    // Parse mask (simplified - would need proper CIDR parsing)
    struct sockaddr_in* genmask = reinterpret_cast<struct sockaddr_in*>(&rt.rt_genmask);
    genmask->sin_family = AF_INET;
    genmask->sin_addr.s_addr = htonl(0xFFFFFFFF);

    rt.rt_metric = static_cast<int>(route.metric);

    const bool success = (ioctl(sock, SIOCADDRT, &rt) == 0);
    close(sock);

    if (!success) {
        return std::unexpected(TunError::RouteFailed);
    }
#elif defined(__APPLE__)
    // macOS uses route command
    std::string cmd = "route add -net " + route.destination;
    if (!route.gateway.empty()) {
        cmd += " " + route.gateway;
    }
    cmd += " -interface " + impl_->config.interface_name;

    if (route.metric > 0) {
        cmd += " -metric " + std::to_string(route.metric);
    }

    if (system(cmd.c_str()) != 0) {
        return std::unexpected(TunError::RouteFailed);
    }
#endif

    impl_->active_routes.push_back(route);
    return {};
}

TunResult<void> TunInterface::remove_route(const Route& route) {
    if (!impl_->open) return std::unexpected(TunError::NotOpen);

#if defined(_WIN32)
    // Would need to find and delete specific route
    MIB_IPFORWARDROW row{};
    const DWORD result = DeleteIpForwardEntry(&row);
    if (result != NO_ERROR) {
        return std::unexpected(TunError::RouteFailed);
    }
#elif defined(__linux__)
    const int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return std::unexpected(TunError::RouteFailed);

    struct rtentry rt{};
    rt.rt_flags = RTF_UP | RTF_GATEWAY;

    struct sockaddr_in* gate = reinterpret_cast<struct sockaddr_in*>(&rt.rt_gateway);
    gate->sin_family = AF_INET;
    inet_pton(AF_INET, route.gateway.c_str(), &gate->sin_addr);

    struct sockaddr_in* dst = reinterpret_cast<struct sockaddr_in*>(&rt.rt_dst);
    dst->sin_family = AF_INET;
    inet_pton(AF_INET, route.destination.c_str(), &dst->sin_addr);

    const bool success = (ioctl(sock, SIOCDELRT, &rt) == 0);
    close(sock);

    if (!success) {
        return std::unexpected(TunError::RouteFailed);
    }
#elif defined(__APPLE__)
    std::string cmd = "route delete -net " + route.destination;
    if (!route.gateway.empty()) {
        cmd += " " + route.gateway;
    }
    cmd += " -interface " + impl_->config.interface_name;

    if (system(cmd.c_str()) != 0) {
        return std::unexpected(TunError::RouteFailed);
    }
#endif

    // Remove from active routes
    auto& routes = impl_->active_routes;
    routes.erase(
        std::remove_if(routes.begin(), routes.end(),
                       [&route](const Route& r) {
                           return r.destination == route.destination &&
                                  r.gateway == route.gateway;
                       }),
        routes.end());

    return {};
}

TunResult<void> TunInterface::enable_dns_interception(bool enable) {
    impl_->dns_interception_enabled = enable;
    return {};
}

void TunInterface::set_dns_callback(std::function<void(DnsQuery&)> callback) {
    impl_->dns_callback = std::move(callback);
}

TunResult<void> TunInterface::set_kill_switch(bool enable) {
    impl_->kill_switch_config.enabled = enable;
    return {};
}

TunResult<void> TunInterface::update_kill_switch_config(const KillSwitchConfig& config) {
    impl_->kill_switch_config = config;
    return {};
}

bool TunInterface::is_traffic_allowed(const Packet& packet) const noexcept {
    if (!impl_->kill_switch_config.enabled) return true;

    // Check allowed networks (bypass kill switch for local traffic)
    if (packet.version() == 4 && packet.length >= 20) {
        const uint8_t* dst_ip = packet.data.data() + 16;
        uint32_t dst_addr;
        std::memcpy(&dst_addr, dst_ip, 4);
        dst_addr = ntohl(dst_addr);

        // Allow loopback (127.0.0.0/8)
        if ((dst_addr >> 24) == 127) return true;

        // Allow link-local (169.254.0.0/16)
        if ((dst_addr >> 16) == 0xA9FE) return true;

        // Allow private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        if ((dst_addr >> 24) == 10) return true;
        if ((dst_addr >> 20) == 0xAC1) return true; // 172.16.0.0/12
        if ((dst_addr >> 16) == 0xC0A8) return true; // 192.168.0.0/16
    }

    // Check allowed IPs (would need to implement proper CIDR matching)
    // Check allowed apps (platform-specific process inspection)

    return false; // Default: block traffic when kill switch is active
}

const TunConfig& TunInterface::config() const noexcept {
    return impl_->config;
}

int TunInterface::native_handle() const noexcept {
#if defined(_WIN32)
    return reinterpret_cast<intptr_t>(impl_->tun_handle);
#elif defined(__linux__)
    return impl_->tun_fd;
#elif defined(__APPLE__)
    return impl_->utun_fd;
#else
    return -1;
#endif
}

} // namespace astrolune::vpn
