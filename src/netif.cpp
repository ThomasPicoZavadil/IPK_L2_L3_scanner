/**
 * @file netif.cpp
 * @brief Implementation of get_interface_info() – retrieves MAC, IPv4, IPv6
 *        for the given network interface using Linux APIs.
 */
#include "netif.hpp"

#include <cerrno>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

// Linux / POSIX headers
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

// Linux-specific header for ARPHRD_ETHER / sockaddr_ll
#include <linux/if_packet.h>
#include <net/ethernet.h>

// Helpers

namespace {

/**
 * @brief Format a 6-byte MAC address as "xx:xx:xx:xx:xx:xx".
 */
std::string format_mac(const unsigned char* bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i) oss << ':';
        oss << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }
    return oss.str();
}

/**
 * @brief Return true if the sockaddr_in6 is a link-local address (fe80::/10).
 */
bool is_link_local_v6(const struct sockaddr_in6* sa6) {
    return sa6->sin6_addr.s6_addr[0] == 0xfe &&
           (sa6->sin6_addr.s6_addr[1] & 0xc0) == 0x80;
}

} // anonymous namespace

// Public API

InterfaceInfo get_interface_info(const std::string& iface_name) {
    InterfaceInfo info;
    info.name = iface_name;

    // 1.  MAC address via ioctl(SIOCGIFHWADDR)
    {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            throw std::runtime_error(
                "socket() failed: " + std::string(std::strerror(errno)));
        }

        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);

        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            int saved = errno;
            close(sock);
            if (saved == ENODEV) {
                throw std::runtime_error(
                    "Interface '" + iface_name + "' does not exist");
            }
            throw std::runtime_error(
                "ioctl(SIOCGIFHWADDR) failed for '" + iface_name +
                "': " + std::strerror(saved));
        }
        close(sock);

        info.mac_address = format_mac(
            reinterpret_cast<const unsigned char*>(ifr.ifr_hwaddr.sa_data));
    }

    // 2.  IPv4 and IPv6 addresses via getifaddrs()
    {
        struct ifaddrs* ifaddr = nullptr;
        if (getifaddrs(&ifaddr) == -1) {
            throw std::runtime_error(
                "getifaddrs() failed: " + std::string(std::strerror(errno)));
        }

        // RAII guard so we always call freeifaddrs()
        struct IfAddrGuard {
            struct ifaddrs* p;
            ~IfAddrGuard() { if (p) freeifaddrs(p); }
        } guard{ifaddr};

        bool found_global_v6 = false;

        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            if (iface_name != ifa->ifa_name) continue;

            int family = ifa->ifa_addr->sa_family;

            if (family == AF_INET && info.ipv4_address.empty()) {
                char buf[INET_ADDRSTRLEN]{};
                auto* sa4 = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
                inet_ntop(AF_INET, &sa4->sin_addr, buf, sizeof(buf));
                info.ipv4_address = buf;
            }

            if (family == AF_INET6) {
                auto* sa6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
                char buf[INET6_ADDRSTRLEN]{};
                inet_ntop(AF_INET6, &sa6->sin6_addr, buf, sizeof(buf));

                if (!is_link_local_v6(sa6)) {
                    // Prefer global / unique-local over link-local
                    info.ipv6_address = buf;
                    found_global_v6 = true;
                } else if (!found_global_v6 && info.ipv6_address.empty()) {
                    // Fall back to link-local if nothing better is available
                    info.ipv6_address = buf;
                }
            }
        }
    }

    return info;
}
