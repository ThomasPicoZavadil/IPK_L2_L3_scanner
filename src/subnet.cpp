/**
 * @file subnet.cpp
 * @brief Implementation of the Subnet class – CIDR parsing & host generation.
 */
#include "subnet.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include <arpa/inet.h>

// IPv4 helpers (file-local)

/// Build a host-order bitmask for the given prefix length (0-32).
static uint32_t ipv4_make_mask(int prefix) {
    return prefix == 0 ? 0u : (~0u << (32 - prefix));
}

/// Convert a host-order uint32_t to dotted-decimal string.
static std::string ipv4_to_str(uint32_t host_order) {
    struct in_addr ia{};
    ia.s_addr = htonl(host_order);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ia, buf, sizeof(buf));
    return buf;
}

/// Parse a dotted-decimal string to a host-order uint32_t.
static uint32_t ipv4_from_str(const std::string& s) {
    struct in_addr ia{};
    if (inet_pton(AF_INET, s.c_str(), &ia) != 1)
        throw std::invalid_argument("Invalid IPv4 address: " + s);
    return ntohl(ia.s_addr);
}

// IPv6 helpers (file-local)

using IPv6Addr = std::array<uint8_t, 16>;

static IPv6Addr ipv6_from_str(const std::string& s) {
    struct in6_addr ia{};
    if (inet_pton(AF_INET6, s.c_str(), &ia) != 1)
        throw std::invalid_argument("Invalid IPv6 address: " + s);
    IPv6Addr a;
    std::memcpy(a.data(), ia.s6_addr, 16);
    return a;
}

static std::string ipv6_to_str(const IPv6Addr& a) {
    struct in6_addr ia{};
    std::memcpy(ia.s6_addr, a.data(), 16);
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ia, buf, sizeof(buf));
    return buf;
}

/// Zero out the host bits, returning the network address.
static IPv6Addr ipv6_network(const IPv6Addr& addr, int prefix) {
    IPv6Addr net = addr;
    for (int i = 0; i < 16; ++i) {
        int bits = std::clamp(prefix - i * 8, 0, 8);
        auto mask = static_cast<uint8_t>(bits == 8 ? 0xFF : ~((1 << (8 - bits)) - 1));
        net[i] &= mask;
    }
    return net;
}

/// Set all host bits to 1, returning the last address in the subnet.
static IPv6Addr ipv6_last(const IPv6Addr& network, int prefix) {
    IPv6Addr last = network;
    for (int i = 0; i < 16; ++i) {
        int bits = std::clamp(prefix - i * 8, 0, 8);
        auto host_mask = static_cast<uint8_t>(bits == 8 ? 0x00 : (1 << (8 - bits)) - 1);
        last[i] |= host_mask;
    }
    return last;
}

/// Increment a 128-bit address by one (big-endian, in-place).
static void ipv6_increment(IPv6Addr& a) {
    for (int i = 15; i >= 0; --i) {
        if (++a[i] != 0) return;
    }
}

// Subnet class implementation

Subnet::Subnet(const std::string& cidr) : cidr_(cidr) {
    // Split "address/prefix"
    auto slash = cidr.find('/');
    if (slash == std::string::npos)
        throw std::invalid_argument("Missing '/' in CIDR notation: " + cidr);

    std::string addr_str   = cidr.substr(0, slash);
    std::string prefix_str = cidr.substr(slash + 1);

    // Parse prefix length
    char* end = nullptr;
    long prefix = std::strtol(prefix_str.c_str(), &end, 10);
    if (end == prefix_str.c_str() || *end != '\0' || prefix < 0)
        throw std::invalid_argument("Invalid prefix length in: " + cidr);

    prefix_len_ = static_cast<int>(prefix);
    is_ipv6_    = (addr_str.find(':') != std::string::npos);

    if (is_ipv6_) {
        parse_ipv6(addr_str);
    } else {
        parse_ipv4(addr_str);
    }
}

void Subnet::parse_ipv4(const std::string& addr_str) {
    if (prefix_len_ > 32)
        throw std::invalid_argument("IPv4 prefix must be 0-32: " + cidr_);

    uint32_t raw  = ipv4_from_str(addr_str);
    uint32_t mask = ipv4_make_mask(prefix_len_);
    uint32_t net  = raw & mask;
    network_addr_ = ipv4_to_str(net);

    int host_bits = 32 - prefix_len_;
    if (host_bits == 0) {
        usable_host_count_ = 1;                         // /32 – single host
    } else if (host_bits == 1) {
        usable_host_count_ = 2;                         // /31 – point-to-point (RFC 3021)
    } else {
        usable_host_count_ = (1ULL << host_bits) - 2;   // exclude network + broadcast
    }
}

void Subnet::parse_ipv6(const std::string& addr_str) {
    if (prefix_len_ > 128)
        throw std::invalid_argument("IPv6 prefix must be 0-128: " + cidr_);

    IPv6Addr raw = ipv6_from_str(addr_str);
    IPv6Addr net = ipv6_network(raw, prefix_len_);
    network_addr_ = ipv6_to_str(net);

    int host_bits = 128 - prefix_len_;
    if (host_bits == 0) {
        usable_host_count_ = 1;                         // /128 – single host
    } else if (host_bits == 1) {
        usable_host_count_ = 2;                         // /127 – point-to-point (RFC 6164)
    } else if (host_bits > 63) {
        usable_host_count_ = UINT64_MAX;                // capped
    } else {
        usable_host_count_ = (1ULL << host_bits) - 1;   // exclude subnet-router anycast
    }
}

std::vector<std::string> Subnet::generate_host_ips() const {
    std::vector<std::string> hosts;

    if (is_ipv6_) {
        // IPv6 generation
        IPv6Addr net  = ipv6_from_str(network_addr_);
        IPv6Addr last = ipv6_last(net, prefix_len_);
        int host_bits = 128 - prefix_len_;

        if (host_bits == 0) {
            // /128 – single address
            hosts.push_back(ipv6_to_str(net));
        } else if (host_bits == 1) {
            // /127 – both addresses usable (RFC 6164)
            hosts.push_back(ipv6_to_str(net));
            IPv6Addr second = net;
            ipv6_increment(second);
            hosts.push_back(ipv6_to_str(second));
        } else {
            // Skip subnet-router anycast (= network address), start at net+1
            IPv6Addr cur = net;
            ipv6_increment(cur);
            while (cur <= last) {
                hosts.push_back(ipv6_to_str(cur));
                if (cur == last) break;
                ipv6_increment(cur);
            }
        }
    } else {
        // IPv4 generation
        uint32_t net = ipv4_from_str(network_addr_);
        int host_bits = 32 - prefix_len_;

        if (host_bits == 0) {
            // /32 – single host
            hosts.push_back(ipv4_to_str(net));
        } else if (host_bits == 1) {
            // /31 – point-to-point, both usable (RFC 3021)
            hosts.push_back(ipv4_to_str(net));
            hosts.push_back(ipv4_to_str(net + 1));
        } else {
            // Exclude network (first) and broadcast (last)
            uint32_t broadcast = net | ~ipv4_make_mask(prefix_len_);
            for (uint32_t ip = net + 1; ip < broadcast; ++ip) {
                hosts.push_back(ipv4_to_str(ip));
            }
        }
    }

    return hosts;
}
