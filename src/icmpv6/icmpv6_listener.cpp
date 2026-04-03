/**
 * @file icmpv6_listener.cpp
 * @brief Icmpv6Listener::parse_packet() - extracts Source IPv6 from
 *        ICMPv6 Echo Reply (Type 129) frames.
 */
#include "icmpv6_listener.hpp"

#include <cstring>
#include <iostream>

#include <arpa/inet.h>      // inet_ntop, ntohs
#include <net/ethernet.h>   // struct ether_header

// EtherType for IPv6
static constexpr uint16_t ETHER_TYPE_IPV6 = 0x86DDu;

// IPv6 Next Header value for ICMPv6
static constexpr uint8_t NEXT_HEADER_ICMPV6 = 58;

// ICMPv6 Echo Reply type
static constexpr uint8_t ICMPV6_TYPE_ECHO_REPLY = 129;

// Header sizes
static constexpr size_t ETH_HDR_LEN  = 14;
static constexpr size_t IPV6_HDR_LEN = 40;
static constexpr size_t ICMPV6_HDR_MIN = 4; // type(1) + code(1) + checksum(2)

// Minimum frame: Ethernet + IPv6 + ICMPv6 minimum
static constexpr size_t MIN_FRAME = ETH_HDR_LEN + IPV6_HDR_LEN + ICMPV6_HDR_MIN;

bool Icmpv6Listener::parse_packet(const uint8_t* buffer, uint32_t length)
{
    // 1. Check Ethernet header for IPv6 EtherType (0x86DD)
    if (length < MIN_FRAME) {
        return false;
    }

    auto* eth = reinterpret_cast<const struct ether_header*>(buffer);
    if (ntohs(eth->ether_type) != ETHER_TYPE_IPV6) {
        return false;
    }

    // 2. IPv6 header - verify Next Header is ICMPv6 (58)
    const uint8_t* ipv6 = buffer + ETH_HDR_LEN;
    uint8_t next_header = ipv6[6];
    if (next_header != NEXT_HEADER_ICMPV6) {
        return false;
    }

    // 3. ICMPv6 header - check type is 129 (Echo Reply)
    const uint8_t* icmpv6 = buffer + ETH_HDR_LEN + IPV6_HDR_LEN;
    if (icmpv6[0] != ICMPV6_TYPE_ECHO_REPLY) {
        return false;
    }

    // 4. Extract Source IPv6 address from IPv6 header (offset 8, 16 bytes)
    const uint8_t* src_addr = ipv6 + 8;
    char ipv6_str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, src_addr, ipv6_str, sizeof(ipv6_str)) == nullptr) {
        return false;
    }

    manager_.update_l3(ipv6_str);

    return true;
}
