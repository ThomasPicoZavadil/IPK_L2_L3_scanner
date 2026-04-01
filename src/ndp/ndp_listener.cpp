/**
 * @file ndp_listener.cpp
 * @brief NdpListener::parse_packet() - extracts Target IPv6 and MAC
 *        from ICMPv6 Neighbor Advertisement (Type 136) frames.
 */
#include "ndp_listener.hpp"

#include <cstdio>
#include <cstring>
#include <iostream>

#include <arpa/inet.h>      // inet_ntop, ntohs
#include <net/ethernet.h>   // struct ether_header, ETH_ALEN

// EtherType for IPv6
static constexpr uint16_t ETHER_TYPE_IPV6 = 0x86DDu;

// IPv6 Next Header value for ICMPv6
static constexpr uint8_t NEXT_HEADER_ICMPV6 = 58;

// ICMPv6 Neighbor Advertisement type
static constexpr uint8_t ICMPV6_TYPE_NA = 136;

// NDP option type: Target Link-Layer Address
static constexpr uint8_t NDP_OPT_TGT_LLA = 2;

// Header sizes
static constexpr size_t ETH_HDR_LEN  = 14;
static constexpr size_t IPV6_HDR_LEN = 40;

// ICMPv6 NA fixed part: type(1) + code(1) + checksum(2) + flags+reserved(4) + target(16) = 24
static constexpr size_t NA_FIXED_LEN = 24;

// Minimum frame: Ethernet + IPv6 + NA fixed part
static constexpr size_t MIN_FRAME = ETH_HDR_LEN + IPV6_HDR_LEN + NA_FIXED_LEN;

bool NdpListener::parse_packet(const uint8_t* buffer, uint32_t length)
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

    // Read payload length from IPv6 header (offset 4, 2 bytes)
    uint16_t payload_len = ntohs(*reinterpret_cast<const uint16_t*>(ipv6 + 4));

    // 3. ICMPv6 header - check type is 136 (Neighbor Advertisement)
    const uint8_t* icmpv6 = buffer + ETH_HDR_LEN + IPV6_HDR_LEN;
    uint8_t icmpv6_type = icmpv6[0];
    if (icmpv6_type != ICMPV6_TYPE_NA) {
        return false;
    }

    // 4. Extract Target IPv6 Address (bytes 8-23 of the ICMPv6 body)
    const uint8_t* target_addr = icmpv6 + 8;
    char ipv6_str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, target_addr, ipv6_str, sizeof(ipv6_str)) == nullptr) {
        return false;
    }

    // 5. Iterate through ICMPv6 NDP options to find Target Link-Layer Address (Type 2)
    //    Options start right after the NA fixed part (24 bytes into ICMPv6)
    size_t opts_offset = NA_FIXED_LEN;
    size_t opts_end    = static_cast<size_t>(payload_len); // payload_len covers ICMPv6 body

    while (opts_offset + 2 <= opts_end) {
        uint8_t opt_type = icmpv6[opts_offset];
        uint8_t opt_len  = icmpv6[opts_offset + 1]; // in units of 8 bytes

        // opt_len == 0 would cause infinite loop
        if (opt_len == 0) {
            break;
        }

        size_t opt_bytes = static_cast<size_t>(opt_len) * 8;

        // Bounds check
        if (opts_offset + opt_bytes > opts_end) {
            break;
        }

        if (opt_type == NDP_OPT_TGT_LLA && opt_bytes >= 8) {
            // MAC address is at offset +2 within the option (6 bytes)
            const uint8_t* mac = icmpv6 + opts_offset + 2;
            char mac_str[18]; // "xx-xx-xx-xx-xx-xx\0"
            std::snprintf(mac_str, sizeof(mac_str),
                          "%02x-%02x-%02x-%02x-%02x-%02x",
                          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

            // 6. Update the result manager
            manager_.update_l2(ipv6_str, mac_str);
            return true;
        }

        opts_offset += opt_bytes;
    }

    // NA received but no Target Link-Layer Address option found
    return false;
}
