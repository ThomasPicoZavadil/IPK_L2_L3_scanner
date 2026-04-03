/**
 * @file icmpv6_crafter.cpp
 * @brief Icmpv6Crafter::send_request() - builds and sends an ICMPv6
 *        Echo Request (Type 128) frame.
 *
 * Frame layout (78 bytes total):
 *   [Ethernet 14] [IPv6 40] [ICMPv6 Echo 8] [Payload 16]
 */
#include "icmpv6_crafter.hpp"

#include <cstring>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>        // inet_pton, htons, htonl
#include <linux/if_packet.h>  // sockaddr_ll
#include <net/ethernet.h>     // ETH_ALEN
#include <netinet/in.h>       // in6_addr
#include <sys/socket.h>       // sendto

// Constants

/// EtherType for IPv6
static constexpr uint16_t ETHER_TYPE_IPV6 = 0x86DDu;

/// ICMPv6 Echo Request type
static constexpr uint8_t ICMPV6_TYPE_ECHO_REQUEST = 128;

// Frame component sizes
static constexpr size_t ETH_HDR_LEN      = 14;
static constexpr size_t IPV6_HDR_LEN     = 40;
static constexpr size_t ICMPV6_HDR_LEN   = 8;   // type(1)+code(1)+cksum(2)+id(2)+seq(2)
static constexpr size_t ICMPV6_DATA_LEN  = 16;  // payload bytes
static constexpr size_t ICMPV6_TOTAL_LEN = ICMPV6_HDR_LEN + ICMPV6_DATA_LEN; // 24
static constexpr size_t FRAME_LEN        = ETH_HDR_LEN + IPV6_HDR_LEN + ICMPV6_TOTAL_LEN; // 78

// Checksum helpers

uint16_t Icmpv6Crafter::calculate_checksum(const uint16_t* data, size_t length)
{
    uint32_t sum = 0;
    const uint16_t* ptr = data;

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }
    if (length == 1) {
        sum += *reinterpret_cast<const uint8_t*>(ptr);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

uint16_t Icmpv6Crafter::compute_icmpv6_checksum(const uint8_t* src_addr,
                                                const uint8_t* dst_addr,
                                                const uint8_t* icmpv6_buf,
                                                uint32_t       icmpv6_len)
{
    // Pseudo-header: src(16) + dst(16) + upper-layer-length(4) + zeros(3) + next-header(1)
    static constexpr size_t PSEUDO_LEN = 40;
    size_t total_len = PSEUDO_LEN + icmpv6_len;
    size_t padded = total_len + (total_len & 1);

    uint8_t buf[PSEUDO_LEN + ICMPV6_TOTAL_LEN + 1]; // +1 for potential pad byte
    std::memset(buf, 0, sizeof(buf));

    size_t off = 0;

    // Source address (16 bytes)
    std::memcpy(buf + off, src_addr, 16);
    off += 16;

    // Destination address (16 bytes)
    std::memcpy(buf + off, dst_addr, 16);
    off += 16;

    // Upper-layer packet length (4 bytes, network order)
    uint32_t ul_len = htonl(icmpv6_len);
    std::memcpy(buf + off, &ul_len, 4);
    off += 4;

    // 3 zero bytes + next header (58 = ICMPv6)
    buf[off]     = 0;
    buf[off + 1] = 0;
    buf[off + 2] = 0;
    buf[off + 3] = 58; // IPPROTO_ICMPV6
    off += 4;

    // ICMPv6 body
    std::memcpy(buf + off, icmpv6_buf, icmpv6_len);

    return calculate_checksum(reinterpret_cast<const uint16_t*>(buf), padded);
}

// send_request

void Icmpv6Crafter::send_request(const std::string& target_ip)
{
    std::cerr << "[ICMPv6] Crafting Echo Request: "
              << iface_.ipv6_address << " -> " << target_ip
              << " on " << iface_.name << "\n";

    // Parse source IPv6 address
    struct in6_addr src_addr{};
    if (inet_pton(AF_INET6, iface_.ipv6_address.c_str(), &src_addr) != 1) {
        throw std::runtime_error(
            "Invalid source IPv6 address: '" + iface_.ipv6_address + "'");
    }

    // Parse target IPv6 address
    struct in6_addr target_addr{};
    if (inet_pton(AF_INET6, target_ip.c_str(), &target_addr) != 1) {
        throw std::runtime_error(
            "Invalid target IPv6 address: '" + target_ip + "'");
    }

    uint8_t dst_mac[6];
    dst_mac[0] = 0x33;
    dst_mac[1] = 0x33;
    dst_mac[2] = target_addr.s6_addr[12];
    dst_mac[3] = target_addr.s6_addr[13];
    dst_mac[4] = target_addr.s6_addr[14];
    dst_mac[5] = target_addr.s6_addr[15];

    // Build frame buffer
    uint8_t frame[FRAME_LEN];
    std::memset(frame, 0, FRAME_LEN);

    // 1. Ethernet header (14 bytes)
    uint8_t* eth = frame;
    std::memcpy(eth, dst_mac, ETH_ALEN);                           // dst: multicast MAC
    std::memcpy(eth + ETH_ALEN, local_mac_, ETH_ALEN);             // src: our MAC
    *reinterpret_cast<uint16_t*>(eth + 12) = htons(ETHER_TYPE_IPV6); // EtherType: IPv6

    // 2. IPv6 header (40 bytes)
    uint8_t* ipv6 = frame + ETH_HDR_LEN;

    // Version (4) + Traffic Class (8) + Flow Label (20) = 4 bytes
    *reinterpret_cast<uint32_t*>(ipv6) = htonl(0x60000000u);

    // Payload length (2 bytes) at offset 4
    *reinterpret_cast<uint16_t*>(ipv6 + 4) = htons(ICMPV6_TOTAL_LEN);

    // Next header (1 byte) at offset 6 = 58 (ICMPv6)
    ipv6[6] = 58;

    // Hop limit (1 byte) at offset 7
    ipv6[7] = 64;

    // Source address (16 bytes) at offset 8
    std::memcpy(ipv6 + 8, &src_addr, 16);

    // Destination address (16 bytes) at offset 24
    std::memcpy(ipv6 + 24, &target_addr, 16);

    // 3. ICMPv6 Echo Request (8 bytes header + 16 bytes data)
    uint8_t* icmpv6 = frame + ETH_HDR_LEN + IPV6_HDR_LEN;

    icmpv6[0] = ICMPV6_TYPE_ECHO_REQUEST; // Type: Echo Request (128)
    icmpv6[1] = 0;                         // Code: 0
    // Checksum at bytes 2-3 - filled later
    // Identifier at bytes 4-5
    *reinterpret_cast<uint16_t*>(icmpv6 + 4) = htons(1234);
    // Sequence number at bytes 6-7
    *reinterpret_cast<uint16_t*>(icmpv6 + 6) = htons(1);

    // 4. Payload data
    uint8_t* payload = icmpv6 + ICMPV6_HDR_LEN;
    std::memset(payload, 'A', ICMPV6_DATA_LEN);

    // 5. ICMPv6 checksum (over pseudo-header + ICMPv6 body)
    uint16_t cksum = compute_icmpv6_checksum(
        src_addr.s6_addr,
        target_addr.s6_addr,
        icmpv6,
        ICMPV6_TOTAL_LEN);
    std::memcpy(icmpv6 + 2, &cksum, 2);

    // 6. Send via raw socket
    struct sockaddr_ll dest{};
    dest.sll_family   = AF_PACKET;
    dest.sll_protocol = htons(ETHER_TYPE_IPV6);
    dest.sll_ifindex  = static_cast<int>(if_index_);
    dest.sll_halen    = ETH_ALEN;
    std::memcpy(dest.sll_addr, dst_mac, ETH_ALEN);

    ssize_t sent = sendto(sock_fd_, frame, FRAME_LEN, 0,
                          reinterpret_cast<struct sockaddr*>(&dest),
                          sizeof(dest));
    if (sent < 0) {
        throw std::runtime_error(
            "sendto() failed for ICMPv6 Echo Request to '" + target_ip +
            "': " + std::strerror(errno));
    }

    std::cerr << "[ICMPv6] Sent " << sent << "/" << FRAME_LEN
              << " bytes (echo to " << target_ip << ")\n";
}
