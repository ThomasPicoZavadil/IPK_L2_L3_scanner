/**
 * @file ndp_crafter.cpp
 * @brief NdpCrafter::send_request() - builds and sends an ICMPv6
 *        Neighbor Solicitation (Type 135) frame.
 *
 * Frame layout (86 bytes total):
 *   [Ethernet 14] [IPv6 40] [ICMPv6 NS 24] [SrcLLA option 8]
 */
#include "ndp_crafter.hpp"

#include <cstring>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>        // inet_pton, htons, htonl
#include <linux/if_packet.h>  // sockaddr_ll
#include <net/ethernet.h>     // ETH_ALEN
#include <netinet/in.h>       // in6_addr, IPPROTO_ICMPV6
#include <sys/socket.h>       // sendto

// Constants

/// EtherType for IPv6
static constexpr uint16_t ETHER_TYPE_IPV6 = 0x86DDu;

/// ICMPv6 Neighbor Solicitation type
static constexpr uint8_t ICMPV6_TYPE_NS = 135;

/// ICMPv6 NDP option: Source Link-Layer Address
static constexpr uint8_t NDP_OPT_SRC_LLA = 1;

// Frame component sizes
static constexpr size_t ETH_HDR_LEN      = 14;
static constexpr size_t IPV6_HDR_LEN     = 40;
static constexpr size_t NS_HDR_LEN       = 24;  // type(1)+code(1)+cksum(2)+reserved(4)+target(16)
static constexpr size_t SRC_LLA_OPT_LEN  = 8;   // type(1)+len(1)+mac(6)
static constexpr size_t ICMPV6_TOTAL_LEN = NS_HDR_LEN + SRC_LLA_OPT_LEN; // 32
static constexpr size_t FRAME_LEN        = ETH_HDR_LEN + IPV6_HDR_LEN + ICMPV6_TOTAL_LEN; // 86

// Checksum helpers

uint16_t NdpCrafter::calculate_checksum(const uint16_t* data, size_t length)
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

uint16_t NdpCrafter::compute_icmpv6_checksum(const uint8_t* src_addr,
                                             const uint8_t* dst_addr,
                                             const uint8_t* icmpv6_buf,
                                             uint32_t       icmpv6_len)
{
    // Build a pseudo-header + ICMPv6 buffer for checksumming.
    // Pseudo-header: src(16) + dst(16) + upper-layer-length(4) + zeros(3) + next-header(1)
    static constexpr size_t PSEUDO_LEN = 40;
    size_t total_len = PSEUDO_LEN + icmpv6_len;

    // Ensure even length for 16-bit sum
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

void NdpCrafter::send_request(const std::string& target_ip)
{

    // -- Parse source IPv6 address (interface link-local / global) --
    struct in6_addr src_addr{};
    if (inet_pton(AF_INET6, iface_.ipv6_address.c_str(), &src_addr) != 1) {
        throw std::runtime_error(
            "Invalid source IPv6 address: '" + iface_.ipv6_address + "'");
    }

    // -- Parse target IPv6 address --
    struct in6_addr target_addr{};
    if (inet_pton(AF_INET6, target_ip.c_str(), &target_addr) != 1) {
        throw std::runtime_error(
            "Invalid target IPv6 address: '" + target_ip + "'");
    }

    // -- Compute Solicited-Node multicast address --
    // ff02::1:ffXX:XXXX  (last 24 bits of target)
    struct in6_addr sol_node_addr{};
    std::memset(&sol_node_addr, 0, sizeof(sol_node_addr));
    sol_node_addr.s6_addr[0]  = 0xff;
    sol_node_addr.s6_addr[1]  = 0x02;
    // bytes 2..10 are zero
    sol_node_addr.s6_addr[11] = 0x01;
    sol_node_addr.s6_addr[12] = 0xff;
    sol_node_addr.s6_addr[13] = target_addr.s6_addr[13];
    sol_node_addr.s6_addr[14] = target_addr.s6_addr[14];
    sol_node_addr.s6_addr[15] = target_addr.s6_addr[15];

    // -- Compute multicast destination MAC --
    // 33:33:ff:XX:XX:XX  (last 32 bits of solicited-node multicast IPv6)
    uint8_t dst_mac[6];
    dst_mac[0] = 0x33;
    dst_mac[1] = 0x33;
    dst_mac[2] = sol_node_addr.s6_addr[12];
    dst_mac[3] = sol_node_addr.s6_addr[13];
    dst_mac[4] = sol_node_addr.s6_addr[14];
    dst_mac[5] = sol_node_addr.s6_addr[15];

    // -- Build frame buffer --
    uint8_t frame[FRAME_LEN];
    std::memset(frame, 0, FRAME_LEN);

    // 1. Ethernet header (14 bytes)
    uint8_t* eth = frame;
    std::memcpy(eth, dst_mac, ETH_ALEN);                              // dst: multicast MAC
    std::memcpy(eth + ETH_ALEN, local_mac_, ETH_ALEN);                // src: our MAC
    *reinterpret_cast<uint16_t*>(eth + 12) = htons(ETHER_TYPE_IPV6);       // EtherType: IPv6

    // 2. IPv6 header (40 bytes)
    uint8_t* ipv6 = frame + ETH_HDR_LEN;

    // Version (4) + Traffic Class (8) + Flow Label (20) = 4 bytes
    // Version = 6 → first nibble = 0x6, rest = 0
    *reinterpret_cast<uint32_t*>(ipv6) = htonl(0x60000000u);

    // Payload length (2 bytes) at offset 4
    *reinterpret_cast<uint16_t*>(ipv6 + 4) = htons(ICMPV6_TOTAL_LEN);

    // Next header (1 byte) at offset 6 → 58 = ICMPv6
    ipv6[6] = 58; // IPPROTO_ICMPV6

    // Hop limit (1 byte) at offset 7 → must be 255 for NDP
    ipv6[7] = 255;

    // Source address (16 bytes) at offset 8
    std::memcpy(ipv6 + 8, &src_addr, 16);

    // Destination address (16 bytes) at offset 24
    std::memcpy(ipv6 + 24, &sol_node_addr, 16);

    // 3. ICMPv6 Neighbor Solicitation (24 bytes)
    uint8_t* icmpv6 = frame + ETH_HDR_LEN + IPV6_HDR_LEN;

    icmpv6[0] = ICMPV6_TYPE_NS;  // Type: Neighbor Solicitation (135)
    icmpv6[1] = 0;                // Code: 0
    // Checksum at bytes 2-3 - filled later
    // Reserved at bytes 4-7 - already zeroed
    // Target Address at bytes 8-23
    std::memcpy(icmpv6 + 8, &target_addr, 16);

    // 4. ICMPv6 Option: Source Link-Layer Address (8 bytes)
    uint8_t* opt = icmpv6 + NS_HDR_LEN;
    opt[0] = NDP_OPT_SRC_LLA;    // Type: Source Link-Layer Address
    opt[1] = 1;                   // Length: 1 (in units of 8 bytes)
    std::memcpy(opt + 2, local_mac_, 6);

    // 5. ICMPv6 checksum (over pseudo-header + ICMPv6 body)
    uint16_t cksum = compute_icmpv6_checksum(
        src_addr.s6_addr,
        sol_node_addr.s6_addr,
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
            "sendto() failed for NDP NS to '" + target_ip +
            "': " + std::strerror(errno));
    }
}
