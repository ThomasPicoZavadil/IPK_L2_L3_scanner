/**
 * @file icmpv4_crafter.cpp
 * @brief Icmpv4Crafter::send_request() - builds and sends an ICMPv4 Echo Request.
 */
#include "icmpv4_crafter.hpp"

#include <cstring>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>          // inet_pton, htons
#include <linux/if_packet.h>    // sockaddr_ll
#include <net/ethernet.h>       // ETH_ALEN, ETH_P_IP
#include <netinet/in.h>         // in_addr, IPPROTO_ICMP
#include <netinet/ip.h>         // struct ip
#include <netinet/ip_icmp.h>    // struct icmphdr
#include <sys/socket.h>         // sendto

// Frame component sizes
static constexpr size_t ETH_HDR_LEN   = 14;
static constexpr size_t IP_HDR_LEN    = 20;
static constexpr size_t ICMP_HDR_LEN  = 8;
static constexpr size_t ICMP_DATA_LEN = 32;

static constexpr size_t ICMP_TOT_LEN  = ICMP_HDR_LEN + ICMP_DATA_LEN;
static constexpr size_t IP_TOT_LEN    = IP_HDR_LEN + ICMP_TOT_LEN;
static constexpr size_t FRAME_LEN     = ETH_HDR_LEN + IP_TOT_LEN;

// Checksum calculation
uint16_t Icmpv4Crafter::calculate_checksum(const uint16_t* data, size_t length)
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

// Send Echo Request
void Icmpv4Crafter::send_request(const std::string& target_ip)
{

    // Parse sender and target IPv4 addresses
    struct in_addr sender_addr{};
    if (inet_pton(AF_INET, iface_.ipv4_address.c_str(), &sender_addr) != 1) {
        throw std::runtime_error(
            "Invalid sender IPv4 address: '" + iface_.ipv4_address + "'");
    }

    struct in_addr target_addr{};
    if (inet_pton(AF_INET, target_ip.c_str(), &target_addr) != 1) {
        throw std::runtime_error(
            "Invalid target IPv4 address: '" + target_ip + "'");
    }

    // Allocate frame buffer
    uint8_t frame[FRAME_LEN];
    std::memset(frame, 0, FRAME_LEN);

    // -- 1. Ethernet header (14 bytes) --
    uint8_t* eth = frame;
    std::memset(eth, 0xff, ETH_ALEN);                          // dst: broadcast
    std::memcpy(eth + ETH_ALEN, local_mac_, ETH_ALEN);         // src: our MAC
    *reinterpret_cast<uint16_t*>(eth + 12) = htons(ETH_P_IP);  // EtherType

    // -- 2. IPv4 header (20 bytes) --
    struct ip* ip_hdr = reinterpret_cast<struct ip*>(frame + ETH_HDR_LEN);
    ip_hdr->ip_v   = 4;                                        // Version 4
    ip_hdr->ip_hl  = IP_HDR_LEN >> 2;                          // Header length in 32-bit words (5)
    ip_hdr->ip_tos = 0;                                        // Type of service
    ip_hdr->ip_len = htons(IP_TOT_LEN);                        // Total length
    ip_hdr->ip_id  = htons(54321);                             // Identification
    ip_hdr->ip_off = 0;                                        // Fragment offset field
    ip_hdr->ip_ttl = 64;                                       // Time to live
    ip_hdr->ip_p   = IPPROTO_ICMP;                             // Protocol
    ip_hdr->ip_sum = 0;                                        // Initial checksum
    ip_hdr->ip_src = sender_addr;                              // Source IP
    ip_hdr->ip_dst = target_addr;                              // Target IP

    // Compute IPv4 checksum
    ip_hdr->ip_sum = calculate_checksum(reinterpret_cast<uint16_t*>(ip_hdr), IP_HDR_LEN);

    // -- 3. ICMPv4 header (8 bytes) + Data (32 bytes) --
    struct icmphdr* icmp_hdr = reinterpret_cast<struct icmphdr*>(frame + ETH_HDR_LEN + IP_HDR_LEN);
    icmp_hdr->type             = ICMP_ECHO;                    // Echo request (8)
    icmp_hdr->code             = 0;
    icmp_hdr->un.echo.id       = htons(1234);                  // Arbitrary ID
    icmp_hdr->un.echo.sequence = htons(1);                     // Sequence number 1
    icmp_hdr->checksum         = 0;                            // Initial checksum

    // Fill the dummy payload with 'A's
    uint8_t* payload_ptr = frame + ETH_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN;
    std::memset(payload_ptr, 'A', ICMP_DATA_LEN);

    // Compute ICMPv4 checksum over header + data
    icmp_hdr->checksum = calculate_checksum(reinterpret_cast<uint16_t*>(icmp_hdr), ICMP_TOT_LEN);

    // Prepare destination address for sendto()
    struct sockaddr_ll dest{};
    dest.sll_family   = AF_PACKET;
    dest.sll_protocol = htons(ETH_P_IP);
    dest.sll_ifindex  = static_cast<int>(if_index_);
    dest.sll_halen    = ETH_ALEN;
    std::memset(dest.sll_addr, 0xff, ETH_ALEN);                // broadcast

    ssize_t sent = sendto(sock_fd_, frame, FRAME_LEN, 0,
                          reinterpret_cast<struct sockaddr*>(&dest),
                          sizeof(dest));
    if (sent < 0) {
        throw std::runtime_error(
            "sendto() failed for ICMP request to '" + target_ip +
            "': " + std::strerror(errno));
    }
}
