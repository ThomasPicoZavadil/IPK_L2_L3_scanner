/**
 * @file arp_crafter.cpp
 * @brief ArpCrafter::send_request() – builds and sends an ARP Request frame.
 */
#include "arp_crafter.hpp"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>          // inet_pton, htons
#include <linux/if_packet.h>    // sockaddr_ll
#include <net/ethernet.h>       // ETH_ALEN, ETH_P_ARP
#include <netinet/in.h>         // in_addr
#include <sys/socket.h>         // sendto

// ARP header field values
static constexpr uint16_t ARP_HTYPE_ETHERNET = 1;
static constexpr uint16_t ARP_PTYPE_IPV4     = 0x0800;
static constexpr uint8_t  ARP_HLEN           = 6;   // MAC length
static constexpr uint8_t  ARP_PLEN           = 4;   // IPv4 length
static constexpr uint16_t ARP_OPER_REQUEST   = 1;

// Total frame size: 14 (Ethernet) + 28 (ARP) = 42 bytes
static constexpr size_t ETH_HDR_LEN = 14;
static constexpr size_t ARP_PKT_LEN = 28;
static constexpr size_t FRAME_LEN   = ETH_HDR_LEN + ARP_PKT_LEN;

void ArpCrafter::send_request(const std::string& target_ip) {
    std::cerr << "[ARP] Crafting request: "
              << iface_.mac_address << " (" << iface_.ipv4_address << ") -> "
              << target_ip << " on " << iface_.name << "\n";

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

    // Build frame buffer
    uint8_t frame[FRAME_LEN];
    std::memset(frame, 0, FRAME_LEN);

    // -- Ethernet header (14 bytes) --
    uint8_t* eth = frame;
    std::memset(eth, 0xff, ETH_ALEN);                         // dst: broadcast
    std::memcpy(eth + ETH_ALEN, local_mac_, ETH_ALEN);        // src: our MAC
    *reinterpret_cast<uint16_t*>(eth + 12) = htons(ETH_P_ARP); // EtherType

    // -- ARP payload (28 bytes) --
    uint8_t* arp = frame + ETH_HDR_LEN;
    size_t off = 0;

    // htype (2)
    *reinterpret_cast<uint16_t*>(arp + off) = htons(ARP_HTYPE_ETHERNET);
    off += 2;

    // ptype (2)
    *reinterpret_cast<uint16_t*>(arp + off) = htons(ARP_PTYPE_IPV4);
    off += 2;

    // hlen (1) + plen (1)
    arp[off++] = ARP_HLEN;
    arp[off++] = ARP_PLEN;

    // oper (2)
    *reinterpret_cast<uint16_t*>(arp + off) = htons(ARP_OPER_REQUEST);
    off += 2;

    // Sender hardware address (6)
    std::memcpy(arp + off, local_mac_, ETH_ALEN);
    off += ETH_ALEN;

    // Sender protocol address (4)
    std::memcpy(arp + off, &sender_addr.s_addr, 4);
    off += 4;

    // Target hardware address (6) — all zeros (unknown)
    std::memset(arp + off, 0x00, ETH_ALEN);
    off += ETH_ALEN;

    // Target protocol address (4)
    std::memcpy(arp + off, &target_addr.s_addr, 4);

    // Prepare destination address for sendto()
    struct sockaddr_ll dest{};
    dest.sll_family   = AF_PACKET;
    dest.sll_protocol = htons(ETH_P_ARP);
    dest.sll_ifindex  = static_cast<int>(if_index_);
    dest.sll_halen    = ETH_ALEN;
    std::memset(dest.sll_addr, 0xff, ETH_ALEN);   // broadcast

    ssize_t sent = sendto(sock_fd_, frame, FRAME_LEN, 0,
                          reinterpret_cast<struct sockaddr*>(&dest),
                          sizeof(dest));
    if (sent < 0) {
        throw std::runtime_error(
            "sendto() failed for ARP request to '" + target_ip +
            "': " + std::strerror(errno));
    }

    std::cerr << "[ARP] Sent " << sent << "/" << FRAME_LEN
              << " bytes (who-has " << target_ip << ")\n";
}
