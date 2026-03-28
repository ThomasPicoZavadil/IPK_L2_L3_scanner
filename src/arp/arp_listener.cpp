/**
 * @file arp_listener.cpp
 * @brief ArpListener::parse_packet() - extracts sender MAC/IP from ARP Replies.
 */
#include "arp_listener.hpp"

#include <cstdio>
#include <cstring>
#include <iostream>

#include <arpa/inet.h>      // ntohs, inet_ntop
#include <net/ethernet.h>    // ETH_ALEN, struct ether_header

// ---- ARP constants (same values used by ArpCrafter) ----
static constexpr uint16_t ARP_HTYPE_ETHERNET = 1;
static constexpr uint16_t ARP_PTYPE_IPV4     = 0x0800;
static constexpr uint8_t  ARP_HLEN           = 6;   // MAC length
static constexpr uint8_t  ARP_PLEN           = 4;   // IPv4 length
static constexpr uint16_t ARP_OPER_REPLY     = 2;

// Sizes
static constexpr size_t ETH_HDR_LEN = 14;
static constexpr size_t ARP_PKT_LEN = 28;
static constexpr size_t MIN_FRAME   = ETH_HDR_LEN + ARP_PKT_LEN; // 42

// ---- Offsets within the 28-byte ARP payload ----
//  0..1   htype
//  2..3   ptype
//  4      hlen
//  5      plen
//  6..7   oper
//  8..13  sender hardware address  (SHA)
// 14..17  sender protocol address  (SPA)
// 18..23  target hardware address  (THA)
// 24..27  target protocol address  (TPA)
static constexpr size_t ARP_OFF_HTYPE = 0;
static constexpr size_t ARP_OFF_PTYPE = 2;
static constexpr size_t ARP_OFF_HLEN  = 4;
static constexpr size_t ARP_OFF_PLEN  = 5;
static constexpr size_t ARP_OFF_OPER  = 6;
static constexpr size_t ARP_OFF_SHA   = 8;
static constexpr size_t ARP_OFF_SPA   = 14;

bool ArpListener::parse_packet(const uint8_t* buffer, uint32_t length)
{
    // Need at least a full Ethernet + ARP frame.
    if (length < MIN_FRAME) {
        return false;
    }

    // --- Ethernet header check ---
    auto* eth = reinterpret_cast<const struct ether_header*>(buffer);
    if (ntohs(eth->ether_type) != ETH_P_ARP) {
        return false;   // not ARP
    }

    // --- ARP header validation ---
    const uint8_t* arp = buffer + ETH_HDR_LEN;

    uint16_t htype = ntohs(*reinterpret_cast<const uint16_t*>(arp + ARP_OFF_HTYPE));
    uint16_t ptype = ntohs(*reinterpret_cast<const uint16_t*>(arp + ARP_OFF_PTYPE));
    uint8_t  hlen  = arp[ARP_OFF_HLEN];
    uint8_t  plen  = arp[ARP_OFF_PLEN];
    uint16_t oper  = ntohs(*reinterpret_cast<const uint16_t*>(arp + ARP_OFF_OPER));

    if (htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 ||
        hlen  != ARP_HLEN           || plen  != ARP_PLEN       ||
        oper  != ARP_OPER_REPLY) {
        return false;   // not an Ethernet/IPv4 ARP Reply
    }

    // --- Extract sender MAC (SHA) ---
    const uint8_t* sha = arp + ARP_OFF_SHA;
    char mac_str[18]; // "xx-xx-xx-xx-xx-xx\0"
    std::snprintf(mac_str, sizeof(mac_str),
                  "%02x-%02x-%02x-%02x-%02x-%02x",
                  sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);

    // --- Extract sender IP  (SPA) ---
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp + ARP_OFF_SPA, ip_str, sizeof(ip_str));

    // --- Deliver result ---
    manager_.update_l2(ip_str, mac_str);

    return true;
}
