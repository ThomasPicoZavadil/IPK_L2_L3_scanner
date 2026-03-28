/**
 * @file icmpv4_listener.cpp
 * @brief Icmpv4Listener::parse_packet() - extracts Source IP from ICMPv4 Echo Replies.
 */
#include "icmpv4_listener.hpp"

#include <iostream>

#include <arpa/inet.h>          // inet_ntop, ntohs
#include <net/ethernet.h>       // struct ether_header, ETH_P_IP
#include <netinet/in.h>         // AF_INET, IPPROTO_ICMP
#include <netinet/ip.h>         // struct ip
#include <netinet/ip_icmp.h>    // struct icmphdr, ICMP_ECHOREPLY

bool Icmpv4Listener::parse_packet(const uint8_t* buffer, uint32_t length)
{
    // -- 1. Ethernet header check --
    if (length < sizeof(struct ether_header)) {
        return false;
    }
    
    auto* eth = reinterpret_cast<const struct ether_header*>(buffer);
    if (ntohs(eth->ether_type) != ETH_P_IP) {
        return false;   // Not an IPv4 packet
    }

    size_t offset = sizeof(struct ether_header);

    // -- 2. IPv4 header check --
    if (length < offset + sizeof(struct ip)) {
        return false;
    }
    
    auto* ip_hdr = reinterpret_cast<const struct ip*>(buffer + offset);
    if (ip_hdr->ip_p != IPPROTO_ICMP) {
        return false;   // Not an ICMP packet
    }

    // Calculate actual IPv4 header length (IHL field is in 32-bit words)
    size_t ip_hdr_len = ip_hdr->ip_hl * 4;
    
    if (length < offset + ip_hdr_len + sizeof(struct icmphdr)) {
        return false;   // Packet too short for ICMP header
    }

    // -- 3. ICMP header check --
    offset += ip_hdr_len;
    auto* icmp_hdr = reinterpret_cast<const struct icmphdr*>(buffer + offset);
    
    if (icmp_hdr->type != ICMP_ECHOREPLY) {
        return false;   // Not an Echo Reply (Type 0)
    }

    // -- 4. Extract Source IP and print --
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), ip_str, INET_ADDRSTRLEN);

    std::cout << "[ICMPv4 Listener] Received Echo Reply from IP: " << ip_str << "\n";

    return true;
}
