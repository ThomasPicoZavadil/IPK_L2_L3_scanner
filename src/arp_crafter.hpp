/**
 * @file arp_crafter.hpp
 * @brief ArpCrafter – sends ARP Request frames over a raw socket.
 */
#ifndef ARP_CRAFTER_HPP
#define ARP_CRAFTER_HPP

#include "packet_crafter.hpp"

/**
 * @brief Crafts and sends ARP Request (who-has) frames.
 *
 * Constructs a 42-byte Ethernet + ARP packet and broadcasts it
 * on the interface to resolve a target IPv4 address.
 */
class ArpCrafter : public PacketCrafter {
public:
    using PacketCrafter::PacketCrafter;   // inherit constructor

    /**
     * @brief Send an ARP Request for the given IPv4 address.
     * @param target_ip  Dotted-decimal IPv4 address to resolve.
     * @throws std::runtime_error on invalid address or sendto() failure.
     */
    void send_request(const std::string& target_ip) override;
};

#endif // ARP_CRAFTER_HPP
