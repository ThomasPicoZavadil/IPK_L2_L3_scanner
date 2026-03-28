/**
 * @file icmpv4_crafter.hpp
 * @brief Icmpv4Crafter - sends ICMPv4 Echo Requests over a raw socket.
 */
#ifndef ICMPV4_CRAFTER_HPP
#define ICMPV4_CRAFTER_HPP

#include "packet_crafter.hpp"

#include <cstdint>
#include <string>

/**
 * @brief Crafts and sends ICMPv4 Echo Requests (ping).
 *
 * Constructs an Ethernet, IPv4, and ICMPv4 Echo Request packet,
 * calculates required checksums, and broadcasts the frame over the
 * target interface.
 */
class Icmpv4Crafter : public PacketCrafter {
public:
    using PacketCrafter::PacketCrafter;

    /**
     * @brief Build and send an ICMPv4 Echo Request.
     * @param target_ip  Dotted-decimal IPv4 address to ping.
     * @throws std::runtime_error on invalid address or sendto() failure.
     */
    void send_request(const std::string& target_ip) override;

private:
    /**
     * @brief Utility function to calculate the standard Internet checksum.
     * @param data   Pointer to the data.
     * @param length Length of the data in bytes.
     * @return The calculated 16-bit checksum in network byte order.
     */
    static uint16_t calculate_checksum(const uint16_t* data, size_t length);
};

#endif // ICMPV4_CRAFTER_HPP
