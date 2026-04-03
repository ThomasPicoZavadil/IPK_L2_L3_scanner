/**
 * @file icmpv6_crafter.hpp
 * @brief Icmpv6Crafter - sends ICMPv6 Echo Requests over a raw socket.
 */
#ifndef ICMPV6_CRAFTER_HPP
#define ICMPV6_CRAFTER_HPP

#include "packet_crafter.hpp"

#include <cstdint>
#include <string>

/**
 * @brief Crafts and sends ICMPv6 Echo Request (Type 128) packets.
 *
 * Constructs an Ethernet + IPv6 + ICMPv6 Echo Request frame,
 * calculates the ICMPv6 checksum using the IPv6 pseudo-header,
 * and sends it via the raw AF_PACKET socket.
 */
class Icmpv6Crafter : public PacketCrafter {
public:
    using PacketCrafter::PacketCrafter;

    /**
     * @brief Build and send an ICMPv6 Echo Request.
     * @param target_ip  IPv6 address string to ping (e.g. "fe80::1").
     * @throws std::runtime_error on invalid address or sendto() failure.
     */
    void send_request(const std::string& target_ip) override;

private:
    /**
     * @brief Standard Internet checksum (RFC 1071).
     */
    static uint16_t calculate_checksum(const uint16_t* data, size_t length);

    /**
     * @brief Compute ICMPv6 checksum using the IPv6 pseudo-header.
     */
    static uint16_t compute_icmpv6_checksum(const uint8_t* src_addr,
                                            const uint8_t* dst_addr,
                                            const uint8_t* icmpv6_buf,
                                            uint32_t       icmpv6_len);
};

#endif // ICMPV6_CRAFTER_HPP
