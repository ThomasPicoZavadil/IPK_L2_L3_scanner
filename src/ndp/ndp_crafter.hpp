/**
 * @file ndp_crafter.hpp
 * @brief NdpCrafter - sends ICMPv6 Neighbor Solicitation over a raw socket.
 */
#ifndef NDP_CRAFTER_HPP
#define NDP_CRAFTER_HPP

#include "packet_crafter.hpp"

#include <cstdint>
#include <string>

/**
 * @brief Crafts and sends ICMPv6 Neighbor Solicitation (Type 135) packets.
 *
 * Computes the solicited-node multicast IPv6 address and the corresponding
 * multicast MAC address for the target, constructs the Ethernet + IPv6 +
 * ICMPv6 frame with a correct pseudo-header checksum, and sends it via
 * the raw AF_PACKET socket.
 */
class NdpCrafter : public PacketCrafter {
public:
    using PacketCrafter::PacketCrafter;

    /**
     * @brief Build and send an ICMPv6 Neighbor Solicitation.
     * @param target_ip  IPv6 address string to resolve (e.g. "fe80::1").
     * @throws std::runtime_error on invalid address or sendto() failure.
     */
    void send_request(const std::string& target_ip) override;

private:
    /**
     * @brief Standard Internet checksum (RFC 1071).
     * @param data   Pointer to data (cast to uint16_t*).
     * @param length Length of data in bytes.
     * @return 16-bit checksum in network byte order.
     */
    static uint16_t calculate_checksum(const uint16_t* data, size_t length);

    /**
     * @brief Compute ICMPv6 checksum using the IPv6 pseudo-header.
     * @param src_addr   Source IPv6 address (16 bytes, network order).
     * @param dst_addr   Destination IPv6 address (16 bytes, network order).
     * @param icmpv6_buf Pointer to the ICMPv6 payload.
     * @param icmpv6_len Length of ICMPv6 payload in bytes.
     * @return 16-bit checksum in network byte order.
     */
    static uint16_t compute_icmpv6_checksum(const uint8_t* src_addr,
                                            const uint8_t* dst_addr,
                                            const uint8_t* icmpv6_buf,
                                            uint32_t       icmpv6_len);
};

#endif // NDP_CRAFTER_HPP
