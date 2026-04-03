/**
 * @file icmpv6_listener.hpp
 * @brief Icmpv6Listener - parses ICMPv6 Echo Reply from captured packets.
 */
#ifndef ICMPV6_LISTENER_HPP
#define ICMPV6_LISTENER_HPP

#include "packet_listener.hpp"

#include <cstdint>
#include "../scan_result_manager.hpp"

/**
 * @brief Listens for ICMPv6 Echo Reply (Type 129) frames.
 *
 * Extracts the Source IPv6 address from the IPv6 header and updates
 * the central ScanResultManager with the L3 result.
 */
class Icmpv6Listener : public PacketListener {
public:
    explicit Icmpv6Listener(ScanResultManager& manager) : manager_(manager) {}

    bool parse_packet(const uint8_t* buffer, uint32_t length) override;

private:
    ScanResultManager& manager_;
};

#endif // ICMPV6_LISTENER_HPP
