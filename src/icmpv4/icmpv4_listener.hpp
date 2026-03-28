/**
 * @file icmpv4_listener.hpp
 * @brief Icmpv4Listener - parses ICMPv4 Echo Reply frames from captured packets.
 */
#ifndef ICMPV4_LISTENER_HPP
#define ICMPV4_LISTENER_HPP

#include "packet_listener.hpp"

#include <cstdint>
#include "../scan_result_manager.hpp"

/**
 * @brief Listens for ICMPv4 Echo Reply frames (Ping replies).
 *
 * Extracts the Source IP address from the IPv4 header and prints it.
 */
class Icmpv4Listener : public PacketListener {
public:
    explicit Icmpv4Listener(ScanResultManager& manager) : manager_(manager) {}

    /**
     * @brief Inspects a captured packet.
     * Checks if it's an IPv4 ICMP Echo Reply, and if so, prints the source IP.
     */
    bool parse_packet(const uint8_t* buffer, uint32_t length) override;

private:
    ScanResultManager& manager_;
};

#endif // ICMPV4_LISTENER_HPP
