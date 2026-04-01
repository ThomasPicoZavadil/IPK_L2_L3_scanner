/**
 * @file ndp_listener.hpp
 * @brief NdpListener - parses ICMPv6 Neighbor Advertisement from captured packets.
 */
#ifndef NDP_LISTENER_HPP
#define NDP_LISTENER_HPP

#include "packet_listener.hpp"

#include <cstdint>
#include "../scan_result_manager.hpp"

/**
 * @brief Listens for ICMPv6 Neighbor Advertisement (Type 136) frames.
 *
 * Extracts the Target IPv6 address and the Target Link-Layer Address
 * (option type 2) from the NDP payload, then updates the central
 * ScanResultManager with the L2 result.
 */
class NdpListener : public PacketListener {
public:
    explicit NdpListener(ScanResultManager& manager) : manager_(manager) {}

    bool parse_packet(const uint8_t* buffer, uint32_t length) override;

private:
    ScanResultManager& manager_;
};

#endif // NDP_LISTENER_HPP
