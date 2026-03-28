/**
 * @file arp_listener.hpp
 * @brief ArpListener - parses ARP Reply frames from captured packets.
 */
#ifndef ARP_LISTENER_HPP
#define ARP_LISTENER_HPP

#include "packet_listener.hpp"

#include <mutex>
#include <string>
#include "../scan_result_manager.hpp"

/**
 * @brief Listens for ARP Reply frames and extracts sender MAC + IP.
 *
 * When an ARP Reply (opcode 2) is detected the listener invokes an
 * optional user-supplied callback with the sender's MAC and IPv4
 * address strings.  If no callback is set the information is printed
 * to stderr.
 */
class ArpListener : public PacketListener {
public:
    /**
     * @brief Construct an ArpListener.
     */
    explicit ArpListener(ScanResultManager& manager) : manager_(manager) {}

    bool parse_packet(const uint8_t* buffer, uint32_t length) override;

private:
    ScanResultManager& manager_;
};

#endif // ARP_LISTENER_HPP
