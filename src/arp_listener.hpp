/**
 * @file arp_listener.hpp
 * @brief ArpListener – parses ARP Reply frames from captured packets.
 */
#ifndef ARP_LISTENER_HPP
#define ARP_LISTENER_HPP

#include "packet_listener.hpp"

#include <functional>
#include <string>

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
    /// Callback signature: (sender_mac, sender_ip)
    using Callback = std::function<void(const std::string& mac,
                                        const std::string& ip)>;

    /**
     * @brief Construct with an optional result callback.
     * If @p cb is empty, results are printed to stderr instead.
     */
    explicit ArpListener(Callback cb = nullptr);

    bool parse_packet(const uint8_t* buffer, uint32_t length) override;

private:
    Callback callback_;
};

#endif // ARP_LISTENER_HPP
