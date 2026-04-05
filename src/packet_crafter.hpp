/**
 * @file packet_crafter.hpp
 * @brief Abstract base class for protocol-specific packet crafters.
 *
 * Each derived crafter knows how to build and send one kind of request
 * (ARP, NDP, ICMPv4 echo, ...) through a pre-opened raw socket.
 */
#ifndef PACKET_CRAFTER_HPP
#define PACKET_CRAFTER_HPP

#include "netif.hpp"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include <net/if.h>   // if_nametoindex

/**
 * @brief Base class for all packet crafters.
 *
 * Holds the raw AF_PACKET socket file descriptor, a copy of the local
 * interface information, the resolved interface index, and the local
 * MAC address as raw bytes.
 *
 * The socket is **not** owned by this class - the caller is responsible
 * for creating and closing it.
 */
class PacketCrafter {
public:
    /**
     * @param raw_socket_fd  An open AF_PACKET/SOCK_RAW socket.
     * @param iface          Interface info (name, MAC, IPs).
     * @throws std::runtime_error if the interface index cannot be resolved
     *         or the MAC string is malformed.
     */
    PacketCrafter(int raw_socket_fd, const InterfaceInfo& iface)
        : sock_fd_(raw_socket_fd), iface_(iface)
    {
        // Resolve interface index
        if_index_ = if_nametoindex(iface_.name.c_str());
        if (if_index_ == 0) {
            throw std::runtime_error(
                "if_nametoindex() failed for '" + iface_.name + "'");
        }

        // Parse "aa:bb:cc:dd:ee:ff" → 6 raw bytes
        if (iface_.mac_address.size() != 17) {
            throw std::runtime_error(
                "Malformed MAC address: '" + iface_.mac_address + "'");
        }
        unsigned int b[6];
        if (std::sscanf(iface_.mac_address.c_str(),
                        "%02x:%02x:%02x:%02x:%02x:%02x",
                        &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
            throw std::runtime_error(
                "Failed to parse MAC address: '" + iface_.mac_address + "'");
        }
        for (int i = 0; i < 6; ++i) {
            local_mac_[i] = static_cast<uint8_t>(b[i]);
        }
    }

    virtual ~PacketCrafter() = default;

    /**
     * @brief Build and send a single protocol request targeting @p target_ip.
     * @throws std::runtime_error on send failure or invalid target address.
     */
    virtual void send_request(const std::string& target_ip) = 0;

protected:
    int              sock_fd_;       ///< Raw socket fd (not owned)
    InterfaceInfo    iface_;         ///< Local interface details
    unsigned int     if_index_;      ///< Interface index (for sockaddr_ll)
    uint8_t          local_mac_[6];  ///< Local MAC as raw bytes
};

#endif // PACKET_CRAFTER_HPP
