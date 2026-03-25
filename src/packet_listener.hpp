/**
 * @file packet_listener.hpp
 * @brief Abstract base class for protocol-specific packet listeners.
 *
 * Each derived listener knows how to parse one kind of response
 * (ARP reply, NDP, ICMPv4 echo reply, …) from a captured byte buffer.
 */
#ifndef PACKET_LISTENER_HPP
#define PACKET_LISTENER_HPP

#include <cstdint>

/**
 * @brief Interface for objects that consume captured packets.
 *
 * Derive from this class and implement parse_packet() to handle
 * specific protocol responses. Register instances with a PcapEngine
 * to receive every captured frame.
 */
class PacketListener {
public:
    virtual ~PacketListener() = default;

    /**
     * @brief Inspect a captured packet and extract relevant information.
     *
     * @param buffer  Pointer to the first byte of the captured frame
     *                (starting at the link-layer header).
     * @param length  Number of bytes available in @p buffer.
     * @return true   if the packet was recognised and processed,
     *         false  otherwise.
     */
    virtual bool parse_packet(const uint8_t* buffer, uint32_t length) = 0;
};

#endif // PACKET_LISTENER_HPP
