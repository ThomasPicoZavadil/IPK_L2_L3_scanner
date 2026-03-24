/**
 * @file netif.hpp
 * @brief Retrieve local MAC, IPv4, and IPv6 addresses for a network interface.
 */
#ifndef NETIF_HPP
#define NETIF_HPP

#include <string>

/**
 * @brief Holds the local addresses associated with a network interface.
 */
struct InterfaceInfo {
    std::string name;          ///< Interface name (e.g. "eth0")
    std::string mac_address;   ///< MAC address in "aa:bb:cc:dd:ee:ff" format, or empty
    std::string ipv4_address;  ///< IPv4 address in dotted-decimal, or empty
    std::string ipv6_address;  ///< IPv6 address (first non-link-local, or link-local), or empty
};

/**
 * @brief Query the local addresses of the given network interface.
 *
 * Uses ioctl(SIOCGIFHWADDR) for the MAC address and getifaddrs() for
 * IPv4/IPv6 addresses.  For IPv6, a global/unique-local address is preferred
 * over a link-local address.
 *
 * @param  iface_name  Name of the network interface (e.g. "eth0").
 * @return InterfaceInfo with whatever addresses could be resolved.
 * @throws std::runtime_error if the interface does not exist or a
 *         system call fails fatally.
 */
InterfaceInfo get_interface_info(const std::string& iface_name);

#endif // NETIF_HPP
