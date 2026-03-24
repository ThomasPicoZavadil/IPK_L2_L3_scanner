/**
 * @file main.cpp
 * @brief Entry point for ipk-l2l3-scan – parses CLI args, resolves subnets.
 */
#include "config.hpp"
#include "subnet.hpp"
#include "netif.hpp"
#include "arp_crafter.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iostream>

#include <net/ethernet.h>       // ETH_P_ALL
#include <arpa/inet.h>          // htons
#include <sys/socket.h>         // socket, AF_PACKET, SOCK_RAW
#include <unistd.h>             // close

int main(int argc, char* argv[]) {
    Config cfg = Config::parse(argc, argv);

    // Print parsed configuration
    std::cout << "=== Parsed Configuration ===\n";
    std::cout << "Interface : " << cfg.interface() << "\n";
    std::cout << "Timeout   : " << cfg.timeout_ms() << " ms\n";
    std::cout << "Subnets   :\n";
    for (const auto& s : cfg.subnets()) {
        std::cout << "  - " << s << "\n";
    }
    std::cout << "\n";

    // Resolve interface info (MAC, IPv4, IPv6)
    InterfaceInfo ifinfo;
    try {
        ifinfo = get_interface_info(cfg.interface());
        std::cout << "=== Interface Info ===\n";
        std::cout << "  Name : " << ifinfo.name << "\n";
        std::cout << "  MAC  : " << (ifinfo.mac_address.empty()  ? "(none)" : ifinfo.mac_address)  << "\n";
        std::cout << "  IPv4 : " << (ifinfo.ipv4_address.empty() ? "(none)" : ifinfo.ipv4_address) << "\n";
        std::cout << "  IPv6 : " << (ifinfo.ipv6_address.empty() ? "(none)" : ifinfo.ipv6_address) << "\n";
        std::cout << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error querying interface '" << cfg.interface() << "': " << e.what() << "\n";
        return 1;
    }

    // Open raw socket for packet crafting
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        std::cerr << "Failed to open raw socket: " << std::strerror(errno)
                  << " (are you running as root?)\n";
        return 1;
    }

    // Create ARP crafter
    ArpCrafter arp(raw_sock, ifinfo);

    // Parse each subnet and send ARP requests for IPv4 hosts
    for (const auto& cidr : cfg.subnets()) {
        try {
            Subnet subnet(cidr);

            std::cout << "=== Subnet: " << subnet.cidr() << " ===\n";
            std::cout << "  Network    : " << subnet.network_address() << "\n";
            std::cout << "  Prefix     : /" << subnet.prefix_length() << "\n";
            std::cout << "  Type       : " << (subnet.is_ipv6() ? "IPv6" : "IPv4") << "\n";
            std::cout << "  Usable IPs : " << subnet.usable_host_count() << "\n";

            auto hosts = subnet.generate_host_ips();
            std::cout << "  Generated  : " << hosts.size() << " addresses\n\n";

            if (!subnet.is_ipv6()) {
                // Send ARP request for each host in this IPv4 subnet
                for (const auto& host : hosts) {
                    try {
                        arp.send_request(host);
                    } catch (const std::exception& e) {
                        std::cerr << "ARP send error: " << e.what() << "\n";
                    }
                }
            } else {
                std::cout << "  (IPv6 subnet – skipping ARP)\n\n";
            }

        } catch (const std::exception& e) {
            std::cerr << "Error parsing '" << cidr << "': " << e.what() << "\n";
            close(raw_sock);
            return 1;
        }
    }

    close(raw_sock);
    return 0;
}

