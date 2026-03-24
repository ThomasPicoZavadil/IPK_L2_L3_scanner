/**
 * @file main.cpp
 * @brief Entry point for ipk-l2l3-scan – parses CLI args, resolves subnets.
 */
#include "config.hpp"
#include "subnet.hpp"
#include "netif.hpp"

#include <algorithm>
#include <iostream>

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

    // Print interface info (MAC, IPv4, IPv6)
    try {
        InterfaceInfo ifinfo = get_interface_info(cfg.interface());
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

    // Parse each subnet and generate host IPs
    for (const auto& cidr : cfg.subnets()) {
        try {
            Subnet subnet(cidr);

            std::cout << "=== Subnet: " << subnet.cidr() << " ===\n";
            std::cout << "  Network    : " << subnet.network_address() << "\n";
            std::cout << "  Prefix     : /" << subnet.prefix_length() << "\n";
            std::cout << "  Type       : " << (subnet.is_ipv6() ? "IPv6" : "IPv4") << "\n";
            std::cout << "  Usable IPs : " << subnet.usable_host_count() << "\n";

            auto hosts = subnet.generate_host_ips();
            std::cout << "  Generated  : " << hosts.size() << " addresses\n";

            // Show first and last few addresses
            constexpr size_t PREVIEW = 5;
            size_t show = std::min(hosts.size(), PREVIEW);
            for (size_t i = 0; i < show; ++i) {
                std::cout << "    " << hosts[i] << "\n";
            }
            if (hosts.size() > 2 * PREVIEW) {
                std::cout << "    ... (" << hosts.size() - 2 * PREVIEW << " more)\n";
                for (size_t i = hosts.size() - PREVIEW; i < hosts.size(); ++i) {
                    std::cout << "    " << hosts[i] << "\n";
                }
            } else if (hosts.size() > PREVIEW) {
                for (size_t i = show; i < hosts.size(); ++i) {
                    std::cout << "    " << hosts[i] << "\n";
                }
            }
            std::cout << "\n";

        } catch (const std::exception& e) {
            std::cerr << "Error parsing '" << cidr << "': " << e.what() << "\n";
            return 1;
        }
    }

    return 0;
}
