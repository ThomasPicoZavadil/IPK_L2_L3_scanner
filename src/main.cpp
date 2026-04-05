/**
 * @file main.cpp
 * @brief Entry point for ipk-l2l3-scan - parses CLI args, resolves subnets.
 */
#include "config.hpp"
#include "subnet.hpp"
#include "netif.hpp"
#include "arp/arp_crafter.hpp"
#include "arp/arp_listener.hpp"
#include "scan_result_manager.hpp"
#include "icmpv4/icmpv4_crafter.hpp"
#include "icmpv4/icmpv4_listener.hpp"
#include "ndp/ndp_crafter.hpp"
#include "ndp/ndp_listener.hpp"
#include "icmpv6/icmpv6_crafter.hpp"
#include "icmpv6/icmpv6_listener.hpp"
#include "pcap_engine.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>

#include <net/ethernet.h>       // ETH_P_ALL
#include <arpa/inet.h>          // htons
#include <sys/socket.h>         // socket, AF_PACKET, SOCK_RAW
#include <unistd.h>             // close

int main(int argc, char* argv[]) {
    Config cfg = Config::parse(argc, argv);

    // Resolve interface info (MAC, IPv4, IPv6)
    InterfaceInfo ifinfo;
    try {
        ifinfo = get_interface_info(cfg.interface());
    } catch (const std::exception& e) {
        std::cerr << "Error querying interface '" << cfg.interface() << "': " << e.what() << "\n";
        return 1;
    }

    std::vector<Subnet> parsed_subnets;
    std::cout << "Scanning ranges:\n";
    for (const auto& cidr : cfg.subnets()) {
        try {
            Subnet subnet(cidr);
            parsed_subnets.push_back(subnet);
            std::cout << subnet.network_address() << "/" << subnet.prefix_length() << " " << subnet.usable_host_count() << "\n";
        } catch (const std::exception& e) {
            std::cerr << "Error parsing '" << cidr << "': " << e.what() << "\n";
            return 1;
        }
    }
    std::cout << "\n";

    // Open raw socket for packet crafting
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        std::cerr << "Failed to open raw socket: " << std::strerror(errno)
                  << " (are you running as root?)\n";
        return 1;
    }

    // Create ARP crafter
    ArpCrafter arp(raw_sock, ifinfo);

    // Create ICMPv4 crafter
    Icmpv4Crafter icmp(raw_sock, ifinfo);

    // Create NDP crafter
    NdpCrafter ndp(raw_sock, ifinfo);

    // Create ICMPv6 crafter
    Icmpv6Crafter icmpv6(raw_sock, ifinfo);

    // Create central result manager
    ScanResultManager manager;

    // Create ARP listener (pushes to manager)
    ArpListener arp_listener(manager);

    // Create ICMPv4 listener (pushes to manager)
    Icmpv4Listener icmp_listener(manager);

    // Create NDP listener (pushes to manager)
    NdpListener ndp_listener(manager);

    // Create ICMPv6 listener (pushes to manager)
    Icmpv6Listener icmpv6_listener(manager);

    // Start packet capture on the interface (filter: ARP, ICMP, and ICMPv6)
    PcapEngine engine(cfg.interface(), "arp or icmp or icmp6");
    engine.add_listener(&arp_listener);
    engine.add_listener(&icmp_listener);
    engine.add_listener(&ndp_listener);
    engine.add_listener(&icmpv6_listener);
    engine.start();

    // Send ARP and ICMPv4 requests for each host in each parsed subnet
    for (const auto& subnet : parsed_subnets) {
        auto hosts = subnet.generate_host_ips();

        if (!subnet.is_ipv6()) {
            for (const auto& host : hosts) {
                manager.add_target(host, false);
                try {
                    arp.send_request(host);
                    icmp.send_request(host);
                } catch (const std::exception& e) {
                    std::cerr << "Send error for host " << host << ": " << e.what() << "\n";
                }
            }
        } else {
            for (const auto& host : hosts) {
                manager.add_target(host, true);
                try {
                    ndp.send_request(host);
                    icmpv6.send_request(host);
                } catch (const std::exception& e) {
                    std::cerr << "Send error for host " << host << ": " << e.what() << "\n";
                }
            }
        }
    }

    // Wait for remaining ARP replies to arrive
    std::this_thread::sleep_for(
        std::chrono::milliseconds(cfg.timeout_ms()));

    engine.stop();

    // --- Output Results ---
    manager.print_results();

    close(raw_sock);
    return 0;
}

