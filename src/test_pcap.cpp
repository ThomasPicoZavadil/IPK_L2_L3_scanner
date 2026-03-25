/**
 * @file test_pcap.cpp
 * @brief Smoke-test for the PcapEngine + PacketListener architecture.
 *
 * Registers a DummyListener that prints a hex dump of every captured
 * packet.  Captures for a few seconds, then shuts down cleanly.
 *
 * Build (inside nix develop shell):
 *   g++ -std=c++20 -Wall -Wextra -pedantic -Isrc -o test_pcap \
 *       src/test_pcap.cpp src/pcap_engine.cpp -lpcap -lpthread
 *
 * Run (needs root / CAP_NET_RAW):
 *   sudo ./test_pcap <interface> [seconds]
 */
#include "pcap_engine.hpp"
#include "packet_listener.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <thread>

#include <net/ethernet.h>
#include <arpa/inet.h>

/**
 * @brief Dummy listener that prints basic Ethernet header info and a
 *        short hex dump for every captured frame.
 */
class DummyListener : public PacketListener {
public:
    bool parse_packet(const uint8_t* buffer, uint32_t length) override
    {
        ++count_;
        std::printf("\n--- Packet #%u  (%u bytes) ---\n", count_, length);

        // Need at least an Ethernet header (14 bytes).
        if (length < sizeof(struct ether_header)) {
            std::printf("  (too short for Ethernet header)\n");
            return false;
        }

        auto* eth = reinterpret_cast<const struct ether_header*>(buffer);

        std::printf("  Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
                    eth->ether_dhost[0], eth->ether_dhost[1],
                    eth->ether_dhost[2], eth->ether_dhost[3],
                    eth->ether_dhost[4], eth->ether_dhost[5]);
        std::printf("  Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
                    eth->ether_shost[0], eth->ether_shost[1],
                    eth->ether_shost[2], eth->ether_shost[3],
                    eth->ether_shost[4], eth->ether_shost[5]);
        std::printf("  EtherType: 0x%04x\n", ntohs(eth->ether_type));

        // Print first 64 bytes as hex.
        uint32_t dump_len = std::min(length, uint32_t{64});
        std::printf("  Hex dump (%u bytes): ", dump_len);
        for (uint32_t i = 0; i < dump_len; ++i) {
            std::printf("%02x ", buffer[i]);
        }
        std::printf("\n");

        return true;
    }

private:
    unsigned int count_ = 0;
};

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface> [seconds=5]\n";
        return 1;
    }

    const std::string iface  = argv[1];
    const int         secs   = (argc >= 3) ? std::atoi(argv[2]) : 5;

    // Use an empty filter to capture ALL traffic (not just ARP).
    PcapEngine    engine(iface, "" /* no filter — capture everything */);
    DummyListener dummy;

    engine.add_listener(&dummy);
    engine.start();

    std::cout << "Capturing on " << iface << " for " << secs
              << " seconds … (Ctrl-C to stop early)\n";

    std::this_thread::sleep_for(std::chrono::seconds(secs));

    engine.stop();
    std::cout << "\nCapture stopped.\n";
    return 0;
}
