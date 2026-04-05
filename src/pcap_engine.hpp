/**
 * @file pcap_engine.hpp
 * @brief PcapEngine – threaded packet capture using libpcap.
 *
 * Opens a network interface in promiscuous mode, compiles a BPF filter,
 * and runs pcap_loop() in a dedicated thread.  Every captured frame is
 * forwarded to all registered PacketListener instances.
 */
#ifndef PCAP_ENGINE_HPP
#define PCAP_ENGINE_HPP

#include "packet_listener.hpp"

#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include <pcap/pcap.h>

/**
 * @brief Libpcap-based capture engine that dispatches packets to listeners.
 *
 * Usage:
 * @code
 *   PcapEngine engine("eth0", "arp");
 *   engine.add_listener(&my_listener);
 *   engine.start();        // capture runs in background thread
 *   // send probes
 *   engine.stop();         // breaks loop, joins thread
 * @endcode
 *
 * The engine does **not** own the listeners - the caller must ensure they
 * outlive the engine (or at least the capture loop).
 */
class PcapEngine {
public:
    /**
     * @brief Open @p interface_name for live capture.
     *
     * @param interface_name  Network interface (e.g. "eth0").
     * @param filter          BPF filter expression (default: "arp").
     * @param snap_len        Maximum bytes to capture per frame (default: 65535).
     * @throws std::runtime_error on pcap_open_live / pcap_compile /
     *         pcap_setfilter failure.
     */
    explicit PcapEngine(const std::string& interface_name,
                        const std::string& filter   = "arp",
                        int                snap_len  = 65535);

    /** @brief Stops capture (if running) and closes the pcap handle. */
    ~PcapEngine();

    // Non-copyable, non-movable (owns pcap handle + thread).
    PcapEngine(const PcapEngine&)            = delete;
    PcapEngine& operator=(const PcapEngine&) = delete;
    PcapEngine(PcapEngine&&)                 = delete;
    PcapEngine& operator=(PcapEngine&&)      = delete;

    /**
     * @brief Register a listener to receive captured packets.
     * Must be called **before** start().
     */
    void add_listener(PacketListener* listener);

    /** @brief Spawn the capture thread.  No-op if already running. */
    void start();

    /**
     * @brief Break the capture loop and join the thread.
     * Safe to call multiple times.
     */
    void stop();

    /** @brief True while the capture thread is active. */
    bool running() const noexcept { return running_; }

private:
    /**
     * @brief Static callback passed to pcap_loop().
     *
     * The @p user pointer is a reinterpret_cast of the PcapEngine*,
     * allowing the static function to forward into the C++ context.
     */
    static void packet_handler(u_char*              user,
                               const struct pcap_pkthdr* header,
                               const u_char*        bytes);

    /** @brief Body of the capture thread. */
    void capture_loop();

    pcap_t*                        handle_  = nullptr;
    std::vector<PacketListener*>   listeners_;
    std::thread                    thread_;
    bool                           running_ = false;
};

#endif // PCAP_ENGINE_HPP
