/**
 * @file pcap_engine.cpp
 * @brief Implementation of PcapEngine – threaded libpcap capture.
 */
#include "pcap_engine.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

PcapEngine::PcapEngine(const std::string& interface_name,
                       const std::string& filter,
                       int                snap_len)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the interface in promiscuous mode (promisc = 1), timeout 1 s.
    handle_ = pcap_open_live(interface_name.c_str(),
                             snap_len,
                             /*promisc=*/1,
                             /*to_ms=*/1000,
                             errbuf);
    if (handle_ == nullptr) {
        throw std::runtime_error(
            "pcap_open_live(" + interface_name + "): " + errbuf);
    }

    // Compile the BPF filter expression.
    struct bpf_program bpf{};
    if (pcap_compile(handle_, &bpf, filter.c_str(),
                     /*optimize=*/1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::string msg = "pcap_compile(\"" + filter + "\"): "
                          + pcap_geterr(handle_);
        pcap_close(handle_);
        handle_ = nullptr;
        throw std::runtime_error(msg);
    }

    // Apply the compiled filter.
    if (pcap_setfilter(handle_, &bpf) == -1) {
        std::string msg = std::string("pcap_setfilter: ")
                          + pcap_geterr(handle_);
        pcap_freecode(&bpf);
        pcap_close(handle_);
        handle_ = nullptr;
        throw std::runtime_error(msg);
    }

    pcap_freecode(&bpf);
}

PcapEngine::~PcapEngine()
{
    stop();
    if (handle_ != nullptr) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Listener management
// ---------------------------------------------------------------------------

void PcapEngine::add_listener(PacketListener* listener)
{
    if (listener != nullptr) {
        listeners_.push_back(listener);
    }
}

// ---------------------------------------------------------------------------
// Capture loop
// ---------------------------------------------------------------------------

void PcapEngine::start()
{
    if (running_) {
        return;     // already capturing
    }
    running_ = true;
    thread_  = std::thread(&PcapEngine::capture_loop, this);
}

void PcapEngine::stop()
{
    if (!running_) {
        return;
    }
    // Signal pcap_loop() to break out on the next iteration.
    pcap_breakloop(handle_);

    if (thread_.joinable()) {
        thread_.join();
    }
    running_ = false;
}

void PcapEngine::capture_loop()
{
    // count = 0  →  loop until pcap_breakloop() or error.
    pcap_loop(handle_, /*cnt=*/0, packet_handler,
              reinterpret_cast<u_char*>(this));
}

// ---------------------------------------------------------------------------
// Static pcap callback  →  C++ dispatch
// ---------------------------------------------------------------------------

void PcapEngine::packet_handler(u_char*                   user,
                                const struct pcap_pkthdr* header,
                                const u_char*             bytes)
{
    auto* self = reinterpret_cast<PcapEngine*>(user);

    for (auto* listener : self->listeners_) {
        listener->parse_packet(bytes,
                               static_cast<uint32_t>(header->caplen));
    }
}
