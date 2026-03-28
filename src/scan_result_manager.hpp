/**
 * @file scan_result_manager.hpp
 * @brief Manages centralized state for L2 and L3 scan results.
 */
#ifndef SCAN_RESULT_MANAGER_HPP
#define SCAN_RESULT_MANAGER_HPP

#include <map>
#include <mutex>
#include <string>

/**
 * @brief Aggregated scan result for a single target host.
 */
struct HostResult {
    bool        is_ipv6   = false;
    bool        l2_ok     = false;
    std::string mac_addr;
    bool        l3_ok     = false;
};

/**
 * @brief Thread-safe manager that tracks host scan results and prints them.
 */
class ScanResultManager {
public:
    /**
     * @brief Pre-populate a target so we can report on it even if it doesn't respond.
     */
    void add_target(const std::string& ip, bool is_ipv6);

    /**
     * @brief Update the L2 scan status when an ARP/NDP reply is received.
     */
    void update_l2(const std::string& ip, const std::string& mac);

    /**
     * @brief Update the L3 scan status when an ICMPv4/ICMPv6 reply is received.
     */
    void update_l3(const std::string& ip);

    /**
     * @brief Print all formatted results.
     */
    void print_results() const;

private:
    mutable std::mutex                mutex_;
    std::map<std::string, HostResult> results_;
};

#endif // SCAN_RESULT_MANAGER_HPP
