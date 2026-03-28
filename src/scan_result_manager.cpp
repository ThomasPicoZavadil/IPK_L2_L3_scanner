/**
 * @file scan_result_manager.cpp
 * @brief Implementation of ScanResultManager.
 */
#include "scan_result_manager.hpp"

#include <iostream>

void ScanResultManager::add_target(const std::string& ip, bool is_ipv6)
{
    std::lock_guard<std::mutex> lock(mutex_);
    results_[ip].is_ipv6 = is_ipv6;
}

void ScanResultManager::update_l2(const std::string& ip, const std::string& mac)
{
    std::lock_guard<std::mutex> lock(mutex_);
    results_[ip].l2_ok    = true;
    results_[ip].mac_addr = mac;
}

void ScanResultManager::update_l3(const std::string& ip)
{
    std::lock_guard<std::mutex> lock(mutex_);
    results_[ip].l3_ok = true;
}

void ScanResultManager::print_results() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [ip, res] : results_) {
        std::cout << ip << " arp ";
        if (res.l2_ok) {
            std::cout << "OK (" << res.mac_addr << "), ";
        } else {
            std::cout << "FAIL, ";
        }
        
        std::cout << "icmpv4 ";
        if (res.l3_ok) {
            std::cout << "OK\n";
        } else {
            std::cout << "FAIL\n";
        }
    }
}
