/**
 * @file main.cpp
 * @brief Entry point for ipk-l2l3-scan – parses CLI args and prints the config.
 */
#include "config.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
    Config cfg = parse_args(argc, argv);

    // Print parsed configuration for verification
    std::cout << "=== Parsed Configuration ===\n";
    std::cout << "Interface : " << cfg.interface << "\n";
    std::cout << "Timeout   : " << cfg.timeout_ms << " ms\n";
    std::cout << "Subnets   :\n";
    for (const auto& subnet : cfg.subnets) {
        std::cout << "  - " << subnet << "\n";
    }

    return 0;
}
