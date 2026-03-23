/**
 * @file config.hpp
 * @brief Configuration struct and CLI argument parsing for ipk-l2l3-scan.
 */
#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>
#include <vector>
#include <iostream>
#include <cstdlib>
#include <getopt.h>

/**
 * @brief Holds the parsed configuration for the scanner.
 */
struct Config {
    std::string interface;              ///< Network interface to scan on (-i)
    std::vector<std::string> subnets;   ///< Subnets to scan (-s, can be repeated)
    int timeout_ms = 1000;              ///< Wait timeout in milliseconds (-w, default 1000)
};

/**
 * @brief Prints usage / help information and exits.
 *
 * @param prog_name Name of the executable (argv[0]).
 */
inline void print_help(const char* prog_name) {
    std::cout
        << "Usage: " << prog_name << " [OPTIONS]\n"
        << "\n"
        << "Options:\n"
        << "  -i, --interface IFACE   Network interface to use (required)\n"
        << "  -s, --subnet SUBNET     Subnet to scan (required, may be repeated)\n"
        << "  -w, --wait TIMEOUT      Timeout in milliseconds (default: 1000)\n"
        << "  -h, --help              Show this help message and exit\n"
        << "\n"
        << "Example:\n"
        << "  " << prog_name << " -i eth0 -s 192.168.1.0/24 -s 10.0.0.0/8 -w 2000\n";
}

/**
 * @brief Parses command-line arguments into a Config struct.
 *
 * Exits with code 0 on --help, or code 1 on invalid / missing arguments.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Config Parsed configuration.
 */
inline Config parse_args(int argc, char* argv[]) {
    Config cfg;

    static const struct option long_options[] = {
        {"interface", required_argument, nullptr, 'i'},
        {"subnet",    required_argument, nullptr, 's'},
        {"wait",      required_argument, nullptr, 'w'},
        {"help",      no_argument,       nullptr, 'h'},
        {nullptr,     0,                 nullptr,  0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:s:w:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'i':
                cfg.interface = optarg;
                break;
            case 's':
                cfg.subnets.emplace_back(optarg);
                break;
            case 'w': {
                char* end = nullptr;
                long val = std::strtol(optarg, &end, 10);
                if (end == optarg || *end != '\0' || val <= 0) {
                    std::cerr << "Error: invalid timeout value '" << optarg << "'\n";
                    std::exit(1);
                }
                cfg.timeout_ms = static_cast<int>(val);
                break;
            }
            case 'h':
                print_help(argv[0]);
                std::exit(0);
            default:
                print_help(argv[0]);
                std::exit(1);
        }
    }

    // Validate required arguments
    if (cfg.interface.empty()) {
        std::cerr << "Error: -i / --interface is required.\n\n";
        print_help(argv[0]);
        std::exit(1);
    }
    if (cfg.subnets.empty()) {
        std::cerr << "Error: at least one -s / --subnet is required.\n\n";
        print_help(argv[0]);
        std::exit(1);
    }

    return cfg;
}

#endif // CONFIG_HPP
