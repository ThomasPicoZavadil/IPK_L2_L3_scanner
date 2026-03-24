/**
 * @file config.hpp
 * @brief CLI argument parsing for ipk-l2l3-scan.
 */
#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>

#include <getopt.h>

/**
 * @brief Encapsulates the parsed command-line configuration.
 *
 * Use the static factory Config::parse(argc, argv) to construct.
 */
class Config {
public:
    /// Parse command-line arguments. Exits on --help (code 0) or error (code 1).
    static Config parse(int argc, char* argv[]);

    /// Print usage information to stdout.
    static void print_help(const char* prog_name);

    // Accessors
    const std::string&              interface() const { return interface_; }
    const std::vector<std::string>& subnets()   const { return subnets_;   }
    int                             timeout_ms() const { return timeout_ms_; }

private:
    Config() = default;

    std::string              interface_;
    std::vector<std::string> subnets_;
    int                      timeout_ms_ = 1000;
};

// Inline implementation (header-only)

inline void Config::print_help(const char* prog_name) {
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

inline Config Config::parse(int argc, char* argv[]) {
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
                cfg.interface_ = optarg;
                break;
            case 's':
                cfg.subnets_.emplace_back(optarg);
                break;
            case 'w': {
                char* end = nullptr;
                long val = std::strtol(optarg, &end, 10);
                if (end == optarg || *end != '\0' || val <= 0) {
                    std::cerr << "Error: invalid timeout value '" << optarg << "'\n";
                    std::exit(1);
                }
                cfg.timeout_ms_ = static_cast<int>(val);
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

    if (cfg.interface_.empty()) {
        std::cerr << "Error: -i / --interface is required.\n\n";
        print_help(argv[0]);
        std::exit(1);
    }
    if (cfg.subnets_.empty()) {
        std::cerr << "Error: at least one -s / --subnet is required.\n\n";
        print_help(argv[0]);
        std::exit(1);
    }

    return cfg;
}

#endif // CONFIG_HPP
