/**
 * @file subnet.hpp
 * @brief IPv4/IPv6 CIDR subnet parsing and host IP generation.
 */
#ifndef SUBNET_HPP
#define SUBNET_HPP

#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Represents a parsed IPv4 or IPv6 CIDR subnet.
 *
 * Construct with a CIDR string; the constructor parses the notation,
 * computes the network address, and calculates the usable host count.
 */
class Subnet {
public:
    /**
     * @brief Construct a Subnet by parsing a CIDR string.
     * @param cidr  e.g. "192.168.0.0/25" or "fd00::/126"
     * @throws std::invalid_argument on malformed input.
     */
    explicit Subnet(const std::string& cidr);

    // Accessors
    const std::string& cidr()            const { return cidr_; }
    const std::string& network_address() const { return network_addr_; }
    int                prefix_length()   const { return prefix_len_; }
    bool               is_ipv6()         const { return is_ipv6_; }
    uint64_t           usable_host_count() const { return usable_host_count_; }

    /**
     * @brief Generate all scannable host IP address strings.
     *
     * IPv4: excludes network and broadcast (except /31, /32 per RFC 3021).
     * IPv6: excludes subnet-router anycast (except /127, /128 per RFC 6164).
     *
     * @return Vector of IP address strings.
     */
    std::vector<std::string> generate_host_ips() const;

private:
    std::string cidr_;
    std::string network_addr_;
    int         prefix_len_  = 0;
    bool        is_ipv6_     = false;
    uint64_t    usable_host_count_ = 0;

    /// Parse and populate fields for an IPv4 CIDR.
    void parse_ipv4(const std::string& addr_str);

    /// Parse and populate fields for an IPv6 CIDR.
    void parse_ipv6(const std::string& addr_str);
};

#endif // SUBNET_HPP
