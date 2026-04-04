/**
 * @file test_cidr.cpp
 * @brief GTest unit tests for Subnet CIDR parsing and host IP generation.
 */
#include <gtest/gtest.h>
#include "subnet.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

// IPv4 Tests

/// /32 - single host
TEST(SubnetIPv4, Slash32_SingleHost) {
    Subnet s("10.0.0.1/32");

    EXPECT_EQ(s.network_address(), "10.0.0.1");
    EXPECT_EQ(s.prefix_length(), 32);
    EXPECT_FALSE(s.is_ipv6());
    EXPECT_EQ(s.usable_host_count(), 1u);

    auto hosts = s.generate_host_ips();
    ASSERT_EQ(hosts.size(), 1u);
    EXPECT_EQ(hosts[0], "10.0.0.1");
}

/// /31 - point-to-point link (RFC 3021), both addresses usable
TEST(SubnetIPv4, Slash31_PointToPoint) {
    Subnet s("192.168.1.0/31");

    EXPECT_EQ(s.network_address(), "192.168.1.0");
    EXPECT_EQ(s.prefix_length(), 31);
    EXPECT_EQ(s.usable_host_count(), 2u);

    auto hosts = s.generate_host_ips();
    ASSERT_EQ(hosts.size(), 2u);
    EXPECT_EQ(hosts[0], "192.168.1.0");
    EXPECT_EQ(hosts[1], "192.168.1.1");
}

/// /30 - verifies network address calculation from non-aligned input
TEST(SubnetIPv4, Slash30_NetworkAlignment) {
    Subnet s("192.168.0.1/30");

    // Input 192.168.0.1 should be masked to network 192.168.0.0
    EXPECT_EQ(s.network_address(), "192.168.0.0");
    EXPECT_EQ(s.prefix_length(), 30);
    EXPECT_EQ(s.usable_host_count(), 2u);

    auto hosts = s.generate_host_ips();
    ASSERT_EQ(hosts.size(), 2u);
    EXPECT_EQ(hosts[0], "192.168.0.1");
    EXPECT_EQ(hosts[1], "192.168.0.2");
}

/// /24 - standard subnet, 254 usable hosts (excludes network + broadcast)
TEST(SubnetIPv4, Slash24_StandardSubnet) {
    Subnet s("192.168.0.0/24");

    EXPECT_EQ(s.network_address(), "192.168.0.0");
    EXPECT_EQ(s.prefix_length(), 24);
    EXPECT_EQ(s.usable_host_count(), 254u);

    auto hosts = s.generate_host_ips();
    ASSERT_EQ(hosts.size(), 254u);
    EXPECT_EQ(hosts.front(), "192.168.0.1");
    EXPECT_EQ(hosts.back(), "192.168.0.254");
}

// IPv6 Tests

/// /128 - single host
TEST(SubnetIPv6, Slash128_SingleHost) {
    Subnet s("::1/128");

    EXPECT_EQ(s.network_address(), "::1");
    EXPECT_EQ(s.prefix_length(), 128);
    EXPECT_TRUE(s.is_ipv6());
    EXPECT_EQ(s.usable_host_count(), 1u);

    auto hosts = s.generate_host_ips();
    ASSERT_EQ(hosts.size(), 1u);
    EXPECT_EQ(hosts[0], "::1");
}

/// /127 - point-to-point link (RFC 6164), both addresses usable
TEST(SubnetIPv6, Slash127_PointToPoint) {
    Subnet s("fe80::/127");

    EXPECT_EQ(s.network_address(), "fe80::");
    EXPECT_EQ(s.prefix_length(), 127);
    EXPECT_EQ(s.usable_host_count(), 2u);

    auto hosts = s.generate_host_ips();
    ASSERT_EQ(hosts.size(), 2u);
    EXPECT_EQ(hosts[0], "fe80::");
    EXPECT_EQ(hosts[1], "fe80::1");
}

/// /120 - 256 total addresses, 255 usable (exclude subnet-router anycast)
TEST(SubnetIPv6, Slash120) {
    Subnet s("2001:db8::/120");

    EXPECT_EQ(s.network_address(), "2001:db8::");
    EXPECT_EQ(s.prefix_length(), 120);
    EXPECT_EQ(s.usable_host_count(), 255u);

    auto hosts = s.generate_host_ips();
    ASSERT_EQ(hosts.size(), 255u);
    EXPECT_EQ(hosts.front(), "2001:db8::1");
    EXPECT_EQ(hosts.back(), "2001:db8::ff");
}

// Error Handling Tests

/// Invalid IPv4 octet (256 > 255)
TEST(SubnetErrors, InvalidIPv4Octet) {
    EXPECT_THROW(Subnet("256.0.0.1/24"), std::invalid_argument);
}

/// Completely invalid address string
TEST(SubnetErrors, InvalidAddressString) {
    EXPECT_THROW(Subnet("invalid/24"), std::invalid_argument);
}

/// IPv4 prefix too large
TEST(SubnetErrors, IPv4PrefixTooLarge) {
    EXPECT_THROW(Subnet("192.168.0.0/33"), std::invalid_argument);
}

/// IPv6 prefix too large
TEST(SubnetErrors, IPv6PrefixTooLarge) {
    EXPECT_THROW(Subnet("::1/129"), std::invalid_argument);
}

/// Missing slash in CIDR notation
TEST(SubnetErrors, MissingSlash) {
    EXPECT_THROW(Subnet("192.168.0.0"), std::invalid_argument);
}
