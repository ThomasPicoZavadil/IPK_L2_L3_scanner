/**
 * @file test_packets.cpp
 * @brief GTest unit tests for packet parsing (listeners) and Internet Checksum.
 *
 * Each test constructs a raw byte buffer representing a valid or malformed
 * network frame and feeds it to the corresponding listener's parse_packet().
 */
#include <gtest/gtest.h>

#include "scan_result_manager.hpp"
#include "arp/arp_listener.hpp"
#include "icmpv4/icmpv4_listener.hpp"
#include "ndp/ndp_listener.hpp"
#include "icmpv6/icmpv6_listener.hpp"

#include <cstdint>
#include <cstring>
#include <vector>

// Standalone Internet Checksum (RFC 1071) - identical algorithm to the
// private static Icmpv4Crafter::calculate_checksum.
static uint16_t internet_checksum(const void* data, size_t length) {
    uint32_t sum = 0;
    auto ptr = reinterpret_cast<const uint16_t*>(data);

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }
    if (length == 1) {
        sum += *reinterpret_cast<const uint8_t*>(ptr);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

// Checksum Tests

// All-zero input: one's complement of 0 is 0xFFFF
TEST(Checksum, AllZeros) {
    uint8_t data[8] = {};
    EXPECT_EQ(internet_checksum(data, 8), 0xFFFFu);
}

// All-0xFF input (4 bytes = two 0xFFFF words): sum folds to 0xFFFF, complement = 0
TEST(Checksum, AllOnes) {
    uint8_t data[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_EQ(internet_checksum(data, 4), 0x0000u);
}

// Known ICMP Echo Request header:
// type=8, code=0, checksum=0, id=0x04D2, seq=0x0001
// After computing checksum the result should make the header verify to 0.
TEST(Checksum, IcmpEchoRequest) {
    uint8_t hdr[8] = {0x08, 0x00, 0x00, 0x00, 0x04, 0xD2, 0x00, 0x01};
    uint16_t cksum = internet_checksum(hdr, 8);
    // Place computed checksum back into the header and verify
    std::memcpy(hdr + 2, &cksum, 2);
    EXPECT_EQ(internet_checksum(hdr, 8), 0x0000u);
}

// Odd-length data (5 bytes) - tests the odd-byte tail handling
TEST(Checksum, OddLength) {
    uint8_t data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint16_t cksum = internet_checksum(data, 5);
    // Checksum is deterministic; just verify it's non-zero/non-FFFF
    EXPECT_NE(cksum, 0x0000u);
    EXPECT_NE(cksum, 0xFFFFu);
}

// Helper: build an ARP Reply frame (42 bytes minimum)
static std::vector<uint8_t> build_arp_reply(
    const uint8_t sha[6], const uint8_t spa[4],
    const uint8_t tha[6], const uint8_t tpa[4])
{
    std::vector<uint8_t> frame(42, 0);

    // Ethernet header (14 bytes)
    // dst MAC (6 bytes) - set to broadcast
    std::memset(frame.data(), 0xFF, 6);
    // src MAC (6 bytes) - copy sender HW addr
    std::memcpy(frame.data() + 6, sha, 6);
    // EtherType: ARP = 0x0806
    frame[12] = 0x08;
    frame[13] = 0x06;

    // ARP payload (28 bytes)
    uint8_t* arp = frame.data() + 14;
    // htype = 1 (Ethernet)
    arp[0] = 0x00; arp[1] = 0x01;
    // ptype = 0x0800 (IPv4)
    arp[2] = 0x08; arp[3] = 0x00;
    // hlen = 6, plen = 4
    arp[4] = 0x06; arp[5] = 0x04;
    // oper = 2 (Reply)
    arp[6] = 0x00; arp[7] = 0x02;
    // SHA (sender hardware address)
    std::memcpy(arp + 8, sha, 6);
    // SPA (sender protocol address)
    std::memcpy(arp + 14, spa, 4);
    // THA (target hardware address)
    std::memcpy(arp + 18, tha, 6);
    // TPA (target protocol address)
    std::memcpy(arp + 24, tpa, 4);

    return frame;
}

// Helper: build an ICMPv4 Echo Reply frame
static std::vector<uint8_t> build_icmpv4_echo_reply(const uint8_t src_ip[4]) {
    // Ethernet(14) + IPv4(20) + ICMP(8) = 42 bytes
    std::vector<uint8_t> frame(42, 0);

    // Ethernet header
    std::memset(frame.data(), 0xFF, 6);     // dst MAC
    std::memset(frame.data() + 6, 0x11, 6); // src MAC
    frame[12] = 0x08; frame[13] = 0x00;     // EtherType: IPv4

    // IPv4 header (20 bytes, no options)
    uint8_t* ip = frame.data() + 14;
    ip[0] = 0x45;                // version=4, IHL=5
    ip[1] = 0x00;                // DSCP/ECN
    ip[2] = 0x00; ip[3] = 28;   // total length = 20 + 8 = 28
    ip[4] = 0x00; ip[5] = 0x01; // identification
    ip[6] = 0x00; ip[7] = 0x00; // flags + fragment offset
    ip[8] = 64;                  // TTL
    ip[9] = 1;                   // protocol = ICMP (1)
    ip[10] = 0x00; ip[11] = 0x00; // checksum (skip for test)
    std::memcpy(ip + 12, src_ip, 4); // source IP
    ip[16] = 0xC0; ip[17] = 0xA8; ip[18] = 0x01; ip[19] = 0x01; // dst IP

    // ICMP header (8 bytes)
    uint8_t* icmp = frame.data() + 34;
    icmp[0] = 0;    // type = Echo Reply (0)
    icmp[1] = 0;    // code = 0
    icmp[2] = 0; icmp[3] = 0; // checksum (skip)
    icmp[4] = 0x04; icmp[5] = 0xD2; // id
    icmp[6] = 0x00; icmp[7] = 0x01; // seq

    return frame;
}

// Helper: build an ICMPv6 Echo Reply frame
static std::vector<uint8_t> build_icmpv6_echo_reply(const uint8_t src_ipv6[16]) {
    // Ethernet(14) + IPv6(40) + ICMPv6(8) = 62 bytes
    std::vector<uint8_t> frame(62, 0);

    // Ethernet header
    std::memset(frame.data(), 0xFF, 6);
    std::memset(frame.data() + 6, 0x22, 6);
    frame[12] = 0x86; frame[13] = 0xDD; // EtherType: IPv6

    // IPv6 header (40 bytes)
    uint8_t* ipv6 = frame.data() + 14;
    ipv6[0] = 0x60;            // version 6
    // payload length = 8 (ICMPv6 header only)
    ipv6[4] = 0x00; ipv6[5] = 0x08;
    ipv6[6] = 58;              // next header = ICMPv6
    ipv6[7] = 64;              // hop limit
    // source address (16 bytes at offset 8)
    std::memcpy(ipv6 + 8, src_ipv6, 16);
    // destination address (16 bytes at offset 24) - fill with ::2
    ipv6[39] = 0x02;

    // ICMPv6 header
    uint8_t* icmpv6 = frame.data() + 54;
    icmpv6[0] = 129; // type = Echo Reply
    icmpv6[1] = 0;   // code
    // checksum, id, seq - leave zero for test

    return frame;
}

// Helper: build an NDP Neighbor Advertisement frame
static std::vector<uint8_t> build_ndp_na(const uint8_t target_ipv6[16],
                                          const uint8_t target_mac[6]) {
    // Ethernet(14) + IPv6(40) + ICMPv6 NA fixed(24) + TgtLLA option(8) = 86
    std::vector<uint8_t> frame(86, 0);

    // Ethernet header
    std::memset(frame.data(), 0xFF, 6);
    std::memcpy(frame.data() + 6, target_mac, 6);
    frame[12] = 0x86; frame[13] = 0xDD;

    // IPv6 header
    uint8_t* ipv6 = frame.data() + 14;
    ipv6[0] = 0x60;
    // payload length = 24 (NA fixed) + 8 (TgtLLA option) = 32
    ipv6[4] = 0x00; ipv6[5] = 32;
    ipv6[6] = 58;   // next header = ICMPv6
    ipv6[7] = 255;  // hop limit
    // source address (offset 8) - use target IPv6
    std::memcpy(ipv6 + 8, target_ipv6, 16);
    // destination address (offset 24) - all-nodes multicast
    ipv6[24] = 0xFF; ipv6[25] = 0x02;
    ipv6[39] = 0x01;

    // ICMPv6 NA fixed part (24 bytes)
    uint8_t* icmpv6 = frame.data() + 54;
    icmpv6[0] = 136; // type = Neighbor Advertisement
    icmpv6[1] = 0;   // code
    // checksum (bytes 2-3) - skip for test
    // flags (byte 4): Solicited + Override = 0x60
    icmpv6[4] = 0x60;
    // target address (bytes 8-23)
    std::memcpy(icmpv6 + 8, target_ipv6, 16);

    // NDP option: Target Link-Layer Address (8 bytes)
    uint8_t* opt = frame.data() + 78;
    opt[0] = 2;      // type = Target Link-Layer Address
    opt[1] = 1;      // length = 1 (in units of 8 bytes)
    std::memcpy(opt + 2, target_mac, 6);

    return frame;
}

// ARP Listener Tests

TEST(ArpListener, ValidReply) {
    ScanResultManager mgr;
    ArpListener listener(mgr);

    uint8_t sha[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t spa[4] = {192, 168, 1, 10};
    uint8_t tha[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tpa[4] = {192, 168, 1, 1};

    auto frame = build_arp_reply(sha, spa, tha, tpa);
    EXPECT_TRUE(listener.parse_packet(frame.data(), static_cast<uint32_t>(frame.size())));

    // Verify ScanResultManager received the L2 update
    auto& results = mgr.results();
    ASSERT_EQ(results.count("192.168.1.10"), 1u);
    EXPECT_TRUE(results.at("192.168.1.10").l2_ok);
    EXPECT_EQ(results.at("192.168.1.10").mac_addr, "aa-bb-cc-dd-ee-ff");
}

TEST(ArpListener, TruncatedPacket) {
    ScanResultManager mgr;
    ArpListener listener(mgr);

    std::vector<uint8_t> tiny(10, 0);
    EXPECT_FALSE(listener.parse_packet(tiny.data(), static_cast<uint32_t>(tiny.size())));
}

TEST(ArpListener, WrongEtherType) {
    ScanResultManager mgr;
    ArpListener listener(mgr);

    uint8_t sha[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t spa[4] = {192, 168, 1, 10};
    uint8_t tha[6] = {};
    uint8_t tpa[4] = {};

    auto frame = build_arp_reply(sha, spa, tha, tpa);
    // Overwrite EtherType to IPv4 (0x0800) instead of ARP (0x0806)
    frame[12] = 0x08; frame[13] = 0x00;
    EXPECT_FALSE(listener.parse_packet(frame.data(), static_cast<uint32_t>(frame.size())));
}

// ICMPv4 Listener Tests

TEST(Icmpv4Listener, ValidEchoReply) {
    ScanResultManager mgr;
    Icmpv4Listener listener(mgr);

    uint8_t src_ip[4] = {10, 0, 0, 1};
    auto frame = build_icmpv4_echo_reply(src_ip);
    EXPECT_TRUE(listener.parse_packet(frame.data(), static_cast<uint32_t>(frame.size())));

    auto& results = mgr.results();
    ASSERT_EQ(results.count("10.0.0.1"), 1u);
    EXPECT_TRUE(results.at("10.0.0.1").l3_ok);
}

TEST(Icmpv4Listener, TruncatedPacket) {
    ScanResultManager mgr;
    Icmpv4Listener listener(mgr);

    std::vector<uint8_t> tiny(10, 0);
    EXPECT_FALSE(listener.parse_packet(tiny.data(), static_cast<uint32_t>(tiny.size())));
}

TEST(Icmpv4Listener, WrongEtherType) {
    ScanResultManager mgr;
    Icmpv4Listener listener(mgr);

    uint8_t src_ip[4] = {10, 0, 0, 1};
    auto frame = build_icmpv4_echo_reply(src_ip);
    // Change EtherType to ARP (0x0806)
    frame[12] = 0x08; frame[13] = 0x06;
    EXPECT_FALSE(listener.parse_packet(frame.data(), static_cast<uint32_t>(frame.size())));
}

// ICMPv6 Listener Tests

TEST(Icmpv6Listener, ValidEchoReply) {
    ScanResultManager mgr;
    Icmpv6Listener listener(mgr);

    // 2001:0db8::0001
    uint8_t src[16] = {0x20, 0x01, 0x0D, 0xB8, 0,0,0,0, 0,0,0,0, 0,0,0,0x01};
    auto frame = build_icmpv6_echo_reply(src);
    EXPECT_TRUE(listener.parse_packet(frame.data(), static_cast<uint32_t>(frame.size())));

    auto& results = mgr.results();
    ASSERT_EQ(results.count("2001:db8::1"), 1u);
    EXPECT_TRUE(results.at("2001:db8::1").l3_ok);
}

TEST(Icmpv6Listener, TruncatedPacket) {
    ScanResultManager mgr;
    Icmpv6Listener listener(mgr);

    std::vector<uint8_t> tiny(10, 0);
    EXPECT_FALSE(listener.parse_packet(tiny.data(), static_cast<uint32_t>(tiny.size())));
}

TEST(Icmpv6Listener, WrongEtherType) {
    ScanResultManager mgr;
    Icmpv6Listener listener(mgr);

    uint8_t src[16] = {0x20, 0x01, 0x0D, 0xB8, 0,0,0,0, 0,0,0,0, 0,0,0,0x01};
    auto frame = build_icmpv6_echo_reply(src);
    // Change EtherType to IPv4
    frame[12] = 0x08; frame[13] = 0x00;
    EXPECT_FALSE(listener.parse_packet(frame.data(), static_cast<uint32_t>(frame.size())));
}

// NDP Listener Tests

TEST(NdpListener, ValidNeighborAdvertisement) {
    ScanResultManager mgr;
    NdpListener listener(mgr);

    // fe80::1
    uint8_t target_ip[16] = {0xFE, 0x80, 0,0,0,0,0,0, 0,0,0,0,0,0,0,0x01};
    uint8_t target_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

    auto frame = build_ndp_na(target_ip, target_mac);
    EXPECT_TRUE(listener.parse_packet(frame.data(), static_cast<uint32_t>(frame.size())));

    auto& results = mgr.results();
    ASSERT_EQ(results.count("fe80::1"), 1u);
    EXPECT_TRUE(results.at("fe80::1").l2_ok);
    EXPECT_EQ(results.at("fe80::1").mac_addr, "de-ad-be-ef-00-01");
}

TEST(NdpListener, TruncatedPacket) {
    ScanResultManager mgr;
    NdpListener listener(mgr);

    std::vector<uint8_t> tiny(10, 0);
    EXPECT_FALSE(listener.parse_packet(tiny.data(), static_cast<uint32_t>(tiny.size())));
}

TEST(NdpListener, WrongEtherType) {
    ScanResultManager mgr;
    NdpListener listener(mgr);

    uint8_t target_ip[16] = {0xFE, 0x80, 0,0,0,0,0,0, 0,0,0,0,0,0,0,0x01};
    uint8_t target_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

    auto frame = build_ndp_na(target_ip, target_mac);
    // Change EtherType to IPv4
    frame[12] = 0x08; frame[13] = 0x00;
    EXPECT_FALSE(listener.parse_packet(frame.data(), static_cast<uint32_t>(frame.size())));
}

// ScanResultManager Integration

TEST(ScanResultManagerIntegration, ArpAndIcmpv4Combined) {
    ScanResultManager mgr;
    ArpListener arp(mgr);
    Icmpv4Listener icmpv4(mgr);

    // Pre-populate target
    mgr.add_target("192.168.1.10", false);

    // Feed ARP reply
    uint8_t sha[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t spa[4] = {192, 168, 1, 10};
    uint8_t tha[6] = {};
    uint8_t tpa[4] = {};
    auto arp_frame = build_arp_reply(sha, spa, tha, tpa);
    EXPECT_TRUE(arp.parse_packet(arp_frame.data(), static_cast<uint32_t>(arp_frame.size())));

    // Feed ICMPv4 echo reply
    uint8_t src_ip[4] = {192, 168, 1, 10};
    auto icmp_frame = build_icmpv4_echo_reply(src_ip);
    EXPECT_TRUE(icmpv4.parse_packet(icmp_frame.data(), static_cast<uint32_t>(icmp_frame.size())));

    // Both L2 and L3 should be OK
    auto& results = mgr.results();
    ASSERT_EQ(results.count("192.168.1.10"), 1u);
    const auto& host = results.at("192.168.1.10");
    EXPECT_TRUE(host.l2_ok);
    EXPECT_EQ(host.mac_addr, "aa-bb-cc-dd-ee-ff");
    EXPECT_TRUE(host.l3_ok);
    EXPECT_FALSE(host.is_ipv6);
}

TEST(ScanResultManagerIntegration, NdpAndIcmpv6Combined) {
    ScanResultManager mgr;
    NdpListener ndp(mgr);
    Icmpv6Listener icmpv6(mgr);

    // fe80::1
    uint8_t target_ip[16] = {0xFE, 0x80, 0,0,0,0,0,0, 0,0,0,0,0,0,0,0x01};
    uint8_t target_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

    mgr.add_target("fe80::1", true);

    // Feed NDP NA
    auto na_frame = build_ndp_na(target_ip, target_mac);
    EXPECT_TRUE(ndp.parse_packet(na_frame.data(), static_cast<uint32_t>(na_frame.size())));

    // Feed ICMPv6 Echo Reply - source must be fe80::1
    auto echo_frame = build_icmpv6_echo_reply(target_ip);
    EXPECT_TRUE(icmpv6.parse_packet(echo_frame.data(), static_cast<uint32_t>(echo_frame.size())));

    auto& results = mgr.results();
    ASSERT_EQ(results.count("fe80::1"), 1u);
    const auto& host = results.at("fe80::1");
    EXPECT_TRUE(host.l2_ok);
    EXPECT_EQ(host.mac_addr, "de-ad-be-ef-00-01");
    EXPECT_TRUE(host.l3_ok);
    EXPECT_TRUE(host.is_ipv6);
}
