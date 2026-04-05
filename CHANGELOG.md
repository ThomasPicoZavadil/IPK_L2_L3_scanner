# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Submit version

### Implemented functionality
- IPv4 (including /31 and /32) and IPv6 (including /127 and /128) CIDR parsing and host IP generation.
- Layer 2 scanning natively via ARP (IPv4) and NDP (IPv6) Neighbor Solicitations.
- Layer 3 reachability scanning natively via ICMPv4 Echo Requests and ICMPv6 Echo Requests.
- Dedicated background execution stream using `libpcap` in a thread for asynchronous packet capture and BPF filtering (`arp or icmp or icmp6`).
- Thread-safe aggregation via `ScanResultManager` to dynamically assemble and group L2 and L3 asynchronous responses per host.
- Ability to parse and reject malformed/truncated packets or wrong ether types.
- Interface listing helper (triggerable simply by running `-i`).
- Support for configurable reply wait timeouts via `-w` flag.
- Robust unit testing using Google Test covering packet listeners, CIDR subnet boundary behaviors, and checksums.

### Known limitations
- Sequential sending of probes may cause very large subnets (e.g. `/8` IPv4) to take a noticeably long time to scan.
- A bug can occur where the capture mechanism inadvertently catches the host system's own periodical background ARP scans.