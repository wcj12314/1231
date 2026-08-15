# MoonPCAP

MoonPCAP is a MoonBit library and command line tool for parsing PCAP/PCAPNG
captures and producing practical traffic summaries. The project focuses on the
capture container and lower network layers, so it can complement higher-level
TLS fingerprinting tools instead of duplicating them.

## Features

- PCAP global header and packet record parsing.
- PCAPNG Section Header Block, Interface Description Block and Enhanced Packet
  Block parsing.
- Endianness-aware binary reader with checked offsets.
- Ethernet II and VLAN decoding.
- IPv4, IPv6, TCP, UDP and ICMP basic decoding.
- Five-tuple flow identification and TCP flow aggregation.
- Packet, byte, direction, TCP flag and retransmission statistics.
- DNS query/response parsing for common message shapes.
- Time range, IP, port and protocol filters.
- JSON and CSV report export helpers.
- CLI subcommands: `summary`, `flows`, `dns`, `filter`, `export`.

## Quick Start

```bash
moon test
moon run cmd/main -- summary
moon run cmd/main -- flows
moon run cmd/main -- dns
moon run cmd/main -- export json
moon run cmd/main -- export csv
```

The CLI currently ships with a small embedded fixture so tests and examples are
fully reproducible. Library users can pass any `Bytes` value to the parser API.

## Example

```moonbit
let capture = sample_pcap_fixture()
let parsed = parse_capture(capture)
let report = analyze_packets(parsed.packets)
println(summary_to_json(report))
```

## CLI

`moon run cmd/main -- summary` prints packet totals, protocol totals and top
IP/port counters.

`moon run cmd/main -- flows` prints CSV flow rows sorted by byte count.

`moon run cmd/main -- dns` prints DNS transaction id, question name, type and
rcode for decoded DNS packets.

`moon run cmd/main -- filter` runs a port 53 UDP filter and summarizes the
filtered packets.

`moon run cmd/main -- export json` and `moon run cmd/main -- export csv` export
machine-readable reports.

## Library API

- `parse_capture(data)` automatically detects classic PCAP and PCAPNG.
- `parse_pcap(data)` parses classic PCAP global headers and packet records.
- `parse_pcapng(data)` parses SHB, IDB and EPB blocks.
- `decode_packets(records)` decodes Ethernet, VLAN, IPv4/IPv6, TCP, UDP, ICMP
  and DNS where possible.
- `analyze_decoded_packets(packets)` produces packet, byte, protocol, DNS, Top
  IP, Top Port, packet length bucket and flow statistics.
- `apply_filter(packets, packet_filter(...))` filters by time, IP, port and
  protocol.
- `summary_to_json(summary)` and `flows_to_csv(flows)` produce report output.

## Tests

The test suite includes embedded binary PCAP and PCAPNG fixtures. The DNS PCAP
fixture is a complete Ethernet II + IPv4 + UDP + DNS query packet with matching
container lengths. The PCAPNG fixture validates SHB, IDB and EPB block parsing.
The TCP test uses a compact standard TCP header to verify port extraction,
offset parsing and flag naming.

## Project Scope

MoonPCAP intentionally keeps packet mutation, deep application protocol
dissection and TLS fingerprinting out of scope for the first version. The goal
is a clear, reusable parsing and traffic analysis base that can later power
network teaching tools, security experiments, protocol fixtures and CLI
diagnostics in the MoonBit ecosystem.

## License

Apache-2.0.
