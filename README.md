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

## Project Scope

MoonPCAP intentionally keeps packet mutation, deep application protocol
dissection and TLS fingerprinting out of scope for the first version. The goal
is a clear, reusable parsing and traffic analysis base that can later power
network teaching tools, security experiments, protocol fixtures and CLI
diagnostics in the MoonBit ecosystem.

## License

Apache-2.0.
