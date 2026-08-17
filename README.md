# MoonTraceGuard

MoonTraceGuard is a MoonBit packet-capture security audit and capture-quality
gate. It keeps a small built-in PCAP/PCAPNG reader for reproducible tests, but
the project goal is not to compete with general packet parsers. Its main value
is turning decoded traffic into actionable findings: cleartext service exposure,
sensitive service reachability, DNS anomalies, suspicious TCP signals,
retransmission hints, length buckets, risk scores and JSON/CSV/Text reports.

Existing MoonBit ecosystem projects such as `usagi-star/mooncap`,
`chensuiyi/packet` and `chensuiyi/pcap` cover generic offline parsing, header
decoding or capture bindings. MoonTraceGuard is intentionally positioned one
layer above them: a security/quality rules engine and CLI report tool that can
later consume those parsers as inputs.

## Features

- Security audit findings with severity, rule id, evidence and recommendation.
- Risk score summary for PCAP-derived traffic.
- Cleartext service and sensitive service exposure checks.
- DNS anomaly checks for unusually shaped questions and decode misses.
- TCP retransmission and TCP flag quality signals.
- Five-tuple flow identification and flow-oriented evidence.
- Packet, byte, direction, TCP flag and retransmission statistics.
- Protocol registry labels for services, DNS types, TCP options and IP
  protocols.
- Time range, IP, port and protocol filters.
- JSON, CSV and text report export helpers.
- CLI subcommands: `summary`, `flows`, `dns`, `audit`, `filter`, `export`.

## Quick Start

```bash
moon test
moon run cmd/main -- summary
moon run cmd/main -- flows
moon run cmd/main -- dns
moon run cmd/main -- audit
moon run cmd/main -- export json
moon run cmd/main -- export csv
moon run cmd/main -- export audit
```

The CLI currently ships with a small embedded fixture so tests and examples are
fully reproducible. Library users can pass any `Bytes` value to the parser API.

## Example

```moonbit
let capture = sample_pcap_fixture()
let parsed = parse_capture(capture)
let packets = decode_packets(parsed.packets)
let report = audit_decoded_packets(packets)
println(audit_to_text(report))
```

## CLI

`moon run cmd/main -- summary` prints packet totals, protocol totals and top
IP/port counters.

`moon run cmd/main -- flows` prints CSV flow rows sorted by byte count.

`moon run cmd/main -- dns` prints DNS transaction id, question name, type and
rcode for decoded DNS packets.

`moon run cmd/main -- audit` prints security and capture-quality findings with
rule ids, evidence and recommendations.

`moon run cmd/main -- filter` runs a port 53 UDP filter and summarizes the
filtered packets.

`moon run cmd/main -- export json`, `moon run cmd/main -- export csv` and
`moon run cmd/main -- export audit` export machine-readable reports.

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
- `audit_decoded_packets(packets)` produces security and quality findings.
- `audit_to_text(report)` and `audit_to_json(report)` produce audit output.
- `summary_to_json(summary)` and `flows_to_csv(flows)` produce traffic output.

## Tests

The test suite includes embedded binary PCAP and PCAPNG fixtures. The DNS PCAP
fixture is a complete Ethernet II + IPv4 + UDP + DNS query packet with matching
container lengths. The PCAPNG fixture validates SHB, IDB and EPB block parsing.
The TCP test uses a compact standard TCP header to verify port extraction,
offset parsing and flag naming.

## Project Scope

MoonTraceGuard intentionally keeps generic protocol-parser completeness,
packet mutation, live capture and TLS fingerprinting out of scope for the first
version. Parser coverage exists to support deterministic audit tests. The
long-term goal is a reusable MoonBit rules engine for packet-capture security
review, teaching labs, CI capture gates and network troubleshooting workflows.

## License

Apache-2.0.
