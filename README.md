# MoonTraceGuard

MoonTraceGuard is a MoonBit packet-capture **security audit and capture-quality
gate**. It turns decoded traffic into actionable findings (cleartext service
exposure, sensitive service reachability, DNS anomalies, suspicious TCP signals,
retransmission hints) and evaluates them against a **configurable policy** to
produce a `PASS` / `REVIEW` / `FAIL` verdict with a CI-friendly exit code.

The project is intentionally **not** a general PCAP/PCAPNG parser. Existing
MoonBit ecosystem projects such as `usagi-star/mooncap` (offline PCAP/PCAPNG
parsing and protocol decoding), `chensuiyi/packet` (Ethernet/IP/TCP/UDP header
parsing) and `chensuiyi/pcap` (capture bindings) already cover that space.
MoonTraceGuard embeds only a small built-in reader **for reproducible tests and
examples**, and is designed to consume those parsers as backends. Its deliverable
is the layer above parsing: audit rules, risk scoring, policy evaluation and a
runable capture gate.

## Features

- Security audit findings with severity, rule id, evidence and recommendation.
- **Policy gate**: `PASS` / `REVIEW` / `FAIL` verdict with configurable JSON
  thresholds and denied rule ids; `FAIL` exits non-zero so CI can enforce it.
- Risk score summary for PCAP-derived traffic.
- Cleartext service and sensitive service exposure checks.
- DNS anomaly checks: unusual question shapes, decode misses and
  tunneling-shaped names.
- TCP signals: retransmission hints (sequence-based), zero-flag segments and
  SYN-only bursts.
- Five-tuple flow identification and flow-oriented evidence.
- Packet, byte, direction, TCP flag and retransmission statistics.
- Protocol registry labels for services, DNS types, TCP options and IP
  protocols.
- Time range, IP, port and protocol filters.
- JSON, CSV and text report export helpers.
- CLI subcommands: `summary`, `flows`, `dns`, `audit`, `gate`, `policy`,
  `filter`, `export`.

## Quick Start

```bash
moon test
moon run cmd/main -- summary
moon run cmd/main -- flows
moon run cmd/main -- dns
moon run cmd/main -- audit
moon run cmd/main -- gate
moon run cmd/main -- policy
moon run cmd/main -- gate '{"max_risk_score": 0}'
moon run cmd/main -- export json
moon run cmd/main -- export csv
moon run cmd/main -- export audit
```

The CLI ships with a small embedded fixture so tests and examples are fully
reproducible. Library users can pass any `Bytes` value to the parser API.

## Example

```moonbit
let capture = sample_pcap_fixture()
let parsed = parse_capture(capture)
let packets = decode_packets(parsed.packets)
let report = audit_decoded_packets(packets)
println(audit_to_text(report))
let gate = evaluate_policy(report, default_policy())
println(gate_to_text(gate))
```

## Gate as a CI gate

`moon run cmd/main -- gate` audits the fixture under the default policy. To gate
a real capture with custom thresholds, pass a policy JSON as the second
argument:

```bash
moon run cmd/main -- gate '{"max_risk_score": 30, "max_high": 0, "deny_rule_ids": ["SENSITIVE-SERVICE-EXPOSURE"]}'
echo $?   # 0 on PASS, 1 on FAIL
```

Run `moon run cmd/main -- policy` to print the default policy, and
`export audit` to get a machine-readable report for downstream triage.

## CLI

- `summary` — packet totals, protocol totals and top IP/port counters.
- `flows` — CSV flow rows sorted by byte count.
- `dns` — DNS transaction id, question name, type and rcode.
- `audit` — security and capture-quality findings with rule ids and evidence.
- `gate [policy-json]` — evaluate the audit report against a policy and exit
  non-zero on `FAIL`.
- `policy` — print the default policy as JSON.
- `filter` — run a port 53 UDP filter and summarize the filtered packets.
- `export json|csv|audit` — machine-readable reports.

## Library API

- **Gate and audit (the deliverable)**: `audit_decoded_packets`,
  `evaluate_policy`, `gate_capture`, `default_policy`, `parse_policy_json`,
  `gate_to_text`, `gate_to_json`, `policy_to_json`, `audit_to_text`,
  `audit_to_json`.
- **Analysis**: `analyze_decoded_packets`, `top_flows`, `apply_filter`,
  `packet_filter`.
- **Reports**: `summary_to_text`, `summary_to_json`, `flows_to_csv`,
  `dns_to_text`.
- **Built-in minimal reader (for reproducible tests)**: `parse_capture`,
  `parse_pcap`, `parse_pcapng`, `decode_packets`. This is a small embedded
  subset, not a general parser; MoonTraceGuard is designed to consume
  `mooncap`/`packet`/`pcap` as parsing backends.

## Tests

The test suite includes embedded binary PCAP and PCAPNG fixtures, plus unit
tests for the audit rules and the gate policy engine. The DNS PCAP fixture is a
complete Ethernet II + IPv4 + UDP + DNS query packet with matching container
lengths. The PCAPNG fixture validates SHB, IDB and EPB block parsing.

## Project Scope

MoonTraceGuard deliberately keeps generic protocol-parser completeness, packet
mutation, live capture and TLS fingerprinting out of scope for the first
version. Parser coverage exists only to support deterministic audit tests. The
core logic (parsing excluded) is roughly 2,000 lines; the well-known-port
registry is generated data produced by `tools/generate_registry.ps1`. The
long-term goal is a reusable MoonBit rules engine for packet-capture security
review, teaching labs, CI capture gates and network troubleshooting workflows.

## License

Apache-2.0.
