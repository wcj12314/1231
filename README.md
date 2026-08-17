# MoonFlowGuard

MoonFlowGuard is a MoonBit **traffic-flow security audit and policy gate**. It
turns traffic — a flow table or decoded packets — into actionable findings
(cleartext service exposure, sensitive service reachability, DNS anomalies,
suspicious TCP signals, retransmission hints) and evaluates them against a
**configurable policy** to produce a `PASS` / `REVIEW` / `FAIL` verdict with a
CI-friendly exit code.

The project is deliberately **input-agnostic**. A security review rarely starts
from a capture file: it starts from a flow table exported by a firewall, an
EDR, or a SIEM. So MoonFlowGuard's first-class input is a **CSV flow-record
table**, and decoded packets (from PCAP/PCAPNG) are a second, equivalent input
path. The built-in PCAP reader is only a small adapter kept for reproducible
tests and examples — it is **not** the identity of the project.

That boundary is also the answer to why MoonFlowGuard does not duplicate the
Mooncakes parsing ecosystem. `usagi-star/mooncap` (offline PCAP/PCAPNG parsing
and protocol decoding), `chensuiyi/packet` (Ethernet/IP/TCP/UDP header parsing),
`chensuiyi/pcap` (capture bindings), `oyjh0381/moonipfix` (IPFIX flow telemetry
decoding) and `yhsrtty/moontls-parser` (TLS ClientHello parsing and JA3/JA4
fingerprints) answer *"what can be read out of a capture or flow export"*. MoonFlowGuard answers *"does this traffic pass the policy, which
security and quality risks does it carry, and how is the report exported"* —
and is designed to consume those parsers as backends. A full sweep of the
Mooncakes registry found **no project** doing policy-gated traffic security
auditing. The one conceptually adjacent policy engine,
`lllg123/moontrustflow`, is a Policy-as-Code toolkit for program data-flow
(source-to-sink taint) governance over `.mtf` models — a different subject
matter entirely, sharing only the generic "rules → findings → severity" shape.
`vectie/moonflow` shares part of the name but is a Moon Suite orchestration
engine.

## Features

- Security audit findings with severity, rule id, evidence and recommendation.
- **Inputs**: CSV flow-record tables (the primary input) and decoded packets
  from the built-in minimal reader.
- **Policy gate**: `PASS` / `REVIEW` / `FAIL` verdict with configurable JSON
  thresholds and denied rule ids; `FAIL` exits non-zero so CI can enforce it.
  (Distinct from mooncap's `validate`, which only checks file-format
  well-formedness — a format check, not a policy evaluation.)
- Risk score summary for traffic.
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
- CLI subcommands: `summary`, `flows`, `dns`, `audit`, `gate`, `gate-csv`,
  `policy`, `filter`, `export`.

## Quick Start

```bash
moon test
moon run cmd/main -- summary
moon run cmd/main -- flows
moon run cmd/main -- dns
moon run cmd/main -- audit
moon run cmd/main -- gate
moon run cmd/main -- gate-csv
moon run cmd/main -- policy
moon run cmd/main -- gate '{"max_risk_score": 0}'
moon run cmd/main -- gate-csv '{"max_risk_score": 0}'
moon run cmd/main -- export json
moon run cmd/main -- export csv
moon run cmd/main -- export audit
```

The CLI ships with small embedded fixtures (a DNS PCAP, a TCP PCAP, a PCAPNG
and a CSV flow table) so tests and examples are fully reproducible.

## The CSV flow-record input

The CSV schema is a flat projection of `DecodedPacket`:

```
timestamp_micros,source_ip,destination_ip,protocol,source_port,destination_port,tcp_flags,frame_length
1700000000000000,10.0.0.5,93.184.216.34,6,49152,80,24,66
```

- `protocol` is an IP protocol number (6=TCP, 17=UDP).
- `tcp_flags` is the raw TCP flag byte in decimal.
- The header row, blank lines and malformed rows are skipped tolerantly, so
  exports from other tools can be gated without clean-up.

```bash
moon run cmd/main -- gate-csv        # PASS on the embedded fixture
moon run cmd/main -- gate-csv '{"max_risk_score": 0}'   # FAIL, exit 1
```

## Example

```moonbit
let flows = sample_flow_csv_fixture()
let packets = parse_flow_csv(flows)
let report = audit_decoded_packets(packets)
println(audit_to_text(report))
let gate = evaluate_policy(report, default_policy())
println(gate_to_text(gate))
```

## Gate as a CI gate

`moon run cmd/main -- gate` audits the PCAP fixture under the default policy;
`gate-csv` does the same for the CSV flow table. To gate real traffic with
custom thresholds, pass a policy JSON as the second argument:

```bash
moon run cmd/main -- gate-csv '{"max_risk_score": 30, "max_high": 0, "deny_rule_ids": ["SENSITIVE-SERVICE-EXPOSURE"]}'
echo $?   # 0 on PASS, 1 on FAIL
```

Run `moon run cmd/main -- policy` to print the default policy, and
`export audit` to get a machine-readable report for downstream triage.

## CLI

- `summary` — packet totals, protocol totals and top IP/port counters.
- `flows` — CSV flow rows sorted by byte count.
- `dns` — DNS transaction id, question name, type and rcode.
- `audit` — security and capture-quality findings with rule ids and evidence.
- `gate [policy-json]` — evaluate decoded packets against a policy and exit
  non-zero on `FAIL`.
- `gate-csv [policy-json]` — same gate over a CSV flow-record table.
- `policy` — print the default policy as JSON.
- `filter` — run a port 53 UDP filter and summarize the filtered packets.
- `export json|csv|audit` — machine-readable reports.

## Library API

- **Inputs**: `parse_flow_csv` (CSV flow records), `parse_capture` /
  `parse_pcap` / `parse_pcapng` / `decode_packets` (built-in minimal reader
  for reproducible tests — designed to be swapped for `mooncap`/`packet`/
  `pcap` backends).
- **Gate and audit (the deliverable)**: `audit_decoded_packets`,
  `audit_flow_csv`, `evaluate_policy`, `gate_capture`, `gate_flow_csv`,
  `default_policy`, `parse_policy_json`, `gate_to_text`, `gate_to_json`,
  `policy_to_json`, `audit_to_text`, `audit_to_json`.
- **Analysis**: `analyze_decoded_packets`, `top_flows`, `apply_filter`,
  `packet_filter`.
- **Reports**: `summary_to_text`, `summary_to_json`, `flows_to_csv`,
  `dns_to_text`.

## Tests

The test suite covers embedded binary PCAP/PCAPNG fixtures, the CSV flow-table
parser (including blank/malformed-row tolerance), the audit rules and the gate
policy engine. The DNS PCAP fixture is a complete Ethernet II + IPv4 + UDP +
DNS query packet with matching container lengths; the PCAPNG fixture validates
SHB, IDB and EPB block parsing.

## Project Scope

MoonFlowGuard deliberately keeps generic protocol-parser completeness, packet
mutation, live capture and TLS fingerprinting out of scope for the first
version. Parser coverage exists only to support deterministic audit tests, and
the flow-table input means a reviewer can gate traffic without any parser at
all. Total code is roughly 8,100 lines, of which the well-known-port registry
is about 5,700 generated data lines produced by `tools/generate_registry.ps1`;
the audit/gate/report core, excluding the parsing layer and input adaptation,
is roughly 1,000 lines. The long-term goal is a reusable MoonBit rules engine
for traffic security review, teaching labs, CI traffic gates and network
troubleshooting workflows.

## License

Apache-2.0.
