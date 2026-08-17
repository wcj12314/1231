///|
test "parse classic pcap fixture" {
  let capture = try! parse_capture(sample_dns_pcap_fixture())
  @test.assert_eq(capture.packets.length(), 1)
  let packet = capture.packets[0]
  @test.assert_eq(packet.captured_length, 71)
  @test.assert_eq(packet.payload.length(), 71)
}

///|
test "parse standard tcp flags" {
  let tcp = try! parse_tcp(
    b"\xDB\x2D\x02\x34\x00\x00\x00\x10\x00\x00\x00\x00\x50\x12\x20\x00\x00\x00\x00\x00",
  )
  @test.assert_eq(tcp.source_port, 56109)
  @test.assert_eq(tcp.destination_port, 564)
  @test.assert_eq(tcp.data_offset, 20)
  @test.assert_eq(tcp_flag_names(tcp.flags), "SYN|ACK")
}

///|
test "parse dns query fixture" {
  let capture = try! parse_capture(sample_dns_pcap_fixture())
  @test.assert_eq(capture.packets.length(), 1)
  let decoded = decode_packets(capture.packets)
  @test.assert_eq(decoded.length(), 1)
  @test.assert_eq(decoded[0].source_ip, "192.168.0.2")
  @test.assert_eq(decoded[0].destination_ip, "8.8.8.8")
  @test.assert_eq(decoded[0].protocol, 17)
  @test.assert_eq(decoded[0].source_port, 49153)
  @test.assert_eq(decoded[0].destination_port, 53)
  guard decoded[0].dns is Some(dns) else { fail("expected dns message") }
  @test.assert_eq(dns.transaction_id, 0x1234)
  @test.assert_eq(dns.is_response, false)
  @test.assert_eq(dns.question_count, 1)
  @test.assert_eq(dns.questions[0].name, "example.com")
  @test.assert_eq(dns.questions[0].qtype, 1)
}

///|
test "pcapng block fixture" {
  let capture = try! parse_capture(sample_pcapng_fixture())
  @test.assert_eq(capture.interfaces.length(), 1)
  @test.assert_eq(capture.interfaces[0].link_type, 1)
  @test.assert_eq(capture.packets.length(), 1)
  @test.assert_eq(capture.packets[0].captured_length, 4)
}

///|
test "traffic summary and report exporters" {
  let capture = try! parse_capture(sample_dns_pcap_fixture())
  let packets = decode_packets(capture.packets)
  let summary = analyze_decoded_packets(packets)
  @test.assert_eq(summary.packets, 1)
  @test.assert_eq(summary.bytes, 71)
  @test.assert_eq(summary.ipv4_packets, 1)
  @test.assert_eq(summary.udp_packets, 1)
  @test.assert_eq(summary.dns_messages, 1)
  @test.assert_eq(summary.flows.length(), 1)
  @test.assert_eq(summary.flows[0].packets, 1)
  @test.assert_eq(summary.top_ports[0].name, "49153/dynamic-port-49153")
  let json = summary_to_json(summary)
  assert_true(json.contains("\"dns_messages\": 1"))
  let csv = flows_to_csv(summary.flows)
  assert_true(csv.contains("192.168.0.2:49153/dynamic-port-49153"))
}

///|
test "filters select by ip port and protocol" {
  let capture = try! parse_capture(sample_dns_pcap_fixture())
  let packets = decode_packets(capture.packets)
  let by_ip = apply_filter(packets, packet_filter(ip=Some("8.8.8.8")))
  @test.assert_eq(by_ip.length(), 1)
  let by_tcp = apply_filter(packets, packet_filter(protocol=Some(6)))
  @test.assert_eq(by_tcp.length(), 0)
}

///|
test "audit report flags cleartext service" {
  let capture = try! parse_capture(sample_dns_pcap_fixture())
  let packets = decode_packets(capture.packets)
  let report = audit_decoded_packets(packets)
  assert_true(report.findings.length() > 0)
  let text = audit_to_text(report)
  assert_true(text.contains("DNS-CLEARTEXT-METADATA"))
  assert_true(text.contains("example.com"))
}

///|
fn synthetic_tcp(
  source_port : Int,
  destination_port : Int,
  flags : Int,
) -> DecodedPacket {
  DecodedPacket::{
    timestamp_micros: 0L,
    frame_length: 60,
    ether_type: 0x0800,
    vlan_id: None,
    source_ip: "192.168.1.1",
    destination_ip: "192.168.1.2",
    protocol: 6,
    source_port,
    destination_port,
    tcp_flags: flags,
    tcp_sequence: 100,
    tcp_payload_length: 0,
    dns: None,
  }
}

///|
fn has_rule(report : AuditReport, rule_id : String) -> Bool {
  for finding in report.findings {
    if finding.rule_id == rule_id {
      return true
    }
  }
  false
}

///|
fn has_finding(findings : Array[AuditFinding], rule_id : String) -> Bool {
  for finding in findings {
    if finding.rule_id == rule_id {
      return true
    }
  }
  false
}

///|
test "gate passes a clean capture under default policy" {
  let result = gate_capture([synthetic_tcp(12345, 443, 0x02)], default_policy())
  assert_true(result.verdict is Pass)
  @test.assert_eq(gate_to_text(result).contains("PASS"), true)
}

///|
test "gate fails when a sensitive service is exposed" {
  let result = gate_capture(
    [synthetic_tcp(12345, 3306, 0x18)],
    default_policy(),
  )
  assert_true(result.verdict is Fail)
  assert_true(gate_to_text(result).contains("SENSITIVE-SERVICE-EXPOSURE"))
}

///|
test "gate honors a custom max_risk_score policy" {
  let capture = try! parse_capture(sample_dns_pcap_fixture())
  let packets = decode_packets(capture.packets)
  let strict = AuditPolicy::{
    max_risk_score: 0,
    max_high: 0,
    max_medium: 0,
    max_low: 0,
    deny_rule_ids: [],
  }
  let result = gate_capture(packets, strict)
  assert_true(result.verdict is Fail)
  assert_true(gate_to_text(result).contains("RISK-SCORE"))
}

///|
test "policy json parsing fills defaults" {
  let policy = parse_policy_json(
    "{\"max_risk_score\": 5, \"deny_rule_ids\": [\"DNS-CLEARTEXT-METADATA\"]}",
  )
  @test.assert_eq(policy.max_risk_score, 5)
  @test.assert_eq(policy.max_high, default_policy().max_high)
  @test.assert_eq(policy.deny_rule_ids.length(), 1)
  @test.assert_eq(policy.deny_rule_ids[0], "DNS-CLEARTEXT-METADATA")
  let bad = parse_policy_json("not json")
  @test.assert_eq(bad.max_risk_score, default_policy().max_risk_score)
}

///|
test "syn burst rule flags scan-like flow" {
  let packets = [
    synthetic_tcp(12345, 22, 0x02),
    synthetic_tcp(12345, 22, 0x02),
    synthetic_tcp(12345, 22, 0x02),
  ]
  let report = audit_decoded_packets(packets)
  assert_true(has_rule(report, "SYN-BURST-NO-COMPLETION"))
}

///|
test "dns tunnel shape rule flags deep name" {
  let dns = DnsMessage::{
    transaction_id: 1,
    is_response: false,
    opcode: 0,
    rcode: 0,
    question_count: 1,
    answer_count: 0,
    questions: [
      DnsQuestion::{ name: "a.b.c.d.e.f.g.h.example.com", qtype: 16, qclass: 1 },
    ],
  }
  let packet = DecodedPacket::{
    timestamp_micros: 0L,
    frame_length: 60,
    ether_type: 0x0800,
    vlan_id: None,
    source_ip: "192.168.1.1",
    destination_ip: "8.8.8.8",
    protocol: 17,
    source_port: 49153,
    destination_port: 53,
    tcp_flags: 0,
    tcp_sequence: 0,
    tcp_payload_length: 0,
    dns: Some(dns),
  }
  let report = audit_decoded_packets([packet])
  assert_true(has_rule(report, "DNS-TUNNEL-SHAPE"))
}

///|
test "parse flow csv into decoded packets" {
  let packets = parse_flow_csv(sample_flow_csv_fixture())
  @test.assert_eq(packets.length(), 2)
  @test.assert_eq(packets[0].source_ip, "10.0.0.5")
  @test.assert_eq(packets[0].destination_ip, "93.184.216.34")
  @test.assert_eq(packets[0].protocol, 6)
  @test.assert_eq(packets[0].source_port, 49152)
  @test.assert_eq(packets[0].destination_port, 80)
  @test.assert_eq(packets[0].tcp_flags, 24)
  @test.assert_eq(packets[0].frame_length, 66)
  @test.assert_eq(packets[1].destination_port, 25)
}

///|
test "parse flow csv tolerates blank and malformed rows" {
  let packets = parse_flow_csv(
    "timestamp_micros,source_ip,destination_ip,protocol,source_port,destination_port,tcp_flags,frame_length\n\n1700000000000000,10.0.0.5,93.184.216.34,6,49152,80,24,66\nbad,row\n   \n",
  )
  @test.assert_eq(packets.length(), 1)
  @test.assert_eq(packets[0].destination_port, 80)
}

///|
test "gate passes the flow csv fixture under default policy" {
  let result = gate_flow_csv(sample_flow_csv_fixture(), default_policy())
  assert_true(result.verdict is Pass)
  assert_true(has_finding(result.findings, "CLEARTEXT-SERVICE"))
}

///|
test "gate fails on a csv flow to a sensitive service" {
  let result = gate_flow_csv(
    "timestamp_micros,source_ip,destination_ip,protocol,source_port,destination_port,tcp_flags,frame_length\n1700000000000000,10.0.0.5,192.168.0.10,6,49153,3306,24,66\n",
    default_policy(),
  )
  assert_true(result.verdict is Fail)
  assert_true(has_finding(result.findings, "SENSITIVE-SERVICE-EXPOSURE"))
}
