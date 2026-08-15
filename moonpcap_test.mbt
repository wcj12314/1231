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
