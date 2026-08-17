///|
fn main {
  let args = @env.args()
  let command = if args.length() > 1 { args[1] } else { "summary" }
  let capture = try! @pcap.parse_capture(@pcap.sample_pcap_fixture())
  let packets = @pcap.decode_packets(capture.packets)
  let summary = @pcap.analyze_decoded_packets(packets)
  match command {
    "summary" => println(@pcap.summary_to_text(summary))
    "flows" => println(@pcap.flows_to_csv(@pcap.top_flows(summary, 20)))
    "dns" => println(@pcap.dns_to_text(packets))
    "audit" =>
      println(@pcap.audit_to_text(@pcap.audit_decoded_packets(packets)))
    "filter" => {
      let filtered = @pcap.apply_filter(
        packets,
        @pcap.packet_filter(port=Some(53), protocol=Some(17)),
      )
      println(@pcap.summary_to_text(@pcap.analyze_decoded_packets(filtered)))
    }
    "export" => {
      let format = if args.length() > 2 { args[2] } else { "json" }
      match format {
        "csv" => println(@pcap.flows_to_csv(@pcap.top_flows(summary, 20)))
        "audit" =>
          println(@pcap.audit_to_json(@pcap.audit_decoded_packets(packets)))
        _ => println(@pcap.summary_to_json(summary))
      }
    }
    _ =>
      println(
        "MoonTraceGuard commands: summary | flows | dns | audit | filter | export [json|csv|audit]",
      )
  }
}
