///|
fn json_string(value : String) -> String {
  let buf = StringBuilder()
  buf.write_char('"')
  for ch in value {
    match ch {
      '"' => buf.write_string("\\\"")
      '\\' => buf.write_string("\\\\")
      '\n' => buf.write_string("\\n")
      '\r' => buf.write_string("\\r")
      '\t' => buf.write_string("\\t")
      _ => buf.write_char(ch)
    }
  }
  buf.write_char('"')
  buf.to_string()
}

///|
fn counter_json(counter : Counter) -> String {
  "{ \"name\": \{json_string(counter.name)}, \"count\": \{counter.count} }"
}

///|
fn counters_json(counters : Array[Counter]) -> String {
  let parts : Array[String] = []
  for counter in counters {
    parts.push(counter_json(counter))
  }
  "[\{join_strings(parts, ", ")}]"
}

///|
fn flow_json(flow : FlowStats) -> String {
  "{ \"flow\": \{json_string(flow_label(flow.key))}, \"packets\": \{flow.packets}, \"bytes\": \{flow.bytes}, \"upstream_packets\": \{flow.upstream_packets}, \"downstream_packets\": \{flow.downstream_packets}, \"tcp_syn\": \{flow.tcp_syn}, \"tcp_fin\": \{flow.tcp_fin}, \"tcp_rst\": \{flow.tcp_rst}, \"last_tcp_sequence\": \{flow.last_tcp_sequence}, \"tcp_retransmissions\": \{flow.tcp_retransmissions} }"
}

///|
fn flows_json(flows : Array[FlowStats]) -> String {
  let parts : Array[String] = []
  for flow in flows {
    parts.push(flow_json(flow))
  }
  "[\{join_strings(parts, ", ")}]"
}

///|
pub fn summary_to_json(summary : TrafficSummary) -> String {
  "{ \"packets\": \{summary.packets}, \"bytes\": \{summary.bytes}, \"ipv4_packets\": \{summary.ipv4_packets}, \"ipv6_packets\": \{summary.ipv6_packets}, \"tcp_packets\": \{summary.tcp_packets}, \"udp_packets\": \{summary.udp_packets}, \"icmp_packets\": \{summary.icmp_packets}, \"dns_messages\": \{summary.dns_messages}, \"top_ips\": \{counters_json(summary.top_ips)}, \"top_ports\": \{counters_json(summary.top_ports)}, \"length_buckets\": \{counters_json(summary.length_buckets)}, \"flows\": \{flows_json(top_flows(summary, 20))} }"
}

///|
pub fn flows_to_csv(flows : Array[FlowStats]) -> String {
  let buf = StringBuilder()
  buf.write_string(
    "flow,packets,bytes,upstream_packets,downstream_packets,first_seen,last_seen,tcp_syn,tcp_fin,tcp_rst,last_tcp_sequence,tcp_retransmissions\n",
  )
  for flow in flows {
    buf.write_string(csv_escape(flow_label(flow.key)))
    buf.write_string(
      ",\{flow.packets},\{flow.bytes},\{flow.upstream_packets},\{flow.downstream_packets},\{flow.first_seen},\{flow.last_seen},\{flow.tcp_syn},\{flow.tcp_fin},\{flow.tcp_rst},\{flow.last_tcp_sequence},\{flow.tcp_retransmissions}\n",
    )
  }
  buf.to_string()
}

///|
pub fn summary_to_text(summary : TrafficSummary) -> String {
  let buf = StringBuilder()
  buf.write_string("MoonPCAP summary\n")
  buf.write_string("packets: \{summary.packets}\n")
  buf.write_string("bytes: \{summary.bytes}\n")
  buf.write_string(
    "ipv4: \{summary.ipv4_packets}, ipv6: \{summary.ipv6_packets}\n",
  )
  buf.write_string(
    "tcp: \{summary.tcp_packets}, udp: \{summary.udp_packets}, icmp: \{summary.icmp_packets}\n",
  )
  buf.write_string("dns messages: \{summary.dns_messages}\n")
  buf.write_string("top ips:\n")
  for ip in summary.top_ips {
    buf.write_string("  \{ip.name} \{ip.count}\n")
  }
  buf.write_string("top ports:\n")
  for port in summary.top_ports {
    buf.write_string("  \{port.name} \{port.count}\n")
  }
  buf.to_string()
}

///|
pub fn dns_to_text(packets : Array[DecodedPacket]) -> String {
  let buf = StringBuilder()
  for packet in packets {
    if packet.dns is Some(dns) {
      let side = if dns.is_response { "response" } else { "query" }
      for question in dns.questions {
        buf.write_string(
          "\{packet.timestamp_micros} \{side} id=\{dns.transaction_id} name=\{question.name} qtype=\{question.qtype} rcode=\{dns.rcode}\n",
        )
      }
    }
  }
  buf.to_string()
}
