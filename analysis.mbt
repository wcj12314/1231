///|
pub fn flow_key(packet : DecodedPacket) -> FlowKey {
  FlowKey::{
    source_ip: packet.source_ip,
    destination_ip: packet.destination_ip,
    source_port: packet.source_port,
    destination_port: packet.destination_port,
    protocol: packet.protocol,
  }
}

///|
fn same_flow(a : FlowKey, b : FlowKey) -> Bool {
  a.source_ip == b.source_ip &&
  a.destination_ip == b.destination_ip &&
  a.source_port == b.source_port &&
  a.destination_port == b.destination_port &&
  a.protocol == b.protocol
}

///|
fn reverse_flow(a : FlowKey, b : FlowKey) -> Bool {
  a.source_ip == b.destination_ip &&
  a.destination_ip == b.source_ip &&
  a.source_port == b.destination_port &&
  a.destination_port == b.source_port &&
  a.protocol == b.protocol
}

///|
fn empty_flow(packet : DecodedPacket) -> FlowStats {
  FlowStats::{
    key: flow_key(packet),
    packets: 0,
    bytes: 0,
    upstream_packets: 0,
    downstream_packets: 0,
    first_seen: packet.timestamp_micros,
    last_seen: packet.timestamp_micros,
    tcp_syn: 0,
    tcp_fin: 0,
    tcp_rst: 0,
    last_tcp_sequence: -1,
    tcp_retransmissions: 0,
  }
}

///|
fn update_flag_counts(flow : FlowStats, packet : DecodedPacket) -> FlowStats {
  let syn_inc = if (packet.tcp_flags & 0x02) != 0 { 1 } else { 0 }
  let fin_inc = if (packet.tcp_flags & 0x01) != 0 { 1 } else { 0 }
  let rst_inc = if (packet.tcp_flags & 0x04) != 0 { 1 } else { 0 }
  FlowStats::{
    ..flow,
    tcp_syn: flow.tcp_syn + syn_inc,
    tcp_fin: flow.tcp_fin + fin_inc,
    tcp_rst: flow.tcp_rst + rst_inc,
  }
}

///|
fn may_retransmit(flow : FlowStats, packet : DecodedPacket) -> Bool {
  packet.protocol == 6 &&
  packet.tcp_payload_length > 0 &&
  flow.last_tcp_sequence >= 0 &&
  packet.tcp_sequence <= flow.last_tcp_sequence
}

///|
fn add_packet_to_flow(
  flow : FlowStats,
  packet : DecodedPacket,
  downstream : Bool,
) -> FlowStats {
  let flagged = update_flag_counts(flow, packet)
  let upstream_inc = if downstream { 0 } else { 1 }
  let downstream_inc = if downstream { 1 } else { 0 }
  let retrans_inc = if may_retransmit(flagged, packet) { 1 } else { 0 }
  FlowStats::{
    ..flagged,
    packets: flagged.packets + 1,
    bytes: flagged.bytes + packet.frame_length,
    upstream_packets: flagged.upstream_packets + upstream_inc,
    downstream_packets: flagged.downstream_packets + downstream_inc,
    first_seen: if packet.timestamp_micros < flagged.first_seen {
      packet.timestamp_micros
    } else {
      flagged.first_seen
    },
    last_seen: if packet.timestamp_micros > flagged.last_seen {
      packet.timestamp_micros
    } else {
      flagged.last_seen
    },
    last_tcp_sequence: if packet.protocol == 6 && packet.tcp_payload_length > 0 {
      packet.tcp_sequence + packet.tcp_payload_length
    } else {
      flagged.last_tcp_sequence
    },
    tcp_retransmissions: flagged.tcp_retransmissions + retrans_inc,
  }
}

///|
fn add_flow(flows : Array[FlowStats], packet : DecodedPacket) -> Unit {
  let key = flow_key(packet)
  for i in 0..<flows.length() {
    let existing = flows[i].key
    if same_flow(existing, key) {
      flows[i] = add_packet_to_flow(flows[i], packet, false)
      return
    }
    if reverse_flow(existing, key) {
      flows[i] = add_packet_to_flow(flows[i], packet, true)
      return
    }
  }
  flows.push(add_packet_to_flow(empty_flow(packet), packet, false))
}

///|
fn add_counter(counters : Array[Counter], name : String, amount : Int) -> Unit {
  if name == "" {
    return
  }
  for i in 0..<counters.length() {
    if counters[i].name == name {
      counters[i] = Counter::{ name, count: counters[i].count + amount }
      return
    }
  }
  counters.push(Counter::{ name, count: amount })
}

///|
pub fn length_bucket(length : Int) -> String {
  if length < 64 {
    "0-63"
  } else if length < 128 {
    "64-127"
  } else if length < 256 {
    "128-255"
  } else if length < 512 {
    "256-511"
  } else if length < 1024 {
    "512-1023"
  } else if length < 1519 {
    "1024-1518"
  } else {
    "1519+"
  }
}

///|
pub fn packet_filter(
  start_micros? : Int64? = None,
  end_micros? : Int64? = None,
  ip? : String? = None,
  port? : Int? = None,
  protocol? : Int? = None,
) -> PacketFilter {
  PacketFilter::{ start_micros, end_micros, ip, port, protocol }
}

///|
pub fn filter_packet(packet : DecodedPacket, filter : PacketFilter) -> Bool {
  if filter.start_micros is Some(start) {
    if packet.timestamp_micros < start {
      return false
    }
  }
  if filter.end_micros is Some(end) {
    if packet.timestamp_micros > end {
      return false
    }
  }
  if filter.ip is Some(ip) {
    if packet.source_ip != ip && packet.destination_ip != ip {
      return false
    }
  }
  if filter.port is Some(port) {
    if packet.source_port != port && packet.destination_port != port {
      return false
    }
  }
  if filter.protocol is Some(protocol) {
    if packet.protocol != protocol {
      return false
    }
  }
  true
}

///|
pub fn apply_filter(
  packets : Array[DecodedPacket],
  filter : PacketFilter,
) -> Array[DecodedPacket] {
  let out : Array[DecodedPacket] = []
  for packet in packets {
    if filter_packet(packet, filter) {
      out.push(packet)
    }
  }
  out
}

///|
fn top_counters(counters : Array[Counter], limit : Int) -> Array[Counter] {
  let result : Array[Counter] = []
  for counter in counters {
    let mut inserted = false
    for i in 0..<result.length() {
      if counter.count > result[i].count {
        result.insert(i, counter)
        inserted = true
        break
      }
    }
    if !inserted {
      result.push(counter)
    }
  }
  while result.length() > limit {
    ignore(result.pop())
  }
  result
}

///|
pub fn analyze_decoded_packets(
  packets : Array[DecodedPacket],
) -> TrafficSummary {
  let flows : Array[FlowStats] = []
  let ips : Array[Counter] = []
  let ports : Array[Counter] = []
  let lengths : Array[Counter] = []
  let mut total_bytes = 0
  let mut ipv4_packets = 0
  let mut ipv6_packets = 0
  let mut tcp_packets = 0
  let mut udp_packets = 0
  let mut icmp_packets = 0
  let mut dns_messages = 0
  for packet in packets {
    total_bytes = total_bytes + packet.frame_length
    if packet.ether_type == 0x0800 {
      ipv4_packets = ipv4_packets + 1
    }
    if packet.ether_type == 0x86dd {
      ipv6_packets = ipv6_packets + 1
    }
    match packet.protocol {
      6 => tcp_packets = tcp_packets + 1
      17 => udp_packets = udp_packets + 1
      1 | 58 => icmp_packets = icmp_packets + 1
      _ => ()
    }
    if packet.dns is Some(_) {
      dns_messages = dns_messages + 1
    }
    add_counter(ips, packet.source_ip, 1)
    add_counter(ips, packet.destination_ip, 1)
    if packet.source_port > 0 {
      add_counter(ports, "\{packet.source_port}", 1)
    }
    if packet.destination_port > 0 {
      add_counter(ports, "\{packet.destination_port}", 1)
    }
    add_counter(lengths, length_bucket(packet.frame_length), 1)
    if packet.protocol == 6 || packet.protocol == 17 {
      add_flow(flows, packet)
    }
  }
  TrafficSummary::{
    packets: packets.length(),
    bytes: total_bytes,
    ipv4_packets,
    ipv6_packets,
    tcp_packets,
    udp_packets,
    icmp_packets,
    dns_messages,
    flows,
    top_ips: top_counters(ips, 10),
    top_ports: top_counters(ports, 10),
    length_buckets: top_counters(lengths, 10),
  }
}

///|
pub fn analyze_records(records : Array[PacketRecord]) -> TrafficSummary {
  analyze_decoded_packets(decode_packets(records))
}

///|
pub fn flow_label(key : FlowKey) -> String {
  "\{key.source_ip}:\{key.source_port} -> \{key.destination_ip}:\{key.destination_port} \{protocol_name(key.protocol)}"
}

///|
pub fn top_flows(summary : TrafficSummary, limit : Int) -> Array[FlowStats] {
  let result : Array[FlowStats] = []
  for flow in summary.flows {
    let mut inserted = false
    for i in 0..<result.length() {
      if flow.bytes > result[i].bytes {
        result.insert(i, flow)
        inserted = true
        break
      }
    }
    if !inserted {
      result.push(flow)
    }
  }
  while result.length() > limit {
    ignore(result.pop())
  }
  result
}
