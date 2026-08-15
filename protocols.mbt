///|
fn read_mac(reader : Reader, offset : Int) -> MacAddress raise ParseError {
  MacAddress::{
    b0: reader.u8(offset),
    b1: reader.u8(offset + 1),
    b2: reader.u8(offset + 2),
    b3: reader.u8(offset + 3),
    b4: reader.u8(offset + 4),
    b5: reader.u8(offset + 5),
  }
}

///|
pub fn parse_ethernet(frame : Bytes) -> EthernetFrame raise ParseError {
  let reader = Reader::new(frame, endian=Big)
  reader.ensure(0, 14, "ethernet header")
  let destination = read_mac(reader, 0)
  let source = read_mac(reader, 6)
  let raw_type = reader.u16_be(12)
  if raw_type == 0x8100 || raw_type == 0x88a8 {
    reader.ensure(0, 18, "vlan ethernet header")
    let tci = reader.u16_be(14)
    EthernetFrame::{
      destination,
      source,
      ether_type: reader.u16_be(16),
      vlan_id: Some(tci & 0x0fff),
      payload_offset: 18,
      payload_length: frame.length() - 18,
    }
  } else {
    EthernetFrame::{
      destination,
      source,
      ether_type: raw_type,
      vlan_id: None,
      payload_offset: 14,
      payload_length: frame.length() - 14,
    }
  }
}

///|
pub fn ipv4_text(reader : Reader, offset : Int) -> String raise ParseError {
  "\{reader.u8(offset)}.\{reader.u8(offset + 1)}.\{reader.u8(offset + 2)}.\{reader.u8(offset + 3)}"
}

///|
pub fn ipv6_text(reader : Reader, offset : Int) -> String raise ParseError {
  let parts : Array[String] = []
  for i in 0..<8 {
    let word = reader.u16_be(offset + i * 2)
    parts.push("\{byte_hex((word >> 8) & 255)}\{byte_hex(word & 255)}")
  }
  join_strings(parts, ":")
}

///|
pub fn parse_ipv4(packet : Bytes) -> Ipv4Packet raise ParseError {
  let reader = Reader::new(packet, endian=Big)
  reader.ensure(0, 20, "ipv4 header")
  let version_ihl = reader.u8(0)
  let version = version_ihl >> 4
  if version != 4 {
    raise ParseError::InvalidHeader("expected IPv4 version 4")
  }
  let ihl = version_ihl & 15
  let header_length = ihl * 4
  reader.ensure(0, header_length, "ipv4 variable header")
  let total_length = reader.u16_be(2)
  let flags_fragment = reader.u16_be(6)
  Ipv4Packet::{
    source: IpAddress::{ text: ipv4_text(reader, 12), version: 4 },
    destination: IpAddress::{ text: ipv4_text(reader, 16), version: 4 },
    protocol: reader.u8(9),
    ttl: reader.u8(8),
    total_length,
    identification: reader.u16_be(4),
    flags: flags_fragment >> 13,
    fragment_offset: flags_fragment & 0x1fff,
    header_length,
    payload_offset: header_length,
    payload_length: imax(0, total_length - header_length),
  }
}

///|
pub fn parse_ipv6(packet : Bytes) -> Ipv6Packet raise ParseError {
  let reader = Reader::new(packet, endian=Big)
  reader.ensure(0, 40, "ipv6 header")
  let version = reader.u8(0) >> 4
  if version != 6 {
    raise ParseError::InvalidHeader("expected IPv6 version 6")
  }
  Ipv6Packet::{
    source: IpAddress::{ text: ipv6_text(reader, 8), version: 6 },
    destination: IpAddress::{ text: ipv6_text(reader, 24), version: 6 },
    next_header: reader.u8(6),
    hop_limit: reader.u8(7),
    payload_length: reader.u16_be(4),
    payload_offset: 40,
  }
}

///|
pub fn parse_tcp(segment : Bytes) -> TcpSegment raise ParseError {
  let reader = Reader::new(segment, endian=Big)
  reader.ensure(0, 20, "tcp header")
  let data_offset = (reader.u8(12) >> 4) * 4
  reader.ensure(0, data_offset, "tcp variable header")
  TcpSegment::{
    source_port: reader.u16_be(0),
    destination_port: reader.u16_be(2),
    sequence: reader.u32_be(4),
    acknowledgement: reader.u32_be(8),
    data_offset,
    flags: reader.u8(13),
    window: reader.u16_be(14),
    payload_offset: data_offset,
    payload_length: imax(0, segment.length() - data_offset),
  }
}

///|
pub fn parse_udp(datagram : Bytes) -> UdpDatagram raise ParseError {
  let reader = Reader::new(datagram, endian=Big)
  reader.ensure(0, 8, "udp header")
  let length = reader.u16_be(4)
  UdpDatagram::{
    source_port: reader.u16_be(0),
    destination_port: reader.u16_be(2),
    length,
    checksum: reader.u16_be(6),
    payload_offset: 8,
    payload_length: imax(0, length - 8),
  }
}

///|
pub fn parse_icmp(packet : Bytes) -> IcmpPacket raise ParseError {
  let reader = Reader::new(packet, endian=Big)
  reader.ensure(0, 4, "icmp header")
  IcmpPacket::{
    icmp_type: reader.u8(0),
    code: reader.u8(1),
    checksum: reader.u16_be(2),
  }
}

///|
fn dns_read_name(data : Bytes, start : Int) -> (String, Int) raise ParseError {
  let reader = Reader::new(data, endian=Big)
  let labels : Array[String] = []
  let mut offset = start
  let mut jumps = 0
  let mut consumed = 0
  let mut jumped = false
  while true {
    reader.ensure(offset, 1, "dns label length")
    let len = reader.u8(offset)
    if (len & 0xc0) == 0xc0 {
      reader.ensure(offset, 2, "dns compressed name")
      let pointer = ((len & 0x3f) << 8) | reader.u8(offset + 1)
      if !jumped {
        consumed = offset + 2 - start
      }
      offset = pointer
      jumped = true
      jumps = jumps + 1
      if jumps > 8 {
        raise ParseError::InvalidHeader("dns name compression loop")
      }
    } else if len == 0 {
      if !jumped {
        consumed = offset + 1 - start
      }
      return (join_strings(labels, "."), start + consumed)
    } else {
      reader.ensure(offset + 1, len, "dns label")
      let chars : Array[Char] = []
      for i in 0..<len {
        chars.push(reader.u8(offset + 1 + i).unsafe_to_char())
      }
      labels.push(String::from_array(chars))
      offset = offset + 1 + len
    }
  }
  ("", start)
}

///|
pub fn parse_dns(message : Bytes) -> DnsMessage raise ParseError {
  let reader = Reader::new(message, endian=Big)
  reader.ensure(0, 12, "dns header")
  let flags = reader.u16_be(2)
  let question_count = reader.u16_be(4)
  let answer_count = reader.u16_be(6)
  let questions : Array[DnsQuestion] = []
  let mut offset = 12
  let question_limit = imin(question_count, 16)
  for _ in 0..<question_limit {
    let (name, next) = dns_read_name(message, offset)
    offset = next
    reader.ensure(offset, 4, "dns question tail")
    questions.push(DnsQuestion::{
      name,
      qtype: reader.u16_be(offset),
      qclass: reader.u16_be(offset + 2),
    })
    offset = offset + 4
  }
  DnsMessage::{
    transaction_id: reader.u16_be(0),
    is_response: (flags & 0x8000) != 0,
    opcode: (flags >> 11) & 15,
    rcode: flags & 15,
    question_count,
    answer_count,
    questions,
  }
}

///|
fn slice_payload(
  data : Bytes,
  offset : Int,
  length : Int,
  context : String,
) -> Bytes raise ParseError {
  Reader::new(data, endian=Big).slice(offset, length, context)
}

///|
pub fn decode_packet(record : PacketRecord) -> DecodedPacket raise ParseError {
  let ethernet = parse_ethernet(record.payload)
  let network_payload = slice_payload(
    record.payload,
    ethernet.payload_offset,
    ethernet.payload_length,
    "ethernet payload",
  )
  match ethernet.ether_type {
    0x0800 => decode_ipv4_record(record, ethernet, network_payload)
    0x86dd => decode_ipv6_record(record, ethernet, network_payload)
    _ =>
      DecodedPacket::{
        timestamp_micros: record.timestamp_micros,
        frame_length: record.original_length,
        ether_type: ethernet.ether_type,
        vlan_id: ethernet.vlan_id,
        source_ip: "",
        destination_ip: "",
        protocol: 0,
        source_port: 0,
        destination_port: 0,
        tcp_flags: 0,
        tcp_sequence: 0,
        tcp_payload_length: 0,
        dns: None,
      }
  }
}

///|
fn decode_ipv4_record(
  record : PacketRecord,
  ethernet : EthernetFrame,
  packet : Bytes,
) -> DecodedPacket raise ParseError {
  let ipv4 = parse_ipv4(packet)
  decode_transport(
    record,
    ethernet,
    ipv4.source.text,
    ipv4.destination.text,
    ipv4.protocol,
    slice_payload(
      packet,
      ipv4.payload_offset,
      ipv4.payload_length,
      "ipv4 payload",
    ),
  )
}

///|
fn decode_ipv6_record(
  record : PacketRecord,
  ethernet : EthernetFrame,
  packet : Bytes,
) -> DecodedPacket raise ParseError {
  let ipv6 = parse_ipv6(packet)
  decode_transport(
    record,
    ethernet,
    ipv6.source.text,
    ipv6.destination.text,
    ipv6.next_header,
    slice_payload(
      packet,
      ipv6.payload_offset,
      ipv6.payload_length,
      "ipv6 payload",
    ),
  )
}

///|
fn decode_transport(
  record : PacketRecord,
  ethernet : EthernetFrame,
  source_ip : String,
  destination_ip : String,
  protocol : Int,
  payload : Bytes,
) -> DecodedPacket raise ParseError {
  let mut source_port = 0
  let mut destination_port = 0
  let mut tcp_flags = 0
  let mut tcp_sequence = 0
  let mut tcp_payload_length = 0
  let mut dns : DnsMessage? = None
  match protocol {
    6 => {
      let tcp = parse_tcp(payload)
      source_port = tcp.source_port
      destination_port = tcp.destination_port
      tcp_flags = tcp.flags
      tcp_sequence = tcp.sequence
      tcp_payload_length = tcp.payload_length
    }
    17 => {
      let udp = parse_udp(payload)
      source_port = udp.source_port
      destination_port = udp.destination_port
      if source_port == 53 || destination_port == 53 {
        let dns_payload = slice_payload(
          payload,
          udp.payload_offset,
          udp.payload_length,
          "dns payload",
        )
        dns = Some(parse_dns(dns_payload))
      }
    }
    1 | 58 => {
      let _icmp = parse_icmp(payload)
    }
    _ => ()
  }
  DecodedPacket::{
    timestamp_micros: record.timestamp_micros,
    frame_length: record.original_length,
    ether_type: ethernet.ether_type,
    vlan_id: ethernet.vlan_id,
    source_ip,
    destination_ip,
    protocol,
    source_port,
    destination_port,
    tcp_flags,
    tcp_sequence,
    tcp_payload_length,
    dns,
  }
}

///|
pub fn decode_packets(records : Array[PacketRecord]) -> Array[DecodedPacket] {
  let decoded : Array[DecodedPacket] = []
  for packet in records {
    decoded.push(decode_packet(packet)) catch {
      _ => ()
    }
  }
  decoded
}
