///|
pub enum Endian {
  Little
  Big
} derive(Debug, Eq)

///|
pub suberror ParseError {
  Truncated(context~ : String, offset~ : Int, needed~ : Int, length~ : Int)
  InvalidMagic(String)
  InvalidHeader(String)
}

///|
pub struct Reader {
  data : Bytes
  endian : Endian
} derive(Debug)

///|
pub struct PcapHeader {
  endian : Endian
  version_major : Int
  version_minor : Int
  thiszone : Int
  sigfigs : Int
  snaplen : Int
  network : Int
  nanos : Bool
} derive(Debug, Eq)

///|
pub struct PacketRecord {
  timestamp_micros : Int64
  captured_length : Int
  original_length : Int
  payload : Bytes
} derive(Debug, Eq)

///|
pub struct PcapNgSection {
  endian : Endian
  major : Int
  minor : Int
  section_length : Int64
} derive(Debug, Eq)

///|
pub struct PcapNgInterface {
  link_type : Int
  snaplen : Int
} derive(Debug, Eq)

///|
pub enum CaptureKind {
  ClassicPcap(PcapHeader)
  PcapNg(PcapNgSection)
} derive(Debug, Eq)

///|
pub struct ParsedCapture {
  kind : CaptureKind
  packets : Array[PacketRecord]
  interfaces : Array[PcapNgInterface]
} derive(Debug, Eq)

///|
pub struct MacAddress {
  b0 : Int
  b1 : Int
  b2 : Int
  b3 : Int
  b4 : Int
  b5 : Int
} derive(Debug, Eq)

///|
pub struct EthernetFrame {
  destination : MacAddress
  source : MacAddress
  ether_type : Int
  vlan_id : Int?
  payload_offset : Int
  payload_length : Int
} derive(Debug, Eq)

///|
pub struct IpAddress {
  text : String
  version : Int
} derive(Debug, Eq)

///|
pub struct Ipv4Packet {
  source : IpAddress
  destination : IpAddress
  protocol : Int
  ttl : Int
  total_length : Int
  identification : Int
  flags : Int
  fragment_offset : Int
  header_length : Int
  payload_offset : Int
  payload_length : Int
} derive(Debug, Eq)

///|
pub struct Ipv6Packet {
  source : IpAddress
  destination : IpAddress
  next_header : Int
  hop_limit : Int
  payload_length : Int
  payload_offset : Int
} derive(Debug, Eq)

///|
pub struct TcpSegment {
  source_port : Int
  destination_port : Int
  sequence : Int
  acknowledgement : Int
  data_offset : Int
  flags : Int
  window : Int
  payload_offset : Int
  payload_length : Int
} derive(Debug, Eq)

///|
pub struct UdpDatagram {
  source_port : Int
  destination_port : Int
  length : Int
  checksum : Int
  payload_offset : Int
  payload_length : Int
} derive(Debug, Eq)

///|
pub struct IcmpPacket {
  icmp_type : Int
  code : Int
  checksum : Int
} derive(Debug, Eq)

///|
pub struct DnsQuestion {
  name : String
  qtype : Int
  qclass : Int
} derive(Debug, Eq)

///|
pub struct DnsMessage {
  transaction_id : Int
  is_response : Bool
  opcode : Int
  rcode : Int
  question_count : Int
  answer_count : Int
  questions : Array[DnsQuestion]
} derive(Debug, Eq)

///|
pub struct DecodedPacket {
  timestamp_micros : Int64
  frame_length : Int
  ether_type : Int
  vlan_id : Int?
  source_ip : String
  destination_ip : String
  protocol : Int
  source_port : Int
  destination_port : Int
  tcp_flags : Int
  tcp_sequence : Int
  tcp_payload_length : Int
  dns : DnsMessage?
} derive(Debug, Eq)

///|
pub struct FlowKey {
  source_ip : String
  destination_ip : String
  source_port : Int
  destination_port : Int
  protocol : Int
} derive(Debug, Eq)

///|
pub struct FlowStats {
  key : FlowKey
  packets : Int
  bytes : Int
  upstream_packets : Int
  downstream_packets : Int
  first_seen : Int64
  last_seen : Int64
  tcp_syn : Int
  tcp_fin : Int
  tcp_rst : Int
  last_tcp_sequence : Int
  tcp_retransmissions : Int
} derive(Debug, Eq)

///|
pub struct TrafficSummary {
  packets : Int
  bytes : Int
  ipv4_packets : Int
  ipv6_packets : Int
  tcp_packets : Int
  udp_packets : Int
  icmp_packets : Int
  dns_messages : Int
  flows : Array[FlowStats]
  top_ips : Array[Counter]
  top_ports : Array[Counter]
  length_buckets : Array[Counter]
} derive(Debug, Eq)

///|
pub struct Counter {
  name : String
  count : Int
} derive(Debug, Eq)

///|
pub struct PacketFilter {
  start_micros : Int64?
  end_micros : Int64?
  ip : String?
  port : Int?
  protocol : Int?
} derive(Debug, Eq)
