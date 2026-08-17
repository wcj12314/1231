///|
/// Parse a CSV flow-record document into decoded packets. This is the
/// input-agnostic half of MoonFlowGuard: a capture file is one way to get
/// traffic, but a flow table (exported from a tool, a firewall, or written by
/// hand) is often what a security review actually has. The CSV schema is
/// deliberately a flat projection of `DecodedPacket`:
///
///   timestamp_micros,source_ip,destination_ip,protocol,source_port,destination_port,tcp_flags,frame_length
///
/// The header row, blank lines and malformed rows are skipped tolerantly.
/// `protocol` is an IP protocol number (6=TCP, 17=UDP), `tcp_flags` is the raw
/// TCP flag byte in decimal and `frame_length` is the captured frame size.
pub fn parse_flow_csv(text : String) -> Array[DecodedPacket] {
  let packets : Array[DecodedPacket] = []
  let mut first = true
  for line in text.split("\n") {
    let trimmed = line.trim()
    if trimmed.length() == 0 {
      continue
    }
    if first {
      first = false
      continue // header row
    }
    let cells = split_csv_row(trimmed)
    if cells.length() < 8 {
      continue
    }
    packets.push(DecodedPacket::{
      timestamp_micros: parse_int64(cells[0]),
      source_ip: cells[1],
      destination_ip: cells[2],
      protocol: parse_int(cells[3]),
      source_port: parse_int(cells[4]),
      destination_port: parse_int(cells[5]),
      tcp_flags: parse_int(cells[6]),
      frame_length: parse_int(cells[7]),
      ether_type: 0x0800,
      vlan_id: None,
      tcp_sequence: 0,
      tcp_payload_length: 0,
      dns: None,
    })
  }
  packets
}

///|
/// Audit a CSV flow-record document directly, without a binary capture file.
pub fn audit_flow_csv(text : String) -> AuditReport {
  audit_decoded_packets(parse_flow_csv(text))
}

///|
/// Evaluate a CSV flow-record document against a policy gate.
pub fn gate_flow_csv(text : String, policy : AuditPolicy) -> GateResult {
  evaluate_policy(audit_flow_csv(text), policy)
}

///|
fn split_csv_row(line : StringView) -> Array[String] {
  let cells : Array[String] = []
  for cell in line.split(",") {
    cells.push(cell.trim().to_owned())
  }
  cells
}

///|
fn parse_int(text : String) -> Int {
  @string.parse_int(text.to_string_view(), base=0) catch {
    _ => 0
  }
}

///|
fn parse_int64(text : String) -> Int64 {
  @string.parse_int64(text.to_string_view(), base=0) catch {
    _ => 0L
  }
}
