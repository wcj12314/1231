///|
pub fn parse_capture(data : Bytes) -> ParsedCapture raise ParseError {
  let reader = Reader::new(data)
  if reader.length() < 4 {
    raise ParseError::Truncated(
      context="capture magic",
      offset=0,
      needed=4,
      length=reader.length(),
    )
  }
  let magic = reader.u32_be(0)
  if magic == 0xa1b2c3d4 ||
    magic == 0xd4c3b2a1 ||
    magic == 0xa1b23c4d ||
    magic == 0x4d3cb2a1 {
    parse_pcap(data)
  } else if magic == 0x0a0d0d0a {
    parse_pcapng(data)
  } else {
    raise ParseError::InvalidMagic(
      "unknown capture magic 0x\{byte_hex((magic >> 24) & 255)}\{byte_hex((magic >> 16) & 255)}\{byte_hex((magic >> 8) & 255)}\{byte_hex(magic & 255)}",
    )
  }
}

///|
pub fn parse_pcap(data : Bytes) -> ParsedCapture raise ParseError {
  let probe = Reader::new(data)
  let magic_be = probe.u32_be(0)
  let (endian, nanos) = match magic_be {
    0xa1b2c3d4 => (Big, false)
    0xd4c3b2a1 => (Little, false)
    0xa1b23c4d => (Big, true)
    0x4d3cb2a1 => (Little, true)
    _ => raise ParseError::InvalidMagic("not a classic pcap")
  }
  let reader = Reader::new(data, endian~)
  reader.ensure(0, 24, "pcap global header")
  let header = PcapHeader::{
    endian,
    version_major: reader.u16(4),
    version_minor: reader.u16(6),
    thiszone: reader.u32(8),
    sigfigs: reader.u32(12),
    snaplen: reader.u32(16),
    network: reader.u32(20),
    nanos,
  }
  let packets : Array[PacketRecord] = []
  let mut offset = 24
  while offset < reader.length() {
    reader.ensure(offset, 16, "pcap packet header")
    let ts_sec = reader.u32(offset).to_int64()
    let ts_sub = reader.u32(offset + 4).to_int64()
    let incl_len = reader.u32(offset + 8)
    let orig_len = reader.u32(offset + 12)
    let payload = reader.slice(offset + 16, incl_len, "pcap packet payload")
    let divisor = if nanos { 1000L } else { 1L }
    packets.push(PacketRecord::{
      timestamp_micros: ts_sec * 1000000L + ts_sub / divisor,
      captured_length: incl_len,
      original_length: orig_len,
      payload,
    })
    offset = offset + 16 + incl_len
  }
  ParsedCapture::{ kind: ClassicPcap(header), packets, interfaces: [] }
}

///|
pub fn parse_pcapng(data : Bytes) -> ParsedCapture raise ParseError {
  let base = Reader::new(data)
  base.ensure(0, 12, "pcapng section block")
  let block_type = base.u32_be(0)
  if block_type != 0x0a0d0d0a {
    raise ParseError::InvalidMagic("not a pcapng section")
  }
  let bom_be = base.u32_be(8)
  let endian = if bom_be == 0x1a2b3c4d { Big } else { Little }
  let reader = Reader::new(data, endian~)
  let section_len = reader.u32(4)
  reader.ensure(0, section_len, "pcapng section block length")
  let section = PcapNgSection::{
    endian,
    major: reader.u16(12),
    minor: reader.u16(14),
    section_length: 0L,
  }
  let interfaces : Array[PcapNgInterface] = []
  let packets : Array[PacketRecord] = []
  let mut offset = section_len
  while offset + 12 <= reader.length() {
    let block = reader.u32(offset)
    let length = reader.u32(offset + 4)
    if length < 12 {
      raise ParseError::InvalidHeader(
        "pcapng block length is smaller than trailer",
      )
    }
    reader.ensure(offset, length, "pcapng block")
    match block {
      1 => {
        reader.ensure(offset + 8, 8, "pcapng interface block")
        interfaces.push(PcapNgInterface::{
          link_type: reader.u16(offset + 8),
          snaplen: reader.u32(offset + 12),
        })
      }
      6 => {
        reader.ensure(offset + 8, 20, "pcapng enhanced packet block")
        let captured_length = reader.u32(offset + 20)
        let payload = reader.slice(
          offset + 28,
          captured_length,
          "pcapng enhanced packet payload",
        )
        packets.push(PacketRecord::{
          timestamp_micros: reader.u32(offset + 12).to_int64() * 1000000L +
          reader.u32(offset + 16).to_int64(),
          captured_length,
          original_length: reader.u32(offset + 24),
          payload,
        })
      }
      _ => ()
    }
    offset = offset + length
  }
  ParsedCapture::{ kind: PcapNg(section), packets, interfaces }
}
