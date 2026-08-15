///|
pub fn Reader::new(data : Bytes, endian? : Endian = Big) -> Reader {
  { data, endian }
}

///|
pub fn Reader::length(self : Reader) -> Int {
  self.data.length()
}

///|
fn Reader::ensure(
  self : Reader,
  offset : Int,
  needed : Int,
  context : String,
) -> Unit raise ParseError {
  if offset < 0 || needed < 0 || offset + needed > self.length() {
    raise ParseError::Truncated(
      context~,
      offset~,
      needed~,
      length=self.length(),
    )
  }
}

///|
pub fn Reader::u8(self : Reader, offset : Int) -> Int raise ParseError {
  self.ensure(offset, 1, "u8")
  self.data[offset].to_int()
}

///|
pub fn Reader::u16(self : Reader, offset : Int) -> Int raise ParseError {
  self.ensure(offset, 2, "u16")
  match self.endian {
    Little => self.data.unsafe_read_uint16_le(offset).to_int()
    Big => self.data.unsafe_read_uint16_be(offset).to_int()
  }
}

///|
pub fn Reader::u16_be(self : Reader, offset : Int) -> Int raise ParseError {
  self.ensure(offset, 2, "u16_be")
  self.data.unsafe_read_uint16_be(offset).to_int()
}

///|
pub fn Reader::u16_le(self : Reader, offset : Int) -> Int raise ParseError {
  self.ensure(offset, 2, "u16_le")
  self.data.unsafe_read_uint16_le(offset).to_int()
}

///|
pub fn Reader::u32(self : Reader, offset : Int) -> Int raise ParseError {
  self.ensure(offset, 4, "u32")
  match self.endian {
    Little => self.data.unsafe_read_uint32_le(offset).reinterpret_as_int()
    Big => self.data.unsafe_read_uint32_be(offset).reinterpret_as_int()
  }
}

///|
pub fn Reader::u32_be(self : Reader, offset : Int) -> Int raise ParseError {
  self.ensure(offset, 4, "u32_be")
  self.data.unsafe_read_uint32_be(offset).reinterpret_as_int()
}

///|
pub fn Reader::u32_le(self : Reader, offset : Int) -> Int raise ParseError {
  self.ensure(offset, 4, "u32_le")
  self.data.unsafe_read_uint32_le(offset).reinterpret_as_int()
}

///|
pub fn Reader::u64_parts(
  self : Reader,
  offset : Int,
) -> (Int, Int) raise ParseError {
  match self.endian {
    Little => (self.u32_le(offset), self.u32_le(offset + 4))
    Big => (self.u32_be(offset), self.u32_be(offset + 4))
  }
}

///|
pub fn Reader::slice(
  self : Reader,
  offset : Int,
  length : Int,
  context : String,
) -> Bytes raise ParseError {
  self.ensure(offset, length, context)
  Bytes::from_array(self.data[offset:offset + length].to_array())
}

///|
pub fn byte_hex(n : Int) -> String {
  let digits = "0123456789abcdef"
  let high = digits[(n >> 4) & 15]
  let low = digits[n & 15]
  "\{high}\{low}"
}

///|
pub fn mac_to_string(mac : MacAddress) -> String {
  "\{byte_hex(mac.b0)}:\{byte_hex(mac.b1)}:\{byte_hex(mac.b2)}:\{byte_hex(mac.b3)}:\{byte_hex(mac.b4)}:\{byte_hex(mac.b5)}"
}

///|
pub fn protocol_name(protocol : Int) -> String {
  match protocol {
    1 => "icmp"
    6 => "tcp"
    17 => "udp"
    58 => "icmpv6"
    _ => "ip-\{protocol}"
  }
}

///|
pub fn ether_type_name(ether_type : Int) -> String {
  match ether_type {
    0x0800 => "ipv4"
    0x86dd => "ipv6"
    0x0806 => "arp"
    0x8100 => "vlan"
    0x88a8 => "provider-vlan"
    _ => "0x\{byte_hex((ether_type >> 8) & 255)}\{byte_hex(ether_type & 255)}"
  }
}

///|
pub fn tcp_flag_names(flags : Int) -> String {
  let parts : Array[String] = []
  if (flags & 0x01) != 0 {
    parts.push("FIN")
  }
  if (flags & 0x02) != 0 {
    parts.push("SYN")
  }
  if (flags & 0x04) != 0 {
    parts.push("RST")
  }
  if (flags & 0x08) != 0 {
    parts.push("PSH")
  }
  if (flags & 0x10) != 0 {
    parts.push("ACK")
  }
  if (flags & 0x20) != 0 {
    parts.push("URG")
  }
  if (flags & 0x40) != 0 {
    parts.push("ECE")
  }
  if (flags & 0x80) != 0 {
    parts.push("CWR")
  }
  if parts.length() == 0 {
    "NONE"
  } else {
    join_strings(parts, "|")
  }
}

///|
pub fn join_strings(items : Array[String], sep : String) -> String {
  let buf = StringBuilder()
  for i in 0..<items.length() {
    if i > 0 {
      buf.write_string(sep)
    }
    buf.write_string(items[i])
  }
  buf.to_string()
}

///|
pub fn csv_escape(value : String) -> String {
  let mut needs_quote = false
  for ch in value {
    if ch == ',' || ch == '"' || ch == '\n' || ch == '\r' {
      needs_quote = true
    }
  }
  if !needs_quote {
    value
  } else {
    let buf = StringBuilder()
    buf.write_char('"')
    for ch in value {
      if ch == '"' {
        buf.write_char('"')
      }
      buf.write_char(ch)
    }
    buf.write_char('"')
    buf.to_string()
  }
}
