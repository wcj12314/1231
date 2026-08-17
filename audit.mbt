///|
pub fn severity_name(severity : AuditSeverity) -> String {
  match severity {
    Info => "info"
    Low => "low"
    Medium => "medium"
    High => "high"
  }
}

///|
fn severity_weight(severity : AuditSeverity) -> Int {
  match severity {
    Info => 1
    Low => 5
    Medium => 15
    High => 30
  }
}

///|
fn push_finding(
  findings : Array[AuditFinding],
  severity : AuditSeverity,
  rule_id : String,
  title : String,
  subject : String,
  evidence : String,
  recommendation : String,
) -> Unit {
  findings.push(AuditFinding::{
    severity,
    rule_id,
    title,
    subject,
    evidence,
    recommendation,
  })
}

///|
fn is_cleartext_service(port : Int) -> Bool {
  match port {
    20 | 21 | 23 | 25 | 69 | 80 | 110 | 143 | 389 | 514 => true
    _ => false
  }
}

///|
fn is_admin_or_database_port(port : Int) -> Bool {
  match port {
    22
    | 445
    | 1433
    | 1521
    | 2049
    | 2375
    | 2376
    | 3306
    | 3389
    | 5432
    | 5900
    | 6379
    | 9200
    | 9300
    | 11211
    | 27017 => true
    _ => false
  }
}

///|
fn is_dns_unusual_question(question : DnsQuestion) -> Bool {
  question.name.length() > 80 || question.qtype == 255 || question.qclass != 1
}

///|
/// A deeply nested name or a very long single label over UDP/53 is a shape
/// consistent with DNS tunneling. Returns the offending shape as evidence, or
/// `None` when the name looks ordinary.
fn dns_tunnel_shape(question : DnsQuestion) -> String? {
  let labels = question.name.split(".")
  if labels.length() >= 8 {
    return Some("label_count=\{labels.length()}")
  }
  for label in labels {
    if label.length() > 30 {
      return Some("max_label_length=\{label.length()}")
    }
  }
  None
}

///|
fn audit_packet(findings : Array[AuditFinding], packet : DecodedPacket) -> Unit {
  if packet.protocol == 17 &&
    (packet.source_port == 53 || packet.destination_port == 53) {
    if packet.dns is Some(dns) {
      for question in dns.questions {
        push_finding(
          findings,
          Info,
          "DNS-CLEARTEXT-METADATA",
          "Plain DNS exposes query metadata",
          question.name,
          "qtype=\{dns_type_registered_name(question.qtype)}, transport=udp/53",
          "Consider DoT/DoH or document why plaintext DNS is acceptable in this environment.",
        )
        if is_dns_unusual_question(question) {
          push_finding(
            findings,
            Medium,
            "DNS-QUESTION-ANOMALY",
            "DNS question has unusual shape",
            question.name,
            "qtype=\{dns_type_registered_name(question.qtype)}, qclass=\{question.qclass}, rcode=\{dns.rcode}",
            "Review whether this query is expected; unusually long names and ANY queries are often useful triage signals.",
          )
        }
        match dns_tunnel_shape(question) {
          Some(shape) =>
            push_finding(
              findings,
              Low,
              "DNS-TUNNEL-SHAPE",
              "DNS name shape is consistent with tunneling",
              question.name,
              shape,
              "Deeply nested names or very long labels over UDP/53 can indicate DNS tunneling; validate the client behavior.",
            )
          None => ()
        }
      }
    } else {
      push_finding(
        findings,
        Low,
        "DNS-DECODE-MISS",
        "UDP/53 packet was not decoded as DNS",
        "\{packet.source_ip}:\{packet.source_port} -> \{packet.destination_ip}:\{packet.destination_port}",
        "payload length could be truncated or malformed",
        "Check capture snaplen and packet integrity before relying on DNS statistics.",
      )
    }
  }
  if packet.protocol == 6 && packet.tcp_flags == 0 {
    push_finding(
      findings,
      Low,
      "TCP-ZERO-FLAGS",
      "TCP segment has no control flags",
      "\{packet.source_ip}:\{packet.source_port} -> \{packet.destination_ip}:\{packet.destination_port}",
      "flags=NONE",
      "Confirm whether this is expected middle-of-flow traffic or a scan/evasion artifact.",
    )
  }
  if packet.frame_length < 42 {
    push_finding(
      findings,
      Medium,
      "FRAME-TOO-SHORT",
      "Frame length is shorter than common Ethernet/IP minimums",
      "\{packet.source_ip} -> \{packet.destination_ip}",
      "frame_length=\{packet.frame_length}",
      "Review snaplen, capture truncation, and link-layer assumptions.",
    )
  }
}

///|
fn audit_flow(findings : Array[AuditFinding], flow : FlowStats) -> Unit {
  let service_port = if flow.key.destination_port < 49152 {
    flow.key.destination_port
  } else {
    flow.key.source_port
  }
  if is_cleartext_service(service_port) {
    push_finding(
      findings,
      Medium,
      "CLEARTEXT-SERVICE",
      "Flow uses a common cleartext service",
      flow_label(flow.key),
      "service=\{registered_service_name(service_port)}, packets=\{flow.packets}, bytes=\{flow.bytes}",
      "Prefer encrypted alternatives or document why cleartext transport is acceptable.",
    )
  }
  if is_admin_or_database_port(service_port) {
    push_finding(
      findings,
      High,
      "SENSITIVE-SERVICE-EXPOSURE",
      "Flow touches an administrative or database service",
      flow_label(flow.key),
      "service=\{registered_service_name(service_port)}, risk=\{port_risk_tag(service_port)}",
      "Verify network boundary, authentication, and whether this service should be reachable in the capture scope.",
    )
  }
  if flow.tcp_retransmissions > 0 {
    push_finding(
      findings,
      Low,
      "TCP-RETRANSMISSION",
      "Flow contains possible TCP retransmissions",
      flow_label(flow.key),
      "retransmissions=\{flow.tcp_retransmissions}, packets=\{flow.packets}",
      "Use this as a capture-quality and network-health signal, not as a full TCP reassembly verdict.",
    )
  }
  if flow.tcp_syn >= 3 && flow.tcp_syn == flow.packets {
    push_finding(
      findings,
      Medium,
      "SYN-BURST-NO-COMPLETION",
      "Flow consists only of repeated SYN segments",
      flow_label(flow.key),
      "syn=\{flow.tcp_syn}, packets=\{flow.packets}, rst=\{flow.tcp_rst}",
      "A flow where every segment is a SYN may indicate a scan or connection flood; verify against application behavior.",
    )
  }
}

///|
pub fn audit_decoded_packets(packets : Array[DecodedPacket]) -> AuditReport {
  let findings : Array[AuditFinding] = []
  let summary = analyze_decoded_packets(packets)
  for packet in packets {
    audit_packet(findings, packet)
  }
  for flow in summary.flows {
    audit_flow(findings, flow)
  }
  let mut high = 0
  let mut medium = 0
  let mut low = 0
  let mut info = 0
  let mut score = 0
  for finding in findings {
    score = score + severity_weight(finding.severity)
    match finding.severity {
      High => high = high + 1
      Medium => medium = medium + 1
      Low => low = low + 1
      Info => info = info + 1
    }
  }
  AuditReport::{ findings, high, medium, low, info, risk_score: score }
}

///|
pub fn audit_records(records : Array[PacketRecord]) -> AuditReport {
  audit_decoded_packets(decode_packets(records))
}

///|
pub fn audit_to_text(report : AuditReport) -> String {
  let buf = StringBuilder()
  buf.write_string("MoonTraceGuard audit\n")
  buf.write_string(
    "risk_score: \{report.risk_score}, high: \{report.high}, medium: \{report.medium}, low: \{report.low}, info: \{report.info}\n",
  )
  for finding in report.findings {
    buf.write_string(
      "- [\{severity_name(finding.severity)}] \{finding.rule_id}: \{finding.title}\n",
    )
    buf.write_string("  subject: \{finding.subject}\n")
    buf.write_string("  evidence: \{finding.evidence}\n")
    buf.write_string("  recommendation: \{finding.recommendation}\n")
  }
  buf.to_string()
}

///|
pub fn audit_to_json(report : AuditReport) -> String {
  let parts : Array[String] = []
  for finding in report.findings {
    parts.push(
      "{ \"severity\": \"\{severity_name(finding.severity)}\", \"rule_id\": \"\{finding.rule_id}\", \"title\": \"\{finding.title}\", \"subject\": \"\{finding.subject}\", \"evidence\": \"\{finding.evidence}\", \"recommendation\": \"\{finding.recommendation}\" }",
    )
  }
  "{ \"risk_score\": \{report.risk_score}, \"high\": \{report.high}, \"medium\": \{report.medium}, \"low\": \{report.low}, \"info\": \{report.info}, \"findings\": [\{join_strings(parts, ", ")}] }"
}
