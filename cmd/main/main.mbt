///|
fn policy_arg(args : Array[String]) -> @guard.AuditPolicy {
  if args.length() > 2 {
    @guard.parse_policy_json(args[2])
  } else {
    @guard.default_policy()
  }
}

///|
fn main {
  let args = @env.args()
  let command = if args.length() > 1 { args[1] } else { "summary" }
  let capture = try! @guard.parse_capture(@guard.sample_pcap_fixture())
  let packets = @guard.decode_packets(capture.packets)
  let summary = @guard.analyze_decoded_packets(packets)
  match command {
    "summary" => println(@guard.summary_to_text(summary))
    "flows" => println(@guard.flows_to_csv(@guard.top_flows(summary, 20)))
    "dns" => println(@guard.dns_to_text(packets))
    "audit" =>
      println(@guard.audit_to_text(@guard.audit_decoded_packets(packets)))
    "gate" => {
      let result = @guard.gate_capture(packets, policy_arg(args))
      println(@guard.gate_to_text(result))
      match result.verdict {
        @guard.Fail => abort("MoonFlowGuard gate: FAIL")
        _ => ()
      }
    }
    "gate-csv" => {
      let result = @guard.gate_flow_csv(
        @guard.sample_flow_csv_fixture(),
        policy_arg(args),
      )
      println(@guard.gate_to_text(result))
      match result.verdict {
        @guard.Fail => abort("MoonFlowGuard gate-csv: FAIL")
        _ => ()
      }
    }
    "policy" => println(@guard.policy_to_json(@guard.default_policy()))
    "filter" => {
      let filtered = @guard.apply_filter(
        packets,
        @guard.packet_filter(port=Some(53), protocol=Some(17)),
      )
      println(@guard.summary_to_text(@guard.analyze_decoded_packets(filtered)))
    }
    "export" => {
      let format = if args.length() > 2 { args[2] } else { "json" }
      match format {
        "csv" => println(@guard.flows_to_csv(@guard.top_flows(summary, 20)))
        "audit" =>
          println(@guard.audit_to_json(@guard.audit_decoded_packets(packets)))
        _ => println(@guard.summary_to_json(summary))
      }
    }
    _ =>
      println(
        "MoonFlowGuard commands: summary | flows | dns | audit | gate [policy-json] | gate-csv [policy-json] | policy | filter | export [json|csv|audit]",
      )
  }
}
