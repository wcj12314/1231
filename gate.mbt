///|
/// Verdict produced by evaluating an audit report against an `AuditPolicy`.
pub enum GateVerdict {
  Pass
  Review
  Fail
} derive(Debug, Eq)

///|
/// A configurable capture gate policy: thresholds above which a capture is
/// gated to `Review`, and rule ids that hard-fail the gate when present.
pub struct AuditPolicy {
  max_risk_score : Int
  max_high : Int
  max_medium : Int
  max_low : Int
  deny_rule_ids : Array[String]
} derive(Debug, Eq)

///|
/// A single reason why the gate did not pass.
pub struct GateViolation {
  rule_id : String
  reason : String
} derive(Debug, Eq)

///|
/// Outcome of evaluating an audit report against a policy. Carries the
/// underlying findings so gate output is actionable, not just a verdict.
pub struct GateResult {
  verdict : GateVerdict
  risk_score : Int
  high : Int
  medium : Int
  low : Int
  info : Int
  findings : Array[AuditFinding]
  violations : Array[GateViolation]
} derive(Debug, Eq)

///|
pub fn verdict_name(verdict : GateVerdict) -> String {
  match verdict {
    Pass => "PASS"
    Review => "REVIEW"
    Fail => "FAIL"
  }
}

///|
pub fn default_policy() -> AuditPolicy {
  AuditPolicy::{
    max_risk_score: 50,
    max_high: 0,
    max_medium: 10,
    max_low: 50,
    deny_rule_ids: [],
  }
}

///|
fn list_contains(items : Array[String], needle : String) -> Bool {
  for item in items {
    if item == needle {
      return true
    }
  }
  false
}

///|
pub fn evaluate_policy(
  report : AuditReport,
  policy : AuditPolicy,
) -> GateResult {
  let violations : Array[GateViolation] = []
  let mut fail = false
  let mut review = false
  for finding in report.findings {
    if list_contains(policy.deny_rule_ids, finding.rule_id) {
      violations.push(GateViolation::{
        rule_id: finding.rule_id,
        reason: "rule is denied by policy: \{finding.title} (\{finding.subject})",
      })
      fail = true
    }
  }
  if report.risk_score > policy.max_risk_score {
    violations.push(GateViolation::{
      rule_id: "RISK-SCORE",
      reason: "risk score \{report.risk_score} exceeds limit \{policy.max_risk_score}",
    })
    fail = true
  }
  if report.high > policy.max_high {
    violations.push(GateViolation::{
      rule_id: "HIGH-FINDINGS",
      reason: "\{report.high} high finding(s) exceeds limit \{policy.max_high}",
    })
    fail = true
  }
  if report.medium > policy.max_medium {
    violations.push(GateViolation::{
      rule_id: "MEDIUM-FINDINGS",
      reason: "\{report.medium} medium finding(s) exceeds limit \{policy.max_medium}",
    })
    review = true
  }
  if report.low > policy.max_low {
    violations.push(GateViolation::{
      rule_id: "LOW-FINDINGS",
      reason: "\{report.low} low finding(s) exceeds limit \{policy.max_low}",
    })
    review = true
  }
  GateResult::{
    verdict: if fail {
      Fail
    } else if review {
      Review
    } else {
      Pass
    },
    risk_score: report.risk_score,
    high: report.high,
    medium: report.medium,
    low: report.low,
    info: report.info,
    findings: report.findings,
    violations,
  }
}

///|
pub fn gate_capture(
  packets : Array[DecodedPacket],
  policy : AuditPolicy,
) -> GateResult {
  evaluate_policy(audit_decoded_packets(packets), policy)
}

///|
pub fn gate_records(
  records : Array[PacketRecord],
  policy : AuditPolicy,
) -> GateResult {
  gate_capture(decode_packets(records), policy)
}

///|
pub fn gate_to_text(result : GateResult) -> String {
  let buf = StringBuilder()
  buf.write_string("MoonTraceGuard gate: \{verdict_name(result.verdict)}\n")
  buf.write_string(
    "risk_score: \{result.risk_score}, high: \{result.high}, medium: \{result.medium}, low: \{result.low}, info: \{result.info}\n",
  )
  if result.violations.length() == 0 {
    buf.write_string("no policy violations\n")
  }
  for violation in result.violations {
    buf.write_string("- [\{violation.rule_id}] \{violation.reason}\n")
  }
  for finding in result.findings {
    buf.write_string(
      "  finding: [\{severity_name(finding.severity)}] \{finding.rule_id}: \{finding.title}\n",
    )
    buf.write_string("    subject: \{finding.subject}\n")
  }
  buf.to_string()
}

///|
pub fn gate_to_json(result : GateResult) -> String {
  let parts : Array[String] = []
  for violation in result.violations {
    parts.push(
      "{ \"rule_id\": \"\{violation.rule_id}\", \"reason\": \"\{violation.reason}\" }",
    )
  }
  "{ \"verdict\": \"\{verdict_name(result.verdict)}\", \"risk_score\": \{result.risk_score}, \"high\": \{result.high}, \"medium\": \{result.medium}, \"low\": \{result.low}, \"info\": \{result.info}, \"violations\": [\{join_strings(parts, ", ")}] }"
}

///|
fn rule_ids_json(ids : Array[String]) -> String {
  let parts : Array[String] = []
  for id in ids {
    parts.push("\"\{id}\"")
  }
  "[\{join_strings(parts, ", ")}]"
}

///|
pub fn policy_to_json(policy : AuditPolicy) -> String {
  "{ \"max_risk_score\": \{policy.max_risk_score}, \"max_high\": \{policy.max_high}, \"max_medium\": \{policy.max_medium}, \"max_low\": \{policy.max_low}, \"deny_rule_ids\": \{rule_ids_json(policy.deny_rule_ids)} }"
}

///|
/// Parse a policy from its JSON form. Missing fields fall back to
/// `default_policy`; invalid JSON also returns the default policy.
pub fn parse_policy_json(text : String) -> AuditPolicy {
  let fallback = default_policy()
  let parsed = @json.parse(text) catch { _ => return fallback }
  guard parsed is Object(members) else { return fallback }
  let get_int = fn(key : String, fallback : Int) -> Int {
    match members.get(key) {
      Some(Number(n, ..)) => n.to_int()
      _ => fallback
    }
  }
  let deny : Array[String] = []
  match members.get("deny_rule_ids") {
    Some(Array(items)) =>
      for item in items {
        if item is String(s) {
          deny.push(s)
        }
      }
    _ => ()
  }
  AuditPolicy::{
    max_risk_score: get_int("max_risk_score", fallback.max_risk_score),
    max_high: get_int("max_high", fallback.max_high),
    max_medium: get_int("max_medium", fallback.max_medium),
    max_low: get_int("max_low", fallback.max_low),
    deny_rule_ids: if deny.length() > 0 {
      deny
    } else {
      fallback.deny_rule_ids
    },
  }
}
