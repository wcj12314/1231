// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "wcj12314/moon-flow-guard"

version = "0.1.0"

readme = "README.md"

repository = "https://github.com/wcj12314/1231"

license = "Apache-2.0"

keywords = [ "security", "audit", "gate", "flow", "dns", "tcp", "moonbit" ]

preferred_target = "wasm"

description = "MoonFlowGuard: a MoonBit traffic-flow security audit and policy gate with PASS/REVIEW/FAIL verdicts, risk scoring and CI reports. Inputs are flow records (CSV) or decoded traffic; PCAP reading is a small built-in capability for tests, not the deliverable."
