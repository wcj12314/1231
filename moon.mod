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

name = "wcj12314/moon-trace-guard"

version = "0.1.0"

readme = "README.md"

repository = "https://github.com/wcj12314/moon-trace-guard"

license = "Apache-2.0"

keywords = [ "security", "audit", "gate", "pcap", "dns", "tcp", "moonbit" ]

preferred_target = "wasm"

description = "MoonTraceGuard: a MoonBit security audit and capture-quality gate for PCAP traffic, with policy-based PASS/FAIL verdicts, risk scoring and CI reports. Parsing is a built-in minimal capability for reproducible tests, not the deliverable."
