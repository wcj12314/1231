# MoonFlowGuard 项目申报书

## 基本信息

项目名称：MoonFlowGuard：流量记录安全审计与策略门禁工具  
参赛者：吴朝杰  
联系方式：2182047566@qq.com  
GitHub 仓库链接：https://github.com/wcj12314/1231  
项目方向：MoonBit 网络安全审计工具 / 流量策略门禁（输入无关，支持流记录表与解析流量）  
是否为移植项目：否，原创项目

## 项目简介

MoonFlowGuard 使用 MoonBit 实现一个输入无关的流量安全审计与策略门禁规则引擎与命令行工具。项目明确不把“通用抓包解析库”作为核心卖点：Mooncakes 上已有 usagi-star/mooncap（纯 MoonBit PCAP/PCAPNG 离线解析与协议解码）、chensuiyi/packet（Ethernet/IPv4/IPv6/TCP/UDP 头解析）、chensuiyi/pcap（抓包绑定）覆盖解析层能力，因此 MoonFlowGuard 的第一类输入是 CSV 流记录表（防火墙 / EDR / SIEM 导出或手工整理的流表），解码流量（PCAP/PCAPNG）作为等价的第二类输入路径，内置 PCAP 读取器仅保留最小可验证子集用于测试与示例，并设计为可消费 mooncap / packet / pcap 作为解析后端。产品定位落在解析之上的一层：安全审计规则、风险评分、策略门禁（PASS/REVIEW/FAIL 判定与 CI 退出码）和可执行报告。

已对 mooncakes.io 全量注册表进行核查（含 usagi-star/mooncap、chensuiyi/packet、chensuiyi/pcap 及其相邻安全类项目），无同用途的“策略门禁式流量安全审计”实现：mooncap 仅提供格式级 `validate`（校验文件格式合法性），不含审计规则、风险评分或策略判定；本项目的 `gate` / `gate-csv` 是策略评估，与格式校验是不同层级的交付物。

## 核心功能范围

提供安全审计 Finding 模型，包含 severity、rule_id、subject、evidence 和 recommendation；  
提供输入无关的流量入口：CSV 流记录表解析（`parse_flow_csv`，含表头/空行/畸形行容错）与内置最小 PCAP/PCAPNG 读取；  
提供可配置 AuditPolicy（max_risk_score / max_high / max_medium / max_low / deny_rule_ids）与 JSON 策略解析；  
提供 gate 判定：PASS / REVIEW / FAIL，失败时命令行退出码非零，可接入 CI 作为流量门禁；  
支持明文服务暴露检测，如 HTTP、FTP、Telnet、SMTP、POP3、IMAP、LDAP 等；  
支持敏感服务访问检测，如 SSH、SMB、RDP、MySQL、PostgreSQL、Redis、Elasticsearch、MongoDB 等；  
支持 DNS 异常检测，包括异常 qtype、非 IN class、超长域名、UDP/53 解码失败提示和隧道形状（深嵌套/超长 label）启发式；  
支持 TCP 质量信号：基于序列号的 TCP 重传线索、零 flags 异常段、SYN-only 突发（扫描/洪水启发式）和短帧/截断风险；  
支持五元组流识别、上下行包数量、流量大小、Top IP、Top Port、Top Flow 和包长分布；  
提供协议注册表，覆盖常见端口、IP Protocol、DNS Type、TCP Option 和 EtherType 标签；  
支持时间范围过滤、IP / Port / Protocol Filter，便于做审计范围收敛；  
支持 JSON / CSV / Text 安全审计报告导出；  
提供 CLI 命令 summary、flows、dns、audit、gate、gate-csv、policy、filter、export；  
提供真实小型 .pcap / .pcapng 与 CSV 流表 fixture，用于验证两类输入路径；  
提供持续集成配置，保证项目能够正常构建、测试、运行示例，并验证 gate 与 gate-csv 在严格策略下必须失败。

## 技术路线与预期目标

项目采用 MoonBit 作为主要实现语言，按 reader、protocols、container、flow、stats、filter、registry、flow_input、audit、gate、report、cli、tests 等模块组织代码。底层保留最小可验证的 PCAP/PCAPNG 与协议字段读取能力（仅为测试与示例服务，不追求通用解析器完整性）；输入层同时接受 CSV 流记录表与解码流量，证明审计与门禁逻辑与输入来源无关；中层生成五元组流、DNS 事件、端口/协议标签和统计证据；上层实现安全规则、风险评分、策略门禁、Finding 汇总、JSON/CSV/Text 报告和 CLI 输出。

代码规模说明（如实申报，按实测）：项目总行数约 8,100 行，其中 well-known 端口注册表约 5,700 行由 tools/generate_registry.ps1 脚本生成，属静态数据而非算法；解析与输入适配层（reader、protocols、container、flow_input）约 800 行；核心逻辑（解析与输入适配之外的 flow/analysis、audit、gate、report、cli）约 1,000 行。项目保留 11 次 GitHub 提交记录，提供可实际运行的测试、示例和文档。

差异化结论（2026-08-17 全量注册表复查）：本项目与解析层的边界是“解析 vs 审计门禁”，且本项目以流记录表为第一类输入，解析层完全可选。解析层项目（usagi-star/mooncap：PCAP/PCAPNG 解析解码；chensuiyi/packet：Ethernet/IP/TCP/UDP 头解析；chensuiyi/pcap：抓包绑定；oyjh0381/moonipfix：IPFIX 流遥测协议解码；yhsrtty/moontls-parser：TLS ClientHello 解析与 JA3/JA4 指纹）提供“能从流量里读出什么”，MoonFlowGuard 提供“这份流量按策略能不能放行、有哪些安全与质量风险、如何导出报告”，两者互补而不重复。与策略引擎类项目 lllg123/moontrustflow（Policy-as-Code 程序数据流 source→sink 污点路径治理，处理 .mtf 模型与调用图，不处理网络流量）相比，两者只是“规则→Finding→严重级别”的表层形态相似，分析对象与输入完全不同。注册表（约 1,976 个包）全量核查无同用途实现；vectie/moonflow 为 Moon Suite 编排引擎，与本项目同名不同域，无功能重合。

## 原创或参考说明

本项目为原创 MoonBit 项目，不直接移植其他语言项目源码。项目会参考公开协议规范（PCAP/PCAPNG、Ethernet、IPv4/IPv6、TCP/UDP、DNS 相关 RFC）和 Mooncakes 上已有项目的生态边界：usagi-star/mooncap 侧重纯 MoonBit PCAP/PCAPNG 离线解析与协议解码，chensuiyi/packet 侧重 Ethernet/IPv4/IPv6/TCP/UDP 头解析，chensuiyi/pcap 侧重抓包绑定，oyjh0381/moonipfix 侧重 IPFIX 流遥测协议解码，yhsrtty/moontls-parser 侧重 TLS 指纹；MoonFlowGuard 的差异化范围是输入无关的流量安全审计规则、风险评分、策略门禁和可执行报告，并声明可消费上述解析库作为解析后端。若后续复用或适配第三方测试样例，将在 README 和许可证说明中明确列出来源链接、许可证及参考范围。本项目采用 Apache License 2.0 作为开源许可证。
