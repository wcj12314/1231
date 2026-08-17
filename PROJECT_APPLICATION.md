# MoonTraceGuard 项目申报书

## 基本信息

项目名称：MoonTraceGuard：PCAP 流量安全审计与捕获质量门禁工具  
参赛者：吴朝杰  
联系方式：2182047566@qq.com  
GitHub 仓库链接：https://github.com/wcj12314/1231  
项目方向：MoonBit 网络安全审计工具 / 抓包质量分析与规则引擎  
是否为移植项目：否，原创项目  

## 项目简介

MoonTraceGuard 计划使用 MoonBit 实现一个面向 PCAP 流量安全审计和捕获质量门禁的规则引擎与命令行工具。Mooncakes 上已有 usagi-star/mooncap、chensuiyi/packet、chensuiyi/pcap 等项目覆盖通用 PCAP/PCAPNG 解析、协议头解析或抓包绑定，因此本项目不把“通用抓包解析库”作为核心卖点，而是将解析能力作为内置最小基础，重点提供明文服务暴露、敏感端口访问、DNS 异常、TCP 重传线索、捕获截断风险、Top Flow 证据、风险评分和 JSON/CSV/Text 审计报告。

## 核心功能范围

提供安全审计 Finding 模型，包含 severity、rule_id、subject、evidence 和 recommendation；  
支持明文服务暴露检测，如 HTTP、FTP、Telnet、SMTP、POP3、IMAP、LDAP 等；  
支持敏感服务访问检测，如 SSH、SMB、RDP、MySQL、PostgreSQL、Redis、Elasticsearch、MongoDB 等；  
支持 DNS 异常检测，包括异常 qtype、非 IN class、超长域名和 UDP/53 解码失败提示；  
支持 TCP 重传线索、TCP flags 异常、短帧/截断风险和捕获质量提示；  
支持五元组流识别、上下行包数量、流量大小、Top IP、Top Port、Top Flow 和包长分布；  
提供协议注册表，覆盖常见端口、IP Protocol、DNS Type、TCP Option 和 EtherType 标签；  
支持时间范围过滤、IP / Port / Protocol Filter，便于做审计范围收敛；  
支持 JSON / CSV / Text 安全审计报告导出；  
提供 CLI 命令 summary、flows、dns、audit、filter、export；  
提供真实小型 .pcap / .pcapng fixture，用于验证二进制解析结果；  
提供 README 示例，覆盖库 API 使用、CLI 使用、抓包摘要、流列表、DNS 分析、安全审计和导出报告；  
提供持续集成配置，保证项目能够正常构建、测试和运行示例。

## 技术路线与预期目标

项目将采用 MoonBit 作为主要实现语言，按 container、protocols、flow、stats、filter、registry、audit、report、cli、tests 等模块组织代码。底层保留最小可验证的 PCAP/PCAPNG 与协议字段读取能力；中层生成五元组流、DNS 事件、端口/协议标签和统计证据；上层实现安全规则、风险评分、Finding 汇总、JSON/CSV/Text 报告和 CLI 门禁输出。项目预计完成 4,000 行以上有效 MoonBit 代码，保留不少于 6 次 GitHub 提交记录，并提供可实际运行的测试、示例和文档。

## 原创或参考说明

本项目为原创 MoonBit 项目，不直接移植其他语言项目源码。项目会参考公开协议规范和 Mooncakes 上已有项目的生态边界：usagi-star/mooncap 侧重纯 MoonBit PCAP/PCAPNG 离线解析与协议解码，chensuiyi/packet 侧重 Ethernet/IPv4/IPv6/TCP/UDP 头解析，chensuiyi/pcap 侧重抓包绑定；MoonTraceGuard 的差异化范围是安全审计规则、风险评分、捕获质量门禁和可执行报告。若后续复用或适配第三方测试样例，将在 README 和许可证说明中明确列出来源链接、许可证及参考范围。本项目采用 Apache License 2.0 作为开源许可证。
