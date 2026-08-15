# MoonPCAP 项目申报书

## 基本信息

项目名称：MoonPCAP：PCAP/PCAPNG 网络抓包解析与流量分析库  
参赛者：吴朝杰  
联系方式：2182047566@qq.com  
GitHub 仓库链接：https://github.com/wcj12314/1231  
项目方向：MoonBit 网络协议解析基础库 / 流量分析工具  
是否为移植项目：否，原创项目  

## 项目简介

MoonPCAP 计划使用 MoonBit 实现一个可复用的 PCAP/PCAPNG 抓包文件解析与网络流量分析库，为网络调试、协议学习、安全分析、流量统计、教学实验和命令行诊断工具提供基础能力。项目不重复实现已有 TLS ClientHello 指纹分析能力，而是聚焦更底层的抓包容器解析、链路层/网络层/传输层协议解析、五元组流识别和统计报告生成，形成 MoonBit 生态中可长期维护的网络分析基础库。

## 核心功能范围

提供 PCAP 文件头、Packet Record 解析能力，支持大小端字节序处理；  
支持 PCAPNG Section Header Block、Interface Description Block、Enhanced Packet Block 基础解析；  
支持 Ethernet II、VLAN、IPv4、IPv6 基础协议解析；  
支持 TCP、UDP、ICMP 基础解析，并提取关键协议字段；  
支持五元组 src ip、dst ip、src port、dst port、protocol 流识别；  
提供 TCP Flow 聚合、上下行包数量、流量大小统计和 TCP Flags 分析；  
支持 TCP 重传基础检测、包长度分布统计、Top IP、Top Port、Top Flow 分析；  
支持 DNS Query/Response 基础解析，提取域名、类型、响应码和应答信息；  
支持时间范围过滤、IP / Port / Protocol Filter；  
支持 JSON / CSV 流量报告导出；  
提供 CLI 命令 summary、flows、dns、filter、export；  
提供真实小型 .pcap / .pcapng fixture，用于验证二进制解析结果；  
提供 README 示例，覆盖库 API 使用、CLI 使用、抓包摘要、流列表、DNS 分析和导出报告；  
提供持续集成配置，保证项目能够正常构建、测试和运行示例。

## 技术路线与预期目标

项目将采用 MoonBit 作为主要实现语言，按 container、link、network、transport、app、flow、stats、filter、report、cli、tests 等模块组织代码。底层使用字节读取器统一处理二进制偏移、整数读取、字节序和错误返回；中层解析 PCAP/PCAPNG 容器和常见网络协议；上层提供流量聚合、统计分析、过滤器和报告导出。项目预计完成 4,000 行以上有效 MoonBit 代码，保留不少于 6 次 GitHub 提交记录，并提供可实际运行的测试、示例和文档。

## 原创或参考说明

本项目为原创 MoonBit 项目，不直接移植其他语言项目源码。实现过程中会参考公开协议规范和文件格式说明，包括 PCAP 文件格式、PCAPNG 文件格式、Ethernet、IPv4、IPv6、TCP、UDP、ICMP、DNS 等公开协议资料。若后续参考具体开源项目的设计或测试样例，将在 README 和许可证说明中明确列出项目名称、来源链接、许可证及参考范围。本项目采用 Apache License 2.0 作为开源许可证。
