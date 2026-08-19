# 文档目录

按主题分类。`unified-improvement-plan.md` 是跨线执行与进度跟踪的活文档,保留在根目录。

## 根目录 — 横向审查

* [admin-web-ui-audit-2026-07-24.md](admin-web-ui-audit-2026-07-24.md) — 管理后台前端 UI/交互审查清单(2026-07-24)：高危/系统性/传输页/外壳/面板五类问题(H/S/T/E/A/B 编号)，兼作修复进度清单。

## architecture/ — 总体设计与架构演进

* [design.md](architecture/design.md) — 系统详细设计:协议、模块职责、数据模型、并发与安全模型。
* [server-control-edge-ha-plan.md](architecture/server-control-edge-ha-plan.md) — 控制端 / 连接端拆分与高可用演进方案。

## peer-mesh/ — 私有组网与 NAT 打洞

* [peer-mesh-implementation.md](peer-mesh/peer-mesh-implementation.md) — peer mesh 实现全貌、部署开关与验收步骤。
* [peer-mesh-mobile-plan.md](peer-mesh/peer-mesh-mobile-plan.md) — Android/iOS 目标方案与当前 Android 实现偏差说明。
* [peer-mesh-java-client-audit-fixes.md](peer-mesh/peer-mesh-java-client-audit-fixes.md) — Java 客户端打洞审计与修复记录(2026-07),含成功率观测方法。
* [direct-connect-hole-punching-research.md](peer-mesh/direct-connect-hole-punching-research.md) — P2P 直连打洞历史调研（基线 `57f1a67`）。
* [peer-mesh-dataplane-optimization-audit-2026-07.md](peer-mesh/peer-mesh-dataplane-optimization-audit-2026-07.md) — 数据面性能审计(2026-07)：每包成本、并发模型、协议开销与 IPv6 连通性优化项清单。
* [peer-mesh-hole-punching-audit-2026-07.md](peer-mesh/peer-mesh-hole-punching-audit-2026-07.md) — 打洞成功率第二轮审计(2026-07-21)：候选交换同步、重试节奏、端口预测、生日悖论打洞等优化项(H-1~H-8)。
* [turn-relay-failure-diagnosis-2026-07.md](peer-mesh/turn-relay-failure-diagnosis-2026-07.md) — TURN 中继失败诊断(2026-07-22)：手机端中继发文件失败与网页互传无法使用内置 TURN 的根因与修法。
* [peer-mesh-ipv6-nat64-acceptance.md](peer-mesh/peer-mesh-ipv6-nat64-acceptance.md) — IPv6-only、双栈、NAT64 与 Android 网络切换的生产验收矩阵、通过标准和证据清单。

## transfer/ — 免登录互传

* 互传模块支持文件传输、剪贴板同步和同步白板；[public-file-transfer-audit.md](transfer/public-file-transfer-audit.md) 记录其中的文件传输实现与审计清单(2026-07)。“接收前确认”默认关闭（自动接收），开启后才要求接收/拒绝，拒绝不回退 OSS。
* [professional-diagram-complete-plan.md](transfer/professional-diagram-complete-plan.md) — 专业流程图完整改造说明，统一记录目标架构、当前已实现能力、明确边界、未实现功能、实施顺序和完成验收标准。
* [professional-diagram-audit-2026-07.md](transfer/professional-diagram-audit-2026-07.md) — 专业流程图页面审查清单(2026-07)：交互、功能、界面美化三维度问题、优先级总览与建议修复顺序，兼作修复进度清单。

## cross-language/ — 多语言移植与一致性

* [cross-language-java-alignment-plan.md](cross-language/cross-language-java-alignment-plan.md) — 以 Java 为参考实现的对齐索引，按关注点分为四篇：
  * [协议兼容](cross-language/alignment/protocol-compatibility.md) — 必须逐字节一致的线上格式
  * [运行时语义](cross-language/alignment/runtime-semantics.md) — 协议之外必须表现相同的行为
  * [安全差异](cross-language/alignment/security-differences.md) — 必须一致、故意不同，以及为什么
  * [环境验证](cross-language/alignment/environment-verification.md) — 实际跑过什么，以及结论的边界
* [peer-mesh-client-decomposition-plan.md](cross-language/peer-mesh-client-decomposition-plan.md) — Peer Mesh 客户端在四端都长到 4000-5000 行，按变更节奏拆分的分阶段方案。
* [cross-language-e2e-acceptance-matrix.md](cross-language/cross-language-e2e-acceptance-matrix.md) — 三语言 server/client 端到端验收矩阵。
* [specus-server-go-port-plan.md](cross-language/specus-server-go-port-plan.md) — Go 服务端移植计划。
* [specus-server-csharp-port-plan.md](cross-language/specus-server-csharp-port-plan.md) — C# 服务端重写计划(原文件名 eventual-tickling-waffle.md,已更正)。
* [specus-server-c-port-plan.md](cross-language/specus-server-c-port-plan.md) — C 语言服务端移植计划。

## performance/ — 性能与容量

* [single-node-10k-connections-optimization-plan.md](performance/single-node-10k-connections-optimization-plan.md) — 单机 10k 连接历史基线与优化清单；进度以统一改进计划为准。
* [custom-protocol-performance-audit-2026-07.md](performance/custom-protocol-performance-audit-2026-07.md) — 全局自定义协议审计(2026-07)：覆盖控制隧道、HTTP/WS、Peer Mesh、TURN/STUN 转发、网页互传、消息协议、认证及跨语言演进。

## references/ — 外部参考资料

* [STUN-服务器介绍.pdf](references/STUN-服务器介绍.pdf)
* [Tailscale-NAT-穿透中文导读.pdf](references/Tailscale-NAT-穿透中文导读.pdf)
