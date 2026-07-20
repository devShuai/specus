# 文档目录

按主题分类。`unified-improvement-plan.md` 是跨线执行与进度跟踪的活文档,保留在根目录。

## architecture/ — 总体设计与架构演进

* [design.md](architecture/design.md) — 系统详细设计:协议、模块职责、数据模型、并发与安全模型。
* [server-control-edge-ha-plan.md](architecture/server-control-edge-ha-plan.md) — 控制端 / 连接端拆分与高可用演进方案。

## peer-mesh/ — 私有组网与 NAT 打洞

* [peer-mesh-implementation.md](peer-mesh/peer-mesh-implementation.md) — peer mesh 实现全貌、部署开关与验收步骤。
* [peer-mesh-mobile-plan.md](peer-mesh/peer-mesh-mobile-plan.md) — Android/iOS 目标方案与当前 Android 实现偏差说明。
* [peer-mesh-java-client-audit-fixes.md](peer-mesh/peer-mesh-java-client-audit-fixes.md) — Java 客户端打洞审计与修复记录(2026-07),含成功率观测方法。
* [direct-connect-hole-punching-research.md](peer-mesh/direct-connect-hole-punching-research.md) — P2P 直连打洞历史调研（基线 `57f1a67`）。

## transfer/ — 免登录互传

* 互传模块支持文件传输、剪贴板同步和同步白板；[public-file-transfer-audit.md](transfer/public-file-transfer-audit.md) 记录其中的文件传输实现与审计清单(2026-07)。“接收前确认”默认关闭（自动接收），开启后才要求接收/拒绝，拒绝不回退 OSS。
* [professional-diagram-complete-plan.md](transfer/professional-diagram-complete-plan.md) — 专业流程图完整改造说明，统一记录目标架构、当前已实现能力、明确边界、未实现功能、实施顺序和完成验收标准。
* [professional-diagram-audit-2026-07.md](transfer/professional-diagram-audit-2026-07.md) — 专业流程图页面审查清单(2026-07)：交互、功能、界面美化三维度问题、优先级总览与建议修复顺序，兼作修复进度清单。

## cross-language/ — 多语言移植与一致性

* [cross-language-java-alignment-plan.md](cross-language/cross-language-java-alignment-plan.md) — 以 Java 为参考实现的对齐计划。
* [cross-language-e2e-acceptance-matrix.md](cross-language/cross-language-e2e-acceptance-matrix.md) — 三语言 server/client 端到端验收矩阵。
* [tunnel-server-go-port-plan.md](cross-language/tunnel-server-go-port-plan.md) — Go 服务端移植计划。
* [tunnel-server-csharp-port-plan.md](cross-language/tunnel-server-csharp-port-plan.md) — C# 服务端重写计划(原文件名 eventual-tickling-waffle.md,已更正)。
* [tunnel-server-c-port-plan.md](cross-language/tunnel-server-c-port-plan.md) — C 语言服务端移植计划。

## performance/ — 性能与容量

* [single-node-10k-connections-optimization-plan.md](performance/single-node-10k-connections-optimization-plan.md) — 单机 10k 连接历史基线与优化清单；进度以统一改进计划为准。

## references/ — 外部参考资料

* [STUN-服务器介绍.pdf](references/STUN-服务器介绍.pdf)
* [Tailscale-NAT-穿透中文导读.pdf](references/Tailscale-NAT-穿透中文导读.pdf)
