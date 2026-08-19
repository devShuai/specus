# 多语言实现对齐 Java 计划

本文以 `implementations/java/server` 和 `implementations/java/client` 为参考实现，记录 Go、.NET、C 以及 Android client 的对齐状态。当前"全量对齐"门禁覆盖 Go、.NET 与 Android client；C server 冻结为轻量兼容子集，不纳入 v2/SWS2 完整对齐结论，所有差异必须显式列出。

## 这份文档为什么被拆开

原来是一篇按"阶段 1..6"编排的长文。阶段编号在所有阶段都完成之后就不再承载信息，而文中同时混着四类彼此独立的内容：线上必须逐字节一致的格式、必须表现相同的运行时行为、各端有意不同的安全取舍，以及实际跑过哪些验证。任何一个读者只关心其中一类，却必须读完四类才能确认自己没漏掉相关条目。

现在按关注点分成四篇。本文保留为索引，原有指向它的链接不会失效。

| 文档 | 回答的问题 |
| --- | --- |
| [协议兼容](alignment/protocol-compatibility.md) | 哪些字节必须完全一致？分叉了就连不上，或者更糟——连上了但对同一份数据理解不同 |
| [运行时语义](alignment/runtime-semantics.md) | 协议之外，同一个请求在不同实现上会不会得到同一个结果？多租户与权限、HTTP 直转与流量观测、Peer Mesh 控制面与数据面 |
| [安全差异](alignment/security-differences.md) | 哪些安全机制必须一致、哪些故意不同、以及为什么那是对的 |
| [环境验证](alignment/environment-verification.md) | 实际跑过什么？哪些结论必须在真实环境里才能得到，不能由源码自动化替代 |

## 阅读顺序

排查互通问题从[协议兼容](alignment/protocol-compatibility.md)开始；行为不一致但能连上，看[运行时语义](alignment/runtime-semantics.md)；评估某一端的安全姿态，或想知道某个检查是不是只在部分实现上存在，看[安全差异](alignment/security-differences.md)；引用"已通过"结论之前，先看[环境验证](alignment/environment-verification.md)里这条结论的边界。

## 相关文档

- [跨语言端到端验收矩阵](cross-language-e2e-acceptance-matrix.md)
- [Go server 与 Java server 差异审计](go-server-vs-java-server-audit-2026-07.md)
- [Go server 对齐实施计划](go-server-parity-implementation-plan.md)
