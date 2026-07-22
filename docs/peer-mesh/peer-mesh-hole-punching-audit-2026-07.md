# Peer Mesh 打洞成功率审计（2026-07-21）

以专业网络工程视角对当前打洞（NAT traversal）实现的第二轮审计。上一轮（2026-07-05，见
`peer-mesh-java-client-audit-fixes.md`）修复了 roster 丢候选、keepalive 单包脆弱、endpoint
摆动、广播风暴等缺陷并补齐了 `/api/admin/peer-mesh/stats` 聚合端点；本轮在其基础上审视
**剩余的成功率与收敛时间优化空间**。

审计对象：`implementations/java/client/.../peer/PeerMeshClient.java`（main 分支，行号为
2026-07-21 近似位置，代码变动后以符号名检索为准）。

状态标记：`OPEN` 未处理 / `IN_PROGRESS` 进行中 / `DONE` 已完成。

---

## 成功率现状判断

代码层面无法直接回答成功率，须以 `/api/admin/peer-mesh/stats` 的 `activeDirectRatio`
（活跃会话 DIRECT 占比）作为代理指标建立数据基线；`natTypes` 分布用于定位失败集中的
NAT 组合。机制完备度推出的理论预期：

| NAT 组合 | 预期 | 依据 |
| --- | --- | --- |
| Full/Restricted Cone × Cone | 高（~95%） | srflx 稳定，burst 探测对抗 conntrack race |
| Cone × Symmetric | 高 | Cone 端 srflx 是稳定靶子，对称端主动打出即通 |
| Port-Restricted × Port-Restricted | 中高 | 依赖双向打洞时序同步——当前最大短板（H-1） |
| Symmetric × Symmetric | 低 | 仅靠 UPnP 端口映射或 IPv6，否则落 relay（H-5） |

行业参照：Tailscale 公开数据约 90%+ 直连（IPv6 + 端口映射 + 生日悖论打洞三件套），libp2p
社区数据 70~80%。本实现在家宽场景合理预期 **80~90%**；无 UPnP 的企业网/移动网明显偏低。

已确认在位的机制强项（免重复怀疑）：burst 探测（3×30ms 同 nonce）、触发式双向探测、
自适应端口预测、UPnP/NAT-PMP/PCP 端口映射（priority 900）、公网 IPv6 host candidate、
hairpin 同 NAT 检测、RTT EWMA + 100ms 滞回选路、direct keepalive 25s + burst 重发。

---

## 优化项（按收益排序）

### H-1 候选交换缺"回礼"，双端打洞窗口不同步 — DONE（2026-07-22）

位置：`handleCandidates`（约 L499）。

B 收到 A 的 candidates 后只做 `sendConnectivityChecks`，**不回发自己的候选**；A 何时向 B
打洞取决于 A 自身的 announce 时机（候选变化事件或 30s maintenance tick）。Port-restricted
组合下打洞本质是"双方几乎同时互射"——B 先打出的包被 A 的 NAT 过滤（但打开了 B 侧
pinhole），必须等 A 也向 B 发包才能建链。当前两端 burst 窗口（90ms）可能错位长达 30s，
首轮命中基本靠运气。触发式双向探测（P1-5）救不了该场景：B 的入站探针根本到不了 A。

修法（低成本高收益）：`handleCandidates` 中若本端尚无对端的健康 direct 路径，立即
`sendCandidatesToPeer` 回发自身候选——等效 ICE triggered check，把双端打洞窗口从最坏
30s 错位压到一个信令 RTT（数百 ms）内对齐。注意加节流防两端互触发循环。

### H-2 打洞重试节奏 30s 一轮，收敛太慢 — DONE（2026-07-22）

位置：`probeKnownCandidates` 挂在 maintenance 30s tick（约 L1367）。

首轮 checks 失败后要等 30s 才重试；ICE 的做法是 50ms pacing 持续重试、数秒内收敛。
建议 session 建立后前 ~10s 做密集重试（1s/2s/4s 退避），之后落回 30s 周期。不改变最终
成功率，但把"ping 通之前丢包多久"从最坏 30–60s 缩到数秒——用户体感上等同于"打洞成不成"。
关联：`pendingVirtualPackets` 的 30s TTL 恰卡在该边界，首包常在路径建立前过期。

### H-3 连通性检查未按 priority 排序 — DONE

位置：`sendConnectivityChecks`（约 L990）。

按对端候选列表原始顺序打，20ms pacing 下排后的候选多等数百 ms。应按 priority 降序
（port-map 900 → host 1000/srflx 800 → relay），LAN 与显式映射先命中。一行改动。

### H-4 端口预测只做 ±delta 一跳，且不消费 NAT 行为探测结果 — OPEN

位置：`adaptivePredictedPorts` / `deltasFromPorts`（约 L1109–L1178）。

- 仅补探 `port ± delta` 一跳。顺序分配对称 NAT（每新目的地端口 +1）下，对端实际新映射 =
  观测值 + 期间新建会话数，一跳经常不够；应按 `±k·delta (k=1..n)` 外推至
  `MAX_ADAPTIVE_PREDICTED_PORTS=16` 上限。
- RFC 5780 行为探测结果（`natMappingBehavior`）只上报服务端，未反向指导打洞策略：
  `ENDPOINT_INDEPENDENT` 时预测纯属浪费，`ADDRESS_AND_PORT_DEPENDENT` 时才应激进外推。

### H-5 Symmetric × Symmetric 生日悖论多 socket 打洞未实现 — OPEN（进阶可选）

当前该组合在无端口映射、无 IPv6 时直接放弃走 relay。Natter/Tailscale 方案：一端开 ~256
个临时 socket 向对端预测区间发包，另一端扫描，生日悖论下碰撞概率 >98%，可把最难组合从
~0% 提到 90%+。代价是瞬时数百 UDP 流（企业防火墙可能告警），适合做默认关闭的配置项。

### H-6 Hairpin 剪枝应改为降级 — DONE（2026-07-22）

位置：`handleCandidates` 同 NAT 检测（约 L509）。

检测到同 NAT 时直接剔除对端 srflx 候选。但同 NAT 下 host 不一定通（AP 隔离、同 NAT 不同
子网），而 NAT 若支持 hairpin，srflx 反而能通。应降低优先级而非剪除（relay 兜底已保留）。

### H-7 移动网 keepalive 间隔偏大 — OPEN

`DIRECT_KEEPALIVE_INTERVAL_MILLIS=25s` 压得住家宽 30–60s 映射 TTL，但部分移动运营商 UDP
超时仅 15–20s。Android 客户端场景建议做成可配置或按网络类型自适应（移动网 ~15s）。

### H-8 IPv6 srflx 缺失 — 部分完成（v6 host candidate 与地址族排序已落地）

v6 host candidate 已收集（`gatherHostCandidates` 含 2000::/3 过滤逻辑），但 STUN 观测仅
IPv4，NAT66/有状态防火墙后的 v6 映射无从上报。详见数据面审计文档 P3-2（已按此修正）。

---

## 落地记录（2026-07-22）

- **H-1**：`handleCandidates` 末尾调用 `reciprocateCandidates`，本端无健康 direct 路径时立即
  回发自身候选，带 2 秒节流防信令循环。
- **H-2**：`scheduleHolePunchRetries` 在 session 首次发起检查后按 1s/2s/4s/8s 退避重试，
  打通或过期即停，本轮结束释放标记以便路径失效后重新进入密集重试。
- **H-3**：`sendConnectivityChecks` 与 `mergePeer` 统一走 `sortedCandidates`（priority 降序）。
- **H-6**：改为 `demoteSameNatReflexiveCandidates`，同 NAT reflexive 候选降到 priority=1 而非剪除。
- 未处理：H-4（端口预测多跳外推 / NAT 行为驱动）、H-5（生日悖论多 socket）、H-7（移动网
  keepalive 自适应）、H-8 剩余的 IPv6 srflx 观测。

## 建议动手顺序

1. 先抓 `/api/admin/peer-mesh/stats` 建立 `activeDirectRatio` 与 `natTypes` 基线——没有
   基线的参数调优无法验证效果。
2. **H-1 → H-2 → H-3**：纯客户端小改动，直接作用于 restricted NAT 组合首轮命中率与收敛
   时间，性价比最高。
3. H-4 / H-5：待基线数据确认对称 NAT 占比高时再投入。
4. H-6 / H-7 / H-8 可穿插单独处理。

改动落地后跨 Java/Go/C#/Android 客户端对齐（参照 `docs/cross-language/
cross-language-java-alignment-plan.md` 的既有节奏）。

## 相关文档

- 上轮打洞审计与修复：`peer-mesh-java-client-audit-fixes.md`
- 数据面性能审计：`peer-mesh-dataplane-optimization-audit-2026-07.md`
- 打洞技术调研：`direct-connect-hole-punching-research.md`
