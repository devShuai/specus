# Peer Mesh 数据面性能实施复核（2026-07）

最后复核：2026-07-22（同日修正 SPMTU2 固定头长度为 17 字节，并澄清 P2-1 有界 worker 仅 Java 落地）

本文是 Peer Mesh 专项审计的实施后版本。当前数据面固定为 SPM2，不保留 SPM1 编解码、能力协商、发送回退或
兼容 fixture。旧帧只允许出现在拒绝测试中。

## 1. 总体结论

专项审计中影响每包 CPU、内存、安全性和 relay 稳定性的主要问题已经修复：

- SPM2 固定开销为 36 字节，不再逐包发送 from/to ID、nonce 或密文长度；
- 方向独立 HKDF traffic key 与 nonce prefix，64 位 sequence 单调递增；
- replay window 从 64 位扩大到 4096 位；
- Java、Go、.NET 与 Android 热路径均按方向/session 缓存 traffic codec、AEAD/Cipher 与派生密钥；
- Peer/session 查找改为不可变双索引，Java 接收解密分片到有界 worker；
- TURN allocation 绑定客户端身份，relay 具备有界队列、指标和 ChannelData；
- direct/relay 路径均实现 SPMTU2 PLPMTUD、路径 MTU 缓存、TCP MSS clamp 和 IPv4 ICMP PTB；
- Java、Go、.NET、Android 使用同一 SPM2 与 SPMTU2 字节约束。

剩余项是 IPv6/NAT64 真机矩阵、持续容量压测和平台 socket 行为观测，不再是协议格式缺陷。

## 2. 状态表

本表的 `DONE` 表示仓库内实现、规范、测试或验收工具已经落地。目标机器容量数字和运营商 IPv6/NAT64 真机证据
属于发布门禁，单独记录在第 8 节，不把无法在开发仓库中伪造的外部证据混作代码未完成项。

| 编号 | 状态 | 复核结果 |
| --- | --- | --- |
| P1-1 | DONE | Java 使用线程本地 Cipher，Go/.NET/Android 使用 session 级 codec；四端都不再逐包 HKDF 或创建 AEAD/Cipher |
| P1-2 | DONE | 方向子密钥、session 隔离和 counter nonce 已实现 |
| P1-3 | DONE | codec 支持 offset/length，异步所有权边界只做必要复制 |
| P1-4 | DONE | clientId 与虚拟 IPv4 双索引 O(1) 查找，roster 原子替换 |
| P1-5 | DONE | 日志级别短路，节流表有容量与 TTL |
| P1-6 | DONE | 未认证 UDP 先做 magic/长度廉价预检，非法流量不进入 JSON 或异常栈热路径 |
| P2-1 | DONE | Java 入站数据按 session 分片到有界单线程 worker（`ArrayBlockingQueue` 容量 2048），控制消息留在收包线程；Go/.NET/Android 在 UDP 收包线程内联同步处理（decode + replay accept + 设备写），单 session 顺序由会话锁保证，未引入独立 worker 池 |
| P2-2 | DONE | 明确采用单 session 顺序加密以保持 sequence/发送顺序；三端 64/512/1200 B 基准与容量工具已固化，只有目标机证明 AES-GCM 为瓶颈时才另立按 flow 分片变更 |
| P2-3 | DONE | Java allocation 接收使用虚拟线程，生命周期与 socket 关闭绑定 |
| P2-4 | DONE | relay 有界队列、拒绝/发送失败/高水位指标及 UDP buffer 配置已实现 |
| P2-5 | DONE | 流量批次提交成功后才清零，失败恢复 pending 并暴露 lag/failure 指标 |
| P3-1 | DONE | SPM2 固定开销从旧设计 70 字节降为 36 字节，旧格式删除 |
| P3-2 | DONE | A/AAAA candidate、priority、按地址族 active/direct/relay 指标、跨端测试与生产验收手册均已实现；IPv6-only/NAT64 真机证据仍是发布门禁 |
| P3-3 | DONE | 慢路径使用显式事务边界，不依赖 Spring 自调用代理 |
| P3-4 | DONE | 四个客户端统一 exact-length，拒绝截断和未认证尾随字节 |
| P4-1 | DONE | roster 构建完成后一次替换不可变索引 |
| P4-2 | DONE | 待发送队列使用 ArrayDeque/等价环形结构 |
| P4-3 | DONE | 与 P1-6 合并，未知 UDP 不再构造字符串或进入 Jackson |
| P4-4 | DONE | 配置 UDP 收发 buffer 与 traffic class；路径尺寸由 PLPMTUD 处理，不依赖平台 DF API |
| P5-1 | DONE | SPMTU2、路径 MTU 缓存、MSS clamp 与 ICMP PTB 已跨 Java/Go/.NET/Android 实现 |

## 3. SPM2 线格式

```text
offset  size  field
0       4     ASCII "SPM2"
4       8     sessionId, big-endian uint64
12      8     sequence, big-endian uint64, first value 1
20      N     AES-GCM ciphertext
20+N    16    AES-GCM authentication tag
```

20 字节头作为 AAD。datagram 总长度必须精确等于 `20 + plaintextLength + 16`。接收端不接受尾随字节、
sequence 0、未知 session、方向不匹配或 tag 错误。

固定开销：

| payload | SPM2 总长 | 开销比例 |
| ---: | ---: | ---: |
| 64 B | 100 B | 56.25% |
| 512 B | 548 B | 7.03% |
| 1200 B | 1236 B | 3.00% |

## 4. 密钥、nonce 与 replay

双方从 X25519 shared secret 与当前 Peer session 授权派生 PRK，再按规范化方向标签派生：

- A 到 B traffic key；
- B 到 A traffic key；
- 每个方向独立 32 位 nonce prefix。

GCM nonce 为 `noncePrefix32 || sequence64`。sessionId/token 构成当前授权 epoch；重新建立 session 必须产生新的
授权与派生上下文。sequence 达到 `uint64` 上限前停止发送并换 session，禁止回卷。

接收端在 GCM 校验成功后提交 replay 状态。4096 位滑动窗口允许常见乱序，但拒绝重复 sequence 和窗口之外旧包。
replay 拒绝、窗口深度和乱序距离应作为低基数指标，不记录 sessionId 标签。

## 5. 热路径实现

### 5.1 客户端

- Java 复用 Cipher/SecretKeySpec，Go/.NET/Android 的 Peer session 缓存方向 traffic codec；
- codec 接受数组 offset/length，减少切片和拼接；
- roster 更新先构造不可变 clientId/IPv4 索引，再原子替换；
- 入站数据 Java 按 session hash 分发到有界 worker 保证单 session 顺序，Go/.NET/Android 在收包线程内联同步处理（单 session 顺序由会话锁保证）；
- probe/控制帧先做固定 magic 和长度预检，未知包静默计数；
- 日志只在对应级别开启时构造参数，来源节流表按 TTL 清理。

Go、.NET 与 Android 保持相同线格式、安全不变量和路径 MTU 行为。平台虚拟网卡实现不同，不改变 Peer wire。

### 5.2 服务端 relay

- allocation 与已认证 client/session 绑定；
- CreatePermission 只能指向当前授权 Peer；
- Send Indication 和 ChannelData 都必须通过 SPM2 头/session/方向校验；
- 下行使用有界 worker queue，队满明确拒绝并计数；
- relay socket 配置收发 buffer，发送失败和高水位可观测；
- 流量批次只有在数据库提交成功后才扣减 pending。

内置 TURN 不提供任意目的地址、任意 payload 的通用代理能力。

## 6. PLPMTUD 与 IP 协作

SPMTU2 payload 为 17 字节固定头：

```text
ASCII "SPMTU2"(6) | kind(1) | nonce(8) | innerMtu(2)
```

`kind=1` 为 probe，`kind=2` 为 ack。固定头长度 `6 + 1 + 8 + 2 = 17` 字节，四端 `HEADER_BYTES` 常量与此一致；probe 帧总长等于 `innerMtu`（用零填充至该尺寸以触达路径 MTU 上限），ack 帧总长等于固定头 17 字节。它作为 SPM2 plaintext 发送，因此 session、方向、sequence 和 GCM tag
共同认证探测。实现规则：

1. direct 与 relay 使用不同 path key；
2. 每个候选尺寸最多探测三次；
3. 成功/失败区间使用二分搜索收敛；
4. 结果缓存 10 分钟，路径切换或 session 变更重新探测；
5. 实际可发送 inner MTU 扣除 IP/UDP/SPM2 外层开销；
6. IPv4 TCP SYN/SYN-ACK 的 MSS option 按路径 MTU clamp 并重算校验和；
7. 超出路径 MTU 的 IPv4 包不静默丢弃，向本地 TUN 注入 ICMP type 3/code 4；
8. direct/relay 探测和业务字节分别计入正确的流量统计。

中央固定向量见 [`protocol/test-vectors/peer-path-mtu-v2.json`](../../protocol/test-vectors/peer-path-mtu-v2.json)。

## 7. 验证

已建立的协议级验证包括：

- SPM2 固定向量、双向派生、错误 tag、sequence 0、截断、尾随字节；
- replay duplicate、乱序、窗口外旧包和 session 重建；
- SPMTU2 probe/ack 精确字节、三次确认和二分收敛；
- MSS clamp、TCP checksum 与 ICMP PTB；
- TURN credential、permission、ChannelBind/ChannelData 和越权拒绝；
- relay queue、流量提交失败恢复和 session 身份绑定。

Java JMH、Go benchmark 与 .NET BenchmarkDotNet 已统一提供 64/512/1200 字节 codec 基线；CI 会编译或执行
benchmark smoke test。`tools/loadtest/tcp_stream_load.go` 可对真实 tunnel echo 端点执行 1/10/100/1000 并发流并输出
吞吐、错误率和 p50/p95/p99，`netem-profile.sh` 提供 20/100/300 ms 与 1%/3% 丢包场景。正式发布仍需在目标机器
保存 pps/core、alloc/packet、队列 drop、direct 成功率、relay 比例和 MTU 分布，开发机数字不能代替容量基线。

## 8. 剩余风险

### IPv6 与 NAT64

代码已支持 A/AAAA candidate、优先级选择和地址族聚合指标，但仍需 Linux、Windows、Android 真机覆盖 IPv6-only、
双栈、NAT64、移动网络切换及不同系统 dual-stack socket 行为。执行步骤和证据门槛见
[`peer-mesh-ipv6-nat64-acceptance.md`](peer-mesh-ipv6-nat64-acceptance.md)；完成前不得仅凭单元测试宣称所有 IPv6 路径可用。

### 出站并行度

同一 session 当前保持有序串行加密。只有基准证明单核 AES-GCM 成为瓶颈，才考虑按 flow 分片或批量发送；盲目并行
会增加重排深度、队列和锁竞争。

### 容量规划

虚拟线程降低了 Java 线程成本，但每 allocation 的 UDP socket、FD、内核 buffer 和 relay 端口仍是硬资源。上线前需按
最大 allocation 数核算 `nofile`、端口范围、内存与带宽配额。

## 9. 上线边界

SPM2 是唯一允许发送的 Peer 数据帧。服务端和客户端必须整体升级；发现旧 SPM1 流量时只记录低频拒绝指标并要求升级，
不得恢复旧 decoder、版本列表或自动降级。协议后续变更必须提升 magic/version，并同时提交规范、中央向量和四端测试。
