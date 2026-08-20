# 跨语言恶意输入与故障注入测试矩阵

四端各自独立实现同一套协议，因此"某一端挡住了"不等于"这个攻击被挡住了"——攻击者只需要挑一个部署了最宽实现的节点。这份矩阵按**场景**而不是按实现组织，用来回答一个具体问题：这个场景在四端各由什么覆盖，哪一端还没有。

## 类别

| 类别 | 覆盖什么 | 判定标准 |
| --- | --- | --- |
| 畸形帧 | 截断、结构错误、单字节变异、随机字节 | 干净拒绝，不抛未捕获异常，不返回半构造对象 |
| 超尺寸输入 | 超长 body、超大帧、解压膨胀 | 在明确的上限处拒绝，且上限本身有测试 |
| 资源耗尽 | 流数、线程、队列、内存、连接 | 有上限且到达上限时拒绝或背压，而不是无限增长 |
| 重放与伪造 | 重放窗口、证书钉扎、地址伪造 | 拒绝，且拒绝理由可区分 |
| 认证与授权 | 越权、租户越界、限流、口令降级 | 拒绝，且不因失败路径泄露信息 |
| 故障注入 | 事务回滚、超时、停顿、断连、关停 | 不留半完成状态，不静默丢数据 |

## 数量快照

按测试方法名归类统计（2026-08-19 历史快照；场景矩阵已更新至 2026-08-20）：

| 类别 | Go | Java | Android | .NET |
| --- | --- | --- | --- | --- |
| 畸形帧 | 11 | 2 | 6 | 14 |
| 超尺寸输入 | 5 | 9 | 2 | 6 |
| 资源耗尽 | 47 | 9 | 19 | 28 |
| 重放与伪造 | 11 | 9 | 4 | 18 |
| 认证与授权 | 121 | 72 | 19 | 102 |
| 故障注入 | 37 | 21 | 13 | 41 |

数字用来**发现空白**，不用来比较质量。一个覆盖到位的场景可能只需要一条测试，而数字大也可能只是命名习惯。下面按场景逐条对照才是这份文档的正文。

## 场景对照

### 畸形帧

| 场景 | Go | Java | Android | .NET |
| --- | --- | --- | --- | --- |
| SPM2 帧截断/变异 | `peer_frame_test.go` | `PeerDataFrameCodecTests` | `MalformedFrameTest` | `PeerDataFrameHeaderTests` |
| TURN ChannelData / SPM2 误认领 | `adversarial_vector_test.go` | `SharedAdversarialVectorTests` | `SharedAdversarialVectorTest` | `SharedAdversarialVectorTests` |
| UDP probe 越界 offset/length | `peer_probe_rate_limiter_test.go` | — | `MalformedFrameTest` | `PeerUdpProbeSecurityTests` |
| 随机字节 fuzz | `peer_packet_test.go` | — | `MalformedFrameTest` | — |
| STUN/TURN 报文畸形 | `stun_turn_*_test.go` | `StunTurnServerTests` | — | `StunTurnResilienceTests` |

四端现在都直接读取 `protocol/test-vectors/adversarial-inputs.json`。其中 TURN/SPM2 三个向量不只要求“不崩溃”，还断言分类结果：SPM2 magic 虽落在 TURN ChannelData 的类型区间内，也只有完整 ChannelData 解析成功时才能认领；截断或长度越界必须拒绝。这把曾在 Go 上真实发生过的误认领缺陷变成了四端共享回归门禁。

### 超尺寸输入

| 场景 | Go | Java | Android | .NET |
| --- | --- | --- | --- | --- |
| 解压膨胀（zip bomb） | `decompression_limit_test.go` | `DecompressionLimitsTests` | 不适用（不解压上游 body） | `DecompressionLimitsTests` |
| 请求/响应体上限 | `http_test.go` | — | `SpecusCoreProtocolTest` | `DirectHttpForwarderTests` |
| WebSocket 帧上限 | `nat_ws_test.go` | `NatClientHandlerWebSocketTargetTests` | `NettyWebSocketTransportTest` | `FrameSizeBoundaryTests` |
| STUN 数据报上限 | `stun_turn_resilience_test.go` | — | — | `StunTurnResilienceTests` |

### 资源耗尽

| 场景 | Go | Java | Android | .NET |
| --- | --- | --- | --- | --- |
| 并发流上限 | `stream_limit_test.go` | — | `ResourceLimitsTest` | `BackpressureGateTests` |
| 线程/队列上限 | goroutine 模型，不适用 | — | `ResourceLimitsTest` | — |
| 单流与全局队列预算 | `peer_data_plane_test.go` | — | `SlowStreamIsolationTest` | `BackpressureGateTests` |
| 慢消费者不阻塞其他流 | `peer_data_plane_test.go` | — | `SlowStreamIsolationTest` | `BackpressureGateTests` |
| UDP 洪泛限流 | `stun_turn_resilience_test.go` | — | `PeerUdpProbeCodecTest` | `PeerUdpProbeSecurityTests` |
| 登录限流（IP + 账号） | `login_rate_limiter_test.go` | `LoginRateLimiterTests` | 不适用 | `LoginRateLimiterTests` |

**Java 客户端在流与队列上限上没有对应测试**，因为它依赖 Netty 自己的 water mark 而没有独立的准入上限。这是有意的设计差异还是空白，需要一次确认。

### 重放与伪造

| 场景 | Go | Java | Android | .NET |
| --- | --- | --- | --- | --- |
| SPM2 replay window | `peer_frame_test.go` | `PeerReplayWindowTests` | `PeerMeshProtocolTest` | `PeerMeshCryptoTests` |
| 上游证书钉扎不匹配 | `upstream_tls_test.go` | `UpstreamTlsPolicyTests` | `UpstreamTlsPolicyTest` | `UpstreamTlsPolicyTests` |
| XFF 伪造（不可信来源） | `client_address_test.go` | `ClientAddressResolverTests` | 不适用 | `ClientAddressResolverTests` |
| 口令哈希降级 | `password_hash_test.go` | `PasswordServiceTests` | 不适用 | `PasswordHasherTests` |

### 故障注入

| 场景 | Go | Java | Android | .NET |
| --- | --- | --- | --- | --- |
| 事务失败回滚 | `pairing_redeem_test.go`、`client_identity_provision_test.go` | — | 不适用 | — |
| 关停时刷盘不丢数据 | `shutdown_flush_test.go` | — | 不适用 | — |
| 本地写入停顿超时 | `peer_data_plane_test.go` | — | `LocalStreamBackpressureTest` | — |
| 前台服务超时 | 不适用 | 不适用 | `ForegroundServiceTimeoutInstrumentationTest` | 不适用 |
| 重复重连 | `reconnect_integrity_test.go` | — | — | — |
| 服务目录乱序、重复与撤回后迟到 | `peer_service_test.go` | `PeerServiceRuntimeTests` | `PeerServiceRuntimeTest` | `PeerServiceRuntimeTests` |

服务目录这一行由四端共同读取 `protocol/test-vectors/peer-service-catalog-faults.json`，并把乱序、重复以及撤回后的迟到快照依次喂给真实运行时。测试要求旧 revision 不能回滚新目录、重复快照幂等、撤回后迟到包不能复活服务。

**服务端事务与关停类故障注入仍以 Go 覆盖为主。** Java 已有 relay 流量刷盘失败/重试测试，.NET 也覆盖部分消息刷盘失败，但三端尚没有一份适用于不同存储模型的共同事务/关停序列；这类平台相关故障继续保留为后续加固项，不与已经落地的四端共享目录故障向量混为一谈。

## 已知空白与优先级

1. **服务端故障注入**——事务回滚与关停刷盘仍缺跨存储实现的共享注入协议。
2. **Java 客户端资源上限**——先确认依赖 Netty water mark 是否是有意设计，或还需要独立准入上限。
3. **Java 畸形帧广度**——共享语料已执行，但 Java 专属解码器的定向变异覆盖仍少于其它三端。
4. **Java HTTP body 边界测试**——生产代码已有 16 MiB 请求、64 MiB 响应上限，但尚缺直接命中两个边界的定向测试。

这些没有在本次一并补齐，是因为每一条都需要在对应实现里搭出注入点，而不是照抄一份断言；列在这里是为了它们可被排期，而不是被遗忘。

## 维护方式

新增一条对抗性测试时，把它填进上面的场景表；能跨实现表达的输入或故障序列优先放进 `protocol/test-vectors/`，由四端读取同一文件；实现或平台特有的注入点再保留各自测试。发现一个新的攻击面时，先加一行场景再补测试，四端都留空也比不写下来好——**一个没记录的空白，和一个不存在的防护，对使用者是同一回事**。

统计表用一段脚本从方法名重新生成，命名约定见类别表；命名不落在约定里的测试不会被统计到，这是统计的已知限制，也是它只用来发现空白、不用来比较质量的原因。

场景表里引用的每个文件名都经过存在性核对；写这份文档时有六个是凭印象写的、实际不存在，已全部换成真实文件。文件存在不等于它覆盖了那个场景——"Java 请求/响应体上限"一格最初填了一个实际只测 trailers 的文件，核对后改回空白。填表时请按同一标准：**没核对过就填 `—`，不要填一个看起来合理的名字**。

## 相关

- [安全差异](alignment/security-differences.md) — 各端的安全姿态与故意不一致之处
- [环境验证](alignment/environment-verification.md) — 哪些结论必须在真实环境里取得
