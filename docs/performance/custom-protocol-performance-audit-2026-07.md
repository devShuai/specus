# 全局自定义协议性能、安全与实施复核（2026-07）

最后复核：2026-07-22

本文覆盖 shuai-tunnel 的控制连接、TCP/HTTP/WebSocket 隧道、Peer Mesh、TURN relay、浏览器互传、
分布式 STUN 转发、客户端消息和相关认证入口。它既保留原审计的问题编号，也记录本轮实施结果。

## 1. 结论

当前代码已经完成一次破坏性 v2 切换，不再考虑旧线协议兼容：

- 控制协议只接受 `version=2` 与 CompactBinary serializer `4`；
- v1 command、旧整包 HTTP command、wire deflate、`SPM1`、`STMSG1`、旧 WebSocket 前缀和 `SPR1`
  均已从生产解码路径删除；
- 服务端不监听 v1 端口，不协商旧能力，也不在 v2 失败后降级；
- 旧端连接会在版本、serializer、command 或应用 envelope 校验阶段被明确拒绝；
- 旧格式只允许出现在 malformed/rejection 测试中，不能作为可发送 fixture。

架构上的主要问题已经从“共享控制 TCP + 整包转发”改为“控制/数据连接分离 + 有流控的数据流”。Peer
数据面固定使用 SPM2，浏览器大消息固定使用 STAP2 分块。多实例公共互传和管理事件恢复已落地，剩余工作主要是
目标机器容量基线与 IPv6/NAT64 真机证据，不是继续维护旧协议。

## 2. 状态总览

状态含义：`DONE` 表示仓库内代码、规范、测试或验收工具已落地。目标环境容量数字与真机网络证据属于发布门禁，
不伪装成仓库内可完成的实现状态；本表当前没有遗留的 `PARTIAL` 或 `DEFERRED` 项。

| 编号 | 状态 | 实施结果 |
| --- | --- | --- |
| P0-1 | DONE | Java 生产 profile/强制开关拒绝公网明文或自签名控制连接，允许显式受信上游 TLS + 私网绑定，并暴露 TLS/拒绝指标 |
| P1-1 | DONE | CompactBinary wire 压缩彻底删除，TUN/TCP/HTTP/WS/媒体不再进入通用 deflate |
| P1-2 | DONE | 每会话建立 `control` 与 `data` 两条 TCP/TLS 连接；DATA 使用 `uint32 streamId`、窗口、半关闭、RST 与公平轮转 |
| P1-3 | DONE | HTTP 改为 `OPEN/DATA/FIN/RST/WINDOW_UPDATE` 流式传输，支持首部先达、SSE、trailers 与取消传播 |
| P1-4 | DONE | 固定 wire ID、严格 v2/serializer 校验；采用一次性硬切换，不再做版本协商或 v1 fallback |
| P1-5 | DONE | 登录前完整帧限制为 16 KiB，按 command 限长、分配前校验、exact consumption 和统一拒绝原因 |
| P1-6 | DONE | SPM2 方向密钥、counter nonce、4096 位 replay window、严格长度、PLPMTUD、MSS 与 ICMP PTB 已落地 |
| P1-7 | DONE | 浏览器 STAP2 二进制分块、SHA-256、ACK、重组限额及 interactive/bulk DataChannel 已落地，WS fallback 使用二进制 relay |
| P1-8 | DONE | STFWD2 使用 `keyId + senderEpoch + sequence` 和按发送者滑动窗口，支持 current/previous key 轮换 |
| P1-9 | DONE | 内置 TURN 固定为 Peer Mesh 专用模式，allocation 绑定客户端身份，权限校验 session peer，支持 ChannelBind/ChannelData |
| P1-10 | DONE | 中央目录已覆盖控制 v2、SPM2、SPMTU2、STFWD2、STAP2/STWR2、SWS2、STMSG2、STCLIP2 与 STCE2，适用实现直接读取 canonical/malformed 向量 |
| P2-1 | DONE | WebSocket 明确定义为 frame tunnel，SWS2 保留 opcode/FIN/RSV/close code/reason 并严格限长 |
| P2-2 | DONE | 管理端只在目标 channel write 完成后返回 `written`，失败返回 `failed`；Peer STMSG2 仅在应用 ACK 后返回 `delivered`，协议明确不承诺 read 或离线 outbox |
| P2-3 | DONE | Java/Go/.NET 与 C 管理通道、公共 discovery WebSocket 使用 45 秒、单用途、一次性 ticket，原始 bearer/room token 不进入升级 URL；C 管理事件同时按租户与所有权过滤 |
| P2-4 | DONE | API key 登录以数据库唯一键原子去重 `(apiKey, nonce)`，并按 TTL 清理 |
| P2-5 | DONE | Java/Go/.NET 通过 Redis 共享 presence/pub-sub、全局名称、房间上限、roster revision 与限速；管理事件跨实例广播，前端重连/定时快照加 4096 条缓冲恢复事件空洞 |
| P2-6 | DONE | `SPR1` 类型及活跃引用删除，relay 只接受标准 TURN + SPM2 |

## 3. 当前线协议

### 3.1 控制帧 v2

固定 11 字节 big-endian 头：

```text
magic(4) | version=2(1) | serializer=4(1) | command(1) | bodyLength(4)
```

控制 body 使用固定 schema CompactBinary。serializer 不协商，body 不压缩。command 与 MessageType 都使用
显式常量，不由语言枚举顺序推导。完整登记表见
[`protocol/spec/control-protocol.md`](../../protocol/spec/control-protocol.md)。

### 3.2 NAT stream v2

`NAT_MESSAGE` body 使用 16 字节固定头，因此一个 DATA chunk 的 framing 固定开销为 27 字节：

```text
type(1) | flags(1) | metadataLength(2) | streamId(4) | value(4) | dataLength(4)
```

OPEN 只发送一次 JSON metadata；后续 DATA 不携带 UUID 或 JSON。每流初始窗口 1 MiB，最大累计窗口 16 MiB，
单流待发送上限 4 MiB，发送端按活动流轮转且每轮最多发送一个 64 KiB chunk。FIN 表示半关闭，RST 表示取消，
WINDOW_UPDATE 把下游消费能力反向传播到上游读取。

控制连接仅承载登录、心跳、配置和 Peer 信令；数据连接承载 NAT stream。角色不匹配、重复登录或 data 先于
control 绑定都会关闭连接。

### 3.3 HTTP 与 WebSocket

HTTP 不再使用独立 command。请求头通过 OPEN 先到达客户端，请求体和响应体按 DATA 流式传输，响应 OPEN
携带状态码和 headers，FIN 可携带 trailers。公网调用方断开或超时会触发 RST 并取消客户端 upstream。

WebSocket 在 NAT DATA 内使用 12 字节 SWS2 envelope：

```text
SWS2 | opcode(1) | flags(1) | closeCode(2) | payloadLength(4) | payload
```

该协议保留 frame 语义并拒绝未知 opcode、非法控制帧、错误 close code、截断和尾随字节。

### 3.4 Peer Mesh

SPM2 外层为 20 字节 AAD 头和 16 字节 GCM tag，固定开销 36 字节：

```text
SPM2 | sessionId(8) | sequence(8) | ciphertext | tag(16)
```

发送和接收身份来自已认证 session/allocation，不再逐包携带 from/to ID。HKDF 按方向派生 traffic key 与 nonce
前缀；sequence 从 1 单调递增，达到上限前必须换 session。接收侧使用 4096 位滑动窗口处理乱序和重放。

SPMTU2 probe/ack 作为 SPM2 认证 payload 传输。每条 direct/relay 路径执行三次确认与二分搜索，结果缓存
10 分钟；IPv4 TCP SYN 会按路径 MTU clamp MSS，过大的 IPv4 包会向本地 TUN 注入 ICMP Fragmentation Needed。

TURN 是本产品专用 relay，不是通用匿名 TURN。allocation 绑定登录客户端身份，只允许已授权 Peer session 的地址，
Send Indication 与 ChannelData 都必须承载合法 SPM2。

### 3.5 浏览器应用协议

文件、Yjs update 和其他大对象使用 STAP2 二进制分块，包含 message id、chunk index/count、长度和完整对象
SHA-256。接收端执行总量、分块数、超时、hash 和幂等校验，并返回应用 ACK。

WebRTC 拆为：

- `interactive`：白板笔划、光标、剪贴板与小控制消息；
- `bulk`：文件、快照和大更新。

DataChannel 不可用时，客户端将相同的二进制应用帧放入 STWR relay envelope，经 discovery WebSocket 定向转发。
不允许把大二进制重新编码为 Base64 JSON。

### 3.6 其他协议

- STFWD2：分布式 STUN 转发，HMAC 绑定 `keyId/senderEpoch/sequence/timestamp/target/payload`；
- STMSG2：客户端聊天与附件元数据，唯一支持的消息 envelope；
- STCLIP2：文本、富文本、链接和文件型剪贴板描述；
- STWB/STDG：白板与流程图协作事件，继续使用低频可读 JSON，但大 update 交给 STAP2；
- WebSocket ticket：只在 HTTPS POST 返回，升级 URL 只携带一次性 ticket。

## 4. 关键安全与性能不变量

1. 所有 decoder 必须先校验长度再分配，并完全消费当前 frame/body。
2. NAT DATA、SPM2、STAP2、SWS2 不执行通用压缩，不接受尾随字节。
3. 生产公网控制/数据连接必须加密；上游终止 TLS 时进程只能绑定受控私网或 loopback。
4. GCM key/nonce 空间按方向和 session 隔离，禁止 sequence 回卷或跨 session 复用。
5. 任何发送 API 都不能冒充端到端确认：`written` 仅表示服务端成功写入目标连接，`delivered` 才表示应用 ACK。
6. TURN permission、ChannelBind 和 SPM2 session 必须指向同一已授权 Peer 身份。
7. 浏览器 fallback 必须定向，房间 scope/generation 变化后必须取消旧连接和待发送任务。
8. 不在监控标签中放 clientId、sessionId、messageId 等高基数值。

## 5. 不兼容切换规则

本次上线必须同时升级服务端与需要继续使用的客户端：

1. 停止旧服务并部署 v2 server；不设置 v1 sidecar 或双端口。
2. 部署 Java、Go、.NET、Android v2 client；Java CLI 仍不声明消息能力。
3. 清理旧二进制与旧 fixture，避免运维误启动。
4. 监控 `unsupported_version`、`unsupported_serializer`、`unknown_command` 和应用 envelope 拒绝数。
5. 发现旧端时直接升级或停用，不允许服务端自动降级。

`invalid_version_v1.bin` 等文件是负向测试，存在的目的只是证明 v1 会被拒绝。

## 6. 测试与验收

中央测试向量位于 [`protocol/test-vectors`](../../protocol/test-vectors/README.md)：

- `control-v2/frames`：登录、心跳、消息、NAT stream、HTTP stream 和 malformed frame；
- `peer-mesh-spm2.json`：固定 key/session/sequence 的 SPM2 加解密；
- `peer-path-mtu-v2.json`：固定 SPMTU2 probe/ack 字节。
- `application-protocol-v2.json`：SWS2、STMSG2、STCLIP2、STAP2/STWR2 与 malformed recipe；
- `stun-forward-stfwd2.json`：固定 key/epoch/sequence/timestamp/target/response/HMAC 的完整数据报。
- `public-transfer-cluster-v2.json`：跨 Java/Go/.NET 的 STCE2 discovery 与管理事件帧、房间/租户 group 派生。

Java、Go、.NET 与 C 读取同一套控制 fixture；Java、Go、.NET 与 Android 验证 SPM2、replay、路径 MTU、
SWS2 和 STMSG2；管理前端验证 STAP2/STWR2/STCLIP2；Java 独立 STUN 服务验证 STFWD2；Java/Go/.NET
服务端读取同一 STCE2 向量并在 Redis CI 中验证跨实例投递。
发布前至少执行：

| 范围 | 必测内容 |
| --- | --- |
| 控制协议 | v1/错误 serializer/未知 command/截断/尾随/超限拒绝，control/data 角色与重连 |
| NAT stream | OPEN/DATA/FIN/RST/WINDOW_UPDATE、慢消费者、窗口溢出和半关闭 |
| HTTP | 首字节流式返回、SSE、trailers、16 MiB 以上响应和中途取消 |
| WebSocket | text/binary/continuation/ping/pong/close、非法控制帧和 64 KiB 边界 |
| Peer | 双向首包、4096 窗口乱序/重放、sequence 上限、direct/relay 与 PLPMTUD |
| 浏览器 | interactive 不被 bulk 阻塞、chunk/hash/ACK、断线重组清理和二进制 WS fallback |
| 安全 | 生产明文门禁、nonce 重放、ticket 重用、TURN 越权与 STFWD2 key 轮换 |

## 7. 后续工作

### 7.1 中央向量维护

P1-10 已完成。以后修改 wire schema 时必须先更新 `protocol/test-vectors`，再同步所有适用实现；不得在实现目录
新增可独立漂移的第二份 canonical fixture。

### 7.2 消息产品语义

管理 fallback 已区分 `written` 与 `failed`，Peer direct 已支持 `delivered` ACK。离线聊天和已读状态不是当前协议缺口：
只有产品明确引入持久 outbox、重试、去重和用户阅读事件后，才能扩展对应状态；当前界面不得显示“已读”。

### 7.3 多实例与容量

该项已完成。cluster 模式下 Redis Lua 原子维护 presence、全局名称、房间人数、修订和固定窗口，STCE2 Pub/Sub
承载 roster/text/binary/management 四类事件。discovery 断线以带 revision 的完整 roster 恢复；管理连接在每次 WebSocket
建立后读取 REST 权威快照，同步期间缓存最多 4096 条事件，溢出时重读，并每 60 秒静默校准。该方案不依赖易失的
resume cursor。`.github/workflows/protocol-v2.yml` 使用真实 Redis 分别验证 Java、Go、.NET，在 Linux 构建测试 C server，
并持续执行管理前端测试/构建、Android 测试/打包和负载脚本语法检查。

### 7.4 基准而非协议兼容

`tools/loadtest/tcp_stream_load.go` 已固化 1/10/100/1000 并发流、慢消费者、吞吐/错误率/p50/p95/p99 输出，
`netem-profile.sh` 固化 1%/3% 丢包与 20/100/300 ms 延迟。Java JMH、Go benchmark 和 .NET BenchmarkDotNet
统一覆盖 64/512/1200 字节 SPM2。目标机器和移动网络的实际报告仍属于发布验收证据；只有真实指标证明专用多 TCP
仍受 TCP HOL 明显限制时，才评估 QUIC。QUIC 不作为 v2 上线前置条件。

## 8. 最终评价

原审计识别的核心问题成立，但原先提出的 v1 收口、能力协商、滚动双栈和自动回退已被产品决策取代。当前实现采用
更清晰的 v2 硬切换：控制与数据分离，HTTP/WS 真正流式，Peer 帧缩至 36 字节固定开销，浏览器大对象二进制分块，
鉴权和 replay 边界明确。

现阶段不应再为旧端添加任何兼容代码。后续投入应集中在目标环境容量报告和 IPv6/NAT64 真机网络矩阵；多实例状态层
已不再是未实现项。
