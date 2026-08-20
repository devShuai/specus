# 协议测试向量

本目录是 v2 线协议 fixture 的唯一事实来源。实现目录不得保存第二份可独立修改的副本，也不得加入 v1、
旧 HTTP command、deflate payload、SPM1 或 STMSG1 fixture。

## Control v2

`control-v2/frames` 包含：

- 登录、消息、退出和心跳 CompactBinary 帧。
- NAT stream v2 的 REGISTER/OPEN/DATA/FIN/RST/WINDOW_UPDATE 帧。
- HTTP request/response streaming 示例。
- bad magic、v1 version、错误 serializer、未知 command、截断、尾随和超长声明等 malformed 帧。

Java 生成入口：

```text
implementations/java/common/src/test/java/com/theshuai/common/tools/WireFixtureGenerator.java
```

更新 schema 后必须重新生成整个目录，并让 Java、Go、.NET、C 的 decoder 与 roundtrip 测试同时通过。
`login_request.bin` 固定包含 `connectionRole=control`。

## Peer Mesh

- `peer-mesh-spm2.json`：固定 session key、方向 traffic key、nonce、明文和完整 SPM2 帧。
- `peer-path-mtu-v2.json`：固定 SPMTU2 nonce、inner MTU、probe header、padding 和 ack。
- `peer-service-discovery-v2.json`：Java、Go、.NET、Android 真实客户端序列化路径对应的
  `service-report` 与登录 capability wire fixture，以及旧客户端忽略未知消息/字段的兼容样例。

Java、Go、.NET、Android 使用相同字段和字节序；Java、Go、.NET 服务端同时用 SPM2 向量验证无需解密
的 relay 授权头解析。

## 应用与专用协议

- `application-protocol-v2.json`：SWS2 WebSocket frame、STMSG2 文本消息、STCLIP2 富文本剪贴板、
  STAP2 分块/ACK 以及 STWR2 定向 relay 的确定性 canonical 与 malformed 样例。
- `stun-forward-stfwd2.json`：固定 key id、sender epoch、sequence、时间戳、目标地址、STUN response
  与 HMAC-SHA256 的完整 STFWD2 数据报。
- `public-transfer-cluster-v2.json`：跨 Java/Go/.NET 服务端的 Redis STCE v2 discovery/management Pub/Sub 帧，
  房间 groupId 与 tenant managementGroupId 派生。

Java、Go、.NET 与 Android 直接读取 SWS2/STMSG2 向量；管理前端直接读取
STAP2/STWR2/STCLIP2 向量；Java 独立 STUN 服务直接读取 STFWD2 向量。随机 message id、sender epoch
等运行时字段必须在测试里注入固定值，不能复制向量后只做语义相似断言。

Java、Go 与 .NET 服务端必须直接读取 `public-transfer-cluster-v2.json`，验证 STCE 编解码和 groupId；该内部帧
不是浏览器协议，不得暴露 roomKey 或 Redis key。

## 拒绝规则

每种实现至少覆盖：错误版本、错误 magic/type、截断、尾随字节、越界长度、错误 GCM tag/HMAC、重复
sequence 和窗口外旧 sequence。协议测试必须断言一致的 accept/reject 结果，不能只以“项目能编译”作为
互通证明。
