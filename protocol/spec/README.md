# shuai-tunnel 协议规范

本目录记录跨语言实现必须共同遵守的协议。当前以 Java `tunnel-common`、`tunnel-server`、`tunnel-client` 为参考实现；Go、C#、C 实现需要按这里的语义逐步对齐。

## 文档索引

| 文档 | 说明 |
| --- | --- |
| [control-protocol.md](control-protocol.md) | 控制连接二进制帧、`Command`、`MessageType`、`NAT_MESSAGE`、心跳和 `NAT_CONTROL` |
| [client-auth.md](client-auth.md) | 客户端启动 HTTP 登录、apiKey/secret 签名、运行时 token 和刷新机制 |
| [http-route.md](http-route.md) | HTTP route 直转语义、WebSocket 隧道、Header 透传、响应改写和流量观测 |
| [peer-mesh.md](peer-mesh.md) | Peer Mesh 私有组网、虚拟 IP、信令、STUN/TURN-lite、加密数据帧和管理面 |

## 参考实现入口

| 能力 | Java 入口 |
| --- | --- |
| 二进制编解码 | `implementations/java/common/src/main/java/com/theshuai/common/protocol/PacketCodec.java` |
| 紧凑二进制序列化 | `implementations/java/common/src/main/java/com/theshuai/common/serialize/impl/CompactBinarySerializer.java` |
| 客户端启动登录 | `implementations/java/client/src/main/java/com/theshuai/tunnelclient/TunnelClientApplication.java` |
| 服务端客户端认证 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/service/ClientAuthService.java` |
| `NAT_CONTROL` 下发 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/service/NatControlService.java` |
| HTTP 直转 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/http/HttpTunnelController.java` |
| Peer Mesh 控制面 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/service/PeerSignalService.java` |
| Peer Mesh 客户端数据面 | `implementations/java/client/src/main/java/com/theshuai/tunnelclient/peer/PeerMeshClient.java` |

## 兼容约定

- 新字段优先使用可选字段，旧实现缺失字段时必须保守降级。
- 控制连接主帧的 `magic`、`command`、`serializer` 和 `length` 不可随意变更。
- 默认序列化算法为 `COMPACT_BINARY`；`NAT_MESSAGE` 元数据固定使用 JSON 布局。
- 任何跨语言新增行为都应先更新本目录，再修改具体语言实现。
