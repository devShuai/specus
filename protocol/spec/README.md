# shuai-tunnel 协议规范

本目录记录跨语言实现必须共同遵守的协议。当前以 `implementations/java/common`、`implementations/java/server`、
`implementations/java/client` 为参考实现；Go、C# 与 Android client 需要按各自适用的数据面完整语义对齐。
Android 的源码/协议测试不能替代真机 VPN 与跨 NAT 验收。C server 是明确标注的轻量功能子集，当前不实现
Peer Mesh 数据面，不能因本规范包含 Peer Mesh 就推断 C 已具备该能力。

## 文档索引

| 文档 | 说明 |
| --- | --- |
| [control-protocol.md](control-protocol.md) | 控制连接二进制帧、`Command`、`MessageType`、`NAT_MESSAGE`、心跳和 `NAT_CONTROL` |
| [client-auth.md](client-auth.md) | 客户端启动 HTTP 登录、apiKey/secret 签名、运行时 token 和刷新机制 |
| [http-route.md](http-route.md) | HTTP route 直转语义、WebSocket 隧道、Header 透传、响应改写和流量观测 |
| [peer-mesh.md](peer-mesh.md) | Peer Mesh 私有组网、虚拟 IP、信令、标准 STUN/TURN 子集、加密数据帧和管理面 |
| [public-transfer.md](public-transfer.md) | 免登录公共互传的 ICE 配置、发现信令、附件 REST、对象存储和滥用防护 |
| [public-transfer-cluster.md](public-transfer-cluster.md) | 公共互传多实例 Redis presence、修订、共享限流、管理事件恢复与 STCE v2 内部 Pub/Sub 帧 |
| [client-messages.md](client-messages.md) | 管理端与客户端消息 WebSocket、一次性 ticket、能力判断和服务端备用投递 |

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
| 公共 ICE 配置 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/controller/PublicPeerMeshResource.java` |
| 公共互传发现信令 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/websocket/PublicTransferDiscoveryWebSocketHandler.java` |
| 互传附件 REST | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/controller/TransferAttachmentResource.java` |
| 附件状态与对象存储 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/service/TransferAttachmentService.java` |
| 管理端客户端消息 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/websocket/ClientMessagesWebSocketHandler.java` |
| 客户端消息控制通道 fallback | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/handler/MessageRequestHandler.java` |

## 版本约定

- 控制协议 v2 是唯一支持的线协议；旧版本、旧 command、旧 serializer 和旧应用 envelope 必须拒绝。
- 控制连接主帧的 `magic`、`version`、`command`、`serializer` 和字段顺序不可静默变更。
- 序列化算法固定为 `COMPACT_BINARY`（wire ID `4`）；`NAT_MESSAGE` 元数据固定使用 JSON object。
- 固定 schema 增删字段属于破坏性修改，必须提升协议版本并同步替换所有服务端、客户端和测试向量。
- 当前没有通用公网 UDP 端口映射协议；UDP 仅用于 Peer Mesh 的 STUN/TURN、direct check 和加密数据面。
- 任何跨语言新增行为都必须同时更新规范、中央测试向量和所有适用实现，不提供自动降级。
