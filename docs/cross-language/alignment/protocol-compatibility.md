# 跨语言对齐：协议兼容

> 本文是从 `cross-language-java-alignment-plan.md` 拆分出来的四篇之一。索引与拆分理由见 [该文件](../cross-language-java-alignment-plan.md)。

本篇覆盖必须逐字节一致的部分：线上格式、编码规则、帧结构和登录签名。这些一旦分叉，两端就连不上，或者更糟——连上了但对同一份字节有不同理解。

## 阶段 1：协议与启动登录兼容

状态：已完成。

- Go / .NET / C 同步 `MessageType.PEER_CONTROL=5`（`NAT_CONTROL=4`）。
- Go / .NET 的 CompactBinary UUID 字符串编码已对齐 Java 的严格规则：只有小写 canonical UUID 会走 16 字节二进制分支，非 canonical 或大写 UUID 保留为普通字符串，避免跨语言 round-trip 时大小写漂移。
- Go server / .NET protocol 的 CompactBinary HTTP Method 编码已对齐 Java 的精确匹配规则：只有 `GET` / `POST` / `PUT` / `DELETE` 原样大写值会走枚举短编码，小写或混合大小写 method 保留为普通字符串，避免跨语言转发时把原始请求方法静默改写。
- Go client / Go server / .NET protocol 已补齐 CompactBinary 空字符串边界：空 UUID 和空 HTTP Method 按 Java 语义写成普通字符串 marker，而不是退化成 wire-level null，保留协议层 null / empty 的区别。
- Go client / Go server 已补齐 CompactBinary collection 边界：`nil` slice 写成 Java null marker，空 slice 写成 empty marker，避免 byte array / string list 在跨语言转发时丢失 null / empty 区别。
- Go client / Go server / .NET protocol 已补齐 CompactBinary nullable Long 边界：`0L` 按 Java 语义写成非空 long marker + zigzag 0，不再退化成 wire-level null。
- Go client 的 `DirectHTTPResponse.error` 已改为 nullable string，成功响应写 null，非空或空字符串错误按 Java String marker 保留，避免响应错误字段丢失 null / empty 区别。
- .NET protocol 的 CompactBinary NumericString 已对齐 Java `Long.parseLong`：只允许前导正负号和数字，不接受首尾空白，避免 `" 123"` 被静默归一化成 `"123"`。
- Go / .NET 客户端启动配置支持 `apiKey/secret`、`peerMeshDevice`、`peerMeshTunName` 和 `peerMeshMtu`，并会按 Java 规则归一化 MTU 到 `576..1280`；`serverBaseUrl` 统一要求为 http/https 绝对地址。
- Go / .NET 客户端环境上报会把 Windows `DOMAIN\user` / 路径式用户名归一化为 Java 风格裸用户名，避免服务端按 `machineFingerprint + osUser` 分配客户端身份时产生跨语言漂移。
- Go / .NET 客户端识别 HTTP 登录响应里的 `peerMesh` 配置，并支持 Java 兼容 Peer Mesh UDP 控制面、数据帧和虚拟设备状态上报。
- Go / .NET 客户端已补齐运行时 token 主动刷新：长连接不断开时会在过期前重新 HTTP 登录，热更新 TCP 映射、HTTP route 和 Peer Mesh 配置；刷新失败会延迟重试，不主动打断已有控制连接。
- Go / .NET 客户端已补齐 Java 服务端踢线语义：收到 `LOGOUT_REQUEST` 后关闭当前控制连接，由外层 reconnect loop 重新 HTTP 登录并获取最新运行时策略。
- Go / .NET 客户端控制连接重连策略已对齐 Java：失败后按 `2s -> 4s -> 8s -> 16s -> 32s -> 60s` 指数退避，且只在服务端 `LOGIN_RESPONSE.success=true` 后重置退避计数，TCP 连接建立本身不算登录成功；`访问令牌已过期` 会立即重新 HTTP 登录并重连，`服务器繁忙` / `连接频率超过限制` 走退避，其它认证或策略拒绝会停止重连。
- Go / .NET 客户端控制连接心跳空闲策略已对齐 Java：普通业务写出会刷新写空闲时间，5 秒没有任何写出才发送 `HEARTBEAT_REQUEST`，60 秒读空闲关闭当前连接并进入重连状态机。
- Go / .NET 客户端普通 TCP 映射的 `OPEN` 异常分支已对齐 Java：缺少 `port`、缺少 `channelId` 或端口不在当前配置中时拒绝该 stream；本地真实拨号失败发送 `RST`，已建立通道按双向 `FIN` 半关闭，I/O 错误立即 `RST`。
- Go / .NET 客户端与服务端 NAT metadata 读取已对齐 Java 容错语义：字符串字段对非空值使用 `toString` / `fmt.Sprint`，布尔值按 Java 小写 `true/false` 保留，整数字段接受数字值和数字字符串，`float64` / `double` 等 JSON 数字按 Java `Number.intValue()` 风格截断。
- C server 的 `/api/client/auth/login` 已支持两条路径：SQLite 模式下读取 `specus_client_credential`、按 Java canonical HMAC 校验、创建/复用机器用户身份、写入 `specus_client_session=HTTP_AUTHENTICATED` 并签发 `cs_` token；无匹配 DB 凭证时保留环境变量 smoke-test token 模式。响应保持 Java 当前客户端可解析的 `peerMesh.enabled=false`、`specusConfigList` 和 `httpSpecusConfigList` 结构。

## 阶段 5：公共互传、客户端消息与协议边界

状态：Go server 与 .NET server 的运行时主路径和持久化房间角色已对齐；C server 只提供可验证的兼容/禁用响应，Android client 已补客户端消息和控制通道边界。

- Go server 与 .NET server 已实现 Java 的 6 个附件 REST 接口、Aliyun OSS V4 预签名 PUT/GET/HEAD/DELETE、一次性下载授权、HEAD 完成校验、附件过期清理、公开来源 IP 与房间待上传限流，以及 `/ws/public-transfer/discovery` 的 roomToken 哈希隔离、同公网 IP 附近房间、人数/消息限流、roster 和定向 signal。
- Go server 与 .NET server 已实现 `/ws/client-messages`：管理 JWT 鉴权失败返回 `403 + X-Auth-Reason`，按 tenant/owner 严格区分大小写授权，检查所有 `NETTY_ONLINE` session 的接收能力，并支持 admin 到 client 与 client 到 admin/client 的 Java `CLIENT_TO_CLIENT` fallback。
- Go/.NET 登录会持久化 `clientMessageCapabilities` 并投影到管理客户端和 Peer Mesh roster；各客户端只声明真实能力，尚无附件/媒体预览数据面的客户端不会虚报 `attachments`、`mediaPreview` 或非零 `maxAttachmentBytes`。
- Go server 与 .NET server 已实现 Java 的房间 access token、撤销、短配对码兑换和 OWNER/EDITOR/VIEWER 权限；公共 WebSocket 票据使用持久化 room id 作为 room key，并把 `roomRole`、`discoverable` 传入 discovery。附件完成需要可编辑角色，下载允许只读角色，旧附件仍兼容原始 roomToken hash。
- Go server 与 .NET server 已实现 Java 的公共房间流程图版本与登录用户云端流程图：公共版本限制 3 MiB、每房间保留 50 份；登录用户文档按 tenant/owner 隔离、每用户最多 100 份，并用 revision 做并发更新校验。
- Go/.NET 的公开 ICE 配置和 TURN 服务已补 Java 临时 HMAC-SHA1 credential、realm/nonce、MESSAGE-INTEGRITY、401/438 challenge；Java、Go、.NET 与 Android 客户端会按 transaction 与 TURN endpoint 跟踪受保护请求，更新 challenge 后换新 transaction 最多重试一次；STUN URL 归一化覆盖 `stun://`、显式端口和 IPv6。
- Java、Go、.NET、C 与 Android 的 32 MiB 限制均按“11 字节 header + body 的完整帧”计算；最大 body 为配置值减 11。v2 CompactBinary 直接编码固定 schema，不含 `payloadType` 或 deflate；旧压缩 envelope 和 v1 fixture 必须拒绝。
- C server 可返回 Java-shaped 公共 ICE 配置并为显式配置的外部 TURN 服务签发临时 credential；C 进程本身不监听 STUN/TURN。6 个附件路径会明确返回 `409 OBJECT_STORAGE_DISABLED`，不会伪造成功 URL；启动登录会按真实 wire 字段持久化消息能力，但 C 尚无 live client-message / discovery / object-storage 数据面。
