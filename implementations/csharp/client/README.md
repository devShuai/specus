# implementations/csharp/client

specus 内网客户端的 .NET 实现，可连接 Java / Go / .NET server，并与其它桌面/Android 客户端共享唯一的
**v2 线协议**。客户端为每个会话建立独立的 `control` 与 `data` 连接，自动注册 TCP 端口映射，并以 NAT stream
流式代理 HTTP 和 WebSocket。

## 构建运行

```bash
cd implementations/csharp/client
dotnet build Specus.Client.slnx
dotnet run --project src/Specus.Client                   # 当前目录读取 client.jsonc
dotnet run --project src/Specus.Client -- --config path  # 显式配置文件
dotnet run --project src/Specus.Client.Desktop           # Windows 桌面客户端
```

发布:

```bash
dotnet publish src/Specus.Client -c Release -o out
./out/specus-client --config /etc/specus/client.jsonc
```

桌面版发布:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\publish-desktop-win-x64.ps1
.\out\desktop-win-x64\specus-desktop.exe
```

桌面客户端会在界面上填写 `serverBaseUrl/apiKey/secret`，连接后展示当前客户端名、控制端地址、
Peer Mesh 虚拟 IP、对端路由、活跃 peer session、本机 TCP 端口映射和本机 HTTP route。配置默认保存到
`%APPDATA%\Specus\desktop-client.json`。如果启用 `windows-wintun` 或 `auto` 创建虚拟网卡，
仍然需要管理员权限和随包输出的 `native/windows/<arch>/wintun.dll`。

## 配置 (`client.jsonc`)

与 Java/Go/Android 客户端共享同一 JSONC 结构(可直接互换，支持注释和尾逗号):

```jsonc
{
  "$schema": "https://specus.devshuai.com/schemas/client-startup-config.schema.json",
  // 服务端管理 HTTP 地址
  "serverBaseUrl": "http://127.0.0.1:8088",
  "apiKey": "demo-client",
  "secret": "test1234",
  "peerMeshDevice": "noop",
  "peerMeshTunName": "specus0",
  "peerMeshMtu": 1280
}
```

客户端启动时先调用 `serverBaseUrl + /api/client/auth/login`,使用 `apiKey + secret`
签名登录。登录成功后服务端返回运行时 `clientName/clientSessionId/accessToken`、隧道地址、TCP
映射和 HTTP 路由快照；客户端再分别建立 `control` 与 `data` 长连接。

配置文件加载顺序与 Java 客户端一致:`{cwd}/client.jsonc` → `./client.jsonc` →
失败抛 `FileNotFoundException`。

## 行为对齐(与 Java 严格一致)

- **启动登录**:`HMAC-SHA256(SHA256(secret), apiKey\ntimestamp\nnonce\nmachineFingerprint\nosUser)`,
  十六进制小写字符串；timestamp 为毫秒。
- **v2 通道登录**:使用 HTTP 登录返回的 `clientName/clientSessionId/accessToken`，并显式声明
  `connectionRole=control|data`；其它协议版本、serializer 或角色会被拒绝。
- **运行时刷新**:长连接不断开时会在 token 过期前主动重新 HTTP 登录；刷新成功后热更新 TCP
  映射、HTTP route 和 Peer Mesh 配置，刷新失败 60s 后重试，不主动打断现有控制连接。
- **退避重连**:基础 2s,`min(2 × (1 << min(attempt-1, 5)), 60)` → 2/4/8/16/32/60;控制通道
  `LOGIN_RESPONSE.success=true` 后重置计数；如果失败原因是 `访问令牌已过期`，会立即重新 HTTP 登录，
  且 HTTP 刷新成功后重置退避；错密码/策略拒绝会停止重连，繁忙/限频走退避。
- **空闲**:读 60s 关连接 + 标记 `IDLE_TIMEOUT`;普通业务写出会刷新写空闲时间，5s 没有任何写出才发
  `HeartbeatRequest`(写失败 -> `HEARTBEAT_WRITE_FAILED`)。
- **NAT stream**:登录后对每个 `specusConfigList[i]` 发 `REGISTER`，服务端推 `NAT_CONTROL` 时 diff 出
  `UNREGISTER` 与增量 `REGISTER`；TCP/HTTP/WebSocket 流统一使用 `OPEN/DATA/FIN/RST/WINDOW_UPDATE`。
  本地 `TcpClient` 拨号成功后按窗口读取和转发，写积压超过高水位时暂停读，回落到低水位后恢复。
- **HTTP stream**:`HttpClient` 单例 (`AllowAutoRedirect=false`、`AutomaticDecompression=None`，
  对运维配置的内网 HTTPS upstream 证书按 Java 客户端策略信任),
  `buildTarget` 严格校验(scheme/host/port 一致、拒绝 `.`/`..`、basePath 包含；`//` 按 Java
  一样作为同 host 下普通双斜线路径保留)。请求/响应 metadata 只在 `OPEN` 发送一次，body 通过
  `DATA` 增量传输，支持 trailers、SSE、取消传播和窗口流控；异常通过 `RST` 返回。
- **HTTP route WebSocket**:识别 NAT `OPEN source=ws`，按当前 HTTP route 快照构造
  `ws://` / `wss://` 上游地址，过滤 hop-by-hop 与 WebSocket 握手头后发起本地 WebSocket 握手；
  `//` 按 Java 一样作为同 host 下普通双斜线路径保留；对运维配置的内网 `wss` upstream 证书按
  HTTP stream 策略信任；客户端使用原始 RFC 6455 TCP/TLS transport 完成握手、校验
  `Sec-WebSocket-Accept` 并按规范 mask 写帧。每个 `DATA` payload 使用固定 12 字节 `SWS2` envelope，
  双向保留 continuation、FIN、RSV、ping/pong payload 以及 close code/reason；原始 data frame 最大 16 MiB，
  超过单个 SWS2 payload 上限时按 Java 规则规范化拆成 continuation envelopes，控制帧保持单帧。任一侧断开
  都会回发 `FIN` 或 `RST`，并发 CLOSE 只发送一次。
- **Peer Mesh**:读取与 Java 相同的 `peerMeshDevice/peerMeshTunName/peerMeshMtu` 启动配置，
  登录环境会上报 v2 X25519 public key；已识别 HTTP 登录响应里的 `peerMesh` 配置和控制通道
  `PEER_CONTROL` 消息，支持 roster/session/candidates、标准 STUN/TURN Binding，以及带临时 credential、realm/nonce、MESSAGE-INTEGRITY 的 Allocate/Refresh/CreatePermission、Send/Data Indication；
  收到 `401`/`438` 会更新 realm/nonce、换新 transaction ID 并最多重试一次，pending 请求会在成功、15 秒超时、发送失败、停止或凭证切换时清理；
  同时支持公共 STUN srflx 候选、UDP connectivity check、path-report 与 direct-only traffic-report；relay 字节由服务端 relay 热路径计量；数据面统一使用方向密钥、epoch/counter nonce 和 4096 包重放窗口的 `SPM2`。
  Linux 使用 `/dev/net/tun`，Windows 会随 build/publish 输出 `native/windows/<arch>/wintun.dll`，
  并支持通过 `SPECUS_PEER_MESH_WINTUN_DLL` 覆盖，macOS 使用 `utun`。启用 `peerMeshDevice=linux-tun`、`windows-wintun`、
  `mac-utun`、`utun`、`macos-utun`、`darwin-utun` 或 `auto` 后，虚拟网卡出站 IPv4 packet 会按目标虚拟 IP
  查 peer session 并封装为加密 UDP frame，入站 frame 解密后写回虚拟网卡。
  以上是当前源码与自动化测试覆盖的实现状态；真实 Windows / Linux / macOS 双机 ping、HTTP 和 relay fallback 仍需按跨语言验收矩阵手工验证。
- **客户端消息能力**:登录声明 `sendMessages=true`、`receiveMessages=true`；当前客户端没有附件下载/媒体预览数据面，因此如实声明 `attachments=false`、`mediaPreview=false`、`maxAttachmentBytes=0`。普通文本、ACK 和附件元数据统一编码为 Peer Mesh `STMSG2`；文本仍可走服务端 `CLIENT_TO_CLIENT` 传输兜底。
- **关停**:`IHostApplicationLifetime` 取消,关闭控制 socket;**不发** `LogoutRequest`(对齐 Java)。

## 测试

```bash
dotnet test implementations/csharp/client/Specus.Client.slnx
```

SPM2 codec 基准固定覆盖 64、512、1200 字节 payload，并记录吞吐和每次操作分配量：

```bash
dotnet run -c Release --project implementations/csharp/client/benchmarks/Specus.Client.Benchmarks
```

精确的跨模块验证记录见 `docs/cross-language/cross-language-java-alignment-plan.md`。

- 单元:`HttpRouteTargetResolver` 路径越界 / 跨主机 / 越界段 / scheme 校验、HTTP stream
  流控与取消、自签 HTTPS upstream 默认 handler 策略；HTTP route WebSocket
  target 构造、双斜线路径保留、自签 `wss` upstream 证书策略、握手头过滤和 loopback text frame → NAT `DATA source=ws` 转发；loopback
  `HttpListener` 端到端往返；Peer Mesh frame/replay/key 派生与 IPv4 packet 解析协议测试。
- 端到端:`SpecusControlClientReconnectTests` 用 in-process `TcpListener` 充当服务端，
  验证 control/data 双登录、`REGISTER`、`OPEN`、双向 `DATA/WINDOW_UPDATE` 与断开后自动重连。
- 边界覆盖完整帧 32 MiB（header + body）、TURN MESSAGE-INTEGRITY、真实能力声明和 token 主动刷新。

## TLS

`controlTls.enabled` 未显式设置时，control/data 原始 TCP 通道跟随登录响应的 `nettyTls`；配置 PEM CA、
`serverName` 或 `insecureSkipVerify` 也会启用 TLS。显式 `false` 优先且不能与 TLS 专用选项并用。默认使用
系统信任和主机名校验，PEM CA 替换信任根，`insecureSkipVerify` 仅用于开发；连接和握手均有超时与取消。
