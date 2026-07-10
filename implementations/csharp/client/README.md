# implementations/csharp/client

shuai-tunnel 内网客户端的 .NET 实现,可连接 Java / Go / .NET server，并与其它桌面/Android 客户端共享**线协议**。通过控制
通道登录服务端,自动注册 TCP 端口映射,转发外部连接到本地目标,并代理 Direct HTTP 请求。

## 构建运行

```bash
cd implementations/csharp/client
dotnet build ShuaiTunnel.Client.slnx
dotnet run --project src/ShuaiTunnel.Client                   # 当前目录读取 client.jsonc
dotnet run --project src/ShuaiTunnel.Client -- --config path  # 显式配置文件
dotnet run --project src/ShuaiTunnel.Client.Desktop           # Windows 桌面客户端
```

发布:

```bash
dotnet publish src/ShuaiTunnel.Client -c Release -o out
./out/shuai-tunnel-client --config /etc/shuai-tunnel/client.jsonc
```

桌面版发布:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\publish-desktop-win-x64.ps1
.\out\desktop-win-x64\shuai-tunnel-desktop.exe
```

桌面客户端会在界面上填写 `serverBaseUrl/apiKey/secret`，连接后展示当前客户端名、控制端地址、
Peer Mesh 虚拟 IP、对端路由、活跃 peer session、本机 TCP 端口映射和本机 HTTP route。配置默认保存到
`%APPDATA%\ShuaiTunnel\desktop-client.json`。如果启用 `windows-wintun` 或 `auto` 创建虚拟网卡，
仍然需要管理员权限和随包输出的 `native/windows/<arch>/wintun.dll`。

## 配置 (`client.jsonc`)

与 Java/Go/Android 客户端共享同一 JSONC 结构(可直接互换，支持注释和尾逗号):

```jsonc
{
  "$schema": "https://tunnel.devshuai.com/schemas/client-startup-config.schema.json",
  // 服务端管理 HTTP 地址
  "serverBaseUrl": "http://127.0.0.1:8088",
  "apiKey": "demo-client",
  "secret": "test1234",
  "peerMeshDevice": "noop",
  "peerMeshTunName": "shuai0",
  "peerMeshMtu": 1280
}
```

客户端启动时先调用 `serverBaseUrl + /api/client/auth/login`,使用 `apiKey + secret`
签名登录。登录成功后服务端返回运行时 `clientName/clientSessionId/accessToken`、控制通道地址、TCP
映射和 HTTP 路由快照；客户端再发起控制通道长连接。

配置文件加载顺序与 Java 客户端一致:`{cwd}/client.jsonc` → `./client.jsonc` →
失败抛 `FileNotFoundException`。

## 行为对齐(与 Java 严格一致)

- **启动登录**:`HMAC-SHA256(SHA256(secret), apiKey\ntimestamp\nnonce\nmachineFingerprint\nosUser)`,
  十六进制小写字符串；timestamp 为毫秒。
- **控制通道登录**:使用 HTTP 登录返回的 `clientName/clientSessionId/accessToken`,不再支持旧
  `clientName/password` 启动配置。
- **运行时刷新**:长连接不断开时会在 token 过期前主动重新 HTTP 登录；刷新成功后热更新 TCP
  映射、HTTP route 和 Peer Mesh 配置，刷新失败 60s 后重试，不主动打断现有控制连接。
- **退避重连**:基础 2s,`min(2 × (1 << min(attempt-1, 5)), 60)` → 2/4/8/16/32/60;控制通道
  `LOGIN_RESPONSE.success=true` 后重置计数；如果失败原因是 `访问令牌已过期`，会立即重新 HTTP 登录，
  且 HTTP 刷新成功后重置退避；错密码/策略拒绝会停止重连，繁忙/限频走退避。
- **空闲**:读 60s 关连接 + 标记 `IDLE_TIMEOUT`;普通业务写出会刷新写空闲时间，5s 没有任何写出才发
  `HeartbeatRequest`(写失败 -> `HEARTBEAT_WRITE_FAILED`)。
- **NAT**:登录后对每个 `tunnelConfigList[i]` 发 REGISTER `{port,tunnelAddress,tunnelPort,clientName}`;
  服务端推 NAT_CONTROL 时 diff 出 UNREGISTER + 增量 REGISTER;每会话单次上报 `HTTP_ROUTES_REPORT`。
- **CONNECTED**:本地 `TcpClient` 拨号 → 读循环转发 `NatMessage(Data, channelId)`;入站 DATA 写本地;
  控制通道写积压 ≥ 64KiB 时暂停本地读,降到 ≤ 32KiB 恢复。
- **Direct HTTP**:`HttpClient` 单例 (`AllowAutoRedirect=false`、`AutomaticDecompression=None`，
  对运维配置的内网 HTTPS upstream 证书按 Java 客户端策略信任),
  `buildTarget` 严格校验(scheme/host/port 一致、拒绝 `.`/`..`、basePath 包含；`//` 按 Java
  一样作为同 host 下普通双斜线路径保留),请求体 16 MiB、响应体 64 MiB 限制；单段 `Range` 请求会按 8 MiB 窗口收窄；
  异常落 502 + `Error` 字段。
- **HTTP route WebSocket**:识别 NAT `CONNECTED source=ws`，按当前 HTTP route 快照构造
  `ws://` / `wss://` 上游地址，过滤 hop-by-hop 与 WebSocket 握手头后发起本地 WebSocket 握手；
  `//` 按 Java 一样作为同 host 下普通双斜线路径保留；对运维配置的内网 `wss` upstream 证书按
  Direct HTTP 策略信任；`DATA` payload 首字节 `0x01/0x02` 分别表示 text/binary frame，任一侧断开
  都会回发 `DISCONNECTED source=ws`。
- **Peer Mesh**:读取与 Java 相同的 `peerMeshDevice/peerMeshTunName/peerMeshMtu` 启动配置，
  登录环境会上报 Java 兼容 X25519 public key；已识别 HTTP 登录响应里的 `peerMesh` 配置和控制通道
  `PEER_CONTROL` 消息，支持 roster/session/candidates、标准 STUN/TURN Binding，以及带临时 credential、realm/nonce、MESSAGE-INTEGRITY 的 Allocate/Refresh/CreatePermission、Send/Data Indication；
  收到 `401`/`438` 会更新 realm/nonce、换新 transaction ID 并最多重试一次，pending 请求会在成功、15 秒超时、发送失败、停止或凭证切换时清理；
  同时支持公共 STUN srflx 候选、UDP connectivity check、path-report 与 direct-only traffic-report；relay 字节由服务端 relay 热路径计量；已补 Java 兼容 `SPM1` AES-GCM frame codec 和 replay window。
  Linux 使用 `/dev/net/tun`，Windows 会随 build/publish 输出 `native/windows/<arch>/wintun.dll`，
  并支持通过 `SHUAI_PEER_MESH_WINTUN_DLL` 覆盖，macOS 使用 `utun`。启用 `peerMeshDevice=linux-tun`、`windows-wintun`、
  `mac-utun`、`utun`、`macos-utun`、`darwin-utun` 或 `auto` 后，虚拟网卡出站 IPv4 packet 会按目标虚拟 IP
  查 peer session 并封装为加密 UDP frame，入站 frame 解密后写回虚拟网卡。
  以上是当前源码与自动化测试覆盖的实现状态；真实 Windows / Linux / macOS 双机 ping、HTTP 和 relay fallback 仍需按跨语言验收矩阵手工验证。
- **客户端消息能力**:登录声明 `sendMessages=true`、`receiveMessages=true`；当前客户端没有附件下载/媒体预览数据面，因此如实声明 `attachments=false`、`mediaPreview=false`、`maxAttachmentBytes=0`。普通文本和 ACK 编码为与 Java / Go 互通的 Peer Mesh `STMSG1`，解码器同时兼容 `STMSG1` 与可选附件扩展 `STMSG2`；文本也可走服务端 `CLIENT_TO_CLIENT` fallback。
- **关停**:`IHostApplicationLifetime` 取消,关闭控制 socket;**不发** `LogoutRequest`(对齐 Java)。

## 测试

```bash
dotnet test implementations/csharp/client/ShuaiTunnel.Client.slnx
```

当前全量客户端测试为 86/86；精确的跨模块验证记录见 `docs/cross-language/cross-language-java-alignment-plan.md`。

- 单元:`DirectHttpForwarder.TryBuildTarget` 路径越界 / 跨主机 / 越界段 / scheme 校验,
  16 MiB 请求体被拒、Range 裁剪、自签 HTTPS upstream 默认 handler 策略；HTTP route WebSocket
  target 构造、双斜线路径保留、自签 `wss` upstream 证书策略、握手头过滤和 loopback text frame → NAT `DATA source=ws` 转发；loopback
  `HttpListener` 端到端往返；Peer Mesh frame/replay/key 派生与 IPv4 packet 解析协议测试。
- 端到端:`TunnelControlClientReconnectTests` 用 in-process `TcpListener` 充当服务端,
  验证登录 → REGISTER → CONNECTED → 双向 DATA 回环 → 断开后自动重连。
- 边界覆盖完整帧 32 MiB（header + body）、TURN MESSAGE-INTEGRITY、真实能力声明和 token 主动刷新。

## TLS

当前默认明文 TCP(与 Java 客户端默认一致)。后续可在 `TunnelControlClient.RunOnceAsync` 包一层
`SslStream`(PEM + 可选信任所有),协议字节流不变。
