# implementations/csharp/client

shuai-tunnel 内网客户端的 .NET 实现,与 Java / Go 客户端**线协议字节兼容**。通过控制
通道登录服务端,自动注册 TCP 端口映射,转发外部连接到本地目标,并代理 Direct HTTP 请求。

## 构建运行

```bash
cd implementations/csharp/client
dotnet build ShuaiTunnel.Client.slnx
dotnet run --project src/ShuaiTunnel.Client                   # 当前目录读取 tunnelClientConfig.json
dotnet run --project src/ShuaiTunnel.Client -- --config path  # 显式配置文件
```

发布:

```bash
dotnet publish src/ShuaiTunnel.Client -c Release -o out
./out/shuai-tunnel-client --config /etc/shuai-tunnel/client.json
```

## 配置 (`tunnelClientConfig.json`)

与 Java/Go 客户端共享同一 JSON 结构(可直接互换):

```json
{
  "serverBaseUrl": "http://127.0.0.1:8088",
  "apiKey": "demo-client",
  "secret": "test1234"
}
```

客户端启动时先调用 `serverBaseUrl + /api/client/auth/login`,使用 `apiKey + secret`
签名登录。登录成功后服务端返回运行时 `clientName/clientSessionId/accessToken`、控制通道地址、TCP
映射和 HTTP 路由快照；客户端再发起控制通道长连接。

配置文件加载顺序与 Java 客户端一致:`{cwd}/tunnelClientConfig.json` → `./tunnelClientConfig.json` →
失败抛 `FileNotFoundException`。

## 行为对齐(与 Java 严格一致)

- **启动登录**:`HMAC-SHA256(SHA256(secret), apiKey\ntimestamp\nnonce\nmachineFingerprint\nosUser)`,
  十六进制小写字符串；timestamp 为毫秒。
- **控制通道登录**:使用 HTTP 登录返回的 `clientName/clientSessionId/accessToken`,不再支持旧
  `clientName/password` 启动配置。
- **退避重连**:基础 2s,`min(2 × (1 << min(attempt-1, 5)), 60)` → 2/4/8/16/32/60;**仅在
  `LOGIN_RESPONSE.success=true` 时**重置计数(错密码不会清退避)。
- **空闲**:读 60s 关连接 + 标记 `IDLE_TIMEOUT`;写 5s 发 `HeartbeatRequest`(写失败 ->
  `HEARTBEAT_WRITE_FAILED`)。
- **NAT**:登录后对每个 `tunnelConfigList[i]` 发 REGISTER `{port,tunnelAddress,tunnelPort,clientName}`;
  服务端推 NAT_CONTROL 时 diff 出 UNREGISTER + 增量 REGISTER;每会话单次上报 `HTTP_ROUTES_REPORT`。
- **CONNECTED**:本地 `TcpClient` 拨号 → 读循环转发 `NatMessage(Data, channelId)`;入站 DATA 写本地;
  控制通道写积压 ≥ 64KiB 时暂停本地读,降到 ≤ 32KiB 恢复。
- **Direct HTTP**:`HttpClient` 单例 (`AllowAutoRedirect=false`、`AutomaticDecompression=None`),
  `buildTarget` 严格校验(scheme/host/port 一致、拒绝 `.`/`..`、basePath 包含、`//host` 网络
  路径引用),16 MiB 上/下行限制;异常落 502 + `Error` 字段。
- **关停**:`IHostApplicationLifetime` 取消,关闭控制 socket;**不发** `LogoutRequest`(对齐 Java)。

## 测试

```bash
dotnet test implementations/csharp/client/ShuaiTunnel.Client.slnx
```

- 单元:`DirectHttpForwarder.TryBuildTarget` 路径越界 / 跨主机 / 越界段 / scheme 校验,
  16 MiB 请求体被拒;loopback `HttpListener` 端到端往返。
- 端到端:`TunnelControlClientReconnectTests` 用 in-process `TcpListener` 充当服务端,
  验证登录 → REGISTER → CONNECTED → 双向 DATA 回环 → 断开后自动重连。

## TLS

当前默认明文 TCP(与 Java 客户端默认一致)。后续可在 `TunnelControlClient.RunOnceAsync` 包一层
`SslStream`(PEM + 可选信任所有),协议字节流不变。
