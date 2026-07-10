# 客户端认证协议

客户端不再通过本地 `clientName/password` 登录。当前 Java 实现使用两阶段认证：

1. 客户端启动后先调用服务端 HTTP 接口 `/api/client/auth/login`。
2. HTTP 登录成功后，客户端拿到运行时控制连接信息和短期 `accessToken`。
3. 客户端建立 Netty 控制连接，发送 `LOGIN_REQUEST`，用 `accessToken` 完成控制连接登录。

## 启动配置

客户端从当前工作目录读取 `client.jsonc`。该文件使用 JSONC 语法，支持 `//` / `/* */` 注释和尾逗号：

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

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `serverBaseUrl` | 是 | 服务端管理 HTTP 地址 |
| `apiKey` | 是 | 管理后台创建的客户端凭证 key |
| `secret` | 是 | 客户端凭证明文，只在创建或重置时展示一次 |
| `peerMeshDevice` | 否 | Peer Mesh 虚拟网卡模式，默认 `noop` |
| `peerMeshTunName` | 否 | 虚拟网卡名称，默认 `shuai0` |
| `peerMeshMtu` | 否 | 虚拟网卡 MTU，默认 `1280`；大于 `1280` 会被客户端归一化 |

客户端不需要也不接受本地配置 `clientName`。服务端会按 `apiKey + machineFingerprint + osUser` 找到或创建唯一客户端身份，并分配稳定的 `clientName`。

## HTTP 登录请求

接口：

```http
POST /api/client/auth/login
Content-Type: application/json
```

请求体：

```json
{
  "apiKey": "demo-client",
  "timestamp": "1780000000000",
  "nonce": "e7b8f6f8b1bb4a4fb47d9f281fc0c3a2",
  "signature": "hex-hmac-sha256",
  "environment": {
    "machineFingerprint": "m_xxx",
    "hostname": "workstation",
    "osUser": "shshi",
    "osName": "Windows 11",
    "osVersion": "10.0",
    "osArch": "amd64",
    "clientVersion": "1.0-SNAPSHOT",
    "javaVersion": "21.0.11",
    "peerPublicKey": "base64-x25519-public-key",
    "clientMessageCapabilities": {
      "sendMessages": false,
      "receiveMessages": false,
      "attachments": false,
      "mediaPreview": false,
      "maxAttachmentBytes": 0
    },
    "localAddresses": ["192.168.1.10"],
    "startedAt": "2026-06-24T00:00:00Z"
  }
}
```

### 签名算法

服务端保存的是 `secret` 的 SHA-256 十六进制摘要。客户端签名时使用：

```text
key = SHA256(secret)
message = apiKey + "\n"
        + timestamp + "\n"
        + nonce + "\n"
        + environment.machineFingerprint + "\n"
        + environment.osUser
signature = HEX(HMAC_SHA256(key, message))
```

服务端校验规则：

- `apiKey` 必须存在且启用。
- `timestamp` 与服务端当前时间差不能超过 `60s`。
- `nonce` 当前只参与签名，后续可接入短期去重缓存。
- `environment.machineFingerprint` 和 `environment.osUser` 必须存在。
- `signature` 使用常量时间比较。

## 环境信息

`machineFingerprint` 优先读取用户目录下 `.shuai-tunnel/machine-id`；不存在时生成并保存。写入失败时回退到 `hostname + os.name + os.arch` 的 SHA-256 摘要前缀。

服务端把环境信息写入 `ClientIdentity` 和 `ClientSession`，用于：

- 限制同一机器和同一系统用户只能有一个在线实例。
- 自动生成客户端名。
- 展示主机、操作系统、Java 版本和本地地址。
- Peer Mesh 分配虚拟 IP 和保存设备公钥。
- 在 Peer roster 中发布当前客户端的消息、附件和媒体预览能力。

`environment.clientMessageCapabilities` 是可选能力声明：

| 字段 | 说明 |
| --- | --- |
| `sendMessages` | 客户端能否主动发送点对点消息 |
| `receiveMessages` | 客户端能否接收点对点消息 |
| `attachments` | 客户端能否处理附件 |
| `mediaPreview` | 客户端能否预览媒体附件 |
| `maxAttachmentBytes` | 客户端声明的单附件最大字节数；`0` 表示没有声明 peer-specific 上限，不表示无限制，也不覆盖服务端对象存储上限 |

字段整体缺省时按全部 `false`、大小 `0` 处理，兼容旧客户端。只有 `attachments=true` 才表示附件能力可用；
若同时 `maxAttachmentBytes=0`，发送端不能据此承诺任意大小，只能依赖服务端上传接口的配置上限和实际返回结果。

## HTTP 登录响应

响应体：

```json
{
  "tenantId": "default",
  "clientId": 3813672224291582,
  "clientName": "shuaiwin-shshi-fa22b7af",
  "clientSessionId": 1868708022931423400,
  "accessToken": "cs_xxx",
  "tokenTtlSeconds": 28800,
  "nettyHost": "127.0.0.1",
  "nettyPort": 7010,
  "maxOnlineInstances": 2,
  "policy": {
    "enabled": true,
    "billingStatus": "ACTIVE",
    "retryAfterSeconds": 0
  },
  "tunnelConfigList": [],
  "httpTunnelConfigList": [],
  "peerMesh": {
    "enabled": false,
    "clientId": 3813672224291582,
    "clientName": "shuaiwin-shshi-fa22b7af",
    "virtualIp": null,
    "cidr": "100.96.0.0/11",
    "stunHost": "",
    "stunPort": 3478,
    "turnHost": "",
    "turnPort": 3478,
    "publicStunServers": [],
    "iceUsername": null,
    "iceCredential": null,
    "iceRealm": null,
    "iceNonce": null,
    "serverPublicKey": null,
    "clientPublicKey": null,
    "sessionTtlSeconds": 3600
  }
}
```

| 字段 | 说明 |
| --- | --- |
| `tenantId` | 租户 ID |
| `clientId` | 服务端分配的客户端 ID |
| `clientName` | 服务端分配的客户端名 |
| `clientSessionId` | 本次登录 session ID |
| `accessToken` | 控制连接登录 token，只保存 hash |
| `tokenTtlSeconds` | token 有效期，默认 `28800` 秒 |
| `nettyHost` / `nettyPort` | 控制连接地址 |
| `maxOnlineInstances` | 当前凭证允许同时在线实例数，默认 `2` |
| `policy` | 预留策略字段，目前主要表示启用状态 |
| `tunnelConfigList` | 已启用 TCP 映射初始快照 |
| `httpTunnelConfigList` | 已启用 HTTP route 初始快照 |
| `peerMesh` | Peer Mesh 运行时配置 |

`nettyHost` 优先使用 `TUNNEL_PUBLIC_ADDRESS`，否则使用 HTTP 请求的 server name。公网部署建议显式设置 `TUNNEL_PUBLIC_ADDRESS`。

## 控制连接登录

HTTP 登录成功后，客户端建立控制连接并发送 `LOGIN_REQUEST`：

```json
{
  "clientName": "shuaiwin-shshi-fa22b7af",
  "clientSessionId": 1868708022931423400,
  "accessToken": "cs_xxx"
}
```

服务端校验：

- token hash 存在。
- session 未过期。
- 客户端凭证和客户端账号均启用。
- 客户端连接频率未超限。
- 同一 `credential + machineFingerprint + osUser` 没有其它在线实例。
- 同一凭证在线实例数小于 `maxOnlineInstances`。

登录成功后：

- 服务端绑定 `clientName -> Channel`。
- 连接记录写入成功状态。
- 异步下发 `NAT_CONTROL`。
- Peer Mesh 开启时下发可互联 roster。

登录失败后服务端会主动关闭连接。客户端会按失败原因决定重试、刷新 token 或停止重连。

### runtime token 的重放与传输边界

`accessToken` 是在过期前可复用的 bearer token，不是一次性 token。普通断线重连会继续使用同一
`clientSessionId + accessToken`；它当前不绑定某条 TCP channel、TLS session、源 IP 或设备公钥。
服务端仍会校验 session 过期、客户端/凭证启用状态、同机用户实例数和凭证最大在线实例数，但截获 token 的
一方在这些约束和 TTL 内仍可能尝试重放。

因此生产部署必须为 HTTP 登录和控制连接启用 TLS，并避免把 token 写入日志、命令行或可被其他用户读取的
配置。文档中的 `http://127.0.0.1` 只用于本机开发示例；它不是公网安全部署方式。

## token 刷新

客户端保存 `tokenExpiresAtMillis`，并在过期前主动重新调用 HTTP 登录：

- 剩余时间较长时，提前时间取剩余时间的约 `10%`，最多提前 `300s`，至少提前 `30s`。
- 剩余时间较短时，尽量在中点刷新，但最短延迟 `5s`。
- 主动刷新失败时 `60s` 后重试。
- 控制连接登录返回“客户端访问令牌已过期”时，客户端立即刷新并重连。

刷新成功后客户端会更新：

- `clientName`
- `clientSessionId`
- `accessToken`
- `nettyHost` / `nettyPort`
- TCP 映射和 HTTP route 快照
- Peer Mesh 配置

## 连接数量限制

当前 Java 服务端有两层限制：

| 限制 | 默认 | 说明 |
| --- | ---: | --- |
| `TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` | `1` | 同一凭证、同一机器、同一系统用户只能一个控制连接在线 |
| `TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` | `2` | 新建凭证默认允许的在线实例数 |

单台机器重复启动时，第二个实例会被拒绝。客户端正常停止后服务端在 `channelInactive` 中标记 session 断开；服务端重启时也会关闭遗留 `NETTY_ONLINE` session。
