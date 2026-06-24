# Peer Mesh 私有组网协议

Peer Mesh 让同一租户/同一用户下的多个客户端组成私有虚拟网络。每个客户端分配一个虚拟 IP，客户端之间优先通过 UDP direct 通信；direct 不通时使用服务端内置 TURN-lite relay。服务端负责身份、授权、虚拟 IP、候选交换、session 管理和 relay 授权；业务 IP 包在客户端之间端到端加密，服务端 relay 不解密明文。

当前 Java 实现为实验性能力，默认关闭。

## 配置

服务端配置：

| 配置 | 环境变量 | 默认 | 说明 |
| --- | --- | --- | --- |
| `tunnel.peer-mesh.enabled` | `TUNNEL_PEER_MESH_ENABLED` | `false` | 总开关 |
| `tunnel.peer-mesh.cidr` | `TUNNEL_PEER_MESH_CIDR` | `100.96.0.0/11` | 虚拟网段 |
| `tunnel.peer-mesh.public-address` | `TUNNEL_PEER_MESH_PUBLIC_ADDRESS` | 空 | UDP 探测和 relay 对外地址 |
| `tunnel.peer-mesh.stun-turn-port` | `TUNNEL_PEER_MESH_STUN_TURN_PORT` | `3478` | STUN/TURN-lite UDP 主端口 |
| `tunnel.peer-mesh.nat-probe-alternate-port` | `TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT` | `0` | NAT 辅助探测端口；`0` 表示主端口 + 1 |
| `tunnel.peer-mesh.session-ttl-seconds` | `TUNNEL_PEER_MESH_SESSION_TTL_SECONDS` | `3600` | peer session 授权有效期 |
| `tunnel.peer-mesh.allocation-ttl-seconds` | `TUNNEL_PEER_MESH_ALLOCATION_TTL_SECONDS` | `300` | relay allocation 有效期 |

客户端配置：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `peerMeshDevice` | `noop` | 虚拟网卡模式 |
| `peerMeshTunName` | `shuai0` | 虚拟网卡名 |
| `peerMeshMtu` | `1400` | MTU |

`peerMeshDevice` 可选值：

- `noop`：不创建虚拟网卡，只运行控制面和 UDP 探测。
- `linux-tun`：Linux 使用 `/dev/net/tun`。
- `windows-wintun` / `wintun`：Windows 使用 Wintun，客户端包内包含 `wintun.dll`。
- `auto`：按系统自动选择 Linux TUN 或 Windows Wintun，不支持的平台回退 `noop`。

## 设备与虚拟 IP

服务端开启 Peer Mesh 后，客户端 HTTP 登录时会调用 `PeerMeshService.ensureDevice`：

- 按 `tenantId + clientId` 查找或创建设备。
- 从 `TUNNEL_PEER_MESH_CIDR` 中分配一个 `/32` 虚拟 IP。
- 保存客户端上报的 X25519 public key。
- 更新设备最后在线时间和环境信息。

默认 ACL：

- 同一 `tenantId + ownerUsername` 的客户端允许互联。
- 跨用户默认拒绝。
- admin 可创建显式 ACL 允许跨用户互联。
- 设备被禁用时不能创建新 session。

管理接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/admin/peer-mesh/status` | 查看总开关 |
| `GET` | `/api/admin/peer-mesh/devices` | 查看设备和虚拟 IP |
| `PUT` | `/api/admin/peer-mesh/devices/{clientId}` | 启停设备；在线时会推送配置并关闭相关 session |
| `GET` | `/api/admin/peer-mesh/acls` | 查看 ACL |
| `POST` | `/api/admin/peer-mesh/acls` | 创建 ACL |
| `DELETE` | `/api/admin/peer-mesh/acls/{id}` | 删除 ACL |
| `GET` | `/api/admin/peer-mesh/sessions` | 查看 active session |
| `DELETE` | `/api/admin/peer-mesh/sessions/{id}` | 强制关闭单个 session |
| `DELETE` | `/api/admin/peer-mesh/sessions` | 清理所有可见未关闭 session |

## 登录配置

客户端 HTTP 登录响应里的 `peerMesh` 字段：

| 字段 | 说明 |
| --- | --- |
| `enabled` | 服务端总开关和设备开关共同决定 |
| `clientId` / `clientName` | 当前客户端身份 |
| `virtualIp` | 当前客户端虚拟 IP |
| `cidr` | Mesh 虚拟网段 |
| `stunHost` / `stunPort` | STUN-lite 端点 |
| `turnHost` / `turnPort` | TURN-lite relay 端点 |
| `iceUsername` / `iceCredential` | 候选探测凭证，当前为项目内轻量凭证 |
| `serverPublicKey` | 服务端标识用 public key 摘要，目前不参与业务加密 |
| `clientPublicKey` | 当前客户端 public key |
| `sessionTtlSeconds` | peer session TTL |

运行中启停设备时，服务端会通过 `PEER_CONTROL` 下发 `peer-config`，客户端收到后立即启停 Peer Mesh 和虚拟网卡。

## 控制信令

Peer Mesh 信令复用控制连接的 `MESSAGE_REQUEST` / `MESSAGE_RESPONSE`，`messageType=PEER_CONTROL`，`message` 是 `PeerControlMessage` JSON。

### `roster`

服务端下发给客户端，表示当前允许互联的 peer 列表：

```json
{
  "type": "roster",
  "clientId": 1,
  "clientName": "client-a",
  "peers": [
    {
      "clientId": 2,
      "clientName": "client-b",
      "virtualIp": "100.96.0.2",
      "publicKey": "base64-x25519-public-key",
      "online": true
    }
  ]
}
```

客户端收到后刷新本地 peer 表，并向在线 peer 上报候选地址。

### `candidates`

客户端向目标 peer 上报候选地址。若消息没有 `sessionId`，服务端会先创建 session grant，再把候选消息转发给目标。

```json
{
  "type": "candidates",
  "sourceClientId": 1,
  "sourceClientName": "client-a",
  "sourceVirtualIp": "100.96.0.1",
  "sourcePublicKey": "base64-public-key",
  "targetClientId": 2,
  "targetClientName": "client-b",
  "targetVirtualIp": "100.96.0.2",
  "targetPublicKey": "base64-public-key",
  "candidates": [
    {
      "type": "host",
      "transport": "udp",
      "address": "192.168.1.10",
      "port": 51000,
      "priority": 100,
      "foundation": "host-192.168.1.10"
    },
    {
      "type": "srflx",
      "transport": "udp",
      "address": "58.41.26.74",
      "port": 1132,
      "priority": 90,
      "foundation": "srflx"
    },
    {
      "type": "relay",
      "transport": "udp",
      "address": "tunnel.example.com",
      "port": 3478,
      "priority": 10,
      "foundation": "relay",
      "relayId": "allocation-id"
    }
  ]
}
```

候选类型：

| 类型 | 说明 |
| --- | --- |
| `host` | 本机非 loopback、非 link-local IPv4 地址 |
| `srflx` | 通过 STUN-lite binding 获得的公网映射地址 |
| `relay` | 通过 TURN-lite allocate 获得的 relay allocation |

### `session-grant`

服务端发给发起方，表示一次 peer session 已授权：

```json
{
  "type": "session-grant",
  "sessionId": 8254181000350692,
  "sourceClientId": 1,
  "sourceClientName": "client-a",
  "targetClientId": 2,
  "targetClientName": "client-b",
  "token": "session-token",
  "expiresAt": "2026-06-24T01:00:00Z",
  "pathType": "DIRECT",
  "status": "NEGOTIATING"
}
```

客户端用 `sessionId + token + 双方 clientId + 双方 X25519 key` 派生 AES key。

### `path-report`

客户端连通性检查成功或路径切换后上报：

```json
{
  "type": "path-report",
  "sessionId": 8254181000350692,
  "pathType": "DIRECT",
  "status": "ACTIVE",
  "rttMillis": 12,
  "localEndpoint": "0.0.0.0:51000",
  "remoteEndpoint": "58.41.26.74:1132"
}
```

`pathType` 当前为 `DIRECT` 或 `RELAY`。服务端把 session 状态更新为 `ACTIVE`，管理页展示 RTT 和端点。

### `traffic-report`

客户端周期上报 direct/relay 字节数：

```json
{
  "type": "traffic-report",
  "sessionId": 8254181000350692,
  "directBytes": 10240,
  "relayBytes": 0
}
```

relay 数据在服务端转发时也会计入 session。

### `device-report`

客户端上报虚拟网卡和 NAT 探测结果：

```json
{
  "type": "device-report",
  "virtualDeviceMode": "linux-tun",
  "virtualDeviceName": "shuai0",
  "virtualDeviceStatus": "UP",
  "virtualDeviceError": "",
  "natType": "Symmetric NAT",
  "lastEndpoint": "58.41.26.74:1132"
}
```

### `close`

客户端或管理端关闭 session：

```json
{
  "type": "close",
  "sessionId": 8254181000350692,
  "reason": "admin-force-close"
}
```

服务端标记 session 为 `CLOSED`，并向双方在线客户端转发 close 信令。

## STUN/TURN-lite UDP 协议

服务端开启后监听：

- 主端口：`TUNNEL_PEER_MESH_STUN_TURN_PORT`，默认 `3478/udp`。
- 备用探测端口：`TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT`，默认主端口 + 1。

当前实现是项目内 JSON 协议，不是完整 RFC STUN/TURN。

### JSON 消息格式

所有 JSON 消息都有：

```json
{
  "magic": "shuai-peer-relay",
  "type": "binding",
  "transactionId": "uuid"
}
```

`type`：

| 类型 | 方向 | 说明 |
| --- | --- | --- |
| `binding` | client -> server | 请求公网映射地址 |
| `binding-response` | server -> client | 返回 mapped endpoint、观测端口和备用端口 |
| `allocate` | client -> server | 创建 relay allocation |
| `allocated` | server -> client | 返回 allocationId 和 TTL |
| `refresh` | client -> server | 刷新 allocation TTL |
| `send` | client -> server | 通过 relay 发送加密数据帧 |
| `data` | server -> client | relay 转发到目标 allocation |
| `error` | server -> client | 错误 |

`binding-response` 字段：

| 字段 | 说明 |
| --- | --- |
| `probeRole` | `primary`、`alternate` 或 `changed-port` |
| `mappedAddress` / `mappedPort` | 服务端看到的客户端公网映射 |
| `observedByAddress` / `observedByPort` | 响应该 probe 的服务端端点 |
| `alternateAddress` / `alternatePort` | 备用探测端点 |

### NAT 类型判断

客户端会比较主端口和备用端口观察到的映射：

- 映射端点不同：倾向判断为 `Symmetric NAT`。
- 映射端点相同且能收到备用端口主动回包：展示为 `Full cone / Restricted NAT`。
- 映射端点相同但收不到备用端口主动回包：展示为 `Port Restricted NAT` 或保守 `NAT`。

在只有一个公网 IP 和两个 UDP 端口的部署中，无法严格区分所有 NAT 类型。

## 数据面加密帧

客户端从 TUN/Wintun 读取原始 IPv4 packet，按目的虚拟 IP 找到 peer session，再封装为 AES-GCM 加密帧通过 UDP 发送。

密钥派生：

```text
sharedSecret = X25519(localPrivateKey, remotePublicKey)
salt = SHA256("shuai-peer-mesh\n" + sessionId + "\n" + token + "\n" + min(clientId) + "\n" + max(clientId))
prk = HMAC_SHA256(salt, sharedSecret)
aesKey = HKDF-Expand(prk, "shuai-peer-mesh/aes-gcm/v1", 32)
```

数据帧头：

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| `magic` | 4 字节 | `0x53504D31`，ASCII `SPM1` |
| `version` | 1 字节 | 当前 `1` |
| `type` | 1 字节 | 当前 `1` 表示数据帧 |
| `sessionId` | 8 字节 | peer session ID |
| `fromClientId` | 8 字节 | 发送方客户端 ID |
| `toClientId` | 8 字节 | 接收方客户端 ID |
| `sequence` | 8 字节 | 单 session 出站递增序号 |
| `nonce` | 12 字节 | AES-GCM nonce，随机生成 |
| `ciphertextLength` | 4 字节 | 密文字节数 |
| `ciphertext` | N 字节 | AES-GCM 密文和 tag |

AAD 是从 `magic` 到 `nonce` 的完整头部。接收方校验：

- magic/version/type 正确。
- `sessionId` 等于期望 session。
- `toClientId` 等于当前客户端。
- AES-GCM tag 通过。
- `sequence` 通过 64 位滑动窗口，重复包和窗口外旧包拒绝。

明文是完整 IPv4 packet。接收方解密后写入 TUN/Wintun。

## direct 与 relay

发送优先级：

1. 已有健康 `DIRECT` 路径时直接发送。
2. direct candidate 连通性检查成功后切到 `DIRECT`。
3. direct 不可用但双方有 relay allocation 时走 `RELAY`。

服务端 relay 处理 `send` 时会解析加密帧头，并调用 `PeerMeshService.authorizeRelayFrame`：

- session 必须存在。
- session 未过期。
- session 状态必须为 `ACTIVE`。
- `fromClientId` / `toClientId` 必须匹配 session 的 source/target。

relay 只校验头部和授权，不解密业务明文。

## 虚拟网卡行为

Linux：

- 打开 `/dev/net/tun`。
- 使用 `TUNSETIFF` 创建 TUN。
- 执行 `ip addr replace {virtualIp}/{prefix} dev {name}`。
- 执行 `ip link set dev {name} mtu {mtu} up`。
- 执行 `ip route replace {cidr} dev {name}`。

Windows：

- 加载随包或指定路径的 `wintun.dll`。
- 打开或创建 Wintun adapter。
- 执行 `netsh interface ip set address` 设置虚拟 IP。
- 设置 MTU。
- 添加 mesh CIDR 路由。

只接管 mesh CIDR，不修改默认路由。

## 当前限制

- 当前是 TURN-lite JSON 协议，不兼容标准 coturn。
- macOS `utun` 还未实现。
- `noop` 模式不会创建虚拟网卡，因此无法通过系统 `ping` / `curl` 访问虚拟 IP。
- direct 路径依赖双方 UDP 可达；对称 NAT 或严格防火墙下通常会走 relay。
- 控制连接断开后不能创建新 peer session；已建立 direct session 在 TTL 内可继续传输。
