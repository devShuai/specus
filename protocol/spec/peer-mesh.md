# Peer Mesh 私有组网协议

Peer Mesh 让同一租户/同一用户下的多个客户端组成私有虚拟网络。每个客户端分配一个虚拟 IP，客户端之间优先通过 UDP direct 通信；direct 不通时使用服务端内置 TURN relay。服务端负责身份、授权、虚拟 IP、候选交换、session 管理和 relay 授权；业务 IP 包在客户端之间端到端加密，服务端 relay 不解密明文。

当前跨语言实现仍属于实验性能力，默认关闭。

## 配置

服务端配置：

| 配置 | 环境变量 | 默认 | 说明 |
| --- | --- | --- | --- |
| `tunnel.peer-mesh.enabled` | `TUNNEL_PEER_MESH_ENABLED` | `false` | 总开关 |
| `tunnel.peer-mesh.cidr` | `TUNNEL_PEER_MESH_CIDR` | `100.96.0.0/11` | 虚拟网段 |
| `tunnel.peer-mesh.public-address` | `TUNNEL_PEER_MESH_PUBLIC_ADDRESS` | 空 | UDP 探测和 relay 对外地址 |
| `tunnel.peer-mesh.stun-turn-port` | `TUNNEL_PEER_MESH_STUN_TURN_PORT` | `3478` | 标准 STUN/TURN UDP 主端口 |
| `tunnel.peer-mesh.standalone-stun-address` | `TUNNEL_PEER_MESH_STANDALONE_STUN_ADDRESS` | 空 | 独立 STUN 域名或 IP；配置后 STUN 与 TURN 使用不同入口 |
| `tunnel.peer-mesh.standalone-stun-port` | `TUNNEL_PEER_MESH_STANDALONE_STUN_PORT` | `3478` | 独立 STUN 入口端口 |
| `tunnel.peer-mesh.standalone-stun-alternate-address` | `TUNNEL_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS` | 空 | 独立 STUN 备用域名或 IP；使用主端口加入备用列表，同时作为 RFC 5780 的 A2 |
| `tunnel.peer-mesh.standalone-stun-alternate-port` | `TUNNEL_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT` | `0` | 独立 RFC 5780 的第二端口 P2；`0` 时回退 NAT 探测备用端口 |
| `tunnel.peer-mesh.nat-probe-alternate-port` | `TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT` | `3479` | NAT 辅助探测端口；显式设为 `0` 时使用主端口 + 1 |
| `tunnel.peer-mesh.stun-primary-bind-address` | `TUNNEL_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS` | 空 | RFC 5780 主地址 A1 的本机绑定 IP |
| `tunnel.peer-mesh.stun-alternate-bind-address` | `TUNNEL_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS` | 空 | RFC 5780 备用地址 A2 的本机绑定 IP |
| `tunnel.peer-mesh.stun-alternate-public-address` | `TUNNEL_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS` | 空 | RFC 5780 备用公网 IP A2；A1 使用 `public-address` |
| `tunnel.peer-mesh.stun-behavior-strict` | `TUNNEL_PEER_MESH_STUN_BEHAVIOR_STRICT` | `false` | 四端点配置不完整时是否拒绝启动内置 STUN/TURN |
| `tunnel.peer-mesh.public-stun-servers` | `TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS` | 空 | 额外公共 STUN server，逗号分隔，只补充 `srflx` candidate |
| `tunnel.peer-mesh.session-ttl-seconds` | `TUNNEL_PEER_MESH_SESSION_TTL_SECONDS` | `3600` | peer session 授权有效期 |
| `tunnel.peer-mesh.allocation-ttl-seconds` | `TUNNEL_PEER_MESH_ALLOCATION_TTL_SECONDS` | `300` | relay allocation 有效期 |
| `tunnel.peer-mesh.relay-min-port` / `relay-max-port` | `TUNNEL_PEER_MESH_RELAY_MIN_PORT` / `TUNNEL_PEER_MESH_RELAY_MAX_PORT` | `49152` / `65535` | TURN relay UDP 分配端口范围 |
| `tunnel.peer-mesh.turn-auth-required` | `TUNNEL_PEER_MESH_TURN_AUTH_REQUIRED` | `true` | 是否要求 TURN 长期凭证认证 |
| `tunnel.peer-mesh.turn-realm` | `TUNNEL_PEER_MESH_TURN_REALM` | `shuai-tunnel` | TURN realm |
| `tunnel.peer-mesh.turn-shared-secret` | `TUNNEL_PEER_MESH_TURN_SHARED_SECRET` | 空 | TURN credential 派生密钥；留空时使用本进程随机密钥 |
| `tunnel.peer-mesh.turn-credential-ttl-seconds` | `TUNNEL_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS` | `3600` | 登录响应中 TURN credential 的有效期 |

客户端配置：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `peerMeshDevice` | `noop` | 虚拟网卡模式 |
| `peerMeshTunName` | `shuai0` | 虚拟网卡名 |
| `peerMeshMtu` | `1280` | MTU；为 UDP 封装、AES-GCM tag 和公网路径预留空间，配置大于 `1280` 时客户端会归一化 |

`peerMeshDevice` 可选值：

- `noop`：不创建虚拟网卡，只运行控制面和 UDP 探测。
- `linux-tun`：Linux 使用 `/dev/net/tun`。
- `windows-wintun` / `wintun`：Windows 使用 Wintun，客户端包内包含 `wintun.dll`。
- `mac-utun` / `utun` / `macos-utun` / `darwin-utun`：macOS 使用内核 utun；Java、Go、.NET 客户端均提供实验性实现。
- `auto`：Java、Go、.NET 客户端按系统选择 Linux TUN、Windows Wintun 或 macOS utun；不支持的平台回退 `noop`。

## 设备与虚拟 IP

服务端开启 Peer Mesh 后，客户端 HTTP 登录时会调用 `PeerMeshService.ensureDevice`：

- 按 `tenantId + clientId` 查找或创建设备。
- 从 `TUNNEL_PEER_MESH_CIDR` 中分配一个 `/32` 虚拟 IP。
- 保存客户端上报的 X25519 public key。
- 更新设备最后在线时间和环境信息。

默认 ACL：

- `tenantId` 和规范化后的 `ownerUsername` 都区分大小写；同一 `tenantId + ownerUsername` 的客户端允许互联。
- 跨用户默认拒绝。
- admin 可创建显式 ACL 允许跨用户互联：正向 `source -> target` 使用 `OUTBOUND/BOTH`，反向授权使用
  `target -> source` 记录上的 `INBOUND/BOTH`；只有 `allowed=true` 生效。
- 设备被禁用时不能创建新 session。

`POST /api/admin/peer-mesh/acls` 按 `tenantId + sourceClientId + targetClientId` upsert。新建时省略
`direction` 缺省为 `OUTBOUND`；更新已有记录时省略 `direction` 必须保留原方向，不得重置。显式 direction
不区分输入大小写并归一化为 `OUTBOUND`、`INBOUND` 或 `BOTH`，其他值拒绝。

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
| `stunHost` / `stunPort` | 标准 STUN 端点；可以指向独立部署的 RFC 5780 STUN |
| `turnHost` / `turnPort` | 标准 TURN relay 端点 |
| `publicStunServers` | 额外公共 STUN server 列表，只用于补充 `srflx` candidate |
| `iceUsername` / `iceCredential` | TURN 长期凭证认证使用的临时用户名和 credential |
| `iceRealm` / `iceNonce` | TURN `REALM` / `NONCE`；认证开启时与 `MESSAGE-INTEGRITY` 一起使用 |
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
      "online": true,
      "messageSendCapable": true,
      "messageReceiveCapable": true,
      "messageAttachmentsCapable": true,
      "messageMediaPreviewCapable": true,
      "messageMaxAttachmentBytes": 536870912
    }
  ]
}
```

客户端收到后刷新本地 peer 表，并向在线 peer 上报候选地址。

五个 `message*` 字段来自 peer 当前在线 session 上报的
`environment.clientMessageCapabilities`；peer 离线或没有匹配的在线 session 时为 `false` / `0`。
旧服务端缺省这些字段时，客户端也按 `false` / `0` 处理。

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
      "port": 49152,
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
| `srflx` | 通过标准 STUN Binding 获得的公网映射地址 |
| `relay` | 通过标准 TURN Allocate 获得的 relay allocation |

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

`traffic-report` schema 同时保留 direct/relay 字段；当前客户端周期上报尚未由服务端热路径掌握的 direct
增量，通常把 `relayBytes` 置为 `0`：

```json
{
  "type": "traffic-report",
  "sessionId": 8254181000350692,
  "directBytes": 10240,
  "relayBytes": 0
}
```

relay 数据由服务端 TURN/relay 转发热路径计入 session，客户端不得重复上报同一批 relay 字节。

### `device-report`

客户端上报虚拟网卡和 NAT 探测结果：

```json
{
  "type": "device-report",
  "virtualDeviceMode": "linux-tun",
  "virtualDeviceName": "shuai0",
  "virtualDeviceStatus": "UP",
  "virtualDeviceError": "",
  "natType": "SYMMETRIC_NAT",
  "natMappingBehavior": "ADDRESS_AND_PORT_DEPENDENT",
  "natFilteringBehavior": "ADDRESS_AND_PORT_DEPENDENT",
  "natBehaviorDiscovery": "RFC5780",
  "lastEndpoint": "58.41.26.74:1132"
}
```

`natMappingBehavior` / `natFilteringBehavior` 使用
`ENDPOINT_INDEPENDENT`、`ADDRESS_DEPENDENT`、
`ADDRESS_AND_PORT_DEPENDENT`、`UNKNOWN`；过滤探测还可能上报
`UNSUPPORTED`。`natBehaviorDiscovery` 为 `RFC5780` 或 `BASIC`。
`natType` 保留为旧客户端和路径策略使用的兼容标签。

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

## STUN/TURN UDP 协议与 direct check

服务端开启后监听：

- 主端口：`TUNNEL_PEER_MESH_STUN_TURN_PORT`，默认 `3478/udp`。
- 备用探测端口：`TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT`，默认 `3479/udp`；配置为 `0` 时取主端口 + 1。
- relay 分配端口：默认 `49152-65535/udp`。

STUN/TURN 控制消息使用标准的二进制 STUN 头、magic cookie、transaction ID 和 TLV attribute，
不是旧版 `shuai-peer-relay` JSON。内置服务端实现的是项目所需的 RFC STUN/TURN 子集：

- 线格式使用 20 字节 STUN header、magic cookie `0x2112A442`、12 字节 transaction ID；message length
  不含 header，attribute 按 4 字节补齐。基础头和 XOR 地址遵循 STUN RFC 5389/8489 兼容格式，
  `MAPPED-ADDRESS`、`RESPONSE-ORIGIN` 与 `OTHER-ADDRESS` 使用普通 MAPPED-ADDRESS 地址格式，
  relay 方法采用 TURN RFC 5766/8656 兼容的本项目子集。
- 完整 RFC 5780 模式要求 A1:P1、A1:P2、A2:P1、A2:P2 四个 UDP 端点，并支持
  `CHANGE-REQUEST` 的 change IP / change port 组合。TURN 只在 A1:P1 处理，其他端点只接受 Binding。
- 当前 codec 能编码 IPv4/IPv6 XOR 地址，但 Peer Mesh 业务数据面和虚拟路由只支持 IPv4；这不构成 IPv6
  Mesh 能力声明。
- RFC 5780 行为探测会在单个 transaction 内按约 `250ms`、`750ms` 重试，并在约 `1600ms` 后判定超时；
  独立 STUN 探测周期与 TURN allocation 维护周期分开，后续维护轮次会重新探测或刷新 relay。

| 方法 / indication | 方向 | 关键 attribute / 说明 |
| --- | --- | --- |
| Binding Request / Success | client <-> server | 返回 `MAPPED-ADDRESS`、`XOR-MAPPED-ADDRESS` 和 `RESPONSE-ORIGIN`；完整四端点模式同时返回 `OTHER-ADDRESS` |
| Binding + `CHANGE-REQUEST` | client <-> server | 按 change IP / change port 从对应端点回包；缺少第二公网 IP 时返回 `420 Unknown Attribute` |
| Allocate Request / Success | client <-> server | `REQUESTED-TRANSPORT=UDP`、`XOR-RELAYED-ADDRESS`、`XOR-MAPPED-ADDRESS`、`LIFETIME` |
| Refresh Request / Success | client <-> server | 刷新或释放 allocation |
| Create Permission Request / Success | client <-> server | 为目标 relay endpoint 建立短期 permission |
| Send Indication | client -> server | `XOR-PEER-ADDRESS` + `DATA`，承载加密 peer frame |
| Data Indication | server -> client | `XOR-PEER-ADDRESS` + `DATA`，承载加密 peer frame |

TURN 认证默认开启。登录响应下发 `iceUsername`、`iceCredential`、`iceRealm` 和 `iceNonce`；
受保护请求携带 `USERNAME`、`REALM`、`NONCE` 和 `MESSAGE-INTEGRITY`。认证失败使用标准错误响应，
例如 `401 Unauthorized` 和 `438 Stale Nonce`。

当前长期凭证派生为：`iceUsername` 含过期时间；`iceCredential = Base64Url(HMAC-SHA1(turnSharedSecret,
iceUsername))`；`MESSAGE-INTEGRITY` 使用 HMAC-SHA1，key 为 `MD5(username + ":" + realm + ":" + credential)`。
`Allocate`、`Refresh`、`CreatePermission` 受该校验保护；`Send Indication` 依赖已认证创建的 allocation 和
permission。未配置 `TUNNEL_PEER_MESH_TURN_SHARED_SECRET` 时服务端使用进程内随机密钥，重启后旧凭证失效。

客户端必须按 `transaction ID + TURN endpoint` 跟踪上述受保护请求。收到 `401` 或 `438` 时，客户端从
错误响应更新 `REALM` / `NONCE`，使用新的 transaction ID 和重新计算的 `MESSAGE-INTEGRITY` 最多重试一次；
第二次 challenge、响应端点不匹配或缺少有效凭证时不得继续重试。请求成功、发送失败、超时、配置/凭证切换
以及客户端停止时都必须清理对应 pending 状态。Binding Request 和 Send Indication 不添加这组长期认证属性。

额外的 `publicStunServers` 只接收 Binding 请求，用于补充 server-reflexive candidate；
它们不提供本项目的 relay。

### 客户端间 direct connectivity check

客户端 candidate 之间的连通性检查仍使用项目内 JSON `PeerUdpProbe`，它不经过 STUN/TURN server：

```json
{
  "magic": "shuai-peer-mesh",
  "type": "check",
  "sessionId": 8254181000350692,
  "fromClientId": 1,
  "toClientId": 2,
  "nonce": "random-nonce",
  "token": "peer-session-token",
  "sentAtMillis": 1780000000000
}
```

`type=check-response` 使用相同字段并回显 `nonce`、session 和双方 client ID。接收方同时校验
session、token、目标 client ID 和时间窗口。

### NAT 类型判断

完整 RFC 5780 服务使用两个公网 IP 和同一对 UDP 端口：

- 映射行为：客户端从同一个本地 socket 分别向 A1:P1、A2:P1、A2:P2 发送 Binding，比较
  `XOR-MAPPED-ADDRESS`，区分 Endpoint-Independent、Address-Dependent 和
  Address-and-Port-Dependent Mapping。
- 过滤行为：客户端先向 A1:P1 发送普通 Binding，再分别发送 change IP + change port、
  change port 的 `CHANGE-REQUEST`，根据是否收到来自 A2:P2、A1:P2 的响应判断
  Endpoint-Independent、Address-Dependent 和 Address-and-Port-Dependent Filtering。
- `RESPONSE-ORIGIN` 必须等于实际响应源；`OTHER-ADDRESS` 始终是相对请求目标的另一 IP + 另一端口，
  不随 `CHANGE-REQUEST` 标志改变。

只有一个公网 IP 时，服务端不插入 `OTHER-ADDRESS`，并对 `CHANGE-REQUEST` 返回
`420 Unknown Attribute`。项目兼容模式仍可用双端口收集额外映射观察，但不能据此宣称完整 RFC 5780 分类。
独立 STUN 进程的构建和部署见 `implementations/java/stun-server` 与
`deploy/stun-server/systemd`。

## 数据面加密帧

客户端从 Linux TUN、Windows Wintun 或 macOS utun 读取原始 IPv4 packet，按目的虚拟 IP 找到 peer session，再封装为 AES-GCM 加密帧通过 UDP 发送。

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

发送优先级按当前 Java 状态机执行：

1. session 已绑定 `relayTargetAllocationId` 时优先走 `RELAY`；这表示 relay check/data 已明确选定可用目标。
2. 未绑定 relay 目标且已有健康 `DIRECT` 路径时直接发送。
3. direct candidate 连通性检查成功后切到 `DIRECT`；收到有效 direct 数据会清理旧 relay 目标，避免路径状态残留。
4. direct 尚不可用时继续申请/探测 TURN allocation，relay 目标建立后按第 1 条发送。

服务端 relay 处理 TURN `Send Indication` 中的加密帧时，会解析帧头并调用
`PeerMeshService.authorizeRelayFrame`：

- session 必须存在。
- session 未过期。
- session 状态必须为 `ACTIVE`。
- `fromClientId` / `toClientId` 必须匹配 session 的 source/target。

relay 只校验头部和授权，不解密业务明文。

初次 relay 建链不会被 `ACTIVE` 条件卡住：客户端先通过 TURN `Send/Data Indication` 转发 JSON
`PeerUdpProbe` 检查包；它不是 `SPM1` 业务帧，服务端不会对它执行 `authorizeRelayFrame`。检查响应成功后，
客户端先通过控制连接上报 `path-report(status=ACTIVE, pathType=RELAY)`，随后发送的 `SPM1` 业务帧才满足
relay 授权条件。若 `path-report` 未到达，业务帧会被拒绝。

## 虚拟网卡行为

Linux：

- 打开 `/dev/net/tun`。
- 使用 `TUNSETIFF` 创建 TUN，并给接口配置本机 `{virtualIp}/32`。
- 执行 `ip link set dev {name} mtu {mtu} up`。
- 为 roster 中每个在线 peer 执行 `ip route replace {peerVirtualIp}/32 dev {name}`。

Windows：

- 加载随包或指定路径的 `wintun.dll`。
- 打开或创建 Wintun adapter，并给接口配置本机 `/32` 虚拟 IP。
- 设置 MTU。
- 为 roster 中每个在线 peer 执行 `netsh interface ipv4 delete route {peerVirtualIp}/32 {name} store=active`
  清理旧项，再执行 `netsh interface ipv4 add route {peerVirtualIp}/32 {name} store=active` 添加 host route。

macOS：

- 通过 `com.apple.net.utun_control` 打开 utun，并给接口配置本机 `/32` 虚拟 IP 和 MTU。
- 为 roster 中每个在线 peer 添加 `route -n add -host {peerVirtualIp} -interface {utun}`。

三种实现都不安装整个 mesh CIDR 路由，只为当前在线 peer 维护 `/32` host route；
peer 离线、从 roster 消失或虚拟设备停止时会移除对应路由。默认路由不会被修改。

## 当前限制

- 内置 STUN/TURN server 只实现本项目使用的方法和 attribute，不等同于完整 coturn 功能集。
- RFC 5780 当前实现 `CHANGE-REQUEST`、`RESPONSE-ORIGIN` 和 `OTHER-ADDRESS`；可选的
  `RESPONSE-PORT`、`PADDING` 尚未实现。
- Java、Go、.NET client 的 macOS `utun` 数据面仍属于实验性能力。
- `noop` 模式不会创建虚拟网卡，因此无法通过系统 `ping` / `curl` 访问虚拟 IP。
- direct 路径依赖双方 UDP 可达；对称 NAT 或严格防火墙下通常会走 relay。
- 业务数据面只接受完整 IPv4 packet，未实现 IPv6 Mesh 路由或 IPv6 TUN packet 转发。
- 控制连接断开后不能创建新 peer session；已建立 direct session 在 TTL 内可继续传输。
