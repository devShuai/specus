# Peer Mesh 私有组网协议

Peer Mesh 让同一租户/同一用户下的多个客户端组成私有虚拟网络。每个客户端分配一个虚拟 IP，客户端之间优先通过 UDP direct 通信；direct 不通时使用服务端内置 TURN relay。服务端负责身份、授权、虚拟 IP、候选交换、session 管理和 relay 授权；业务 IP 包在客户端之间端到端加密，服务端 relay 不解密明文。

当前跨语言实现仍属于实验性能力，默认关闭。

## 配置

服务端配置：

| 配置 | 环境变量 | 默认 | 说明 |
| --- | --- | --- | --- |
| `specus.peer-mesh.enabled` | `SPECUS_PEER_MESH_ENABLED` | `false` | 总开关 |
| `specus.peer-mesh.cidr` | `SPECUS_PEER_MESH_CIDR` | `100.96.0.0/11` | 虚拟网段 |
| `specus.peer-mesh.public-address` | `SPECUS_PEER_MESH_PUBLIC_ADDRESS` | 空 | UDP 探测和 relay 对外地址 |
| `specus.peer-mesh.stun-turn-port` | `SPECUS_PEER_MESH_STUN_TURN_PORT` | `3478` | 标准 STUN/TURN UDP 主端口 |
| `specus.peer-mesh.standalone-stun-address` | `SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS` | 空 | 独立 STUN 域名或 IP；配置后 STUN 与 TURN 使用不同入口 |
| `specus.peer-mesh.standalone-stun-port` | `SPECUS_PEER_MESH_STANDALONE_STUN_PORT` | `3478` | 独立 STUN 入口端口 |
| `specus.peer-mesh.standalone-stun-alternate-address` | `SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS` | 空 | 独立 STUN 备用域名或 IP；使用主端口加入备用列表，同时作为 RFC 5780 的 A2 |
| `specus.peer-mesh.standalone-stun-alternate-port` | `SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT` | `0` | 独立 RFC 5780 的第二端口 P2；`0` 时回退 NAT 探测备用端口 |
| `specus.peer-mesh.nat-probe-alternate-port` | `SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT` | `3479` | NAT 辅助探测端口；显式设为 `0` 时使用主端口 + 1 |
| `specus.peer-mesh.stun-primary-bind-address` | `SPECUS_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS` | 空 | RFC 5780 主地址 A1 的本机绑定 IP |
| `specus.peer-mesh.stun-alternate-bind-address` | `SPECUS_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS` | 空 | RFC 5780 备用地址 A2 的本机绑定 IP |
| `specus.peer-mesh.stun-alternate-public-address` | `SPECUS_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS` | 空 | RFC 5780 备用公网 IP A2；A1 使用 `public-address` |
| `specus.peer-mesh.stun-behavior-strict` | `SPECUS_PEER_MESH_STUN_BEHAVIOR_STRICT` | `false` | 四端点配置不完整时是否拒绝启动内置 STUN/TURN |
| `specus.peer-mesh.public-stun-servers` | `SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS` | 空 | 额外公共 STUN server，逗号分隔，只补充 `srflx` candidate |
| `specus.peer-mesh.session-ttl-seconds` | `SPECUS_PEER_MESH_SESSION_TTL_SECONDS` | `3600` | peer session 授权有效期 |
| `specus.peer-mesh.allocation-ttl-seconds` | `SPECUS_PEER_MESH_ALLOCATION_TTL_SECONDS` | `300` | relay allocation 有效期 |
| `specus.peer-mesh.relay-min-port` / `relay-max-port` | `SPECUS_PEER_MESH_RELAY_MIN_PORT` / `SPECUS_PEER_MESH_RELAY_MAX_PORT` | `49152` / `65535` | TURN relay UDP 分配端口范围 |
| `specus.peer-mesh.relay-worker-threads` | `SPECUS_PEER_MESH_RELAY_WORKER_THREADS` | `0` | relay 发送 worker 数；`0` 按 CPU 自动计算 |
| `specus.peer-mesh.relay-worker-queue-capacity` | `SPECUS_PEER_MESH_RELAY_WORKER_QUEUE_CAPACITY` | `10000` | relay 发送有界队列容量 |
| `specus.peer-mesh.udp-receive-buffer-bytes` | `SPECUS_PEER_MESH_UDP_RECEIVE_BUFFER_BYTES` | `4194304` | STUN/TURN 与 allocation socket 请求的接收缓冲区 |
| `specus.peer-mesh.udp-send-buffer-bytes` | `SPECUS_PEER_MESH_UDP_SEND_BUFFER_BYTES` | `4194304` | STUN/TURN 与 allocation socket 请求的发送缓冲区 |
| `specus.peer-mesh.udp-traffic-class` | `SPECUS_PEER_MESH_UDP_TRAFFIC_CLASS` | `16` | UDP `IP_TOS` / traffic class；平台不支持时降级继续运行 |
| `specus.peer-mesh.turn-auth-required` | `SPECUS_PEER_MESH_TURN_AUTH_REQUIRED` | `true` | 是否要求 TURN 长期凭证认证 |
| `specus.peer-mesh.turn-realm` | `SPECUS_PEER_MESH_TURN_REALM` | `specus` | TURN realm |
| `specus.peer-mesh.turn-shared-secret` | `SPECUS_PEER_MESH_TURN_SHARED_SECRET` | 空 | TURN credential 派生密钥；留空时使用本进程随机密钥 |
| `specus.peer-mesh.turn-credential-ttl-seconds` | `SPECUS_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS` | `3600` | 登录响应中 TURN credential 的有效期 |

客户端配置：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `peerMeshDevice` | `noop` | 虚拟网卡模式 |
| `peerMeshTunName` | `specus0` | 虚拟网卡名 |
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
- 从 `SPECUS_PEER_MESH_CIDR` 中分配一个 `/32` 虚拟 IP。
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
| `GET` | `/api/admin/peer-mesh/service-sharing` | 查看 Peer 服务共享状态 |
| `PUT` | `/api/admin/peer-mesh/service-sharing` | 启停租户服务共享总开关；仅租户 ADMIN |
| `GET` | `/api/admin/peer-mesh/services` | 查看本机服务定义与运行实例 |
| `POST` | `/api/admin/peer-mesh/services` | 新增本机服务定义；仅租户 ADMIN；默认关闭 |
| `PUT` | `/api/admin/peer-mesh/services/{id}` | 编辑/启停服务定义；仅租户 ADMIN |
| `DELETE` | `/api/admin/peer-mesh/services/{id}` | 删除服务定义；仅租户 ADMIN |

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
| `peerServiceDiscoveryVersion` | 服务端支持的本地服务发现协议版本；当前为 `1`，旧服务端缺省按 `0` |
| `serviceSharing` | 租户服务共享状态：`deploymentEnabled` / `configuredEnabled` / `effectiveEnabled` / `mdnsImportEnabled` |

`serviceSharing.effectiveEnabled` 为 true 当且仅当部署端 Peer Mesh 开启、租户总开关已开、且当前设备已启用私有组网。客户端只在该值为 true 且存在获授权在线对端时探测并上报本机服务。总开关变更后服务端立即下发 `peer-config`，不能等到下次登录。

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
      "messageMaxAttachmentBytes": 536870912,
      "peerServiceDiscoveryVersion": 1,
      "peerServiceApplications": ["http", "https", "ssh", "tcp"]
    }
  ]
}
```

客户端收到后刷新本地 peer 表，并向在线 peer 上报候选地址。

五个 `message*` 字段来自 peer 当前在线 session 上报的
`environment.clientMessageCapabilities`；peer 离线或没有匹配的在线 session 时为 `false` / `0`。
旧服务端缺省这些字段时，客户端也按 `false` / `0` 处理。Go 服务端必须投影与 Java 相同的能力字段，不能省略。

`peerServiceDiscoveryVersion` 和 `peerServiceApplications` 来自
`environment.clientPeerServiceCapabilities`。版本 `0` 或缺省表示该 peer 不支持服务发现；
一期应用类型仅允许 `http`、`https`、`ssh`、`tcp`。

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
      "foundation": "host-192.168.1.10",
      "addressFamily": "IPv4"
    },
    {
      "type": "srflx",
      "transport": "udp",
      "address": "58.41.26.74",
      "port": 1132,
      "priority": 90,
      "foundation": "srflx",
      "addressFamily": "IPv4"
    },
    {
      "type": "relay",
      "transport": "udp",
      "address": "specus.example.com",
      "port": 49152,
      "priority": 10,
      "foundation": "relay",
      "relayId": "allocation-id",
      "addressFamily": "IPv4"
    }
  ]
}
```

候选类型：

| 类型 | 说明 |
| --- | --- |
| `host` | 本机非 loopback、非 link-local 的 IPv4 或全局 IPv6 地址 |
| `srflx` | 通过标准 STUN Binding 获得的 IPv4/IPv6 公网映射地址 |
| `relay` | 通过标准 TURN Allocate 获得的 relay allocation |

客户端会枚举 STUN 域名的全部 A/AAAA 结果并逐一探测；候选按 `priority` 降序检查，默认全局 IPv6
host、IPv4 host、IPv6 srflx、IPv4 srflx 的 priority 分别为 `1200`、`1000`、`900`、`800`。
Peer 数据面固定使用 SPM2，不提供旧帧协商或降级。

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
  "virtualDeviceName": "specus0",
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
`natType` 是供 UI 和路径策略使用的汇总标签；精确判断以 mapping/filtering 字段为准。

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

## 本地服务发现（默认关闭）

Peer Mesh 设备互联不等于本机服务目录。一期发布用户在控制页显式配置、且实际可探测到的 TCP/UDP 服务，
不扫描局域网、对端或 `1..65535` 全端口。C 实现不纳入一期。mDNS 候选导入默认关闭。

产品约束：

- 租户「Peer 服务共享」总开关独立于 `SPECUS_PEER_MESH_ENABLED` 和设备「启用私有组网」开关，默认关闭。
  新安装和存量升级都必须保持关闭。
- 对端能看到并访问服务，必须同时满足：部署端 Peer Mesh 可用、租户总开关已开、单个服务显式启用、
  发布设备在线且已有获授权在线对端、ACL 允许该方向。
- 默认关闭时不枚举、不探测、不发布。开启但没有获授权在线对端时，客户端不周期广播，也不做无意义扫描。
- 关闭总开关时立即撤回服务目录、拒绝新的服务桥接，并关闭由本功能建立的活动流；基础 Peer Mesh
  和无关流量不随之关闭。
- 服务广告只负责发现，不替代服务自身认证。

### 服务定义

持久化按 `tenantId + clientId` 归属。`serviceId` 稳定且不可由显示名推导。`targetHost` /
`targetPort` 仅管理端和发布设备本机客户端可见；一期 `targetHost` 只允许 loopback 或本机单播地址，
禁止主机名（`localhost` 除外）、URL、通配地址和组播。向对端发布的目录不得包含 `targetHost`、任意 URL、
命令、用户名、token 或进程信息。

| 字段 | 说明 |
| --- | --- |
| `serviceId` | 8..64 字符，`[A-Za-z0-9._-]` |
| `name` / `description` | 展示名称 1..80，说明最长 200；禁止控制字符 |
| `transport` | `tcp` 或 `udp` |
| `application` | `http` / `https` / `ssh` / `tcp` / `udp`；`udp` 必须搭配 UDP 传输 |
| `allowedClientIds` | 可选。`visibility=ACL` 时再限制到这些 clientId；空表示现有 Peer ACL 范围内全部对端 |
| `targetHost` / `targetPort` | 发布设备本机目标；对端不可见 |
| `publishedPort` | Peer 虚拟 IP 上提供给对端的端口，同一设备内已启用服务不可冲突 |
| `path` | HTTP(S) 可选安全路径，必须以 `/` 开头，禁止完整 URL、`..`、反斜杠和空白 |
| `enabled` | 单服务开关，默认 `false` |
| `visibility` | `OWNER`（同归属用户）或 `ACL`（现有 Peer ACL 范围内）；不得扩大现有 ACL |

### `service-report`

客户端在有效共享开启且存在获授权在线对端后，向服务端上报当前实例可发布的服务快照。
`toClientName` 必须为空；服务端绑定已认证的 `publisherClientId` / `publisherSessionId`，
不信任消息体里的 source 身份。

```json
{
  "type": "service-report",
  "enabled": true,
  "revision": 3,
  "publisherSessionId": 1868708022931423400,
  "instanceId": "runtime-1",
  "generatedAt": "2026-08-19T09:00:00Z",
  "expiresAt": "2026-08-19T09:05:00Z",
  "services": [
    {
      "serviceId": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "name": "local-ssh",
      "description": "本机 SSH",
      "transport": "tcp",
      "application": "ssh",
      "publishedPort": 2222
    }
  ]
}
```

可选 `stats[]` 仅出现在 `service-report`，携带每个已发布服务的本机桥接计数（`bytesIn` /
`bytesOut` / `activeConnections` / `totalConnections`）。服务端只用于管理端健康与流量展示，
不得写入 `service-catalog`。

可选 `mdnsCandidates[]` 也只出现在 `service-report`：租户打开「允许 mDNS 候选导入」后，发布端
可把本机 mDNS/DNS-SD 发现的 loopback/本机地址候选交给服务端，供管理员导入为默认关闭的服务定义。
候选含 `targetHost`，不得进入 `service-catalog`。默认关闭时客户端不做 mDNS 查询。

UDP 服务在虚拟 IP 的 `publishedPort` 上做 Peer-only 数据报转发，不走 TCP 探测；未启用的 UDP 端口
同样不能借此功能访问。

`revision` 在同一控制 session 内必须单调递增。小于或等于上次接受值的快照幂等忽略。
每个 session 最多 32 个服务，单快照 JSON 不超过 16 KiB。服务端按持久化定义校验 `serviceId`，
丢弃未配置、未启用或不属于该设备的项，并用服务端字段重写名称、类型、端口和 path。

发布设备通过登录响应和后续 `peer-config` 的 `peerMesh.localServices` 收到本机服务定义（含
`targetHost` / `targetPort`）。该列表只发给所属客户端，不得出现在 `service-catalog` 或其它对端可见载荷中。
客户端仅在 `serviceSharing.effectiveEnabled` 为真且存在获授权在线对端时，对已启用项做探测：TCP 服务
做 TCP 连接探测，UDP 服务做数据报探测。探测成功后上报不含目标地址的 `service-report`，并在本机虚拟
IP 的 `publishedPort` 上绑定 Peer-only TCP 或 UDP 桥。`mdnsImportEnabled` 为真时才允许本机 mDNS
浏览，候选只出现在 `service-report.mdnsCandidates`，不得进入 `service-catalog`。

### `service-catalog`

服务端向每个获授权对端下发个性化全量快照，不把动态目录塞进登录 `environment`：

```json
{
  "type": "service-catalog",
  "publisherClientId": 1,
  "publisherClientName": "client-a",
  "publisherSessionId": 1868708022931423400,
  "revision": 3,
  "expiresAt": "2026-08-19T09:05:00Z",
  "services": [
    {
      "serviceId": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "name": "local-ssh",
      "transport": "tcp",
      "application": "ssh",
      "publishedPort": 2222
    }
  ]
}
```

发送者下线、session 被替换、设备停用、ACL 撤销、总开关关闭或 TTL 到期时，立即发送 `services: []`
并清理目录。重连时发送当前全量快照。多实例按 `(publisherClientId, publisherSessionId, serviceId)`
隔离。`service-catalog` 只能由服务端发出；客户端上报该类型必须拒绝。老客户端不认识新 type 时
安全忽略，不影响基础组网。

HTTP(S)「打开」按钮只能由权威 `virtualIp + publishedPort + 安全 path` 构造，禁止打开对端上报的
任意 URL。SSH/TCP 默认复制 `virtualIp:publishedPort`。

## STUN/TURN UDP 协议与 direct check

服务端开启后监听：

- 主端口：`SPECUS_PEER_MESH_STUN_TURN_PORT`，默认 `3478/udp`。
- 备用探测端口：`SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT`，默认 `3479/udp`；配置为 `0` 时取主端口 + 1。
- relay 分配端口：默认 `49152-65535/udp`。

STUN/TURN 控制消息使用标准的二进制 STUN 头、magic cookie、transaction ID 和 TLV attribute，
不是旧版 `specus-peer-relay` JSON。内置服务端实现的是项目所需的 RFC STUN/TURN 子集：

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
| ChannelBind Request / Success | client <-> server | 将 `0x4000..0x7FFF` channel number 绑定到已授权 peer endpoint |
| Send Indication | client -> server | `XOR-PEER-ADDRESS` + `DATA`，承载加密 peer frame |
| Data Indication | server -> client | `XOR-PEER-ADDRESS` + `DATA`，承载加密 peer frame |
| ChannelData | client <-> server | `channelNumber + length + payload + 4-byte padding`，作为绑定后的低开销数据路径 |

TURN 认证默认开启。登录响应下发 `iceUsername`、`iceCredential`、`iceRealm` 和 `iceNonce`；
受保护请求携带 `USERNAME`、`REALM`、`NONCE` 和 `MESSAGE-INTEGRITY`。认证失败使用标准错误响应，
例如 `401 Unauthorized` 和 `438 Stale Nonce`。

当前长期凭证派生为：`iceUsername` 含过期时间；`iceCredential = Base64Url(HMAC-SHA1(turnSharedSecret,
iceUsername))`；`MESSAGE-INTEGRITY` 使用 HMAC-SHA1，key 为 `MD5(username + ":" + realm + ":" + credential)`。
`Allocate`、`Refresh`、`CreatePermission` 受该校验保护；`Send Indication` 依赖已认证创建的 allocation 和
permission。未配置 `SPECUS_PEER_MESH_TURN_SHARED_SECRET` 时服务端使用进程内随机密钥，重启后旧凭证失效。

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
  "magic": "specus-peer-mesh",
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

公网 UDP 接收路径在 JSON 解析前执行长度、首尾字符和 magic 预检，使用无异常日志的专用解析入口；
probe 按来源地址和全局窗口限速。非法包只进入聚合计数，不逐包输出异常栈。

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

只有一个公网 IP 时，服务端不插入 `OTHER-ADDRESS`，并对无法满足的 `CHANGE-REQUEST` 返回
`420 Unknown Attribute`。单 IP 双端口只能收集额外映射观察，不能据此宣称完整 RFC 5780 分类。
独立 STUN 进程的构建和部署见 `implementations/java/stun-server` 与
`deploy/stun-server/systemd`。

## 数据面加密帧

客户端从 Linux TUN、Windows Wintun 或 macOS utun 读取原始 IPv4 packet，按目的虚拟 IP 找到 peer session，再封装为 AES-GCM 加密帧通过 UDP 发送。

基础 session key 派生：

```text
sharedSecret = X25519(localPrivateKey, remotePublicKey)
salt = SHA256("specus-peer-mesh\n" + sessionId + "\n" + token + "\n" + min(clientId) + "\n" + max(clientId))
prk = HMAC_SHA256(salt, sharedSecret)
aesKey = HKDF-Expand(prk, "specus-peer-mesh/aes-gcm/v1", 32)
```

每个授权 session 都产生新的 `sessionId + token`，它们构成数据面的 key epoch。服务端不得复用已关闭或
过期的 session；客户端重启后必须申请新 session，不能在旧 key 下把 sequence 重置为 1。

### SPM2 帧

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| `magic` | 4 字节 | `0x53504D32`，ASCII `SPM2` |
| `sessionId` | 8 字节 | peer session ID |
| `sequence` | 8 字节 | 当前方向从 1 开始的单调递增计数器 |
| `ciphertext` | N 字节 | AES-GCM 密文，末尾含 16 字节 tag |

固定开销为 `20 + 16 = 36` 字节。UDP datagram 自带总长度，因此不重复携带 ciphertext length。发送方和
接收方身份来自已认证 session；TURN relay 还把 allocation 绑定到登录 client/session，不能仅信任帧内字段。

方向 traffic key 与 nonce 派生为：

```text
sessionBytes = uint64_be(sessionId)
trafficPrk = HMAC_SHA256(sessionBytes, aesKey)
trafficInfo = ASCII("specus-peer-mesh/spm2/aes-gcm\n"
                    + sessionId + "\n" + fromClientId + "\n" + toClientId)
T1 = HMAC_SHA256(trafficPrk, trafficInfo || 0x01)
trafficKey = T1[0..31]
T2 = HMAC_SHA256(trafficPrk, T1 || trafficInfo || 0x02)
nonce = T2[0..3] || uint64_be(sequence)
```

完整 20 字节头作为 AAD。`fromClientId -> toClientId` 参与 traffic key 派生，因此两个方向不会共享
key/nonce 空间。sequence 不允许为 0 或回绕，达到有符号 64 位上限前必须申请新 session。

接收方必须校验：

- magic 必须为 SPM2，帧总长位于 `36..65535`，且整个 datagram 被精确消费。
- `sessionId` 等于期望 session。
- AES-GCM tag 通过。
- `sequence` 通过 4096 项滑动窗口，重复包和窗口外旧包拒绝。
- session 未过期，来源 endpoint 或 TURN allocation 已绑定到该 session 的对端身份。

Java 使用线程本地 AES-GCM `Cipher`，避免每包执行 provider lookup；各客户端缓存 session 的方向 key。
共享固定向量位于 `protocol/test-vectors/peer-mesh-spm2.json`。

明文可以是完整 IPv4 packet 或带独立 magic 的 peer 应用消息。IPv4 packet 解密后写入
TUN/Wintun；应用消息交给客户端消息 codec。

### SPMTU2 路径 MTU 探测

路径 MTU 消息作为 SPM2 的加密明文发送，因此 probe/ack 都继承 session 身份、方向 key、sequence、
replay 和 AES-GCM 认证。明文格式：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| magic | 6 | ASCII `SPMTU2` |
| type | 1 | `1=probe`，`2=ack` |
| nonce | 8 | 正数，big-endian |
| innerMtu | 2 | `576..9000`，big-endian |
| padding | 可变 | 仅 probe 存在，零填充到恰好 `innerMtu` 字节 |

ack 必须恰好 17 字节；probe 必须恰好等于声明的 `innerMtu`。未知 type、错误长度、越界 MTU、尾随
字节或零 nonce 均丢弃。

- 直接路径 cache key 为 `direct|remoteEndpoint`，relay 路径为 `relay|allocationId`。
- cache TTL 为 10 分钟，路径变化立即使用独立状态。
- 从配置 MTU 开始探测，每个尺寸最多发送 3 次；超时后以 576 为下界做二分搜索。
- 首次丢失后立即使用保守的已知上限，不能继续发送超过当前有效 MTU 的 IP 包。
- IPv4 TCP SYN 的 MSS 最多为 `pathMtu - IPv4HeaderLength - 20`，下限 536；修改后重算 TCP checksum。
- 超过有效 MTU 的 IPv4 包不发送，向本地虚拟网卡回注 ICMP Destination Unreachable code 4，并携带
  next-hop MTU 和原 IPv4 header + 8 字节。

共享向量位于 `protocol/test-vectors/peer-path-mtu-v2.json`。Java、Go、.NET 和 Android 均实现该协议；
C 仅提供服务端，不参与客户端路径 MTU 探测。

## direct 与 relay

发送优先级按当前 Java 状态机执行：

1. session 已绑定 `relayTargetAllocationId` 时优先走 `RELAY`；这表示 relay check/data 已明确选定可用目标。
2. 未绑定 relay 目标且已有健康 `DIRECT` 路径时直接发送。
3. direct candidate 连通性检查成功后切到 `DIRECT`；收到有效 direct 数据会清理旧 relay 目标，避免路径状态残留。
4. direct 尚不可用时继续申请/探测 TURN allocation，relay 目标建立后按第 1 条发送。

服务端 relay 处理 TURN `Send Indication` 中的加密帧时，会解析帧头并调用
`PeerMeshService.authorizeRelayFrameForRelay`：

- session 必须存在。
- session 未过期。
- session 状态必须为 `ACTIVE`。
- 来源和目标 TURN allocation 都必须绑定已认证的 client/session，且该 client pair 必须匹配 session 的
  source/target。

relay 只校验头部和授权，不解密业务明文。
带 `SPM2` magic 但结构或严格长度校验失败的数据必须直接丢弃，不能退化成普通 TURN payload
绕过 session 授权。

初次 relay 建链不会被 `ACTIVE` 条件卡住：客户端先通过 TURN `Send/Data Indication` 转发 JSON
`PeerUdpProbe` 检查包；它不是 SPM2 业务帧，服务端对其执行 session token 授权。检查响应成功后，
客户端先通过控制连接上报 `path-report(status=ACTIVE, pathType=RELAY)`，随后发送的 SPM2 业务帧才满足
relay 授权条件。若 `path-report` 未到达，业务帧会被拒绝。

TURN 为 Peer Mesh 专用模式：CreatePermission、ChannelBind、Send Indication 和 ChannelData 都必须落在
已授权 peer session 上，不允许把该 listener 当作通用任意目标 TURN relay。ChannelData 绑定有效时优先使用；
绑定建立前或刷新期间使用 Send/Data Indication。

Java relay 使用有界 worker 队列；拒绝、发送失败、队列深度和高水位分别暴露为
`specus.peer_mesh.turn.relay.queue.dropped`、`specus.peer_mesh.turn.relay.send.failures`、
`specus.peer_mesh.turn.relay.queue.depth`、`specus.peer_mesh.turn.relay.queue.high.water`。
relay 流量先交换到事务批次，提交失败会恢复待写字节，并暴露 flush failure、pending bytes 和 lag 指标。

## 性能基线

Java codec 提供可重复的 JMH 基准，覆盖 SPM2 的 64/512/1200 字节 encode/decode：

```powershell
mvn -f implementations/java/client/pom.xml -Ppeer-mesh-benchmark package -DskipTests
java -jar implementations/java/client/target/specus-client-1.0.0-SNAPSHOT-benchmarks.jar `
  PeerDataFrameCodecBenchmark -prof gc -wi 3 -i 5 -f 1
```

JMH 结果只用于 codec 的 CPU/分配回归；direct/relay 端到端 pps、吞吐、丢包和 socket/队列饱和仍需
在固定拓扑与包长下单独压测，不能由 microbenchmark 外推生产容量。

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
- 独立 Java、Go、.NET STUN server 已实现 `CHANGE-REQUEST`、`RESPONSE-ORIGIN`、`OTHER-ADDRESS`、
  `RESPONSE-PORT` 和有上限的 `PADDING`；内置 TURN 仍只实现本项目需要的子集。
- Java、Go、.NET client 的 macOS `utun` 数据面仍属于实验性能力。
- `noop` 模式不会创建虚拟网卡，因此无法通过系统 `ping` / `curl` 访问虚拟 IP。
- direct 路径依赖双方 UDP 可达；对称 NAT 或严格防火墙下通常会走 relay。
- 业务数据面只接受完整 IPv4 packet，未实现 IPv6 Mesh 路由或 IPv6 TUN packet 转发。
- 控制连接断开后不能创建新 peer session；已建立 direct session 在 TTL 内可继续传输。
