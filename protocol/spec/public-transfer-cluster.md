# 公共互传多实例协调协议

本文定义 Java、Go 与 .NET 服务端在多实例部署时共享的 Redis 状态和内部 Pub/Sub 帧。它承载公共互传协调与
管理连接事件，只用于服务端实例之间，不会替换浏览器可见的 STWR2、STAP2、JSON discovery 或管理 WebSocket 消息。

## 1. 启用与故障边界

`cluster-enabled=false` 时，每个实例使用有界进程内 presence、修订和固定窗口计数。`cluster-enabled=true` 时，
`redis-uri` 必填，服务启动必须完成 PING 和事件频道订阅；失败时启动失败。运行中 Redis 操作失败时，不得退回本地状态：
当前实例关闭受影响的 discovery WebSocket，预签名与配对码入口失败关闭，避免跨实例重复名称、超额房间或静默丢消息。

默认配置：

| 配置 | 默认值 | 约束 |
| --- | ---: | --- |
| `redis-key-prefix` | `specus:v2:public-transfer` | 去除尾部冒号；不同环境必须隔离 |
| `presence-lease-seconds` | 30 | 最少 5 秒 |
| `presence-refresh-interval-ms` | 10000 | 正数且小于租约 TTL 的一半 |
| `redis-command-timeout-ms` | 2000 | 最少 100 ms |

合并可见域（`nets:<netId>` 索引与 net 维度 revision）是后加能力：新旧节点混部会使 roster 读取与定向路由不一致。
升级包含该能力的版本时集群所有节点必须同时发布；需要灰度时必须 bump `redis-key-prefix`，让新旧 fleet 使用隔离的
keyspace。

## 2. 标识与 Redis key

所有摘要均为小写十六进制 SHA-256，输入使用 UTF-8。分组与成员标识为：

```text
groupId = sha256(roomId + U+0000 + internalRoomKey)
netId = sha256(publicAddress)
memberId = sha256(peerId)
normalizedName = NFC(trim(displayName)).toLowerCaseInvariant()
managementGroupId = sha256(trim(tenantId))
```

key 与频道固定为：

```text
<prefix>:presence:<groupId>:<memberId>
<prefix>:members:<groupId>
<prefix>:nets:<netId>
<prefix>:revision:<groupId 或 netId>
<prefix>:name:<sha256(normalizedName)>
<prefix>:rate:<sha256(bucket + U+0000 + identity)>
<prefix>:events
```

`nets:<netId>` 是合并可见域索引：value 为该公网出口上存在成员的 groupId 集合，读取某接收者的可见成员时枚举其
netId 索引下的全部分组（并始终并入接收者自身 groupId），再按 `sameGroup || sameNet` 谓词过滤；`sameNet` 要求双方
`publicAddress` 非空、非 `unknown` 且相等。presence value 为 `leaseId + LF + participant-json`；name value 为
`leaseId + LF + peerId`。participant JSON 使用
camelCase，字段为 `leaseId/peerId/displayName/roomId/publicAddress/roomKey/roomRole/sharedRoom/connectedAt`。
`roomKey` 只存在服务端 Redis 中，不得进入 roster 或浏览器消息。

注册使用单个 Lua 操作完成：清除成员集合中的过期租约，检查合并可见域内（同组与同网各分组）的 peerId、全局
displayName 和房间人数上限（仍按同组计数），写入 presence/name 租约与 members 集合，并把 groupId 登记进
`nets:<netId>`，最后同时递增 `revision:<groupId>` 与 `revision:<netId>`，返回值取两者之和。离开也必须按 lease
value 条件删除，防止旧连接删除重连后的新租约；分组成员清空时从 `nets:<netId>` 移除该 groupId。revision 保留 7 天；
members 与 nets 集合的 TTL 均为 presence TTL 的三倍。

## 3. roster 修订

每次成功加入、离开或清理过期成员都同时递增 `revision:<groupId>` 与 `revision:<netId>` 两个计数器。对任一接收者，
`rosterRevision` 是其所在分组与所在网络两个计数器之和，因此合并可见域任一维度的变化都保持单调递增。roster 事件的
group 字段先后携带 groupId 与 netId 各发布一次，使房间与网络两个受众的实例都重读快照。`hello` 和完整 `roster`
都携带当前修订：

```json
{"type":"roster","rosterRevision":42,"peers":[]}
```

订阅端收到 roster 事件后从 Redis 读取完整快照，并在读取前后比较 revision；发生并发变化时最多重读一次。浏览器忽略
小于当前已应用 revision 的旧快照。断线重连通过 hello 后的完整 roster 恢复，不依赖易丢失的 Pub/Sub 增量事件。

## 4. STCE v2 内部帧

所有整数为 big-endian。固定头为 26 字节：

```text
offset  size  field
0       4     ASCII "STCE"
4       1     version = 2
5       1     kind: 1=roster, 2=text, 3=binary, 4=management
6       1     flags: bit0=excludeSource，其余必须为 0
7       1     reserved = 0
8       8     rosterRevision, uint64
16      2     groupId UTF-8 byte length
18      2     targetPeerId UTF-8 byte length
20      2     sourceLeaseId UTF-8 byte length
22      4     payload byte length
26      N     groupId || targetPeerId || sourceLeaseId || payload
```

限制：group 必填且最多 128 字节；target/source lease 各最多 512 字节；payload 最多 256 KiB；字符串必须是严格 UTF-8；
decoder 必须精确消费整帧。roster payload 必须为空，binary target 必填。text payload 是已序列化的浏览器 JSON envelope；
binary payload 是原始 STWR2 relay envelope，禁止 Base64 化。management 必须满足 revision=0、flags=0、target/source
为空且 payload 非空；group 必须等于 payload 中 `tenantId` 的 `managementGroupId`。频道允许发布实例收到自己的事件，
以统一处理本地和远端连接。

事件的 group 字段按 kind 取义：roster 事件携带变化来源的 groupId 或 netId（各发布一次）；定向 text/binary 事件携带
目标的 groupId——发布方先在来源的合并可见域内解析目标 peer（跨 Token 房间、跨 `roomId` 的同网目标同样可达），解析不到
（例如目标为不注册共享 presence 的隐藏连接）时回退为来源的 groupId，保持旧的同组可达性；无目标的广播 text 事件始终携带
来源 groupId，只投递同组连接，同网陌生人不会收到房间流量。接收实例把事件 group 与本地连接的 netId/groupID 双匹配后投递。

中央确定性向量见
[`protocol/test-vectors/public-transfer-cluster-v2.json`](../test-vectors/public-transfer-cluster-v2.json)。

## 5. 管理事件恢复

管理连接事件使用 kind 4，payload 为对外 `/ws/connections` 使用的 camelCase `ConnectionEvent` JSON。接收实例必须先
反序列化并校验 tenant 与 management group 的摘要绑定，再执行本实例原有的 tenant/owner 过滤；不得因为事件来自 Redis
而跳过授权。

Redis Pub/Sub 只负责低延迟通知，不充当持久事件日志。管理前端在每次 WebSocket 建立后先读取 REST 权威快照，同步期间
将实时事件放入最多 4096 条的缓冲区，快照安装完成后再顺序回放。缓冲溢出时丢弃增量并重读快照；连接保持期间每 60 秒
静默重读一次，以修复 Redis 短时故障、实例切换或浏览器挂起造成的事件空洞。因此管理面不依赖易失的 resume cursor。

## 6. 共享固定窗口

限流 key 通过 Lua `INCR`，第一次计数时设置窗口 TTL，计数大于配置上限即拒绝。bucket 至少包含：

- `discovery-message`，identity 为 `groupId + LF + peerId`；
- `presign-upload`，identity 为可信代理解析后的来源 IP；
- `pairing-code-redeem`（实现该入口的服务端），identity 同样为来源 IP。

固定窗口边界允许理论上的双倍短时突发，这是既定滥用防护语义，不用于精确计费。
