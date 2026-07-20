# 公共互传协议

本文定义免登录公共互传的浏览器与服务端协议，覆盖文件附件、剪贴板文本和同步白板，包括公共 ICE 配置、发现信令、
浏览器应用消息、附件 REST、对象存储和滥用防护。
Java server 是语义基准；Go、.NET server 的完整实现必须保持一致。文中的“必须”“应当”“可以”分别对应
MUST、SHOULD、MAY。

公共互传由以下相互独立但可组合的路径构成：

1. `GET /api/public/transfer/ice-config` 提供 STUN/TURN 候选；
2. `/ws/public-transfer/discovery` 负责浏览器发现、roster、定向信令，以及 DataChannel 不可用时的应用消息回退；
3. WebRTC `RTCDataChannel` 优先承载剪贴板和白板等浏览器应用消息；
4. 登录用户可通过附件 REST 获取短期预签名 URL，文件内容由客户端直接上传/下载对象存储。

ICE 配置、发现 WebSocket、WebRTC Direct 和 TURN 均无需管理 JWT。公开附件接口用于 OSS 数据面，必须同时提供
有效的管理账号 Bearer JWT 和房间凭据；因此匿名用户只能使用 Direct/TURN，不得申请、完成或下载 OSS 附件。
共享房间仍由高熵 `roomToken` 隔离，附近房间由可信反向代理提供的来源 IP 隔离。

## 1. 公共 ICE 配置

### 1.1 请求与响应

```http
GET /api/public/transfer/ice-config
```

成功响应为 `200 application/json`：

```json
{
  "peerMeshEnabled": true,
  "iceServers": [
    {
      "urls": "stun:stun.example.com:3478",
      "username": "",
      "credential": ""
    },
    {
      "urls": "turn:tunnel.example.com:3478?transport=udp",
      "username": "1780000000:public-transfer:1a2b3c4d",
      "credential": "base64url-hmac-sha1"
    }
  ],
  "turnAuthRequired": true,
  "stunTurnPort": 3478
}
```

字段语义：

| 字段 | 语义 |
| --- | --- |
| `peerMeshEnabled` | `tunnel.peer-mesh.enabled` 的值；控制 Peer Mesh 和自托管 TURN，不关闭显式配置的独立 STUN |
| `iceServers` | WebRTC 风格的有序 ICE server 列表；每项的 `urls` 是单个字符串，不是数组 |
| `turnAuthRequired` | TURN listener 是否要求长期凭证 |
| `stunTurnPort` | 兼容字段，表示业务服务的 STUN/TURN 主端口；独立 STUN 的实际端口以 `iceServers[].urls` 为准 |

列表顺序必须为：自托管 STUN（若可用）、配置的公共 STUN（保持配置顺序并去重）、自托管 TURN（若可用）。
配置的公共 STUN 在 `peerMeshEnabled=false` 时仍保留。显式配置
`tunnel.peer-mesh.standalone-stun-address` 后，独立 STUN 也不受 enabled 开关控制；自托管 TURN 仍只在
`peerMeshEnabled=true` 时生成。
STUN 项必须返回空 `username` 和空 `credential`；TURN 项返回临时凭证。
Java 即使在 `turnAuthRequired=false` 时也会给 TURN 项签发非空 username/credential；跨语言实现不得据此删掉字段，
客户端可以在认证关闭时忽略它们。

### 1.2 地址选择与规范化

Java 按以下顺序选择自托管 STUN 地址：

1. `tunnel.peer-mesh.standalone-stun-address`；
2. `tunnel.peer-mesh.public-address`；
3. `X-Forwarded-Host` 第一项；
4. `Host` 第一项；
5. servlet `serverName`。

只有独立 STUN 地址非空且端口大于 `0` 时才启用独立入口；部分配置会整体回退原入口。启用后使用
`tunnel.peer-mesh.standalone-stun-port`，否则使用 `tunnel.peer-mesh.stun-turn-port`。TURN 地址不使用
独立 STUN 配置，仍从 `public-address` 或请求 Host 解析，并始终使用 `stun-turn-port`。

主机名必须去除 scheme、路径和单个 `:port`。IPv6 地址必须用方括号包围。端口必须在
`1..65535`，配置的公共 STUN 地址未给出有效端口时使用 `3478`。输入 `stun://host`、
`stun:host`、显式端口和方括号 IPv6 都必须归一化为 `stun:<host>:<port>`。

### 1.3 TURN 临时凭证

TURN username 格式为：

```text
<expiresAtEpochSeconds>:public-transfer:<8-lowercase-hex>
```

有效期为 `max(60, tunnel.peer-mesh.turn-credential-ttl-seconds)` 秒。credential 为：

```text
base64url-no-padding(HMAC-SHA1(turnSecret, UTF8(username)))
```

`turnSecret` 优先使用配置的 shared secret；未配置时 Java 在进程启动时生成随机 secret，服务重启会使旧凭证失效。
TURN 长期认证的 realm、nonce、401/438 challenge 和 `MESSAGE-INTEGRITY` 见 [peer-mesh.md](peer-mesh.md)。

## 2. 发现 WebSocket

### 2.1 握手查询参数

```text
/ws/public-transfer/discovery
  ?roomId=<room>
  &roomToken=<secret>
  &peerId=<peer>
  &displayName=<name>
```

该端点无 JWT。每个参数只取第一个值，去除首尾空白后使用：

| 参数 | 缺省值 | 最大 Java `String.length()` |
| --- | --- | ---: |
| `roomId` | `nearby` | 120 |
| `roomToken` | 空 | 512 |
| `peerId` | 自动生成 `web-` + 8 个 UUID 字符 | 120 |
| `displayName` | `web` | 120 |

超过上限的查询参数按 UTF-16 code unit 截断，不拒绝握手；若截断点落在补充字符的 surrogate pair 中间，
回退一个 code unit，不产生未配对 surrogate。`roomToken` 不会回显或持久化明文。

### 2.2 来源地址与房间隔离

来源地址按以下优先级确定：

1. 非空 `X-Real-IP`；
2. `X-Forwarded-For` 的最后一项；
3. TCP 对端地址；
4. 无法取得时为 `unknown`。

部署反向代理时必须覆盖或清除客户端传入的 `X-Real-IP`，并追加 `X-Forwarded-For`；否则附近房间隔离可被伪造。

房间分组键同时包含 `roomId` 和内部 `roomKey`：

```text
roomToken 非空: roomKey = "room:"   + persistentRoomId
roomToken 为空: roomKey = "public:" + publicAddress
```

首次使用某个 `roomId + roomToken` 时，Java server 创建持久房间，并把该 Token 的 SHA-256 哈希登记为房主凭证；
明文 Token 不持久化。以后房主 Token 解析为 `OWNER`，房主签发且未撤销的邀请 Token 按其记录解析为 `EDITOR` 或
`VIEWER`，三者都通过相同 `persistentRoomId` 加入同一分组。已撤销或已过期的邀请必须返回 `403`，不能回退为新房间的
房主。普通未知高熵 Token 仍按旧协议语义创建独立房间，因此升级前已有的房间链接无需迁移，且相同房间名配不同旧 Token
仍彼此隔离；但未知的 `st-editor-` 或 `st-viewer-` 前缀 Token 必须返回 `403`，防止被删除的邀请创建“影子房主”房间。
未提供 Token 的参与者只有在 `roomId` 与来源地址都相同时才能互见。`sharedRoom` 表示是否使用 Token 房间。

### 2.3 加入、hello 与 roster

同一分组（相同 `roomId` 和内部 `roomKey`）内的 `peerId` 必须唯一。新连接的 `peerId` 已被同组连接占用时，
服务端先发送：

```json
{"type":"error","error":"peer id is already connected"}
```

随后以 WebSocket close code `1008` 关闭，不加入该连接，也不触发 roster 更新。该重复检查先于房间容量检查；不同分组
可以复用相同 `peerId`。

每个分组最多允许 `max(1, max-discovery-peers-per-room)` 个连接，默认 `32`。房间已满时服务端先发送：

```json
{"type":"error","error":"room is full"}
```

随后以 WebSocket close code `1008` 关闭，不把该连接加入 roster。

加入成功后服务端首先发送：

```json
{
  "type": "hello",
  "peerId": "web-12345678",
  "roomId": "nearby",
  "publicAddress": "203.0.113.10",
  "sharedRoom": false,
  "roomRole": "EDITOR",
  "connectedAt": "2026-07-10T00:00:00Z"
}
```

随后向同组所有连接广播 `roster`。加入和正常离开都必须触发 roster 更新：

```json
{
  "type": "roster",
  "roomId": "nearby",
  "publicAddress": "203.0.113.10",
  "sharedRoom": false,
  "peers": [
    {
      "peerId": "web-12345678",
      "displayName": "web",
      "roomId": "nearby",
      "publicAddress": "203.0.113.10",
      "sharedRoom": false,
      "roomRole": "EDITOR",
      "connectedAt": "2026-07-10T00:00:00Z"
    }
  ]
}
```

`peers` 按 `connectedAt` 升序排列。

### 2.3.1 房间角色与邀请

Token 房间角色如下：

| 角色 | 文件/剪贴板/白板写入 | 创建或恢复流程图版本 | 删除版本 | 管理邀请 |
| --- | --- | --- | --- | --- |
| `OWNER` | 允许 | 允许 | 允许 | 允许 |
| `EDITOR` | 允许 | 允许 | 不允许 | 不允许 |
| `VIEWER` | 不允许 | 不允许 | 不允许 | 不允许 |

发现 WebSocket 必须拒绝 VIEWER 发出的 `attachment`、`clipboard` 和 `whiteboard` 消息，并返回
`{"type":"error","error":"viewer is read-only"}`。`signal` 和 `ping` 仍允许，以便 VIEWER 建立接收通道。
浏览器也必须在文件选择、剪贴板、自由白板和专业流程图入口执行只读限制；仅依赖 WebSocket 拒绝不足以约束已经建立的
DataChannel。撤销邀请后，新连接和重连必须失败；已经连接的会话可以持续到断开。

房主邀请接口均为免管理 JWT 的 POST，`roomId`、`roomToken` 和 `peerId` 放在 JSON body，不能把 Token 放入 URL：

```text
POST /api/public/transfer/rooms/access-tokens/list
POST /api/public/transfer/rooms/access-tokens
POST /api/public/transfer/rooms/access-tokens/{accessId}/revoke
```

每个房间最多保留 20 个未撤销邀请。服务端只保存邀请 Token 的 SHA-256 哈希；创建响应是唯一返回明文 Token 的时机。
创建请求可以提供 `expiresInSeconds`，有效范围为 `300..604800`；省略时保留历史上的长期 Token 语义。网页的快捷邀请必须
使用 24 小时 `EDITOR` 或 `VIEWER` Token，不能复制、分享或生成包含 `OWNER` Token 的二维码。邀请 Token 只允许放在页面
URL fragment 中；页面读取后必须立即从地址栏清除，统计脚本也不得上报 query 或 fragment。

房主还可以创建短时配对码，访客无需先取得房间名或 Token：

```text
POST /api/public/transfer/rooms/pairing-codes
POST /api/public/transfer/rooms/pairing-codes/redeem
```

创建接口要求 `OWNER` 房间凭据，并接受 `role=EDITOR|VIEWER`、`label` 和 `maxUses`。`maxUses` 默认为 `1`，最大为 `5`；
返回 8 位数字明文码、角色和过期时间，并设置 `Cache-Control: no-store`。服务端只能持久化带域分隔的 HMAC-SHA256 摘要，
不得保存明文码。有效期由 `pairing-code-ttl-seconds` 控制，Java 会约束在 `60..900` 秒内，默认 300 秒。

兑换接口只接受 `code` 与 `peerId`。消费必须以数据库条件更新原子执行，同时验证未撤销、未过期且未超过使用次数；默认
一次性码的并发兑换只能有一个成功。成功后签发相同角色的 24 小时访问 Token，并返回 `roomId`、`role`、明文 Token 和
过期时间；失败统一返回 `400`“配对码无效或已过期”，不泄露码是否曾存在。兑换按来源 IP 独立限流，默认每 300 秒 10 次。

### 2.4 ping、信令与应用消息转发

客户端发送：

```json
{"type":"ping"}
```

服务端回复当前 UTC 时间：

```json
{"type":"pong","ts":"2026-07-10T00:00:01Z"}
```

其他 JSON 文本按信令转发。客户端输入结构为：

```json
{
  "type": "offer",
  "targetPeerId": "web-87654321",
  "payload": {"sdp":"..."}
}
```

`type` 缺省为 `signal`。服务端不信任客户端声明的来源字段，而是生成如下 envelope：

```json
{
  "type": "offer",
  "sourcePeerId": "web-12345678",
  "targetPeerId": "web-87654321",
  "roomId": "nearby",
  "publicAddress": "203.0.113.10",
  "payload": {"sdp":"..."}
}
```

有非空 `targetPeerId` 时仅投递给同组目标；目标不存在时静默丢弃。未给目标时广播给同组其他连接，不回送来源连接。
无效 JSON 返回 `{"type":"error","error":"invalid message"}`，连接保持打开。

#### 2.4.1 浏览器应用消息

浏览器间的同步白板和剪贴板同步复用发现 WebSocket，但应用消息应当优先通过已经建立的 WebRTC
`RTCDataChannel` 发送。承载应用消息的 DataChannel 必须使用有序、可靠传输；DataChannel 的远端连接身份即为接收处理
时使用的 `sourcePeerId`。DataChannel 上的文本帧使用以下应用 envelope：

```json
{
  "kind": "app-message",
  "messageType": "clipboard",
  "payload": {}
}
```

DataChannel 的对端即为应用消息的隐含目标。对本协议而言，“DataChannel 发送成功”只表示通道处于 `open` 状态且
本地 `send()` 调用未抛出异常，不表示对端已经收到或处理；没有应用层确认时，发送端不得显示“对方已收到”。
等待通道打开的超时时间可以由客户端实现决定，但一旦某个事件对某个目标决定走 WebSocket 回退路径，就不得在迟到的
DataChannel 打开后再次发送同一事件。具有事件标识的应用 payload 应按其自身协议定义去重；`STCLIP1` 的事件身份和
顺序规则见第 2.4.3 节。

当 `roomId`、`roomToken` 或是否使用共享房间发生变化，使当前房间分组作用域改变时，客户端必须关闭旧作用域的全部
`RTCDataChannel`、`RTCPeerConnection` 和发现 WebSocket，取消仍在打开或等待中的直连任务，并取消尚未执行或尚未
完成的 WebSocket 回退任务。异步任务和入站回调执行时必须重新核对其创建时的房间作用域或连接 generation；旧作用域
事件不得通过新房间的发现 WebSocket 发出，旧 socket 迟到的入站消息也必须忽略。客户端还必须清空旧作用域的剪贴板
事件、白板事件、笔画和快照，不能让它们在新房间重放或参与新快照。

当 DataChannel 未建立、已关闭或在客户端规定的等待时间内不可用时，发送方可以回退到发现 WebSocket。回退消息使用
第 2.4 节的通用 envelope，客户端发送 `type`、非空 `targetPeerId` 和 `payload`，服务端补入可信的
`sourcePeerId` 后仅转发给同组目标。例如：

```json
{
  "type": "clipboard",
  "targetPeerId": "web-87654321",
  "payload": {}
}
```

`whiteboard` 与 `clipboard` 应用消息必须定向发送；需要同步给多台设备时，发送方必须为每个目标分别发送一条消息，
不得省略 `targetPeerId` 使用房间广播。DataChannel 发送成功后不得再发送同一事件的 WebSocket 回退消息。旧客户端必须
忽略不认识的 `messageType`、`type` 或 payload 版本，以保持向后兼容。发现服务端保持第 2.4 节的通用转发行为，
不会按应用类型拒绝缺少目标的消息；因此接收端必须忽略 `targetPeerId` 为空或不等于自身 peer ID 的 `whiteboard`、
`clipboard` WebSocket envelope。

同步白板使用 `messageType: "whiteboard"` 或 WebSocket `type: "whiteboard"`，payload 版本标记为 `STWB1`。
当前定义的白板事件种类为 `stroke-start`、`stroke-points`、`stroke-end`、`remove-stroke`、`object-upsert`、
`remove-object`、`clear` 和 `snapshot`。`object-upsert` 用于新增或更新文本框、矩形、椭圆、箭头与图片对象；对象坐标和尺寸
使用 `0..1` 的画布归一化值，接收端必须拒绝越界对象。`remove-object` 使用对象 ID 删除对应对象，重复接收应保持幂等。

白板图片在发送前必须缩放并编码为 JPEG data URL，完整 `dataUrl` 不超过 `48 KiB` 个 UTF-16 code unit，为 WebSocket
回退 envelope 和对象元数据预留第 2.5 节的消息空间。接收端只能接受 `data:image/jpeg;base64,`，不得加载远程图片 URL。
新成员加入时，现有成员可先发送笔画 `snapshot`，再以独立 `object-upsert` 事件补发最近的对象，避免多张内联图片合并后
超过单消息上限。未知对象种类或未知事件种类必须忽略，以兼容只支持笔画的旧页面。

白板笔画、对象、实时 Yjs 更新和去重状态只保存在参与浏览器的当前内存中，发现服务端只做临时转发。专业流程图可以由
OWNER 或 EDITOR 显式创建持久版本，但服务端不会自动持久化每次实时编辑。

#### 2.4.2 专业流程图版本

Token 房间通过以下 POST 接口管理专业流程图 Yjs 全量快照；`roomId`、`roomToken` 和 `peerId` 同样放在 JSON body：

```text
POST /api/public/transfer/rooms/diagram/versions/list
POST /api/public/transfer/rooms/diagram/versions
POST /api/public/transfer/rooms/diagram/versions/{versionId}
POST /api/public/transfer/rooms/diagram/versions/{versionId}/delete
```

列表只返回元数据，恢复时才按 `versionId` 拉取 Base64 `update`。单个解码后快照不得超过 3 MiB，每个房间最多保留
50 个版本，超出时删除最旧版本。OWNER 和 EDITOR 可以创建、读取和恢复版本；VIEWER 只能读取版本元数据与内容但不能
恢复为当前文档；只有 OWNER 可以删除版本。无 Token 的内网房间继续使用浏览器会话内快照，最多 20 个。

#### 2.4.3 剪贴板文本 `STCLIP1`

剪贴板同步只传输用户在已开启的剪贴板模块中主动粘贴的 `text/plain`，或者用户输入、编辑文本后明确点击“同步”触发的
内容；普通输入事件不得自动发送。除读取用户触发的 paste 事件所携带数据外，客户端不得在后台轮询、监听或主动读取
系统剪贴板，也不得把 `text/html` 剪贴板格式作为富文本同步；纯文本中即使包含标记，也必须按普通文本安全展示。
DataChannel 使用 `messageType: "clipboard"`，WebSocket 回退使用
`type: "clipboard"`。`STCLIP1` payload 为：

```json
{
  "type": "STCLIP1",
  "kind": "text",
  "id": "clip-7f2e4c6a",
  "sessionId": "67f33d8c-52c0-4e52-92f8-5166e5511052",
  "sequence": 1,
  "text": "需要同步的文本",
  "createdAt": 1780000000000
}
```

字段语义：

| 字段 | 规则 |
| --- | --- |
| `type` | 必须为 `STCLIP1`；未知版本必须忽略 |
| `kind` | 当前必须为 `text` |
| `id` | 发送方生成的字符串事件 ID，长度为 `1..128` 个 UTF-16 code unit，且 JavaScript `trim()` 后必须保持不变；在同一发送方和 `sessionId` 内必须唯一 |
| `sessionId` | 当前浏览器房间会话的字符串 ID，适用与 `id` 相同的 `1..128` 长度和首尾空白规则；切换房间时必须重新生成 |
| `sequence` | 非负 JavaScript 安全整数；发送方在同一 `sessionId` 内必须单调递增 |
| `text` | 原样同步的非空纯文本；必须同时满足不超过 `16,384` 个 UTF-16 code unit，且 UTF-8 编码不超过 `32 KiB` |
| `createdAt` | 非负 JavaScript 安全整数，表示发送方生成事件时的 Unix epoch 毫秒数；只用于展示，不作为授权或可信排序依据 |

payload 必须是普通 JSON object，且必须恰好包含上述七个字段；缺少字段或存在未知附加字段都视为不合规事件。接收方
必须校验每个字段的 JSON 类型和约束，按 `(sourcePeerId, sessionId, id)` 去重，并为每个 `(sourcePeerId, sessionId)`
记录已接受的最高 `sequence`；`sequence` 小于或等于该值的迟到或重放事件必须忽略。未来增加字段时必须使用新的
payload `type` 版本，不得在 `STCLIP1` 中直接追加字段。上述括号表达的是无歧义 tuple；协议不规定用冒号拼接成字符串，
实现选择字符串 event key 时必须使用不会因字段内容产生碰撞的编码。

发送方必须在发送前执行两项 `text` 大小检查；任一超限都不得发送。接收方必须重复校验 payload 类型和两项大小上限，
不合规事件应静默忽略。`16,384` code unit 与 `32 KiB` 是原始 `text` 的剪贴板应用层限制，用于为 JSON 和转发
envelope 预留空间，但不替代第 2.5 节的完整消息上限。控制字符等内容经 JSON 转义后可能膨胀；使用 WebSocket 回退前，
发送方还必须确认完整序列化消息不超过 `65,536` 个 UTF-16 code unit，超限时不得走 WebSocket 回退路径。

接收端只有在用户为当前会话开启剪贴板同步后，才可以尝试调用 `navigator.clipboard.writeText(text)` 自动写入系统剪贴板。
自动写入是 best-effort：它要求安全上下文，并且浏览器仍可能因为权限或缺少瞬时用户操作而拒绝。客户端必须等待写入
`Promise` 成功后才能显示“已同步到剪贴板”；失败时必须保留一条内存态收件记录并提供由用户点击触发的“复制”操作，
不得把“消息已收到”表述为“已写入剪贴板”。API 不存在、调用同步抛出异常或 `Promise` rejection 都属于自动写入失败。
客户端可以把长时间未 settle 的写入视为超时失败，但必须解除本地写入占用、停止自动重试同一事件，并允许用户重新点击
“复制”；由于 Clipboard API 不支持取消，迟到完成的旧写入不得最终覆盖客户端随后已成功写入的更新内容。

剪贴板事件、收件历史、写入状态和去重集合只能保存在浏览器当前内存中，刷新页面或切换房间时必须清空；不得写入
`localStorage`、`sessionStorage`、`IndexedDB` 或附件存储。发现服务端只在处理消息时短暂持有并转发 payload，不把
剪贴板内容写入数据库、对象存储或任何级别的应用日志。

### 2.5 消息大小与限流

应用层单条文本上限为 `65,536` 个 Java UTF-16 code unit；超过上限以 close code `1009` 关闭。Java WebSocket
session 的文本/二进制容器 limit 显式设为 `65,536`；按 UTF-8 字节聚合 frame 的实现必须给文本预留足够空间
（当前 Go/.NET 使用 `3 × 65,536` 字节），解码后再按 UTF-16 code unit 执行同一应用层检查。本端点只定义 JSON
文本消息；二进制消息不是协议输入，必须像 Java `TextWebSocketHandler` 一样以 close code `1003` 拒绝。

每连接使用进程内固定窗口限流，默认每 `60` 秒 `360` 条，配置值都按至少 `1` 处理。`ping`、无效 JSON 和普通信令
以及经发现 WebSocket 回退的 `whiteboard`、`clipboard` 应用消息都先计数；DataChannel 应用消息不经过服务端，
不计入该窗口。超限时发送：

```json
{"type":"error","error":"rate limited"}
```

随后以 close code `1008` 关闭。多实例部署时该限额按实例数放大。

## 3. 附件 REST

### 3.1 附件与下载授权端点

| 作用域 | 方法与路径 | 鉴权 | 请求体 |
| --- | --- | --- | --- |
| 公开创建上传 | `POST /api/public/transfer/attachments/presign-upload` | Bearer JWT + 房间权限 | `PresignUploadRequest` |
| 公开确认上传 | `POST /api/public/transfer/attachments/{attachmentId}/complete` | Bearer JWT + 房间权限 | `{"roomToken":"..."}` |
| 公开创建下载 | `POST /api/public/transfer/attachments/{attachmentId}/presign-download` | Bearer JWT + 房间权限 | `{"roomToken":"..."}` |
| 管理创建上传 | `POST /api/admin/client-messages/attachments/presign-upload` | Bearer JWT | `PresignUploadRequest` |
| 管理确认上传 | `POST /api/admin/client-messages/attachments/{attachmentId}/complete` | Bearer JWT | 无 |
| 管理创建下载 | `POST /api/admin/client-messages/attachments/{attachmentId}/presign-download` | Bearer JWT | 无 |
| OSS 上传回调 | `POST /api/public/transfer/oss-callback` | OSS RSA/MD5 签名 | OSS callback JSON |
| 消费下载授权 | `GET /api/public/transfer/downloads/{token}` | 匿名 bearer grant | 无 |

公开作用域为 `PUBLIC_TRANSFER`；管理作用域为 `ADMIN_CLIENT_MESSAGE`。两个作用域的 ID 不得相互访问。公开作用域中的
“公开”表示服务端无需管理端租户资源权限即可按房间授权，不表示允许匿名访问 OSS；面向用户的三个公开附件端点必须先通过 Bearer
认证，再执行房间角色和 `roomToken` 校验。

### 3.2 创建上传请求

```json
{
  "fileName": "photo.jpg",
  "mimeType": "image/jpeg",
  "sizeBytes": 123456,
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "roomId": "nearby",
  "roomToken": "high-entropy-secret",
  "targetClientId": 123
}
```

字段规则：

| 字段 | 公开作用域 | 管理作用域 | 规则 |
| --- | --- | --- | --- |
| `fileName` | 必需 | 必需 | 按下述统一算法去路径并转为安全 ASCII 文件名，最长 180 个字符 |
| `mimeType` | 可选 | 可选 | 缺省 `application/octet-stream`；最长 120；禁止 CR/LF |
| `sizeBytes` | 必需 | 必需 | 正整数且不得大于 `max-attachment-bytes` |
| `sha256` | 可选 | 可选 | 64 个十六进制字符，存储为小写；服务端当前不据此读取并校验对象内容 |
| `roomId` | 可选，缺省 `default` | 忽略 | 最长 120，禁止 CR/LF；过长时拒绝，不截断 |
| `roomToken` | 必需 | 忽略 | 去首尾空白后 SHA-256；数据库只保存 hash |
| `targetClientId` | 忽略 | 必需 | 必须是当前管理上下文可访问的客户端 |

附件 `roomId` 的缺省值是 `default`，与发现 WebSocket 的 `nearby` 不同；调用方需要同一展示分组时应显式传值。
管理权限要求 tenant 完全相等；管理员可访问同 tenant 的客户端，普通用户还必须与 `ownerUsername` 完全相等。

新建公开附件时，服务端把附件关联到解析后的持久房间 ID：OWNER 和 EDITOR 可以创建及确认上传，VIEWER 不得上传；
同一持久房间的 OWNER、EDITOR 和 VIEWER 都可以凭各自 Token 下载已完成附件。待上传配额按持久房间 ID 汇总，不能通过
签发多个邀请 Token 绕过。升级前已存在且没有持久房间 ID 的附件继续按上传时 `roomToken` 哈希精确匹配，以保持旧链接可用。

#### 3.2.1 `fileName` 规范化

Java、Go 和 .NET 必须按以下顺序执行同一算法；长度均指规范化后的 ASCII 字符数：

1. `fileName` 缺失或为空字符串时拒绝请求；不对非空输入做首尾裁剪。仅含空白的非空输入会按第 3 步规范化为 `_`。
2. 同时把 `/` 和 `\` 视为路径分隔符，只取最后一个分隔符之后的末段。末段长度为零时返回 `attachment`。
3. 按 Unicode 码点扫描末段。ASCII 字母、ASCII 数字、`.`、`_`、`-` 原样保留；每个连续的非法码点段替换为一个 `_`。空格和所有非 ASCII 字符都属于非法码点，因此一个 emoji（即使在 UTF-16 中占两个 code unit）只产生一个 `_`。
4. 每个连续的 `.` 段折叠为一个 `.`，保证文件名不含 `..`。若此时结果为空或恰为 `.`，返回 `attachment`。前导单点和尾随单点可以保留，例如 `.env` 和 `file.`。
5. 结果不超过 180 个字符时直接返回。超长时，仅当最后一个 `.` 既不是首字符也不是末字符、且从该点到结尾的扩展名（含 `.`）少于 180 个字符时，保留完整扩展名并把前缀截到 `180 - extension.length`；这保证扩展名前至少保留一个字符。扩展名无法连同至少一个前缀字符放入 180 个字符时，不保留扩展名语义，直接截取规范化结果的前 180 个字符。

边界示例：

| 输入 | 规范化结果 | 说明 |
| --- | --- | --- |
| `mixed/path\photo😀  中文.png` | `photo_.png` | 混合路径分隔符；连续 emoji、空格和中文折叠成一个 `_` |
| `folder/`、`folder\`、`folder/...` | `attachment` | 空末段或纯点末段 |
| `archive..tar...gz` | `archive.tar.gz` | 连续点号折叠 |
| `.env`、`file.` | 原样 | 前导点或尾随点不定义扩展名 |
| 200 个 `a` 后接 `.txt` | 176 个 `a` 后接 `.txt` | 完整扩展名可放入 180 字符上限 |
| `a.` 后接 180 个 `b` | 前 180 个字符 | 181 字符扩展名无法与前缀共同放入，按整体截断 |

公开创建上传还受两层限制：

- 来源 IP 固定窗口：默认 `300` 秒内 `30` 次，只限制公开 `presign-upload`；
- 同一 `roomToken` hash 的 `PENDING` 附件：默认最多 `50` 个。

两项配置都按至少 `1` 处理。来源 IP 的取值与发现握手一致；IP 窗口计数表最多跟踪 `100,000` 个来源，满后拒绝新来源，
并每 10 分钟清理过期窗口。该 IP 计数表是进程内状态，多实例不会形成全局精确限流；房间 `PENDING` 配额则查询附件
持久化表，使用共享数据库部署时按共享数据形成全局计数，不能把它描述为进程内计数器。

Java 的检查顺序是来源 IP 限流、房间 `PENDING` 配额、对象存储启用状态。因此前两项已经超限时，即使对象存储关闭也
返回 `429` 而不是 `409`。上传 URL 过期本身不会把记录移出 `PENDING`；它会继续占用房间配额，直至附件保留期扫描
把记录标为 `EXPIRED`。

### 3.3 创建上传响应

成功返回 `200`：

```json
{
  "attachmentId": 123,
  "objectId": "123",
  "objectKey": "shuai-tunnel/attachments/public-transfer/20260710/123/photo.jpg",
  "uploadUrl": "https://bucket.endpoint/...",
  "uploadHeaders": {"Content-Type":"image/jpeg","x-oss-callback":"<base64-json>"},
  "expiresAt": "2026-07-10T00:15:00Z",
  "attachment": {
    "attachmentId": 123,
    "objectId": "123",
    "fileName": "photo.jpg",
    "mimeType": "image/jpeg",
    "sizeBytes": 123456,
    "sha256": null,
    "status": "PENDING",
    "expiresAt": "2026-07-13T00:00:00Z"
  }
}
```

外层 `expiresAt` 是预签名上传 URL 的过期时间；`attachment.expiresAt` 是附件保留期限。`objectId` 必须是
十进制 `attachmentId` 字符串。object key 格式为：

```text
<normalized-prefix>/<scope-lowercase-with-hyphens>/<UTC-yyyyMMdd>/<attachmentId>/<normalized-fileName>
```

当 `upload-callback-url` 非空时，`uploadHeaders` 额外包含已参与 V4 签名的 `x-oss-callback`。客户端必须逐项原样带入
PUT 请求；OSS 成功保存对象后调用 `POST /api/public/transfer/oss-callback`。回调端点不要求 JWT，但必须验证
`Authorization` 与 `x-oss-pub-key-url`：签名算法为 RSA PKCS#1 v1.5 + MD5，签名内容为
`url_decode(path) + raw_query + "\n" + raw_body`。公钥 URL 只允许 `gosspublic.alicdn.com/callback_pub_key*`，
加载时强制升级 HTTPS、禁止重定向并缓存公钥。

签名通过后还必须校验 callback bucket 等于配置 bucket、object key 已由服务端分配且位于配置 prefix、size 非负且
不超过附件上限，再把记录转为 `UPLOADED`。上传回调与客户端 complete 均为幂等路径：回调成功后客户端继续调用
complete 会直接得到已有记录；OSS 回调失败不会重试且不会删除已上传对象，因此客户端 complete 必须保留为 HEAD 兜底。
callback 服务应在 5 秒内返回 JSON `200`，例如 `{"Status":"OK"}`。

### 3.4 状态机、complete 与下载

```text
PENDING --complete / verified OSS callback--> UPLOADED --expiration scan--> EXPIRED
    \------------------retention expiration------------/
```

公开 complete/download 通过 `attachmentId + scope` 查找，然后比较 `roomToken` hash；不会再次比较 `roomId`。
因此 token 是公开附件的授权凭据，同 token 房间内持有附件 ID 的参与者可以下载该附件。

`complete` 必须满足：

1. 当前状态为 `PENDING`；
2. 预签名上传 URL 尚未过期；
3. 对象存储启用时，以 HEAD 确认对象存在；
4. HEAD 的实际大小不得超过 `max-attachment-bytes`。

预签名 PUT 不绑定 `Content-Length`，请求中的 `sizeBytes` 不可信。HEAD 返回有效长度时必须覆盖声明值；实际大小超限时
必须先删除对象，再以参数错误拒绝 complete。已验证的 OSS callback 以签名 body 中的 `size` 代替 HEAD；成功后设置
`UPLOADED`、`uploadedAt` 和 `updatedAt`。

Java 当前只在对象存储启用时执行 complete 的 HEAD；若运行中关闭存储，已存在的 `PENDING` 记录会跳过 HEAD 后转为
`UPLOADED`。这是现有状态机的兼容边界，不代表禁用实现具有附件数据面；C server 仍按第 6 节对六个路径明确返回 `409`。

下载只允许 `UPLOADED` 且未超过附件保留期限的记录。成功响应为：

```json
{
  "attachmentId": 123,
  "objectId": "123",
  "downloadUrl": "/api/public/transfer/downloads/opaque-single-use-token",
  "downloadHeaders": {},
  "expiresAt": "2026-07-10T00:10:00Z",
  "attachment": {
    "attachmentId": 123,
    "objectId": "123",
    "fileName": "photo.jpg",
    "mimeType": "image/jpeg",
    "sizeBytes": 123456,
    "sha256": null,
    "status": "UPLOADED",
    "expiresAt": "2026-07-13T00:00:00Z"
  }
}
```

`downloadUrl` 不是 OSS 地址，而是站内一次性 bearer grant。服务端数据库只保存 token 的 SHA-256。首次 GET 必须用
条件更新原子写入 `consumedAt`，成功后返回 `302 Location` 到短期 OSS V4 地址；并发或后续 GET 返回 `410 Gone`。
grant 过期、附件过期、对象存储关闭或附件不再是 `UPLOADED` 时同样不得生成跳转。
`HEAD` 探测必须返回 `405 Method Not Allowed` 且不得消费 grant，避免下载器先探测再 GET 时误用掉唯一授权。

为保留客户端直连，`302` 的目标仍是 bearer 型 OSS URL；它在极短 TTL 内可被持有该 `Location` 的客户端再次请求。
要做到 OSS 端每个 HTTP 请求也严格只能一次，必须由业务服务代理文件体或增加受控下载网关，这不属于当前直传架构。

后台按 `expiration-scan-interval-ms` 扫描，每批最多取 100 条但必须循环直至为空。对象存储启用时先删除对象，再把记录标为
`EXPIRED`。扫描范围也包含一直未 complete 的过期 `PENDING` 记录。

## 4. 对象存储与 TTL

### 4.1 启用条件

Java 仅支持 `aliyun-oss`。以下条件必须同时满足才视为启用：

- provider 不区分大小写等于 `aliyun-oss`；
- endpoint、bucket、access key ID、access key secret 均非空。

默认 provider 为 `disabled`。完整实现不得在未启用时返回伪造的成功 URL。

### 4.2 Aliyun OSS V4 签名

对象 URL 使用 virtual-hosted 形式：

```text
<scheme>://<bucket>.<endpoint-host>[:port]/<percent-encoded-object-key>
```

endpoint 未带 scheme 时默认 `https`。预签名 PUT/GET 使用 `OSS4-HMAC-SHA256`，query 至少包含
`x-oss-signature-version`、`x-oss-credential`、`x-oss-date`、`x-oss-expires`、
`x-oss-additional-headers=host` 和 `x-oss-signature`。下载直达 URL还签入 `x-st-grant=<grantId>` 作为日志关联标记，
不得放入可反推 bearer token 的值。canonical URI 为 `/<bucket>/<objectKey>`，payload 为 `UNSIGNED-PAYLOAD`；
PUT 的 canonical Content-Type 必须与返回的 `uploadHeaders.Content-Type` 一致；启用上传回调时，canonical headers 还必须
包含返回的 `x-oss-callback`，浏览器 PUT 必须发送完全相同的值。

签名 scope 为 `<UTC-yyyyMMdd>/<region>/oss/aliyun_v4_request`，密钥依次对日期、region、`oss` 和
`aliyun_v4_request` 做 HMAC-SHA256 派生。标准 `oss-<region>[...].aliyuncs.com` endpoint 可自动推导 region；
CNAME、加速 endpoint 或无法识别的 host 必须显式配置 `region`。

complete 的 HEAD 和过期清理的 DELETE 使用 V4 `Authorization`、`x-oss-date` 与
`x-oss-content-sha256: UNSIGNED-PAYLOAD`。HEAD `404`
表示对象不存在；其他 `>=400` 是存储状态冲突。DELETE `404` 按幂等成功处理。该内部 HTTP client 不自动跟随
重定向；除上述特殊 `404` 外，`<400` 按成功处理，避免在跳转后把带原 host/resource 签名的请求发送到另一端点。

object key 必须非空、不得以 `/` 开头，不得含反斜杠、`..`、`//` 或控制字符，并且必须位于配置的 prefix 下。
网页直传 bucket 的 CORS 至少需要允许站点 Origin、`PUT` 方法，以及 `Content-Type`、`x-oss-callback` 请求头；否则启用
回调后浏览器会在预检阶段失败。callback URL 必须公网可达，反向代理不得改写回调路径或原始 query。

### 4.3 配置值的精确语义

| 配置 | 默认值 | Java 语义 |
| --- | ---: | --- |
| `upload-callback-url` | 空 | OSS 上传成功回调 URL；空值禁用回调并保留客户端 complete + HEAD 流程 |
| `upload-url-ttl-seconds` | 900 | OSS V4 上传 URL TTL；签名器钳制到 1..604800 秒 |
| `download-url-ttl-seconds` | 600 | 一次性站内下载授权有效期；按至少 1 秒处理 |
| `download-object-url-ttl-seconds` | 30 | grant 首次消费后生成的 OSS V4 URL TTL；签名器钳制到 1..604800 秒 |
| `retention-hours` | 72 | 创建附件时按至少 1 小时处理 |
| `max-attachment-bytes` | 536870912 | 原值用于声明大小和 HEAD 实际大小上限 |
| `per-user-storage-quota-bytes` | 1073741824 | 每个登录账号最多占用 1 GiB 有效附件存储；非正值回退到默认值 |
| `per-user-monthly-download-quota-bytes` | 1073741824 | 每个登录账号每个 UTC 自然月最多领取 1 GiB OSS 下载跳转；非正值回退到默认值 |
| `expiration-scan-interval-ms` | 3600000 | 后台扫描间隔 |

OSS V4 签名协议要求 TTL 为正数且最长 7 天，因此上传和直达下载签名器统一钳制到 1..604800 秒；
`max-attachment-bytes <= 0` 会拒绝所有正大小附件。除签名协议范围、grant 最短 1 秒及两项账号额度对非正值显式
回退到 1 GiB 外，跨语言实现不得把显式配置静默替换成默认值。

### 4.4 登录账号额度

六个创建/确认端点都要求 Bearer 登录；一次性 grant 的 GET 自身就是匿名 bearer 凭据。公开互传上传记录也必须写入当前 JWT 对应的 `tenantId/username`，与管理端消息附件
共用账号额度：

- 存储额度统计尚在上传 URL 有效期内的 `PENDING` 声明大小，以及尚未过期的 `UPLOADED` 实际大小；创建上传时先按
  声明大小预留，complete 后以 HEAD 实际大小重新校验并回写。实际大小导致超额时删除对象并拒绝 complete。
- 创建一次性下载 grant 只做额度预检，不扣用量。首次 GET 在同一事务中原子消费 grant 并按附件完整大小写入用量，
  写入成功后才返回 `302`；未访问的 grant 不计费，并发或重复 GET 不重复计费。重新申请并实际消费新 grant 会再次计费。
- 该口径记录的是成功领取 OSS 跳转的附件大小，不是 OSS 实际传输字节。业务服务不代理文件体，无法判断客户端在
  `302` 之后是否完整下载；需要精确实传流量时应接入 OSS 日志/计量数据或受控下载网关。
- 下载流量按 UTC 的 `yyyy-MM` 自然月隔离；存储额度跨公开互传和管理端消息附件合并统计。

## 5. HTTP 状态与错误

创建/确认端点和 OSS callback 成功状态为 `200`，一次性下载成功为 `302`。Java 的稳定错误契约是 HTTP 状态和
`error` 字段，不定义稳定的通用符号 `code`：

| HTTP | JSON | 场景 |
| ---: | --- | --- |
| 400 | `{"error":"..."}` | 缺字段、格式/大小错误、token 错误、附件不存在、目标无权访问 |
| 401 | Bearer challenge | 任一附件端点缺少或使用无效 JWT |
| 403 | `{"error":"..."}` | OSS callback 签名无效，或 callback bucket/object 不匹配 |
| 409 | `{"error":"..."}` | 存储未配置、状态不是 `PENDING/UPLOADED`、URL/附件过期、HEAD/DELETE/签名失败 |
| 410 | `{"error":"..."}` | 一次性下载授权不存在、已过期、已消费或附件不再可下载 |
| 413 | `{"error":"..."}` | OSS callback 请求体超过 64 KiB |
| 429 | `{"error":"..."}` | 公开来源 IP 超限、来源表已满、房间 `PENDING` 配额、账号存储或月下载流量额度超限 |

客户端必须按 HTTP 状态处理，不得依赖自然语言 `error` 文本。实现可以增加机器可读 `code`，但不得改变上述状态语义。

## 6. 轻量 C server 边界

C server 不是本协议的数据面完整实现：

- C 进程不监听 STUN/TURN UDP；公共 ICE 只有在显式配置外部兼容服务时才可以公布该服务，不能根据请求 Host
  伪装成本进程提供了 STUN/TURN；
- C 不实现 `/ws/public-transfer/discovery`；
- C 没有对象存储抽象，六个附件路径不得返回占位成功 URL，必须明确返回 `409 Conflict`。当前兼容响应为：

```json
{
  "error": "object storage is not configured",
  "code": "OBJECT_STORAGE_DISABLED",
  "enabled": false
}
```

`code` 与 `enabled` 是 C 的能力边界扩展，不表示 Java REST 已定义同名字段。管理界面和客户端必须据此禁用附件路径，
不能把路由存在误判为对象存储已启用。

## 7. Java 参考入口

| 能力 | Java 源码 |
| --- | --- |
| ICE REST 与地址规范化 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/controller/PublicPeerMeshResource.java` |
| TURN 临时凭证 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/peer/TurnCredentialService.java` |
| 发现 WebSocket | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/websocket/PublicTransferDiscoveryWebSocketHandler.java` |
| 附件与一次性下载 REST | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/controller/TransferAttachmentResource.java` |
| 附件状态机 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/service/TransferAttachmentService.java` |
| 公开限流 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/service/PublicTransferRateLimiter.java` |
| Aliyun OSS | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/storage/object/AliyunOssObjectStorageService.java` |
| HTTP 错误映射 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/controller/GlobalExceptionHandler.java` |
