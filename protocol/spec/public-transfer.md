# 公共互传协议

本文定义免登录公共文件互传的服务端协议，包括公共 ICE 配置、发现信令、附件 REST、对象存储和滥用防护。
Java server 是语义基准；Go、.NET server 的完整实现必须保持一致。文中的“必须”“应当”“可以”分别对应
MUST、SHOULD、MAY。

公共互传由三条相互独立但可组合的路径构成：

1. `GET /api/public/transfer/ice-config` 提供 STUN/TURN 候选；
2. `/ws/public-transfer/discovery` 负责浏览器发现、roster 和定向信令；
3. 附件 REST 返回短期预签名 URL，文件内容由客户端直接上传/下载对象存储。

发现 WebSocket 和公开附件接口均无需管理 JWT。它们不是安全边界：共享房间的安全性来自高熵
`roomToken`，附近房间的隔离来自可信反向代理提供的来源 IP。

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
      "urls": "stun:tunnel.example.com:3478",
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
| `peerMeshEnabled` | `tunnel.peer-mesh.enabled` 的值；为 `false` 时不生成自托管 STUN/TURN 项 |
| `iceServers` | WebRTC 风格的有序 ICE server 列表；每项的 `urls` 是单个字符串，不是数组 |
| `turnAuthRequired` | TURN listener 是否要求长期凭证 |
| `stunTurnPort` | 对外公布的 STUN/TURN UDP 端口 |

列表顺序必须为：自托管 STUN（若可用）、配置的公共 STUN（保持配置顺序并去重）、自托管 TURN（若可用）。
配置的公共 STUN 在 `peerMeshEnabled=false` 时仍保留，只有自托管 STUN/TURN 受 enabled 开关控制。
STUN 项必须返回空 `username` 和空 `credential`；TURN 项返回临时凭证。
Java 即使在 `turnAuthRequired=false` 时也会给 TURN 项签发非空 username/credential；跨语言实现不得据此删掉字段，
客户端可以在认证关闭时忽略它们。

### 1.2 地址选择与规范化

Java 按以下顺序选择自托管地址：

1. `tunnel.peer-mesh.public-address`；
2. `X-Forwarded-Host` 第一项；
3. `Host` 第一项；
4. servlet `serverName`。

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
roomToken 非空: roomKey = "token:"  + lowercaseHex(SHA-256(UTF8(trim(roomToken))))
roomToken 为空: roomKey = "public:" + publicAddress
```

因此相同 token 但不同 `roomId` 仍是不同房间；未提供 token 的参与者只有在 `roomId` 与来源地址都相同时才能互见。
`sharedRoom` 表示是否使用 token 房间。

### 2.3 加入、hello 与 roster

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
      "connectedAt": "2026-07-10T00:00:00Z"
    }
  ]
}
```

`peers` 按 `connectedAt` 升序排列。

### 2.4 ping 与信令转发

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

### 2.5 消息大小与限流

应用层单条文本上限为 `65,536` 个 Java UTF-16 code unit；超过上限以 close code `1009` 关闭。Java WebSocket
session 的文本/二进制容器 limit 显式设为 `65,536`；按 UTF-8 字节聚合 frame 的实现必须给文本预留足够空间
（当前 Go/.NET 使用 `3 × 65,536` 字节），解码后再按 UTF-16 code unit 执行同一应用层检查。本端点只定义 JSON
文本消息；二进制消息不是协议输入，必须像 Java `TextWebSocketHandler` 一样以 close code `1003` 拒绝。

每连接使用进程内固定窗口限流，默认每 `60` 秒 `120` 条，配置值都按至少 `1` 处理。`ping`、无效 JSON 和普通信令
都先计数。超限时发送：

```json
{"type":"error","error":"rate limited"}
```

随后以 close code `1008` 关闭。多实例部署时该限额按实例数放大。

## 3. 附件 REST

### 3.1 六个端点

| 作用域 | 方法与路径 | 鉴权 | 请求体 |
| --- | --- | --- | --- |
| 公开创建上传 | `POST /api/public/transfer/attachments/presign-upload` | 无 | `PresignUploadRequest` |
| 公开确认上传 | `POST /api/public/transfer/attachments/{attachmentId}/complete` | 无 | `{"roomToken":"..."}` |
| 公开创建下载 | `POST /api/public/transfer/attachments/{attachmentId}/presign-download` | 无 | `{"roomToken":"..."}` |
| 管理创建上传 | `POST /api/admin/client-messages/attachments/presign-upload` | Bearer JWT | `PresignUploadRequest` |
| 管理确认上传 | `POST /api/admin/client-messages/attachments/{attachmentId}/complete` | Bearer JWT | 无 |
| 管理创建下载 | `POST /api/admin/client-messages/attachments/{attachmentId}/presign-download` | Bearer JWT | 无 |

公开作用域为 `PUBLIC_TRANSFER`；管理作用域为 `ADMIN_CLIENT_MESSAGE`。两个作用域的 ID 不得相互访问。

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
  "uploadHeaders": {"Content-Type":"image/jpeg"},
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

### 3.4 状态机、complete 与下载

```text
PENDING --complete--> UPLOADED --expiration scan--> EXPIRED
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
必须先删除对象，再以参数错误拒绝 complete。成功后设置 `UPLOADED`、`uploadedAt` 和 `updatedAt`。

Java 当前只在对象存储启用时执行 complete 的 HEAD；若运行中关闭存储，已存在的 `PENDING` 记录会跳过 HEAD 后转为
`UPLOADED`。这是现有状态机的兼容边界，不代表禁用实现具有附件数据面；C server 仍按第 6 节对六个路径明确返回 `409`。

下载只允许 `UPLOADED` 且未超过附件保留期限的记录。成功响应为：

```json
{
  "attachmentId": 123,
  "objectId": "123",
  "downloadUrl": "https://bucket.endpoint/...",
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

后台按 `expiration-scan-interval-ms` 扫描，每批最多取 100 条但必须循环直至为空。对象存储启用时先删除对象，再把记录标为
`EXPIRED`。扫描范围也包含一直未 complete 的过期 `PENDING` 记录。

## 4. 对象存储与 TTL

### 4.1 启用条件

Java 仅支持 `aliyun-oss`。以下条件必须同时满足才视为启用：

- provider 不区分大小写等于 `aliyun-oss`；
- endpoint、bucket、access key ID、access key secret 均非空。

默认 provider 为 `disabled`。完整实现不得在未启用时返回伪造的成功 URL。

### 4.2 Aliyun OSS v1 签名

对象 URL 使用 virtual-hosted 形式：

```text
<scheme>://<bucket>.<endpoint-host>[:port]/<percent-encoded-object-key>
```

endpoint 未带 scheme 时默认 `https`。预签名 PUT/GET 使用 OSS v1 query 参数
`OSSAccessKeyId`、`Expires`、`Signature`。签名为标准 Base64 HMAC-SHA1，canonical resource 为
`/<bucket>/<objectKey>`；PUT 的 canonical Content-Type 必须与返回的 `uploadHeaders.Content-Type` 一致。

complete 的 HEAD 和过期清理的 DELETE 使用 `Date` 与 `Authorization: OSS <keyId>:<signature>`。HEAD `404`
表示对象不存在；其他 `>=400` 是存储状态冲突。DELETE `404` 按幂等成功处理。该内部 HTTP client 不自动跟随
重定向；除上述特殊 `404` 外，`<400` 按成功处理，避免在跳转后把带原 host/resource 签名的请求发送到另一端点。

object key 必须非空、不得以 `/` 开头，不得含反斜杠、`..`、`//` 或控制字符，并且必须位于配置的 prefix 下。

### 4.3 配置值的精确语义

| 配置 | 默认值 | Java 语义 |
| --- | ---: | --- |
| `upload-url-ttl-seconds` | 900 | 原值传给签名器；不自动替换或钳制 |
| `download-url-ttl-seconds` | 600 | 原值传给签名器；不自动替换或钳制 |
| `retention-hours` | 72 | 创建附件时按至少 1 小时处理 |
| `max-attachment-bytes` | 536870912 | 原值用于声明大小和 HEAD 实际大小上限 |
| `expiration-scan-interval-ms` | 3600000 | 后台扫描间隔 |

因此 URL TTL 为 `0` 或负数会生成当前或过去的过期时间；`max-attachment-bytes <= 0` 会拒绝所有正大小附件。
跨语言实现不得把这些显式配置静默替换成默认值。

## 5. HTTP 状态与错误

附件 REST 的成功状态为 `200`。Java 的稳定错误契约是 HTTP 状态和 `error` 字段，不定义稳定的通用符号 `code`：

| HTTP | JSON | 场景 |
| ---: | --- | --- |
| 400 | `{"error":"..."}` | 缺字段、格式/大小错误、token 错误、附件不存在、目标无权访问 |
| 401 | Bearer challenge | 管理附件端点缺少或使用无效 JWT |
| 409 | `{"error":"..."}` | 存储未配置、状态不是 `PENDING/UPLOADED`、URL/附件过期、HEAD/DELETE/签名失败 |
| 429 | `{"error":"..."}` | 公开来源 IP 超限、来源表已满或房间 `PENDING` 配额超限 |

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
| 六个附件 REST | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/controller/TransferAttachmentResource.java` |
| 附件状态机 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/service/TransferAttachmentService.java` |
| 公开限流 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/service/PublicTransferRateLimiter.java` |
| Aliyun OSS | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/storage/object/AliyunOssObjectStorageService.java` |
| HTTP 错误映射 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/controller/GlobalExceptionHandler.java` |
