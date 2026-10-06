# 直连文件分块续传（v1）

状态：**契约已定（第 14 节各项采用推荐默认），已在公开互传页面实现；第 13 节的跨浏览器、跨 NAT 实机验收尚未完成**。跟踪 issue #38「分块续传」。本文是两个浏览器页面之间的约定；服务端不新增接口、
不保存任何续传状态。共享向量：`protocol/test-vectors/chunked-resume-v1.json`，由
`tools/protocol/generate_chunked_resume_vectors.py` 生成（脚本内含参考模型，写文件前逐条断言手写期望）。
文中“必须”“应当”“可以”对应 MUST、SHOULD、MAY。

## 0. 现状（2026-10 调研）

- 直连文件走 `bulk` RTCDataChannel（ordered/reliable，direct 失败后同一文件以 `relay` 模式经 TURN 重试）。控制消息为
  JSON 文本：`file-meta`（文件名、MIME、大小、整文件 SHA-256）→ `file-ready`（自动或确认后）→ 无头部的 64 KiB 原始
  `ArrayBuffer` → `file-complete` → 接收方在内存拼 Blob、校验整文件 SHA-256 → `file-ack` / `file-reject`。
  背压为 `bufferedAmount` 高水位 4 MiB、低阈值 1 MiB。没有分块校验、偏移、去重或块级确认，依赖 SCTP 有序可靠。
- 断线：通道关闭即删除接收状态；发送方换模式或用户重试都会生成新 `transferId` 从零开始，并重新触发接收确认。
  页面 FAQ 明确写着不支持断点续传。
- 收发两端都执行 `DEFAULT_DIRECT_MEMORY_LIMIT_BYTES = 128 MiB`，因为接收方把全部块留在内存。
- 接收确认：`receiveConfirmationRequired` 存于 sessionStorage，默认关闭（自动接收）；确认等待 118 s，发送方等 120 s。
  每个 bulk 通道同一时间只允许一个待确认或接收中的文件。
- 整文件 SHA-256 用 `apps/admin-web/src/lib/sha256.ts` 的增量纯 JS 实现（Worker），因为 WebCrypto 不支持流式摘要；
  STAP2 的消息摘要使用 `crypto.subtle`。
- STAP2/STWR2 只承载白板、剪贴板、流程图。STWR2 经发现 WebSocket 中转，服务端可见明文、单帧 ≤ 64 KiB 且计入
  360 条/分钟限流，文件从不经过它。
- 云端附件：单次预签名 PUT（OSS V4）+ complete（HEAD 或 OSS 回调），没有分片上传或续传接口。
- 持久状态：浏览器只用 sessionStorage/localStorage 保存房间、peerId 和设置，没有 IndexedDB/OPFS；服务端对直连传输
  不保存任何记录。

## 1. 范围

v1 只覆盖**两个浏览器页面之间经 `bulk` RTCDataChannel 的直连文件**，包括 ICE direct 和 TURN relay 两种路径，
以及二者之间切换。续传分两层（详见第 9 节）：

- **会话内重试**：两端页面都没有重新加载，只是 DataChannel/PeerConnection 断开后重建。
- **刷新恢复**：任一端页面重新加载、关闭后重开或崩溃。接收方从持久存储恢复已校验的块；发送方必须由用户重新选择文件。

不在 v1 范围：

| 路径 | 原因 |
| --- | --- |
| 云端附件（OSS） | 当前只有单次预签名 PUT。续传需要分片上传的创建、分片签名、已传分片列举、合并与中止接口，要在 Java/Go/.NET/C 四端同时实现，还要处理分片级额度预留、未完成分片的过期清理和 bucket CORS 暴露 `ETag`。这是服务端协议变更，另立规范；v1 仅改两端页面，不改服务端 |
| STWR2 发现中转 | 服务端可见明文，帧上限和限流都不适合文件，文件块和续传控制消息都不得经过它 |
| 剪贴板、白板、流程图 | 消息很小，失败后重发即可 |
| 原生客户端、批量级续传 | 批量内每个文件是独立 transfer，各自续传；不定义“整批”状态 |

## 2. 常量

| 名称 | 值 | 说明 |
| --- | ---: | --- |
| `chunkSize` | 默认 1 MiB；允许 64 KiB..4 MiB 内的 2 的幂 | 校验与续传单位，同一清单内固定 |
| `maxChunkCount` | 4096 | 位图最多 512 字节，哈希列表最多 128 KiB |
| `maxResumableBytes` | 2 GiB | 持久模式单文件上限（待决问题 1） |
| `memoryLimitBytes` | 128 MiB | 内存模式上限，等于现有设备内存限制 |
| `maxStoredPartials` | 4 | 接收方同时保留的未清理记录数 |
| `maxPartialBytesTotal` | 4 GiB | 上述记录声明大小之和的上限 |
| `storageMarginBytes` | 64 MiB | 配额检查的安全余量 |
| `maxActiveReceives` | 2 | 同时处于活动会话的接收传输数；每个 bulk 通道仍只有 1 个 |
| `maxChunkMismatchesPerSession` | 3 | 同一块在一个会话内第 3 次校验失败即结束会话 |
| `maxIntegrityFailures` | 16 | 单个 transfer 跨会话累计失败数，持久化保存 |
| `resumeTtlSeconds` | 86400 | 同意与部分数据的绝对有效期，从同意时刻起算 |
| `unackedWindowChunks` | 8 | 发送方未确认块上限，与 `bufferedAmount` 背压共同生效 |
| 帧上限 | `min(64 KiB, sctp.maxMessageSize)`，头 36 字节 | 见第 4 节 |

## 3. 清单与完整性

所有摘要均为 SHA-256，只用 `crypto.subtle.digest`，单次输入不超过一个块。v1 只在安全上下文（`isSecureContext`）
启用；`navigator.storage` 与 `crypto.subtle` 都要求安全上下文。

```text
chunkCount      = ceil(sizeBytes / chunkSize)            （空文件为 0）
chunkLength(i)  = min(chunkSize, sizeBytes - i * chunkSize)
chunkSha256[i]  = SHA-256(第 i 块字节)
rootSha256      = SHA-256(chunkSha256[0] || ... || chunkSha256[n-1])   （空文件为 SHA-256 空串）
manifestDigest  = SHA-256(preimage)
```

`preimage` 为二进制拼接（整数大端）：

| 字段 | 长度 |
| --- | ---: |
| ASCII `STFR1-manifest` 后跟 `0x00` | 15 |
| `sizeBytes` u64 | 8 |
| `chunkSize` u32 | 4 |
| `chunkCount` u32 | 4 |
| `rootSha256` 原始字节 | 32 |
| `fileName` UTF-8 长度 u16 + 字节 | 2 + N |
| `mimeType` 长度 u16 + 字节 | 2 + M |

- 文件完整性锚点是 `rootSha256`：每块到达时对照哈希列表校验，哈希列表整体对照 root，root 被 `manifestDigest` 绑定，
  接收方同意的正是 `manifestDigest`。不使用整文件 SHA-256，因为 WebCrypto 没有流式摘要，大文件只能整段读入内存。
  `file-meta.sha256` 在续传模式下为 `null`（待决问题 5）。
- `transferId` 不进入摘要：摘要只描述内容和展示给接收方的元数据。
- `fileName`：UTF-8 1..1024 字节，不得含 U+0000..U+001F、U+007F、`/`、`\`；发送方沿用现有缺省值 `attachment`，
  孤立代理项按 `TextEncoder` 替换为 U+FFFD 后再参与摘要。`mimeType`：1..255 个 0x20..0x7E 字符，缺省
  `application/octet-stream`。
- 接收方校验 offer 的顺序与错误码（向量 `offerValidation`）：`UNSUPPORTED_VERSION`（缺 `resume` 或版本不是 1）、
  `BAD_TRANSFER_ID`（不是 32 位小写十六进制）、`BAD_SIZE`（非安全非负整数）、`TOO_LARGE`、`BAD_CHUNK_SIZE`、
  `BAD_CHUNK_COUNT`、`TOO_MANY_CHUNKS`、`BAD_FILE_NAME`、`BAD_MIME_TYPE`、`BAD_DIGEST_FORMAT`（不是 64 位小写十六进制）、
  `MANIFEST_DIGEST_MISMATCH`（按本节重算不一致）。

## 4. 二进制帧 STFR1

文件字节和哈希列表都在 `bulk` 通道上以二进制帧传输，控制消息仍是 JSON 文本。整数大端：

| 偏移 | 字段 | 长度 | 规则 |
| ---: | --- | ---: | --- |
| 0 | magic | 4 | ASCII `STFR` |
| 4 | version | 1 | `1` |
| 5 | type | 1 | `1=HASHES`、`2=DATA` |
| 6 | flags | 2 | 必须为 0 |
| 8 | transferId | 16 | 原始字节 |
| 24 | index | 4 | DATA：块序号；HASHES：本帧第一个哈希的块序号 |
| 28 | offset | 4 | DATA：块内字节偏移；HASHES：必须为 0 |
| 32 | payloadLength | 4 | 必须与实际剩余长度完全相等 |
| 36 | payload | N | DATA：块内字节；HASHES：连续的 32 字节摘要 |

解码顺序与错误码（向量 `frames`）：`TRUNCATED`（< 36 字节）、`TOO_LARGE`（> 64 KiB）、`BAD_MAGIC`、`BAD_VERSION`、
`BAD_TYPE`、`BAD_FLAGS`、`LENGTH_MISMATCH`、`EMPTY_PAYLOAD`、`BAD_HASHES_LAYOUT`（HASHES 长度不是 32 的倍数或 offset ≠ 0）。
任何解码错误都按 `PROTOCOL_ERROR` 结束会话。发送方的单帧总长不超过 `min(64 KiB, RTCSctpTransport.maxMessageSize)`；
DATA 帧不得跨块，块按帧顺序从 offset 0 连续发送。

## 5. 控制消息

都是 `bulk` 通道上的 JSON 文本，`transferId` 为 32 位小写十六进制，均不经服务端信令或 STWR2。

| kind | 方向 | 字段 | 语义 |
| --- | --- | --- | --- |
| `file-meta` | S→R | 现有字段 + `resume:{version:1, chunkSize, chunkCount, rootSha256, manifestDigest}` | 新传输的 offer |
| `file-accept` | R→S | `transferId, manifestDigest, resumeToken, storage:"persistent"\|"memory", ttlSeconds, have, needHashes` | 同意；`resumeToken` 为接收方生成的 128 位随机数 |
| `file-reject` | R→S | 现有字段 + `code` | 拒绝 offer，不建立记录 |
| `resume-offer` | S→R | `transferId, manifestDigest, resumeToken` | 断线后请求续传，不含文件名或大小 |
| `resume-state` | R→S | `transferId, manifestDigest, have, needHashes, complete, ttlSeconds` | 续传应答 |
| `resume-reject` | R→S | `transferId, code` | `UNKNOWN_TRANSFER`、`EXPIRED`、`MANIFEST_CHANGED`、`NOT_ALLOWED`、`BUSY` |
| `resume-request` | R→S | `transferId` | 接收方刷新后提示仍在线的原发送方发 `resume-offer` |
| `chunk-ack` | R→S | `transferId, index` | 该块已校验并**持久写入**（内存模式为写入内存存储） |
| `chunk-nack` | R→S | `transferId, index, code` | `HASH_MISMATCH` 或 `STORAGE_CORRUPT`，要求重发该块 |
| `transfer-complete` | R→S | `transferId, manifestDigest` | 终验通过；发送方据此显示“已送达” |
| `transfer-error` | 双向 | `transferId, code` | 结束当前会话：`PROTOCOL_ERROR`、`RETRY_EXHAUSTED`、`INTEGRITY_FAILED`、`STORAGE_FULL`、`SOURCE_CHANGED` |
| `file-cancel` | 双向 | `transferId`，通道外时还需 `resumeToken` | 显式放弃，双方删除状态 |

`have` 是收到块的位图：第 i 块对应字节 `i >> 3` 的第 `i & 7` 位（低位在前），长度 `ceil(chunkCount / 8)`，超出
`chunkCount` 的位必须为 0，编码为无填充 base64url。解码必须严格：非法字符、带 `=`、长度模 4 余 1、末字符剩余位非零
都是 `BAD_ENCODING`；长度不符为 `BAD_LENGTH`；尾部位非零为 `TRAILING_BITS`（向量 `bitmap`）。

## 6. 接收方同意

同意绑定 `(transferId, manifestDigest)`，有效期为 `resumeTtlSeconds`，从同意时刻起算，续传不延长。判定顺序（向量
`consent`）：

1. 来源当前角色无发送权限（VIEWER 等）→ `REJECT NOT_ALLOWED`。
2. 本地已有同一 `transferId` 的记录 → `REJECT TRANSFER_ID_IN_USE`。续传只能走 `resume-offer`。
3. 开启自动接收且 `sizeBytes ≤ memoryLimitBytes` → `AUTO_ACCEPT_MEMORY`。**自动接收不得写磁盘**，只能使用内存模式。
4. 判断持久模式是否可用，依次检查：存储可用（安全上下文、IndexedDB 可开、`navigator.storage.estimate()` 可用）、
   记录数 < `maxStoredPartials`、已有记录声明大小之和 + 本文件 ≤ `maxPartialBytesTotal`、
   `sizeBytes + Σ(其它记录未收字节) + storageMarginBytes ≤ quota - usage`。全部满足时为 `PROMPT_PERSISTENT`：
   必须由用户点击同意，界面说明会写入本机存储、有效期和可随时放弃。
5. 持久模式不可用时：`sizeBytes ≤ memoryLimitBytes` 为 `PROMPT_MEMORY`（附原因，界面说明刷新后无法恢复），否则以
   该原因拒绝：`PERSISTENCE_UNAVAILABLE`、`TOO_MANY_PARTIALS`、`PARTIAL_BYTES_LIMIT`、`INSUFFICIENT_STORAGE`。

规则：

- 同一 `transferId`、同一 `manifestDigest`、有效 `resumeToken`、未过期：续传**不需要**再次同意，界面只显示“继续接收”。
- 清单任何变化（文件名、MIME、大小、块大小、内容）都改变 `manifestDigest`：同一 `transferId` 下返回 `MANIFEST_CHANGED`；
  发送方只能用新的 `transferId` 重新 offer，重新取得同意，从零开始。v1 不跨 transfer 复用已收块。
- 过期后续传返回 `EXPIRED`，数据按第 10 节清理；需要的话重新发送并重新同意。
- 续传时重新检查来源角色（邀请可能已撤销）。

## 7. 会话

一个**会话**是一条 `bulk` 通道上的一次连续传输。新传输：

1. S 读取文件，逐块计算 `chunkSha256`，得到 root 与 `manifestDigest`（与现有整文件哈希同样需要读完整个文件）。
2. S→R `file-meta`；R 按第 3 节校验，再按第 6 节判定；同意后建立记录并回 `file-accept`（新传输 `have` 为空、
   `needHashes=true`）。
3. S 发送 HASHES 帧覆盖全部哈希，随后按块序号升序发送缺失块的 DATA 帧。接收方集齐哈希后对照 root；不一致为
   `ROOT_MISMATCH`，传输失败并删除。未完整的哈希列表不持久化，下次会话从 0 重发。
4. R 每收齐并持久写入一块回 `chunk-ack`。S 未确认块不超过 `unackedWindowChunks`，同时保留现有 `bufferedAmount` 背压。
5. 位图满后 R 终验：逐块重读存储并重算摘要。发现损坏的块清位、计入失败数，并发 `chunk-nack STORAGE_CORRUPT`；
   全部通过则状态为 `COMPLETE` 并回 `transfer-complete`。S 收到后删除自己的记录。

接收方对每个帧的处理（向量 `receiver`，逐事件给出结果、应发消息、会话是否仍打开、状态）：

| 条件（按顺序） | 结果 | 动作 |
| --- | --- | --- |
| 无活动会话 | `NO_SESSION` | 丢弃，状态不变 |
| `transferId` 不是本会话的 | `WRONG_TRANSFER` | 结束会话（`PROTOCOL_ERROR`） |
| DATA 早于哈希列表完整 | `HASHES_INCOMPLETE` | 结束会话 |
| `index ≥ chunkCount` 或越过块长度 | `OUT_OF_RANGE` | 结束会话 |
| 不是正在拼装块的下一个偏移，或上一块未完就开始新块 | `UNEXPECTED_OFFSET` | 结束会话并丢弃拼装中的块 |
| 块未收齐 | `PARTIAL` | 继续 |
| 已有该块 | `DUPLICATE` | 不重算、不重写、不计失败，仍回 `chunk-ack` |
| 摘要匹配 | `STORED` | 原子写入块与位并回 `chunk-ack` |
| 摘要不符：累计失败达 16 | `INTEGRITY_FAILED` | 传输失败，删除数据 |
| 摘要不符：本会话该块第 3 次 | `RETRY_EXHAUSTED` | 结束会话，数据保留 |
| 摘要不符：其它情况 | `HASH_MISMATCH` | 不写入，回 `chunk-nack` |

只有完整校验通过的块会进入位图，拼装中的半块在会话结束时一律丢弃。会话结束（含断线）不影响已存块。

发送方（向量 `senderPlan`）：按 `have` 发送缺失块，升序；`needHashes=true` 时先发哈希列表。读取每块后先对照清单
摘要，不一致说明源文件已变化，立即发 `transfer-error SOURCE_CHANGED` 并停止；用户只能以新的 transfer 重发。
接收方已有的块不再读取，因此变化只发生在这些块里时不影响结果（最终内容仍等于清单）。刷新后重选的文件大小不同则直接
`SOURCE_SIZE_MISMATCH`，不发起握手。

## 8. 断线后的续传握手

1. S 在新的 `bulk` 通道（direct 或 relay 均可）发 `resume-offer`。
2. R 判定顺序（向量 `resume`）：
   - 无记录、记录为 `FAILED`/`CANCELLED` 或 `resumeToken` 不符：`UNKNOWN_TRANSFER`。令牌错误与不存在**不可区分**，
     并且先于其它检查，避免泄露是否过期或清单是否变化。
   - `now ≥ expiresAt`：`EXPIRED`（到期时刻即视为过期）。
   - `manifestDigest` 不符：`MANIFEST_CHANGED`。
   - 来源当前无发送权限：`NOT_ALLOWED`。
   - 已 `COMPLETE`：回 `resume-state complete=true`，用于补发丢失的完成通知，不占用活动名额。
   - 其它传输的活动会话已达 `maxActiveReceives`：`BUSY`。
   - 否则回 `resume-state`。若该 transfer 在另一条通道上还有旧会话，新会话**取代**旧会话（旧通道可能已半断开）。
3. S 按 `have` 继续发送。`resume-state` 附带的 `firstMissing`、`resumeOffset = firstMissing × chunkSize`（全部收齐时
   等于 `sizeBytes`）和 `receivedBytes` 只用于界面，发送范围以位图为准。
4. `resume-offer` 10 秒无应答按 `UNKNOWN_TRANSFER` 处理（对方可能是旧版页面或选错了设备）。

身份由 `transferId + resumeToken` 证明，不依赖 `peerId`：刷新后 `peerId` 可能变化，用户可以在设备列表里重新选择目标。
发给错误设备的 `resume-offer` 只暴露两个随机值和一个摘要；对方无法伪造块（块按清单摘要校验）。v1 不防范用户主动选择的
对端谎报进度：它最多只能让发送方显示“已送达”，这一点与现状相同。

## 9. 会话内重试与刷新恢复的边界

| 场景 | 状态在哪 | 是否自动 | 是否重新同意 |
| --- | --- | --- | --- |
| 通道或 PeerConnection 断开，两端页面都在（含 direct↔relay 切换、网络切换） | 两端内存；接收方的块在存储中（持久或内存） | 是。S 在目标仍在 roster 时最多重试 5 次，退避 1/2/4/8/16 s，有新 `chunk-ack` 即重置 | 否 |
| 房间 scope 变化 | 同上，但旧 generation 的任务按现有规则取消 | 否，停止自动重试，记录保留 | 否（有效期内） |
| 接收方刷新，发送方页面仍在 | R：IndexedDB；S：内存中的 `File` | R 可向原 `peerId`（若在线）发 `resume-request`，S 收到后自动发 `resume-offer` | 否 |
| 发送方刷新 | S：IndexedDB 中的清单、哈希列表与令牌；文件本身**不能**持久化 | 否。浏览器不允许无用户手势重新打开文件，用户必须重新选择同一文件 | 否 |
| 内存模式下任一端刷新 | 无 | — | 只能作为新传输，重新同意 |
| 存储被浏览器清除或驱逐（best-effort 存储） | 无 | — | `UNKNOWN_TRANSFER`，重新同意 |

发送方重选文件后先比较大小，再按第 7 节在发送时逐块核对摘要。Chromium 的 File System Access 句柄可以存入 IndexedDB，
但恢复读取权限仍需用户手势，Firefox/Safari 不支持，v1 不采用（待决问题 9）。

## 10. 存储、过期与清理

- 接收方记录：清单、哈希列表、`resumeToken`、本地时钟的 `expiresAt`、位图、`integrityFailures`、状态
  （`RECEIVING`/`INTERRUPTED`/`COMPLETE`/`FAILED`/`CANCELLED`）、是否已保存，以及仅供界面使用的来源名称。块存储以
  `[transferId, index]` 为键保存 Blob。**块与对应的位必须在同一个 IndexedDB 事务中写入**：位已置位就一定有块。
  基线后端是 IndexedDB，OPFS 是可选优化，且必须保持同等原子性（待决问题 4）。
- 发送方记录：清单、哈希列表、`resumeToken`、本地 `expiresAt = now + ttlSeconds`、目标名称，以及文件名、大小、
  `lastModified` 作为重选提示。不保存文件内容。
- 不比较两台设备的时钟：只传 `ttlSeconds`，各自按本地时钟计算到期时间。
- 清理时机：页面加载、`visibilitychange` 回到前台，以及每次新同意之前。删除已过期（`now ≥ expiresAt`）、`FAILED`、
  `CANCELLED`、`COMPLETE` 且已触发保存的记录，同时删除没有存活记录的孤儿块（向量 `cleanup`）。页面关闭期间不会运行
  定时器，过期数据要到下一次打开本站页面才删除，界面与 FAQ 必须如实说明。
- 已完成未保存的文件可以跨刷新保留到过期，供用户稍后保存。触发保存后不立即删除（浏览器可能仍在读取对象 URL），
  到下次页面加载或用户点击清除时再删。
- 显式放弃：任一端的“放弃/取消”立即删除本地状态。通道可用时发 `file-cancel`；通道外只有携带有效 `resumeToken` 的
  `file-cancel` 才能删除对端数据，防止旁观者删除他人的部分文件。
- 写入时遇到 `QuotaExceededError`：发 `transfer-error STORAGE_FULL`，记录转为 `INTERRUPTED`，用户可以释放空间后续传，
  也可以放弃。
- 默认不调用 `navigator.storage.persist()`（Firefox 会弹出提示）；存储可被浏览器驱逐，界面不承诺一定可恢复（待决问题 10）。
- 页面提供“清除互传本地数据”，一次删除所有记录和块。

## 11. 隐私

- 文件名、MIME、大小、内容、清单、哈希、位图、`transferId`、`resumeToken` 只在两个端点之间、只经 DTLS 加密的
  DataChannel 传递；不得放进发现信令、STWR2、URL、sessionStorage/localStorage 或任何服务端请求。服务端只看到既有的
  SDP/ICE 信令与 roster，TURN 只看到加密流量的体积和时序。
- 持久化后，文件名与部分内容会留在本机直到完成、放弃或过期；同源页面（同一站点的管理端）理论上可以读取。同意界面必须
  说明这一点。共用电脑建议使用内存模式。
- 服务端无新增接口、无新增日志字段、无新增指标。产品指标若将来统计续传成功率，只能在本机聚合后按 #38 的指标规则显式上报。

## 12. 兼容与发布

- 续传 offer 是在现有 `file-meta` 上加 `resume` 字段。旧版接收方忽略未知字段并回 `file-ready`：发送方据此识别旧页面，
  文件 ≤ 128 MiB 时可以按现有无头部流程发送（不可续传），更大的文件发 `file-cancel` 并提示对方刷新页面。
  过渡期结束后删除旧流程（待决问题 7）。
- 新版接收方收到不带 `resume` 的 `file-meta`，继续按现有流程处理。
- 不需要服务端或跨语言实现配合；四端服务端无需改动。

## 13. 跨浏览器与跨 NAT 验收清单

完成以下全部项目才可勾选 issue #38 的「分块续传」。每项都必须记录浏览器版本、路径（host/srflx/relay）、文件大小和结果；
使用模拟 API 的回归不能替代真实网络验收。

- [ ] 向量：前端实现直接读取 `chunked-resume-v1.json` 除 `constants` 外的九个部分，结果逐字段一致；`frames`、`bitmap`、`offerValidation`
      的拒绝用例必须断言拒绝。
- [ ] 浏览器组合（收发双向）：Chrome↔Chrome、Chrome↔Firefox、Chrome↔Safari(macOS)、Firefox↔Safari、
      Android Chrome↔iOS Safari、Edge↔Chrome；验证不同 `maxMessageSize` 下的帧大小。
- [ ] 路径：同局域网 host 候选；跨 NAT 经 STUN 直连；对称 NAT 或 `relay` 模式经 TURN（UDP），以及 TURN TCP/TLS
      （若部署）；direct 中断后改走 relay 并续传。
- [ ] 中断：传输到 30%/50%/99% 时断网再恢复；Wi-Fi 切换蜂窝；TURN 服务重启；只关闭 DataChannel；只关闭
      PeerConnection；手机切后台 1 分钟和 10 分钟后回到前台。
- [ ] 刷新：接收方刷新后续传；发送方刷新并重选同一文件后续传；双方都刷新；重选不同文件被 `SOURCE_CHANGED` 或
      `SOURCE_SIZE_MISMATCH` 拒绝，并且只能作为新传输重新同意。
- [ ] 续传后重复传输的字节数不超过 `unackedWindowChunks × chunkSize` 加一块；不得从零开始。
- [ ] 完整性：用测试钩子篡改一块，观察 `HASH_MISMATCH` 后重传成功；篡改已存块，观察终验 `STORAGE_CORRUPT`；
      累计失败上限导致失败并删除数据。最终 root 与发送方一致，保存的文件与源文件逐字节相同。
- [ ] 同意：自动接收下大于 128 MiB 的文件仍需点击；续传不重复弹窗；修改文件后必须重新同意；过期后续传被拒绝；
      VIEWER 发起的续传被拒绝。
- [ ] 存储：配额不足时拒绝或降为内存模式；写满时 `STORAGE_FULL` 并可在释放空间后续传；完成、放弃、过期后
      `navigator.storage.estimate().usage` 回到基线（容差 1 MiB）；无孤儿块。
- [ ] 隐私模式：Safari/Firefox/Chrome 无痕窗口下行为与第 6 节一致（不可用时为内存模式）。
- [ ] 内存：2 GiB 持久模式接收期间，页面 JS 堆增长不超过 `unackedWindowChunks × chunkSize` 的 2 倍；iOS Safari 不崩溃。
- [ ] 隐私：抓取服务端日志和浏览器网络面板，确认文件名、哈希、`transferId`、`resumeToken` 均未出现在任何
      HTTP/WebSocket 请求中。
- [ ] 界面：FAQ 与离开提醒改为如实描述续传边界（内存模式不可恢复、发送方需要重选文件、有效期 24 小时、
      过期数据下次打开时清理）。

## 14. 已定事项（采用推荐默认值）

以下各项在草案阶段列为待决，按维护者对同类问题的一贯做法，采用各条的推荐默认值。

| # | 问题 | 推荐默认 |
| --- | --- | --- |
| 1 | 持久模式单文件上限 | 2 GiB；iOS Safari 实测稳定后再评估 4 GiB（`chunkSize` 1 MiB 时 `maxChunkCount` 已允许） |
| 2 | 块大小 | 固定发送 1 MiB；协议允许 64 KiB..4 MiB，便于测试与将来调整 |
| 3 | 同意与部分数据有效期 | 24 小时绝对期限，续传不延长；过期后重新同意 |
| 4 | 存储后端 | IndexedDB（块存 Blob，块与位同一事务）；OPFS 推迟，除非实测 Safari 的 IndexedDB Blob 性能不足 |
| 5 | 整文件 SHA-256 | 不纳入 v1，完整性锚点为 `rootSha256`；`file-meta.sha256` 为 `null`，界面不显示整文件摘要 |
| 6 | 自动接收与持久化 | 自动接收只允许内存模式，写磁盘必须点击同意 |
| 7 | 旧页面兼容 | 保留一个发布周期：识别 `file-ready` 后对 ≤ 128 MiB 文件走旧流程，之后删除 |
| 8 | 云端附件续传 | v1 不做；另立规范，定义分片上传 REST、分片额度与清理，并在四端服务端实现 |
| 9 | File System Access 句柄免重选 | v1 不做；以后可作为 Chromium 的增强，恢复读取仍需用户手势 |
| 10 | `navigator.storage.persist()` | 不主动申请；在同意界面说明数据可能被浏览器清除 |
| 11 | 未确认窗口 | 8 块（8 MiB），与现有 4 MiB `bufferedAmount` 高水位共同生效 |
| 12 | 重试上限 | 单块单会话 3 次、单传输累计 16 次、会话内自动重连 5 次（1–16 s 退避，有进展即重置） |
| 13 | 部分数据配额 | 4 条记录、合计 4 GiB，另需 `estimate()` 剩余 ≥ 本文件 + 其它记录未收字节 + 64 MiB |
| 14 | 完成未保存文件的保留 | 保留到过期；触发保存后到下次页面加载或用户清除时删除 |
| 15 | 摘要计算位置 | 在 Worker 中调用 `crypto.subtle`，避免 2 GiB 文件的哈希阻塞页面 |

## 共享向量

`protocol/test-vectors/chunked-resume-v1.json`。文件内容不入库，由公式生成：第 i 字节为
`(i % 251) ^ (floor(i / 251) & 0xff)`，因此任意两块的摘要都不同。各部分：

| 部分 | 内容 |
| --- | --- |
| `constants` | 第 2 节常量 |
| `hashing` | 空文件、单整块、短尾块、Unicode 文件名、1 MiB+1 字节文件的块摘要、root、preimage 与 `manifestDigest` |
| `offerValidation` | offer 及期望的 `OK` 或错误码 |
| `frames` | STFR1 接受与拒绝样例；超长样例以头部加 `appendZeroBytes` 个零字节构造 |
| `bitmap` | 编码、严格解码、续传进度（`firstMissing`/`resumeOffset`/`receivedBytes`/`missing`）、位图合并 |
| `receiver` | 接收方状态机：逐事件的结果、应发消息、会话是否打开、状态，以及最终位图、失败数与状态 |
| `consent` | 同意判定 |
| `resume` | `resume-offer` 判定及 `resume-state` 内容 |
| `cleanup` | 页面加载时的记录与孤儿块清理 |
| `senderPlan` | 发送方依据位图和重选文件的发送计划 |

`receiver` 事件中的 `content: "corrupt"` 表示把该帧载荷（或该 HASHES 帧）首字节按位取反；`final-verify` 的
`corruptStored` 列出终验时读出损坏的已存块。`send` 中的消息省略 `transferId`。
