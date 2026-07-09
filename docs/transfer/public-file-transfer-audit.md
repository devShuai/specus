# 免登录文件互传审计与优化清单

本文记录 2026-07-09 对免登录文件互传功能的一次完整审计:发现的问题、影响、以及建议的修法。审计范围覆盖前端页面、发现/信令 WebSocket、附件预签名服务、对象存储签名与生产部署(CSP / nginx)配置。审计动因是回答"这套互传实现还有哪些可优化、有没有安全或功能隐患"。

涉及的主要文件:

* 前端:`apps/admin-web/src/pages/PublicTransferPage.tsx`(约 2450 行,含 WebRTC 收发、QR 生成、MIME 映射)
* 信令:`implementations/java/server/.../websocket/PublicTransferDiscoveryWebSocketHandler.java`
* 附件服务:`implementations/java/server/.../management/service/TransferAttachmentService.java`
* 附件接口:`implementations/java/server/.../management/controller/TransferAttachmentResource.java`
* 对象存储:`implementations/java/server/.../management/storage/object/AliyunOssObjectStorageService.java`
* 安全/部署:`implementations/java/server/.../config/SecurityConfig.java`、`deploy/openresty/shuai-tunnel.conf`

结论摘要:

* 整体链路设计合理:WebRTC 直连优先、OSS 预签名兜底、信令按 roomKey 分组隔离、附件 ID 随机不可枚举。
* 找到 **4 个 P0**(2 安全 + 2 功能)、**4 个 P1**、多个 P2,详见下表。其中 XFF 伪造与生产 CSP 缺 OSS 域名两项会直接影响可用性/隔离性。
* 截至本次审计,以下问题**均未修复**,本文作为待处理清单。

## 机制强项(审计前已具备,列出以免重复怀疑)

* 直连优先,失败自动退回 OSS 预签名分享链接;两条路径都带房间口令(roomToken)语义。
* 信令按 `roomKey` 分组:带 token 时 `token:sha256(token)`,不带时 `public:publicAddress`,跨房间互不可见。
* 附件 ID 由 `ClientIdGenerator` 随机生成(`ThreadLocalRandom`,范围 1 ~ JS 安全整数上限),**不可枚举**,缓解了遍历下载。
* OSS 附件权限校验:complete / presign-download 都比对 `roomTokenHash`(`requireMatchingRoomToken`)。
* 附件有过期与定时清理(`expireOldAttachments`,默认 72h 保留、每小时扫描),清理时同步删 OSS 对象。
* 前端 MIME 兜底完善(扩展名 → mimeType 映射表),预览覆盖图片/视频/音频/PDF/文本,并有失败回退。

## 优先级总览

| 级别 | 编号 | 问题 | 类型 |
|---|---|---|---|
| P0 | 1 | `X-Forwarded-For` 可伪造,绕过"附近设备"IP 分组隔离 | 安全 |
| P0 | 2 | 同房间成员可下载彼此 OSS 附件(需确认是否预期) | 安全 |
| P0 | 3 | 生产 CSP 未放行 OSS 域名,预签名兜底路径跑不通 | 功能 |
| P0 | 4 | WS 文本缓冲默认 8KB,大信令消息被截断 | 功能 |
| P1 | 5 | 上传预签名不绑定 Content-Length,`maxAttachmentBytes` 可被绕过 | 安全 |
| P1 | 6 | 公开 presign-upload 无限流/无配额 | 安全 |
| P1 | 7 | 直连 ACK 超时在发送前起算,大文件必然"假失败"重传 | 功能 |
| P1 | 8 | `iceConfig` 被信令 effect 闭包捕获为初始 null,被动接收方无 ICE 服务器 | 功能 |
| P2 | 9 | 收发全程内存缓冲,大文件在移动端 OOM | 性能 |
| P2 | 10 | 进度 setState 每 64KB 触发,大文件上万次 re-render | 性能 |
| P2 | 11 | blob URL 与 blob 只增不减,长会话内存持续增长 | 性能 |
| P2 | 12 | 发现 WS 无断线重连、无心跳 | 健壮性 |
| P2 | 13 | 过期清理固定 Top100,滥用时清理跟不上 | 健壮性 |
| P2 | 14 | 附件 ID 随机生成无唯一性重试,撞主键直接抛异常 | 健壮性 |
| P3 | 15 | 直连静默接收,房间内任何人可向对方推文件 | 安全 |
| P3 | 16 | `PublicTransferPage.tsx` 2450 行,QR/MIME/WebRTC 逻辑未拆分 | 结构 |
| P3 | 17 | 一次仅支持单文件,`directIncomingRef` 按 peerId 键控会覆盖并发传输 | 功能 |
| P3 | 18 | 后端已支持 sha256 字段,前端从不计算/传递,直连无完整性校验 | 功能 |

> **修复进展(2026-07-09)**:P0 全部处理(#1、#3、#4 已修复;#2 经产品确认为预期的"房间共享"语义,已补 UI 提示)。P1(#5、#6、#7、#8)已修复,服务端 42 项单测 + 前端 `tsc --noEmit` 全绿(其间顺带修复了与本功能无关、HEAD 上已无法编译的 `PeerMeshServiceTests`)。P2/P3 待排期。各条目末尾附「状态」。

## 问题与建议明细

### 1. `X-Forwarded-For` 可伪造,绕过 IP 分组隔离(P0 安全)

`PublicTransferDiscoveryHandshakeInterceptor.publicAddress()` 取 `X-Forwarded-For` 的**第一个**值作为 `publicAddress`(`PublicTransferDiscoveryWebSocketHandler.java` 的 `firstForwarded`),而 nginx 用的是 `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`(`deploy/openresty/shuai-tunnel.conf:101`)——**追加**语义。攻击者自带 `X-Forwarded-For: <受害者IP>`,经 nginx 变成 `<受害者IP>, <真实IP>`,后端取第一个即拿到伪造值。

不带 token 的房间 `roomKey = public:<publicAddress>`,后果:知道任意人的公网 IP 即可加入其 `nearby` 房间,看到成员列表、伪装名称、给对方静默推文件(见 #15)。

建议:优先信任 `X-Real-IP`(nginx 用 `$remote_addr` 覆写,客户端不可伪造);或从 XFF 取**最后一个**受信代理写入的值。同时移除对未经代理场景下裸 XFF 的信任。

状态:**已修复(2026-07-09)**。`publicAddress()` 改为优先采信 `X-Real-IP`,退而取 `X-Forwarded-For` 末位(`lastForwarded`),不再信任可被客户端伪造的 XFF 首段。

### 2. 同房间成员可下载彼此 OSS 附件(P0 安全,需确认)

`createPublicDownload` 只按 `id + scope` 查附件(`findByIdAndScope`,不含 roomId),再比对 `roomTokenHash`(`TransferAttachmentService.java` `createPublicDownload` / `requireMatchingRoomToken`)。即:只要持有房间 token,就能下载该房间内任意人上传的附件;`fileShareUrl` 甚至不要求 roomId 匹配。

信令侧 attachment 广播消息携带 `attachmentId`,同房间成员据此 + 已知 token 即可 presign-download。这可能是"房间即共享空间"的有意设计,也可能是疏漏。**需产品确认**:若非预期,应在附件上绑定 uploader peerId / roomId,下载时校验;若为预期,应在 UI 明示"同房间可见"。

状态:**已确认为预期行为(2026-07-09)**。产品定为"房间即共享空间",授权模型维持不变;已在前端补 UI 提示:`TransferFaq` 新增"谁能看到我发的文件？"条目并调整"更多说明"文案,分享链接完成卡片对非直连文件标注"同房间成员可下载"。若后续需要私密投递,再评估"收紧到点对点"方案。

### 3. 生产 CSP 未放行 OSS 域名,预签名兜底跑不通(P0 功能)

`SecurityConfig.java:91` 的 CSP `connect-src` 仅含 `'self' ws: wss:` 与 GA 域名,`img-src`/`media-src` 也只含 `'self' blob: data:`,**均无 OSS bucket 域名**;`deploy/openresty/shuai-tunnel.conf:75` 的 CSP 同样缺失。

一旦 `tunnel.object-storage.provider` 启用为 `aliyun-oss`:

* `putObject` 用 XHR PUT 到 `*.aliyuncs.com` → 被 `connect-src 'self'` 拦截;
* `saveUrlAs` 用 fetch GET 下载 → 同样被拦;
* `<img>/<video>` 预览指向 OSS URL → 被 `img-src`/`media-src` 拦截。

结论:直连失败后的 OSS 兜底路径在生产 CSP 下**根本无法工作**。建议将 bucket 域名(如 `https://<bucket>.<region>.aliyuncs.com`)加入 `connect-src`/`img-src`/`media-src`,SecurityConfig 与 nginx 两处同步;或改为经服务端中转下载(牺牲直连带宽换取 CSP 收敛)。当前 `provider` 默认 `disabled`,该问题在开启 OSS 前不暴露,但属上线阻断项。

状态:**已修复(2026-07-09)**。SecurityConfig 新增 `ossCspOrigin()`,`provider=aliyun-oss` 且 endpoint/bucket 已配置时,把精确的 bucket 来源注入 `connect-src`/`img-src`/`media-src`;`disabled`(默认)时后缀为空,CSP 与原先字节一致。生产 nginx(两处 server 块)对应三条指令补 `https://*.aliyuncs.com`(运维可按实际 bucket 收窄为精确域名)。

### 4. WS 文本缓冲默认 8KB,大信令消息被截断(P0 功能)

handler 声明 `MAX_MESSAGE_CHARS = 64 * 1024`,但未找到 `ServletServerContainerFactoryBean` 对 `maxTextMessageBufferSize` 的配置,Spring 默认仅 8192 字节。前端 offer SDP(含多条 ICE candidate,尤其带 TURN 时)常超过 8KB,底层会分片/截断,`JSON.parse` 失败 → 信令丢失 → 直连建连偶发失败。

建议:显式配置 WebSocket container 的 `maxTextMessageBufferSize`(与 handler 的 64KB 对齐),必要时同时调 `maxBinaryMessageBufferSize`。

状态:**已修复(2026-07-09)**。`WebSocketConfig` 新增 `ServletServerContainerFactoryBean` bean,将文本/二进制缓冲上限均设为 64KB,与 handler 的 `MAX_MESSAGE_CHARS` 对齐。

### 5. 上传预签名不绑定 Content-Length(P1 安全)

`AliyunOssObjectStorageService.presignUpload` 的签名串为 `PUT\n\n<contentType>\n<expires>\n<resource>`(`signature` 方法),**未包含 Content-Length / content-md5**。`maxAttachmentBytes`(默认 512MB)只在 presign 阶段校验请求声明的 `sizeBytes`,实际 PUT 可上传任意大小。complete 阶段(`complete` 方法)也只改状态,不回查 OSS 对象。

后果:大小上限形同虚设,可灌入远超声明的对象;还可 complete 一个从未上传的附件。建议:complete 时对 OSS 做一次 HEAD,校验对象存在且实际大小 ≤ 上限,超限则删对象并置失败;或在预签名策略中绑定长度约束(如改用 OSS PostObject policy)。

状态:**已修复(2026-07-09)**。`ObjectStorageService` 新增 `statObject()`(Aliyun 实现走 HEAD),`TransferAttachmentService.complete()` 增加 `verifyUploadedObject()`:对象不存在→拒绝(未真正上传),实际大小超 `maxAttachmentBytes`→删对象并拒绝,否则以 HEAD 返回的实际大小为准回写 `sizeBytes`。公开与管理端 complete 均生效。

### 6. 公开 presign-upload 无限流/无配额(P1 安全)

`TransferAttachmentResource` 的 `/api/public/transfer/attachments/presign-upload` 在 `SecurityConfig` 中 `permitAll`,无鉴权、无 per-IP / per-room 限流。任何人可无限刷预签名 URL 并(结合 #5)向 OSS 灌数据,产生真实存储与流量账单。发现信令 WS 同样无房间人数上限与消息频率限制,64KB 消息广播给全房间存在放大面。

建议:presign-upload 加 per-IP / per-room 限流 + 单房间 PENDING 附件数上限;WS 加房间人数上限与每连接消息速率限制。

状态:**部分修复(2026-07-09)**。新增 `PublicTransferRateLimiter`(按来源 IP 固定窗口限流,默认 30 次 / 300s)与 `PublicTransferProperties` 配置;控制器取来源 IP(与 #1 同口径:X-Real-IP 优先、XFF 末位)后校验,超限抛 `RateLimitedException` → HTTP 429。`createPublicUpload` 增加单房间 PENDING 附件上限(默认 50)。限流为进程内计数,多实例部署时按实例数放大(见类注释);**WS 房间人数 / 消息频率上限尚未做**,留待后续。

### 7. 直连 ACK 超时在发送前起算(P1 功能)

`sendDirect` 中 `waitForDirectAck(transferId, 8000)` 在 `sendFileChunks` **之前**创建,8s 定时器立即启动(`PublicTransferPage.tsx` `sendDirect`)。任何传输耗时超 8s 的文件(几十 MB 起),即使直连正常传输,ACK Promise 也会先超时拒绝 → `upload()` 捕获后转走 OSS → **同一文件传两遍**,且对方直连侧可能已收完。

建议:ACK 等待应在发出 `file-complete` 之后才起算,或超时随文件大小/已用时长动态延长。

状态:**已修复(2026-07-09)**。`sendDirect` 中 `waitForDirectAck` 移到 `sendFileChunks` 之后、`file-complete` 之前注册(先注册再发,避免对端回执抢跑),超时只覆盖"对端接收完成 → 回执"窗口,不再包含整段传输时间;超时值由 8s 提到 15s。

### 8. `iceConfig` 被信令 effect 闭包捕获为初始 null(P1 功能)

信令 effect(`PublicTransferPage.tsx` 约 182~227 行)依赖为 `[peerId, roomId, roomToken, sharedDiscoveryEnabled]`,不含 `iceConfig`。`socket.onmessage → handleSignal → createPeerConnection` 捕获的是 effect 运行时刻的 `iceConfig`(首次为 `null`)。之后 `fetchPublicTransferIceConfig` 返回并 setState,但 socket 不重建,故**被动接收 offer 的一端**始终以空 `iceServers` 建连接(`createPeerConnection` 里 `iceConfig?.iceServers ... ?? []`)。跨 NAT 场景无 STUN/TURN,直连只能靠 host candidate 在同局域网成功——可解释"公网直连常退回 OSS"。

建议:将 `iceConfig` 存入 ref 供 onmessage 读取最新值,或加入 effect 依赖使 socket 在配置就绪后重建。

状态:**已修复(2026-07-09)**。新增 `iceConfigRef`,配置拉取回调里同时写 ref 与 state,`createPeerConnection` 改从 `iceConfigRef.current` 读取,被动接收 offer 的一端也能拿到异步返回后的最新 ICE 配置。

### 9. 收发全程内存缓冲,大文件移动端 OOM(P2 性能)

直连接收把所有 chunk 存入 `chunks: ArrayBuffer[]` 再拼 Blob(`completeDirectIncoming`);OSS 下载 `saveUrlAs` 也是整段读入内存再触发保存。手机上传/接收 1GB+ 文件大概率 OOM 崩页面。建议:桌面端用 File System Access API 流式落盘;下载在无自定义 header 时直接 `<a download href={presignedUrl}>` 交给浏览器流式处理(当前为进度条牺牲了内存,可按文件大小分流)。

### 10. 进度 setState 无节流(P2 性能)

发送端 `sendFileChunks` 的 `onProgress` 与接收端 `updateReceivingTransfer` 每个 64KB chunk 触发一次 React 更新,1GB 文件约 1.6 万次 re-render。建议按时间(如 200ms)或百分比变化节流。

### 11. blob URL 与 blob 只增不减(P2 性能)

`directPreviewUrlsRef` 只 push 不 revoke;`incoming` 列表 `.slice(0, 20)` 淘汰旧项时,对应 `previewUrl` 与 `blob` 未释放。长会话传多个大文件,内存持续增长。建议:列表淘汰或组件卸载时 `URL.revokeObjectURL` 并丢弃 blob 引用。

### 12. 发现 WS 无断线重连、无心跳(P2 健壮性)

`socket.onclose` 仅清空 ref,不重连(`PublicTransferPage.tsx` 信令 effect)。手机锁屏断连后 peers 列表僵死,须刷新页面。建议:加指数退避重连 + 应用层心跳。服务端 `send` 里的 `synchronized(session)` 直发可换 Spring `ConcurrentWebSocketSessionDecorator`,避免慢客户端阻塞广播。

### 13. 过期清理固定 Top100(P2 健壮性)

`expireOldAttachments` 每次(默认每小时)最多清 `findTop100...` 100 条(`TransferAttachmentService.java`)。被滥用时清理速度跟不上堆积。建议改为循环取批直到取空(或提高频率 + 批量删)。

### 14. 附件 ID 随机生成无唯一性重试(P2 健壮性)

`ClientIdGenerator.newId` 用 `ThreadLocalRandom` 随机取值,`createUpload` 直接 `setId` 后 `save`。撞主键(概率约 1/9e15,极低)会直接抛异常而非重试。建议:save 捕获唯一约束冲突后重取 ID 重试有限次数。

### 15. 直连静默接收(P3 安全)

接收方收到 offer 即自动建连、自动收文件(`ondatachannel` / `handleDirectControlMessage` 的 `file-meta`),房间内任何人可向你的设备推任意文件并占用内存。建议:file-meta 到达时弹出接收确认,拒绝则回 reject 控制消息并关闭 channel。

### 16. 单文件超长,工具代码未拆分(P3 结构)

`PublicTransferPage.tsx` 已 2450 行,其中 QR 生成器(Reed-Solomon + 掩码,约 600 行)、MIME 映射(约 150 行)为纯工具代码,建议抽到 `lib/qr.ts`、`lib/mime.ts`;WebRTC 收发适合抽成 `useDirectTransfer` hook,降低单文件复杂度与回归风险。

### 17. 仅支持单文件,并发传输会互相覆盖(P3 功能)

当前一次只能选一个文件,且同一 peer 的 `directIncomingRef` 按 `peerId` 键控(`handleDirectControlMessage`),同一对端的第二个 `file-meta` 会覆盖进行中的接收状态。建议:支持多选并按 `transferId` 键控接收状态;顺带可加拖拽/粘贴上传。

### 18. sha256 后端支持而前端不用(P3 功能)

后端 `TransferAttachment` / presign 请求已含 `sha256` 字段并做格式校验,但前端从不计算或传递,直连路径也无完整性校验。建议:发送端用 `crypto.subtle.digest` 计算并随附件上报,接收端比对,防止静默损坏。

## 建议修复顺序

1. **先做 P0 中改动小、低风险的三项**:#1(XFF 取值改 `X-Real-IP` / 取 XFF 末位)、#3(CSP 加 OSS 域名,SecurityConfig + nginx 同步)、#4(配置 WS buffer size)。
2. **#2 附件下载权限**需产品先确认是否为"房间共享"设计,再决定加隔离还是加 UI 提示。
3. **P1 功能**:#7(ACK 计时后移)、#8(iceConfig 入 ref)直接提升直连成功率、消除重复上传。
4. **P1 安全**:#5(complete 做 HEAD 校验大小)、#6(presign 限流 + 配额)。
5. **P2 性能/健壮性**批量跟进:#9~#14。
6. **P3 结构与增强**放最后:#15~#18。
