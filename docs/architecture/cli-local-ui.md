# CLI 本地管理页面：首批 v1 契约

关联 [#41](https://github.com/devShuai/specus/issues/41)。Java / Go / .NET 均已接入首批 v1 契约；三端可用不代表整个 issue 的扩展范围已全部完成。

## 组件及归属

`ui` 命令先启动回环 HTTP 服务，不加载凭据进行登录。页面经一次性授权后，读取所选配置及现有 CLI 私有快照。显式连接才创建复用各自连接核心的运行时，状态仍由原 CLI 私有状态机制发布；没有 shell 命令代理或另一个登录协议。Java 复用 FirstLoginRetry / NettyClientLifecycle，不启动 Spring 宿主及更新器；.NET 复用 SpecusControlClient 和观察者，不启动普通 CLI 的 Host/更新服务。

管理进程与隧道的生命周期分离：断开隧道保留 HTTP 服务，关闭 HTTP 服务取消其拥有的运行时，关闭/刷新浏览器不影响运行时。写操作在实例内串行，停止尚未完成时不启动第二个运行时。管理进程用每配置独占锁阻止重复启动；非管理 `run` 进程不遵守此锁，只能按新鲜快照保守阻止新增连接，不声称绝对排他。

页面资源统一位于 `implementations/go/client/cmd/specus-client/web/`，Go 使用 `go:embed`，Java Maven 将同一目录打入 JAR 的 `local-ui/`，.NET 将同一目录作为 EmbeddedResource 链接。没有三份页面副本，也不需要前端构建器；构建 Java/.NET 发布包时需完整仓库包含该目录。

Java HTTP 适配器复用现有 Netty HTTP 编解码、聚合及超时处理；.NET 使用 BCL 回环 TcpListener，避免 HTTP.sys 的 Windows URL 预留/管理员要求，也不新增 ASP.NET Core 运行时。后者只处理有界 HTTP/1.1 请求，每连接一次请求并关闭，不支持分块请求、升级、代理或文件路径路由。错误响应在 Windows 会有界排空拒绝请求的剩余数据，避免关闭时 RST 吞掉浏览器应收到的错误。

## HTTP 契约

所有 JSON 返回 `schemaVersion: 1`。只接受精确路径、精确监听 Host；不接受查询参数、CORS 或 WebSocket。API 的未知路径返回 404，不注册任意磁盘目录。

| 方法/路径 | 请求/结果 | 副作用 |
| --- | --- | --- |
| GET `/`、`/app.js`、`/app.css` | 无业务数据的固定页面资源 | 无 |
| POST `/api/session` | `{code}` → `{token}` | 消费一次性连接码，签发仅内存会话 |
| GET `/api/config` | `{revision,exists,configPath,fields,hasApiKey,hasSecret,editableFields}` | 只读脱敏投影，不解析密钥返回前端 |
| GET `/api/status` | `{implementation,version,configPath,runtime,otherInstances,instanceWarning}` | 只读本进程运行时和既有私有状态文件 |
| POST `/api/config/validate` | `{revision,changes}` → `{saved:false,offline:true,warnings}` | 复用核心离线验证，可能读取显式密钥/TLS 引用；不写、不登录 |
| POST `/api/config/save` | `{revision,changes}` → `{saved:true,offline:true,warnings}` | 校验后无损修改所选文件；不重连 |
| POST `/api/connection` | `{action,revision}`，action 为 start/stop/restart | 只控制本管理进程拥有的运行时；restart 先校验再断开 |

`revision` 是原始文件字节 SHA-256；不存在用 `missing`。`changes` 只接受 serverBaseUrl/apiKey/secret/peerMeshDevice，值为字符串；省略表示保留，凭据空字符串也表示保留。请求不接受文件路径、环境变量写入或任意配置属性。新增凭据字段可写入 env:/file: 引用，验证只检查可解析性，不把实际值替换到配置。

应用返回类别：400 格式/超限/未知操作、401 未授权或过期、403 来源/Host 不符、404 路径不存在、405 方法不符、409 配置冲突/实例或运行时控制冲突、415 非 JSON 写请求、422 配置或文件校验失败、429 页面会话上限。传输层可在进入 JSON API 前以 413 拒绝过大请求（Java），或关闭超时/超额连接；前端也必须处理非 JSON/连接失败。错误不包含 HTTP 登录响应体、原始 JSON 解析片段或凭据值。

`runtime.processRunning` 表示本页拥有的连接循环，不是 HTTP 管理进程是否活着；`businessReady` 只表示控制/数据通道就绪，不是目标可达。`runningRevision` 与磁盘 revision 用于提示待应用修改。其他进程仅给出 PID/phase/readiness 与 `readOnly:true`；没有控制通道时不提供接管按钮。

## 安全约束和已知边界

- 只绑定 IPv4 回环 127.0.0.1；当前不提供 IPv6 监听或远程监听开关。Host 必须精确等于实际地址与端口，Origin 如有必须同源，写请求必须带同源 Origin 和 `X-Specus-UI: 1`，且为 JSON。
- 引导码/会话令牌为 256 位系统随机数。引导码有效 5 分钟、一次性，自动打开时由 fragment 传递并立即移除，HTTP 路径不含凭据。令牌只在 JS 内存，凭 Authorization Bearer 使用，绝不写浏览器持久存储或 cookie。会话最长 8 小时、上限 8；刷新或新标签需回终端按回车获取新的引导码。没有终端输入或会话已满时需重新启动管理进程，此限制应明确提示，不绕过授权。
- 页面有 no-store、nosniff、no-referrer、禁止嵌套和仅自身静态资源的 CSP；动态内容只用 textContent，不拼接 HTML。请求体限 64 KiB、配置限 1 MiB、状态文件数限 256、并发 HTTP 请求限 16，HTTP 读取/响应和浏览器请求均有超时。
- 配置路径启动时指定且不可经 HTTP 更换；拒绝路径链上的符号链接/重解析点。写入在同卷私有暂存目录中，验证并再次核对 revision 后替换。Unix 文件权限 0600；Windows 暂存目录 ACL 仅当前用户，文件继承后随重命名保留。外部程序在最终比较和替换之间恶意竞争、同用户恶意进程、OS 管理员及浏览器扩展不在本边界内；这不是操作系统沙箱或跨用户强隔离。
- JSONC 使用顶层值区间替换，保留其他原文；Java 使用 Jackson token 字符区间，.NET 使用 Utf8JsonReader 字节区间，Go 使用注释感知扫描器，最终均复用核心校验。拒绝重复字段及可编辑字段的非规范大小写，避免大小写兼容解析造成凭据歧义。复杂/错误配置可在外部修复，不向前端返回原始带密钥的全文。
- 其他实例发现依赖已有状态刷新和 PID 存活检查，未建立跨语言控制 IPC；不能停止或接管旧实例。管理锁崩溃遗留需要确认 PID 已退出后手工清理。

## 验证与后续

Go `ui_test.go` 覆盖鉴权/重放/到期、恶意 Host/Origin、无效方法/内容类型、查询/路径拒绝、JSONC 原文保留/凭据脱敏/版本冲突、真实 HTTP 拒绝、运行时取消/重复启动、只读配置和请求上限。`scripts/test-cli-ui.py` 复用既有 CLI 测试控制协议，连接的是本机 HTTP/TCP fixture，而非假定模拟快照就代表可连接。

Python Playwright 测试真实嵌入资源，桌面与 360px 页面，首次配置/离线校验/保存、控制认证和数据通道、只读其他实例、刷新授权与关闭浏览器后连接保留；出站浏览器请求仅允许当前回环服务。Linux 真实进程另验证 SIGINT 与锁清理。未模拟公网服务可用性或提升指标。

新增 Java / .NET `UiConfigTests` 检查无损编辑、凭据脱敏、私有权限、版本冲突和畸形/歧义配置；共享进程矩阵还覆盖 Host/Origin/自定义头拒绝、非 JSON、错误方法、超限请求、HTTP 拒绝后管理仍在线、取消在途登录及跨语言管理锁。完整执行记录见 [CLI 使用说明](../cli-usage.md)。`.github/workflows/cli-ui.yml` 将三端 Windows/Ubuntu 进程矩阵纳入后续 CI。

后续按 #41 推进：控制能力协商/接管设计、终端关闭后的会话重新获取体验、主动诊断与安全日志、更多配置字段及差异展示、SSH/IPv6/macOS/读屏与 Windows 控制台交互验收。仅在完整矩阵通过后关闭 issue。
