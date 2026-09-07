# CLI 使用与验收矩阵

本页是 #39 的 Java / Go / .NET CLI 命令与验收契约。查询命令只读取本机现有 CLI 的私有状态，不隐式启动第二个客户端；桌面端和 Android 的图形交互属于 #40。

## 命令入口

Go / .NET 使用 `specus-client` 可执行文件；Java 使用 `java -jar specus-client-exec.jar`。下列参数加到对应入口之后。

| 操作 | 三端共同语法 | 行为 |
| --- | --- | --- |
| 帮助 | `--help` / `-h` | 不读取配置，不联网，退出 0 |
| 版本 | `--version` | 不读取配置，不联网，退出 0 |
| 运行 | `[run] --config PATH` | `run` 可省略；默认当前工作目录的 `client.jsonc` |
| 指定配置 | `--config PATH` / `--config=PATH` / `-c PATH` | 支持绝对路径和带空格的路径；相对路径相对启动工作目录 |
| 离线预检 | `config validate --config PATH` | 检查现有配置校验规则及密钥引用；不会登录、检查更新或启动隧道 |
| 生效配置 | `config show --config PATH` | 显示本实现应用默认值/修正值和更新覆盖参数后的配置；凭据始终脱敏 |
| 运行状态 | `status --config PATH` | 列出同一配置的本实现所有活跃 CLI 实例和连接阶段；不读取配置内容 |
| 在线设备 | `peers --config PATH` | 已连接控制通道收到的 Peer 名称、虚拟 IP 和在线状态；不扫描网络 |
| 访问地址 | `services --config PATH` | 已收到的远端 Peer 服务目录、访问地址与可用标记；不枚举尚未发布的后台配置 |
| 离线排错 | `doctor --config PATH` | 检查配置与密钥引用，不联网 |
| 主动排错 | `doctor --probe --config PATH` | 最多 5 秒的服务端 DNS/TCP 探测；不发送登录、不校验 TLS、不探测转发目标 |
| 机器输出 | 上述单次命令加 `--json` | stdout 只有一个版本化 JSON 文档，日志/警告仍写 stderr；帮助/版本也支持 |
| 禁用更新检查 | `--no-update-check` / `--no-update` | 本次运行禁用检查；优先于自动安装开关 |

例如：

```sh
specus-client --help
specus-client config validate --config "/etc/specus/client.jsonc"
specus-client config show --config "/etc/specus/client.jsonc" --json
specus-client status --config "/etc/specus/client.jsonc" --json
specus-client services --config "/etc/specus/client.jsonc"
specus-client doctor --probe --config "/etc/specus/client.jsonc"
specus-client --config "/etc/specus/client.jsonc"
java -jar specus-client-exec.jar --config "/etc/specus/client.jsonc"
```

选项放在命令后面。文件名以 `-` 开头时使用 `./` 前缀。未知选项、未知子命令、缺失参数值都会在读取配置或联网前失败；不要依赖原先静默忽略参数或将任意参数传给 Spring/.NET Host 的行为。`--probe` 仅可用于 doctor；持续运行的 `run` 不接受 `--json`，请另开终端执行 `status --json`。宿主日志等高级设置仍可通过框架配置文件或环境变量设置。

预检成功只代表配置通过本地校验，不代表 DNS、服务端认证、网卡或转发目标可用。预检会读取 `env:` / `file:` 引用以检查是否可解析，但不会将解析得到的凭据打印到终端。

三端在预检和正常启动时都会将配置警告写到 stderr（不影响成功退出码）：

- 未知字段继续兼容性忽略，但提示字段名称；包括 `controlTls` 等当前实现支持的嵌套对象。
- 明确配置的 `peerMeshMtu` 或 `updateCheckIntervalHours` 被修正时，提示最终数值。默认 MTU 1280、范围 576–1280；默认更新间隔 24 小时、范围 1–168 小时。
- Go 不使用 `openUpdatePage`；.NET 不使用 `upstreamTls` / `openUpdatePage`，出现时提示跨端差异。Java 接受 `autoUpdate: true`，但明确提示仅通知、不自动安装。
- 警告不打印配置值或解析后的密钥。`config show` 将 apiKey、secret（包括引用文本）整体替换为 `<redacted>`，删除 serverBaseUrl 的用户名、密码、查询串和片段；不修改源配置。`controlTls.enabled: null` 表示登录后再按服务端 TLS 标记解析，不代表已确认禁用 TLS。

## 首次 HTTP 登录与重连

三端共同支持 `--login-timeout SEC`（也支持 `--login-timeout=SEC`），指定首次 HTTP 认证预算，默认 60 秒，允许 1–3600 秒。

网络错误、HTTP 408/425/429 和 5xx 在预算内按 1、2、4、5 秒退避，后续间隔最多 5 秒；有效 `Retry-After` 可以延长间隔，但不会延长总预算。每次重试重新解析密钥引用并生成签名。TLS 验证错误、其他 HTTP 拒绝或不合法的登录响应直接失败；400/401/403/409 提示检查凭据、时钟、权限和网关规则，不将所有拒绝归因为密码错误。登录不跟随 HTTP 重定向。

预算覆盖 HTTP 请求、响应体读取和重试等待，不代表控制通道或业务已就绪，也不包含进程、状态目录和框架初始化时间。每次 HTTP 请求最多 20 秒且受剩余预算约束；超时取消请求，避免响应体卡住而永久等待。预算耗尽退出 4。首次 HTTP 认证成功后，控制通道临时断线继续采用既有指数退避；恢复时使用相同的 HTTP 错误分类，明确拒绝停止重连。健康通道的预防性令牌刷新失败不会立即中断正在使用的通道，后续重连仍按拒绝规则处理。HTTP 错误和 JSON 解析错误不输出原始响应体。.NET CLI 与桌面端复用 ClientAuthService，不另写一套认证分类。

## 退出与更新

- `0`：单次命令成功、Go/.NET 正常用户取消、Java 正常关闭上下文。Java 的 Unix SIGINT / Ctrl+C 按 JVM 约定可返回 `130`，不是认证或运行故障。
- `1`：其他运行时失败，如无效登录响应或 TLS 失败。
- `2`：参数或本地配置错误。
- `3`：HTTP 认证/策略拒绝或不可恢复的控制登录拒绝。
- `4`：首次 HTTP 登录预算耗尽，或 doctor TCP 探测失败/超时。
- `5`：对应配置没有新鲜且 PID 仍存活的 CLI 状态；不表示已测试远程服务器。

Java/.NET 遇到明确的控制登录终止拒绝会停止宿主，而不是只保留一个不再连接的进程。.NET 的这一退出策略仅应用于 CLI，不会强制退出 Windows 桌面窗口。

Go 的首次更新检查与隧道并行，Go/.NET 自动检查发现更新时只提示，不读取 stdin。显式 `--auto-update` 或配置 `autoUpdate: true` 仍授权自动安装并重启；禁用更新检查优先。Java 目前只通知更新，不支持该安装开关。

命令结果输出到 stdout，普通运行诊断输出到 stderr。默认查询为按实例分组的简短摘要；`--json` 为机器消费。.NET/Java 的 `--debug` 增加详细日志，Go 增加来源行号与细粒度时间戳。

所有单次 JSON 命令返回 `{ "schemaVersion": 1, "command": "...", "ok": true, "exitCode": 0, "data": {}, "error": null }`。失败时 `ok=false`、退出码非零、error 为可显示的诊断；参数解析失败的 command 为 `arguments`。脚本应依据 `exitCode`/进程退出码，不解析日志语言或文本。

## 本地状态接口与安全边界

默认目录为当前用户目录下的 `.specus-cli`；可通过 `SPECUS_CLI_STATE_DIR` 指定本地目录（父目录需已存在）。状态按实现、规范化绝对配置路径的 SHA-256 和 PID 分开存储，支持同一配置多实例；查询不要求源配置存在。Windows 路径比较不区分大小写；Unix 路径按大小写精确匹配。符号链接配置别名不保证等价，查询时使用启动命令的 `--config` 路径。

目录及文件必须为当前用户私有：Unix 目录 0700、文件 0600；Windows 限制 ACL 为当前用户。读取拒绝符号链接/reparse point 和宽权限路径；权限检查失败不会退回公共 HTTP 监听。Go Windows 用系统 PowerShell 的 .NET ACL API，不依赖用户 profile 或安全模块自动加载。状态写入临时文件后原子替换；不包含凭据、令牌、密钥、候选连接凭据或消息正文。

每秒发布一次，超过 5 秒、PID 已退出、路径/格式版本不匹配的记录不作为在线状态。正常退出删除自己的状态文件；崩溃遗留文件被忽略。单文件限制 1 MiB，同一配置最多检查 256 个文件；长期大量崩溃造成超限时，可停止实例后清理该配置的遗留状态文件。

`status.data.instances` 区分 `processRunning`、`phase`、`controlAuthenticated`、`businessReady`。这里 businessReady **仅表示控制/专用数据通道就绪，可以受理转发**，不是远端目标服务可达证明；`businessReadinessScope` 明确标明未探测目标。peers/services 返回 `catalogAvailable`，控制通道断开时不再把缓存列表作为当前在线目录输出。services 的 available 表示目录允许访问，不代表已经执行 HTTP/业务健康检查。

## 回归验收

新增 Go/.NET/Java 进程入口测试：在独立临时工作目录执行帮助、版本、非法参数、缺失配置、带空格的配置路径与离线预检；检查退出码、输出通道及不输出测试密钥。另测 .NET Host 终止/用户取消、Java 终止通知去重和上下文正常关闭。

测试入口：

```sh
# implementations/go/client 下
go test ./cmd/specus-client ./internal/client
# 仓库根目录下
dotnet test implementations/csharp/client/tests/Specus.Client.Tests/Specus.Client.Tests.csproj
mvn -pl implementations/java/client -am test
# 同一矩阵分别传入 Windows / Linux 构建产物；只连接本机 fixture 服务端
python scripts/test-cli-matrix.py --name go -- /absolute/path/specus-client
python scripts/test-cli-matrix.py --name dotnet -- dotnet /absolute/path/specus-client.dll
python scripts/test-cli-matrix.py --name java -- java -jar /absolute/path/specus-client-exec.jar
```

验收环境：Windows 本机和 Ubuntu 24.04 WSL2（真正的 Linux Go/.NET 产物、Linux Temurin 21 JRE，不通过 Windows 可执行文件代替 Unix 验收）。2026-09-07 末轮真实进程矩阵结果如下，全部通过：

| 实现 | Windows | Ubuntu 24.04 |
| --- | ---: | ---: |
| Go | 32 项 | 33 项 |
| .NET | 32 项 | 33 项 |
| Java | 32 项 | 33 项 |
| 合计 | 96 项 | 99 项 |

共 195 项进程检查通过。完整回归中，Go `go test ./...` 的 3 个包全部通过；.NET 322 项通过、无失败或跳过；Java client/common 共 176 项，175 项通过、1 项跳过、无失败或错误。`git diff --check` 通过。实现与测试结果已同步到 #39；本记录不表示代码已提交、推送或发布。

另有配置警告的三端进程测试（成功结果仍写 stdout、警告写 stderr、密钥不泄露），以及 Java 登录退避/预算/中断/Retry-After 单元测试和本地 HTTP 503 恢复、拒绝/畸形响应脱敏、响应体卡住时超时的测试。

进程矩阵覆盖帮助/版本/参数错误、空格配置路径、脱敏 show、离线/主动 doctor、JSON 通道、慢更新与关闭 stdin、HTTP 401/403/503/DNS/超时/恢复、控制拒绝退出、查询不增登录、两实例、过期/已退出状态。扩展矩阵还覆盖控制认证与数据通道就绪的中间阶段、人类摘要、Windows 路径大小写和宽 ACL 拒绝，以及 Unix 宽权限/符号链接拒绝、SIGINT 和真实 PTY Ctrl+C。Go/.NET 可用更新仅通知、不读 stdin 的场景另有更新器单元测试。

不把真实公网 NAT、所有 Linux 发行版、Windows Service/systemd 安装或业务目标健康检查混入本 issue 的 CLI 验收结论；服务管理器可按上述退出码决定是否重启，不需要解析日志。一次并行完整回归发现 Java/.NET 测试争用示例端口 18080，.NET 对应活桥接用例已改用临时端口，仍校验共享协议向量的其余字段。
