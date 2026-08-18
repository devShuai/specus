<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
  <img alt="specus 引水渠" src="docs/assets/logo-light.svg" width="280">
</picture>

# specus

引水渠 —— 内网服务接入、网络打洞与流量观测。

`specus` 是项目的统一名称。项目以内网服务接入和私有组网为核心，Java 版本是当前基准实现；Go、C# 与 Android 按统一 v2 协议持续对齐，源码自动化与真实环境验收范围见下文，C server 冻结为明确列出的兼容子集。它在公网服务端和内网客户端之间维护控制连接，并在收到映射配置后，将公网 TCP/HTTP 流量转发到客户端可访问的本地服务；Peer Mesh 让同一用户下的多个客户端通过虚拟 IP 互访，数据面优先走 UDP direct，失败时回退到服务端标准 TURN relay。

> 当前 README 按 Java 基准实现维护；其它语言实现的覆盖范围见[当前状态](#当前状态)。

## 工作原理

```mermaid
flowchart TD
    U[公网访问者] -->|访问公网映射端口| P[TcpServer]
    P --> R[RemoteSpecusHandler]
    R <-->|通过 7010 控制连接传输数据| N[NatServerHandler]
    N <-->|Netty 自定义协议| C[NatClientHandler]
    C --> L[LocalSpecusHandler]
    L -->|访问内网地址和端口| S[本地 TCP 服务]
    H[HTTP 访问者] -->|访问 /http/client/route/path| W[HttpSpecusController]
    W <-->|通过 7010 控制连接直转 HTTP| C
    PM[PeerSignalService + 标准 STUN/TURN]
    A[客户端 A specus0] <-->|Peer Mesh UDP direct / relay| B[客户端 B specus0]
    A -.->|PEER_CONTROL / UDP probe| PM
    B -.->|PEER_CONTROL / UDP probe| PM
```

核心流程：

1. `specus-server` 启动 Spring Boot 应用，并在 `7010` 端口监听客户端控制连接。
2. `specus-client` 读取工作目录下的 `client.jsonc`（JSONC），先通过 HTTP `apiKey/secret` 登录，获取运行时 `clientName`、`accessToken`、控制连接地址和初始配置。
3. 客户端建立 Netty 控制连接并发送 `LOGIN_REQUEST`，服务端校验 token 后绑定在线会话。
4. 服务端向客户端发送 `NAT_CONTROL` 消息后，客户端动态添加 `NatClientHandler` 并注册端口映射。
5. 服务端为每个公网映射端口创建一个 `TcpServer`。
6. 公网请求到达映射端口后，数据经控制连接转发至客户端，再由客户端连接目标内网服务。
7. 开启 Peer Mesh 时，服务端通过 `PEER_CONTROL` 做设备列表、候选地址和 session 授权，客户端之间的数据面走加密 UDP direct，失败时回退到标准 TURN relay。

## 模块结构

| 模块 | 说明 |
| --- | --- |
| `implementations/java/common` | Java 公共协议、编解码器、登录鉴权、心跳、会话、消息和同步 HTTP 请求能力，Maven artifact 为 `specus-common` |
| `implementations/java/server` | 公网服务端（Java 参考实现），监听控制连接，并为已注册映射创建公网 TCP 监听端口，Maven artifact 为 `specus-server` |
| `implementations/java/client` | Java 内网客户端，连接服务端，并将隧道数据转发至目标内网服务，Maven artifact 为 `specus-client` |
| `implementations/java/stun-server` | Java 独立 RFC 5780 STUN 服务，支持四端点、限流、指标、`CHANGE-REQUEST`、`RESPONSE-PORT` 和 `PADDING` |
| `apps/admin-web` | 管理后台前端(React + HeroUI)，构建产物供各服务端静态托管 |
| `deploy/java-server` | Java server 的 systemd 安装、更新脚本和环境变量模板 |
| `deploy/stun-server` | 独立 STUN server 的 systemd 安装、更新脚本和四端点配置模板 |
| `deploy/go-server` | Go server 的 Linux 交叉编译、SSH 远端部署、systemd 安装与回滚更新脚本 |
| `deploy/remote` | 从 macOS/Linux 或 Windows 将当前 Java server 与 OpenResty 前端一键构建、上传、更新并验收 |
| `deploy/migrations/specus-v1` | 从旧命名迁移到 Specus 的环境变量、systemd 路径和 SQLite/PostgreSQL/MySQL 数据库迁移工具 |
| `protocol/spec` | 跨语言协议说明、数据面/控制面规范入口 |
| `implementations/go/server` | Go 服务端移植；同时提供独立 `cmd/specus-stun-server` 单文件 STUN 二进制 |
| `implementations/go/client` | Go 内网客户端，与 Java 客户端使用相同配置和紧凑二进制协议 |
| `implementations/csharp/protocol` | .NET 协议库，server/client 共同 ProjectReference 复用 |
| `implementations/csharp/server` | .NET 服务端移植(EF Core,多库)；包含独立 `Specus.StunServer` 项目 |
| `implementations/csharp/client` | .NET 内网客户端（CLI + Windows WPF 桌面客户端），与 Java/Go 客户端使用同一套 v2 线协议 |
| `implementations/android/client` | Android 图形客户端，提供运行控制台、JSONC 配置、前台服务、TCP/HTTP 隧道、VpnService 和 Peer Mesh 基础数据面 |
| `implementations/c/server` | C 服务端轻量移植 |

主要入口：

- 服务端(Java)：`implementations/java/server/src/main/java/com/theshuai/specusserver/SpecusServerApplication.java`
- 独立 STUN(Java)：`implementations/java/stun-server/src/main/java/com/theshuai/stunserver/StunServerApplication.java`
- 独立 STUN(Go)：`implementations/go/server/cmd/specus-stun-server/main.go`
- 独立 STUN(.NET)：`implementations/csharp/server/src/Specus.StunServer/Program.cs`
- 服务端(Go)：`implementations/go/server/cmd/specus-server/main.go`
- 客户端(Java)：`implementations/java/client/src/main/java/com/theshuai/specusclient/SpecusClientApplication.java`
- 客户端(Go)：`implementations/go/client/cmd/specus-client/main.go`
- 客户端(.NET CLI)：`implementations/csharp/client/src/Specus.Client/Program.cs`
- 客户端(.NET 桌面)：`implementations/csharp/client/src/Specus.Client.Desktop/MainWindow.xaml`
- 客户端(Android)：`implementations/android/client/app/src/main/java/com/theshuai/specus/android/MainActivity.java`
- 管理后台前端：`apps/admin-web/`(`npm run dev` / `npm run deploy:java|go|csharp`)
- 协议实现：`implementations/java/common/src/main/java/com/theshuai/common/protocol/PacketCodec.java`

## 环境要求

- JDK 21
- Maven 3.x
- Node.js / npm（构建服务端管理后台静态资源时需要）
- Go 1.26（仅构建 Go 实现时需要）
- .NET 10 SDK（仅构建 .NET 实现时需要；Windows 桌面客户端目标框架为 `net10.0-windows`）

根目录 `pom.xml` 将 Java 编译版本设置为 `21`。仓库中的 Maven Wrapper 脚本没有可执行权限，且未提交 `.mvn` 目录，因此建议使用本机安装的 Maven。

## 构建

在项目根目录执行：

```bash
mvn clean install
```

只构建独立 STUN server：

```bash
mvn -pl :stun-server -am clean package
# implementations/java/stun-server/target/stun-server.jar
```

Go 与 .NET 独立 STUN：

```bash
cd implementations/go/server
go build ./cmd/specus-stun-server

dotnet build \
  implementations/csharp/server/src/Specus.StunServer/Specus.StunServer.csproj
```

`specus-server` 的 Maven 构建会在 `generate-resources` 阶段执行 `apps/admin-web` 的 `npm run deploy:java`：先构建 React 管理后台，再把 `dist/` 只同步到 Java server 的 `src/main/resources/static/`。首次构建前请在 `apps/admin-web` 下执行一次 `npm ci` 安装依赖。
`apps/admin-web/dist/` 和各 server 的静态同步目录都是构建产物,已在 `.gitignore` 中忽略,不要提交到仓库。

如只想构建后端、跳过前端打包与产物同步：

```bash
mvn clean install "-Dspecus.server.web.skip=true"
```

Go / C# server 构建各自处理自己的前端产物：C# 项目构建时执行 `npm run deploy:csharp`；Go server 使用 `go generate ./web` 执行 `npm run deploy:go` 后再 `go build`，这样不会改动其它 server 的静态目录。

.NET 实现统一使用 `net10.0`；CLI 客户端、服务端和 Windows 桌面客户端可在对应 `implementations/csharp/*` 目录下用 `dotnet build` / `dotnet run` 构建运行。

## 启动

### 1. 启动服务端

```bash
cd implementations/java/server
mvn org.springframework.boot:spring-boot-maven-plugin:run
```

服务端会监听两个端口：

| 端口 | 用途 |
| --- | --- |
| `7010` | Netty 控制连接端口，默认值定义在 `application.yml` 中，可通过 `SPECUS_NETTY_PORT` 覆盖 |
| `8088` | Spring Boot Web 和管理后台端口，定义在 `application.yml` 中 |

启动后访问 [http://127.0.0.1:8088](http://127.0.0.1:8088) 可进入管理后台。管理后台支持用户名/密码与 OIDC 登录，管理 API 校验 Bearer JWT，详见[管理后台登录](#管理后台登录)。

服务端默认使用当前工作目录下的 SQLite 数据库 `specus.db`。业务持久化层使用 Spring Data JPA 和 Hibernate；初始化阶段会用少量 `JdbcTemplate` 做旧库字段回填。首次启动时 Hibernate 会自动维护表结构，并创建演示客户端 `Demo client` 与启动凭证 `apiKey=demo-client / secret=test1234`（可通过 `SPECUS_DB_SEED_DEMO_CLIENT=false` 关闭种子数据）。管理后台提供幂等的初始化按钮，用于补齐种子数据，不会清空已有数据。

如需在端口映射日志中显示服务端公网地址，可设置 `SPECUS_PUBLIC_ADDRESS`。未设置时客户端会回退显示控制连接配置中的 `remoteAddress`。

### 日志

默认日志只输出到控制台（本地开发与测试场景）。Linux systemd 部署由 unit 文件设置 `SPECUS_LOG_FILE=/var/log/specus-server/specus-server.log`，应用同时写入滚动文件并保留 journald；安装与目录权限细节见 [`deploy/java-server/systemd`](deploy/java-server/systemd/README.md)。

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `SPECUS_LOG_FILE` | （空） | 日志文件路径；留空时仅输出到控制台 |
| `SPECUS_LOG_MAX_FILE_SIZE` | `50MB` | 单个日志文件大小上限，超过后滚动并 gzip 压缩 |
| `SPECUS_LOG_MAX_HISTORY` | `30` | 保留的滚动历史周期数 |
| `SPECUS_LOG_TOTAL_SIZE_CAP` | `2GB` | 日志目录总量上限，超过后删除最旧归档 |
| `SPECUS_LOG_CLEAN_HISTORY_ON_START` | `true` | 启动时清理过期归档 |

### 多租户

Java `specus-server` 的管理面已经按租户隔离。客户端账号、TCP 映射、HTTP 路由、连接记录、连接归档和流量统计都会绑定 `tenant_id`；本地密码登录签发的 JWT 会写入 `tenant_id` claim，默认来自 `SPECUS_AUTH_TENANT_ID=default`。OIDC 授权码登录按不可变的 `issuer + subject` 绑定本地管理用户，新建用户落在本地默认租户；直接 OIDC Bearer 也必须命中已绑定且启用的本地用户。每次请求和刷新都重新读取当前本地账号的租户、角色与启用状态，不把外部 token 或旧本地 token 中的 tenant/role 当作最终权限。Go server 与 .NET server 已同步管理用户表、`/api/admin/me`、`/api/admin/users`、本地 JWT 的 `tenant_id` / `role` claims，以及客户端、凭证、映射、连接、流量列表的 owner 可见性过滤。

旧库升级时，启动初始化会把历史数据的空 `tenant_id` 回填为默认租户。需要注意的是，公网 TCP `listen_port` 仍是整台 server 的全局资源，不能被不同租户重复绑定。

### 2. 配置并启动客户端

客户端从当前工作目录读取 `client.jsonc`。该文件使用 JSONC 语法，支持 `//` / `/* */` 注释和尾逗号。在 `implementations/java/client` 目录中创建或修改该文件：

```jsonc
{
  "$schema": "https://specus.devshuai.com/schemas/client-startup-config.schema.json",
  // 服务端管理 HTTP 地址
  "serverBaseUrl": "http://127.0.0.1:8088",
  "apiKey": "demo-client",
  "secret": "test1234",
  "peerMeshDevice": "noop",
  "peerMeshTunName": "specus0",
  "peerMeshMtu": 1280
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `serverBaseUrl` | 服务端管理 HTTP 地址，客户端会调用 `/api/client/auth/login` 获取运行时连接信息 |
| `apiKey` | 管理后台创建的客户端启动凭证 key |
| `secret` | 管理后台创建凭证时显示一次的密钥，用于签名启动登录请求 |
| `peerMeshDevice` | Peer Mesh 虚拟网卡模式，默认 `noop`；可选 `linux-tun`、`windows-wintun`、`wintun`、`mac-utun`、`macos-utun`、`darwin-utun`、`utun`、`auto` |
| `peerMeshTunName` | Peer Mesh 虚拟网卡名称，默认 `specus0` |
| `peerMeshMtu` | Peer Mesh 虚拟网卡 MTU，默认 `1280`；大于 `1280` 会被客户端归一化，避免 UDP 封装后公网路径分片丢包 |

> 完整示例见 `implementations/java/client/client.example.jsonc`、`implementations/go/client/client.example.jsonc`、`implementations/csharp/client/src/Specus.Client/client.example.jsonc` 和 `implementations/android/client/client.example.jsonc`。

macOS 推荐通过 Homebrew 安装 Go 客户端；同一条命令会自动选择 Apple Silicon 或 Intel 版本：

```bash
brew install --cask devshuai/specus/specus-client
specus-client -config /path/to/client.jsonc
```

后续升级无需重新下载压缩包：

```bash
brew update
brew upgrade --cask specus-client
```

Homebrew Cask 源码位于 [`devShuai/homebrew-specus`](https://github.com/devShuai/homebrew-specus)。网站的 macOS Release 压缩包仍可用于手动安装。
公开的 [Specus Client 下载页](https://specus.devshuai.com/download) 会按访问设备优先推荐 macOS Homebrew、Windows 桌面版或对应架构的 Go 客户端，并可展开查看全部平台与实现。

从源码启动 Java 客户端：

```bash
cd implementations/java/client
mvn org.springframework.boot:spring-boot-maven-plugin:run
```

Java 客户端使用 `WebApplicationType.NONE`，不启动 Spring Web，也不监听 HTTP 端口；同机运行服务端和客户端时不再需要为客户端覆盖 `server.port`。

Go / .NET CLI 客户端使用同一份配置结构。

Android 客户端位于 `implementations/android/client`，提供运行控制台、配置摘要、JSONC 编辑器、启动/停止按钮和运行事件流；保存的配置兼容 `client.jsonc`，内置 `VpnService` 权限流程。其 control/data 通道支持登录响应驱动的 TLS，TCP 数据面使用 v2 `OPEN/DATA/FIN/RST/WINDOW_UPDATE`、严格半关闭、有界建连缓存与最近关闭流 tombstone；HTTP route 使用支持 request/response trailers、带 body 任意 method 和 early response 的 Netty 流。WebSocket route 按 Java 规则保留 continuation/FIN/RSV/close/ping/pong 语义；单个上游 data frame 可达 16 MiB，超过单个 NAT DATA 容量时规范化拆成连续的 SWS2 continuation envelopes，控制帧不拆分。配置非 `noop` 虚拟设备时 Android 会先申请 VPN 权限；只有服务端也开启 Peer Mesh 才会创建系统 VPN 接口。`noop` 不申请权限、不阻塞 TCP/HTTP，同时仍可运行 Peer Mesh 控制面和 UDP 探测。Peer Mesh 已接入 direct UDP、全 A/AAAA STUN、TURN relay、同 nonce burst、自适应端口预测、UPnP/NAT-PMP/PCP 显式映射、session 刷新、direct-stale fallback 以及链路/流量/设备上报；真实跨 NAT 真机矩阵仍需部署环境验收。

从源码运行 Go 客户端：

```bash
cd implementations/go/client
go run ./cmd/specus-client
```

.NET CLI 客户端：

```bash
cd implementations/csharp/client
dotnet run --project src/Specus.Client -- --config client.jsonc
```

Windows 桌面客户端提供图形化连接入口，不需要手写 `client.jsonc`：在界面填写 `serverBaseUrl`、`apiKey`、`secret`、Peer Mesh 虚拟网卡模式、网卡名和 MTU 后点击连接。它会保存配置到 `%APPDATA%\Specus\desktop-client.json`，并展示当前客户端名、控制端地址、TCP 路由、HTTP 路由、Peer Mesh 对端、活跃 session 和运行日志。主题支持跟随系统、浅色和深色。

```powershell
cd implementations/csharp/client
dotnet run --project src/Specus.Client.Desktop

# 发布 win-x64 单文件桌面包
powershell -ExecutionPolicy Bypass -File scripts\publish-desktop-win-x64.ps1
.\out\desktop-win-x64\specus-desktop.exe
```

如果桌面客户端用 `windows-wintun` 或 `auto` 创建 Peer Mesh 虚拟网卡，需要管理员权限；发布产物会带上 `native/windows/<arch>/wintun.dll`，也可以通过 `SPECUS_PEER_MESH_WINTUN_DLL` 覆盖 Wintun DLL 路径。

### 3. 下发端口映射

端口映射在管理后台维护，并通过 `NAT_CONTROL` 消息下发给在线客户端。客户端收到后会向服务端注册映射，服务端随即在对应公网端口上开始监听。

在管理后台的「端口映射（NAT）」面板中：

1. 选择目标客户端，填写公网端口、内网目标地址和内网端口，新增一条映射。
2. 在线客户端会立即收到完整映射快照；离线客户端会在下次登录时自动收到并注册已启用的映射。

Java/Go/C# 客户端登录成功后收到服务端返回的初始映射快照，并在后续收到 `NAT_CONTROL` 消息时同步注册端口映射。后台新增或删除映射时会向在线客户端自动同步完整映射快照。

也可以直接调用管理 API（`/api/admin/**` 需携带 Bearer JWT，详见[管理后台登录](#管理后台登录)）。先换取一个令牌：

```bash
# 用户名/密码登录换取 HS256 JWT（默认 admin / admin，请务必修改）
TOKEN=$(curl -s -X POST http://127.0.0.1:8088/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | jq -r .accessToken)
```

```bash
# 为客户端 ID=123 新增映射：公网 9000 -> 内网 127.0.0.1:8080
curl -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8088/api/admin/clients/123/specus-mappings \
  -H 'Content-Type: application/json' \
  -d '{"listenPort":9000,"targetAddress":"127.0.0.1","targetPort":8080}'

# 立即向在线客户端下发该客户端启用的全部映射
curl -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8088/api/admin/clients/123/nat-control
```

上面的示例表示：访问服务端 `9000` 端口的 TCP 流量，将被转发到客户端网络中的 `127.0.0.1:8080`。客户端离线时手动下发接口返回 `409`。

## 协议概览

完整跨语言协议说明见 [protocol/spec](protocol/spec/README.md)。根 README 只保留主流程摘要：

| 文档 | 内容 |
| --- | --- |
| [control-protocol.md](protocol/spec/control-protocol.md) | 控制连接帧、`Command`、`MessageType`、`NAT_CONTROL` 和 `NAT_MESSAGE` |
| [client-auth.md](protocol/spec/client-auth.md) | 客户端 HTTP 登录、apiKey/secret 签名、运行时 token 和刷新 |
| [http-route.md](protocol/spec/http-route.md) | HTTP route、WebSocket 隧道、Header 规则、路径改写和观测字段 |
| [peer-mesh.md](protocol/spec/peer-mesh.md) | 私有组网、虚拟 IP、标准 STUN/TURN、加密数据帧和管理面 |
| [public-transfer.md](protocol/spec/public-transfer.md) | 公共发现信令、ICE 配置、附件直传、对象存储和限流 |
| [client-messages.md](protocol/spec/client-messages.md) | 管理端与客户端文本消息、鉴权、能力声明和 fallback |

控制连接使用自定义二进制协议：

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| `magic` | 4 字节 | 固定值 `0x14353565` |
| `version` | 1 字节 | 固定为 `2`；其它版本直接拒绝 |
| `serializer` | 1 字节 | 固定为 CompactBinary `4`；不协商、不回退 |
| `command` | 1 字节 | 消息指令 |
| `length` | 4 字节 | 消息体长度 |
| `body` | N 字节 | 消息体 |

协议分为控制消息和 NAT stream 两层。`Command` 只登记登录、退出、心跳、普通消息与 `NAT_MESSAGE`；普通消息的 `MessageType` 包含 `SERVER_TO_CLIENT`、`CLIENT_TO_SERVER`、`CLIENT_TO_CLIENT`、`NAT_CONTROL` 和 `PEER_CONTROL`。每个客户端会话建立独立的 `control` 与 `data` 连接：控制连接承载登录、心跳、配置和 Peer 信令，数据连接承载 TCP、HTTP 与 WebSocket 流量。

控制消息使用固定 schema 的紧凑二进制（`CompactBinarySerializer`），省略字段名并使用变长整数；wire body 不带压缩标记，也不执行通用 Deflate。`NAT_MESSAGE` 使用固定 16 字节头，通过 `REGISTER`、`REGISTER_RESULT`、`OPEN`、`DATA`、`FIN`、`RST`、`WINDOW_UPDATE`、`KEEPALIVE` 和 `UNREGISTER` 表达流生命周期、半关闭、取消与窗口流控。默认 `SPECUS_NETTY_MAX_FRAME_SIZE=33554432` 按完整帧计算，包含 11 字节控制帧头。v2 是唯一可用版本，服务端和客户端必须同步升级。

## 管理后台

内置管理后台支持：

- 查看、编辑、停用和删除客户端
- 创建和管理客户端启动凭证（apiKey/secret），并限制同一凭证的在线实例数
- 维护每个客户端的 TCP 端口映射，并向在线客户端下发 `NAT_CONTROL` 配置
- 管理私有组网设备、虚拟 IP、在线状态、NAT 探测结果、链路、活跃会话和 ACL，并支持清理会话
- 查看控制连接成功和失败记录
- 按客户端和 UTC 日期汇总上下行流量，并查看 HTTP 请求/响应详情与 TCP payload 记录
- HTTP 记录支持按常用字段、方法、状态码、路径、Header、Body 等字段分页搜索；Header 可在表单/Raw 间切换，并内置常见 Header 说明与规范链接
- HTTP Body 支持 JSON 高亮、表单、HTML、XML、图片和文本预览；遇到 `Content-Encoding: gzip` / `deflate` / `br` 的新记录会在服务端解压后保存，旧记录展示时会做浏览器侧兜底解压或给出不可还原提示
- 配置每个客户端每分钟允许的控制连接次数（新建客户端默认 `30`）；设置为 `0` 表示不限
- 手动执行幂等数据库初始化

客户端启动凭证的 secret 在数据库中以 SHA-256 摘要（十六进制）保存；客户端启动时使用该摘要派生 HMAC-SHA256 签名密钥。secret 明文只在创建或重置凭证时显示一次。

同一凭证的并发在线实例数受以下配置约束（新建客户端默认继承，可在管理后台按客户端覆盖）：

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` | `2` | 同一凭证允许的最大并发在线实例数 |
| `SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` | `1` | 同一凭证在同一「机器指纹 + 系统用户」下的最大在线实例数，用于约束单机多开 |
| `SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS` | `28800` | 客户端运行时控制连接 token 有效期（秒），默认 8 小时 |

## 管理后台登录

管理页面支持两种登录方式，**用户名/密码**与 **OIDC** 可同时启用；管理 API（`/api/admin/**`）统一校验 Bearer JWT（Spring Security OAuth2 Resource Server）。两类令牌按 JWT 头部的 `alg` 路由：本地密码登录签发 HS256（用本地密钥校验），OIDC 网关签发 RS256（按 JWKS 验签）。原先的 Basic Auth 已移除。

### 用户名/密码登录

页面在提交用户名和密码前执行 Cloudflare Turnstile `login` action，再把短期 token 一并发到 `POST /auth/login`；服务端通过 Siteverify 校验 success、action 和 hostname 后才验证密码。注册分两步：`POST /auth/register` 通过 Turnstile `register` action 后发送邮箱验证码，`POST /auth/register/verify` 校验验证码并原子创建默认租户普通用户。验证码只保存 HMAC 摘要，验证前不会创建账号。Java、Go、C# 三套服务端遵循相同接口与安全校验。默认 `admin / admin`，**暴露前务必修改**；把密码设为空即可关闭该登录方式。

自助注册只有在注册开关、Turnstile、hostname 白名单、邮箱验证、SMTP 和发件地址全部配置完成时才会显示。Turnstile secret 和 SMTP 密码只保留在服务端；浏览器只读取公开 site key。OIDC 登录由外部身份提供方完成，不经过本地密码登录端点。

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `SPECUS_AUTH_USERNAME` | `admin` | 管理用户名 |
| `SPECUS_AUTH_PASSWORD` | `admin` | 管理密码；留空则禁用密码登录 |
| `SPECUS_AUTH_TENANT_ID` | `default` | 本地密码登录和内置 admin 使用的默认租户 |
| `SPECUS_AUTH_PASSWORD_LOGIN_ENABLED` | `true` | 是否启用密码登录 |
| `SPECUS_AUTH_REGISTRATION_ENABLED` | `true` | 自助注册总开关；还依赖密码登录、Turnstile、邮箱验证和 SMTP |
| `SPECUS_AUTH_JWT_SECRET` | （空） | HS256 签名密钥；留空则启动时随机生成（重启后旧令牌失效，需重新登录） |
| `SPECUS_AUTH_TOKEN_TTL_SECONDS` | `28800` | 密码登录令牌有效期（秒），默认 8 小时 |
| `SPECUS_AUTH_TURNSTILE_ENABLED` | `false` | 启用后本地密码登录必须通过 Cloudflare Turnstile；自助注册要求为 `true` |
| `SPECUS_AUTH_TURNSTILE_SITE_KEY` / `SPECUS_AUTH_TURNSTILE_SECRET_KEY` | （空） | Turnstile 站点公钥 / 仅服务端保存的密钥 |
| `SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES` | （空） | 必填，逗号分隔的站点域名白名单；服务端逐个精确匹配 |
| `SPECUS_AUTH_EMAIL_VERIFICATION_ENABLED` | `false` | 启用注册邮箱验证码 |
| `SPECUS_AUTH_EMAIL_FROM_ADDRESS` | （空） | 验证邮件发件地址 |
| `SPECUS_AUTH_EMAIL_CODE_TTL_SECONDS` / `SPECUS_AUTH_EMAIL_MAX_ATTEMPTS` | `600` / `5` | 验证码有效期与最大尝试次数 |
| `SPECUS_AUTH_SMTP_HOST` / `SPECUS_AUTH_SMTP_PORT` | （空） / `587` | SMTP 服务地址和端口 |
| `SPECUS_AUTH_SMTP_USERNAME` / `SPECUS_AUTH_SMTP_PASSWORD` | （空） | SMTP 凭据，仅保存在服务端 env |

### OIDC 登录（授权码 + PKCE）

1. 浏览器从 `GET /oidc-config` 读取登录参数，跳转到网关的授权端点（带 `code_challenge`）。
2. 授权完成后带 `code` 回到管理页；页面把 `code`、PKCE verifier 和 nonce 发给同源的 `POST /oidc/token`。服务端用固定回调地址换取令牌，校验 ID Token 的 RS256/JWKS、issuer、`client_id` audience、`azp`、有效期和 nonce，再按不可变的 `issuer + subject` 绑定本地管理用户。
3. 服务端为已绑定且启用的本地用户签发短期 Specus access token；页面用它作为 `Authorization: Bearer` 调用管理 API。刷新和每次授权都会采用数据库中的当前 tenant/role/启用状态，不复制外部 token 的权限 claim。

默认配置指向 Certus `https://certus.devshuai.com`，授权、注册、令牌、JWKS 和登出端点已写入默认值。**每个部署必须设置 `SPECUS_OIDC_CLIENT_ID`，并为该客户端注册回调地址 `SPECUS_OIDC_REDIRECT_URI`（默认 `http://127.0.0.1:8088/`）。** 公共 PKCE 客户端无需 secret；若是机密客户端，再设置 `SPECUS_OIDC_CLIENT_SECRET`。

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `SPECUS_OIDC_CLIENT_ID` | （空） | OIDC 客户端 ID，**必填**；未设置时登录页会提示未配置 |
| `SPECUS_OIDC_REDIRECT_URI` | `http://127.0.0.1:8088/` | 回调地址，需与网关注册的一致，并指向管理页地址 |
| `SPECUS_OIDC_CLIENT_SECRET` | （空） | 机密客户端的密钥；公共 PKCE 客户端留空 |
| `SPECUS_OIDC_SCOPE` | `openid profile email` | 授权请求的 scope |
| `SPECUS_OIDC_AUDIENCE` | （空） | 管理 API 的资源 audience；留空会禁用外部 OIDC token 直传 Bearer，但不影响授权码登录后换取本地 token |
| `SPECUS_OIDC_ISSUER` / `SPECUS_OIDC_JWK_SET_URI` | 指向 Certus | JWT 验签与 issuer 校验；issuer 缺失时 OIDC token 验证 fail closed；JWKS 在首次校验令牌时按需拉取，不在启动时联网 |
| `SPECUS_OIDC_AUTHORIZATION_ENDPOINT` / `SPECUS_OIDC_REGISTRATION_ENDPOINT` / `SPECUS_OIDC_TOKEN_ENDPOINT` / `SPECUS_OIDC_END_SESSION_ENDPOINT` | 指向 Certus | 授权 / 注册 / 令牌 / 登出端点 |
| `SPECUS_OIDC_TENANT_CLAIM` | `tenant_id` | 跨版本兼容的外部资料 claim 名；不会直接授予租户权限，管理权限采用 `issuer + subject` 已绑定本地用户的当前 tenant/role |

> `preferred_username` 只用于首次匹配或创建普通本地用户，不能映射配置中的内置管理员。直接提交外部 OIDC Bearer 时必须配置并匹配 issuer 与资源 audience，且只有已绑定、启用的本地用户可以访问；外部 `role`/tenant claim 不会授予本地权限。Go/.NET 的 JWKS 缓存还对下载体积、键数量、并发刷新、未知 kid 和旧 key 重叠窗口做了有界保护，并保持 Java/Nimbus 的缺失、空值和重复 kid 选键语义。

## HTTP 直转通道

HTTP 直转通道与 TCP 端口映射并行工作。服务端收到请求后，在客户端专用 `data` 连接上创建 NAT stream：请求头先通过 `OPEN` 到达客户端，请求体使用 `DATA` 流式发送，`FIN` 表示半关闭；客户端连接本地目标后，以响应 `OPEN`、`DATA`、`FIN` 流式返回状态码、响应头、响应体和 trailers。断开或超时通过 `RST` 传播，`WINDOW_UPDATE` 将下游消费能力反馈给发送端。

客户端配置中的 `route` 决定可访问的内网目标。例如：

```json
{
  "httpSpecusConfigList": [
    {
      "route": "web",
      "targetBaseUrl": "http://127.0.0.1:8080"
    }
  ]
}
```

客户端登录后，可通过服务端直接访问：

```bash
curl -i http://127.0.0.1:8088/http/Demo%20client/web/api/hello?source=specus
```

该请求会转发到客户端网络中的 `http://127.0.0.1:8080/api/hello?source=specus`。`/http/**` 默认作为公开流量入口，不需要管理令牌；管理页可为每条 route 单独开启 HTTP Basic 认证。开启后使用 `curl -u '用户名:密码' URL` 访问，缺失或错误凭据返回 `401`。入口密码只以哈希保存且不会通过管理 API 回显，也不会下发给客户端；校验成功后的外层 Basic `Authorization` 不会透传给内网服务或写入流量明细。公开 route 仍会保留调用方的 Authorization，以兼容 upstream 自身认证。

只有客户端配置过的 route 可以被访问。单次请求体默认限制为 `16 MiB`，可通过 `SPECUS_HTTP_MAX_REQUEST_BODY_SIZE` 调整。转发超时默认是 `30000` 毫秒，可通过 `SPECUS_HTTP_TIMEOUT_MS` 调整。HTTP 路由开启路径改写时，单次可改写响应体默认上限是 `10 MiB`，可通过 `SPECUS_HTTP_REWRITE_MAX_BODY_BYTES` 调整。

## 私有组网（Peer Mesh）

Peer Mesh 默认关闭。开启后，同一租户和同一用户下的客户端会被分配 `100.96.0.0/11` 内的虚拟 IP，并通过 `specus0` 这类虚拟网卡互访。控制面仍走现有 Netty 连接，服务端通过 `PEER_CONTROL` 下发设备列表、候选地址、session 授权和启停状态；数据面优先走客户端之间的加密 UDP direct，direct 失效或不可达时回退到服务端标准 TURN relay。服务端 relay 只校验会话授权和 frame 头，不解密业务 IP 包明文。

当前实现同时使用自建 STUN/TURN 和可配置公共 STUN。客户端登录后会拿到彼此独立的 `stunHost/stunPort`、`turnHost/turnPort`、公共 STUN 列表和 ICE 凭证；自建 STUN 负责 NAT 探测，TURN 负责 relay，公共 STUN 只用于补充 server-reflexive 候选地址。Java、Go、.NET 均可独立运行完整 RFC 5780 四端点 STUN，支持 `CHANGE-REQUEST`、`RESPONSE-PORT`、`PADDING`、双层请求限流、来源表上限和 Prometheus 指标；Java、Go、.NET 与 Android 客户端会分别上报映射行为、过滤行为和归一化 NAT 标签，并在 direct path 过期后主动触发重新探测和 relay fallback。

服务端相关配置：

| 配置 | 环境变量 | 默认 | 说明 |
| --- | --- | --- | --- |
| `specus.peer-mesh.enabled` | `SPECUS_PEER_MESH_ENABLED` | `false` | 是否启用 Peer Mesh |
| `specus.peer-mesh.cidr` | `SPECUS_PEER_MESH_CIDR` | `100.96.0.0/11` | 虚拟网段 |
| `specus.peer-mesh.public-address` | `SPECUS_PEER_MESH_PUBLIC_ADDRESS` | （空） | 对客户端公布的 STUN/TURN 地址；为空时回退登录请求域名 |
| `specus.peer-mesh.stun-turn-port` | `SPECUS_PEER_MESH_STUN_TURN_PORT` | `3478` | 标准 STUN/TURN UDP 主端口 |
| `specus.peer-mesh.standalone-stun-address` | `SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS` | （空） | 独立 STUN 域名或 IP；配置后只替换 `stunHost`，TURN 地址保持不变 |
| `specus.peer-mesh.standalone-stun-port` | `SPECUS_PEER_MESH_STANDALONE_STUN_PORT` | `3478` | 独立 STUN 入口端口 |
| `specus.peer-mesh.standalone-stun-alternate-address` | `SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS` | （空） | 独立 STUN 备用域名或 IP；使用主端口加入备用 STUN 列表，同时作为 RFC 5780 的 A2 |
| `specus.peer-mesh.standalone-stun-alternate-port` | `SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT` | `0` | 独立 RFC 5780 的第二端口 P2；`0` 时回退 NAT 探测备用端口 |
| `specus.peer-mesh.nat-probe-alternate-port` | `SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT` | `3479` | NAT 探测备用 UDP 端口，用于更准确地区分端口映射行为 |
| `specus.peer-mesh.stun-primary-bind-address` | `SPECUS_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS` | （空） | RFC 5780 主地址 A1 的本机绑定 IP；完整模式必须显式配置 |
| `specus.peer-mesh.stun-alternate-bind-address` | `SPECUS_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS` | （空） | RFC 5780 备用地址 A2 的本机绑定 IP |
| `specus.peer-mesh.stun-alternate-public-address` | `SPECUS_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS` | （空） | RFC 5780 备用公网 IP A2；主公网 IP A1 使用 `public-address` |
| `specus.peer-mesh.stun-behavior-strict` | `SPECUS_PEER_MESH_STUN_BEHAVIOR_STRICT` | `false` | 为 `true` 时四端点配置不完整会阻止内置 STUN/TURN 启动 |
| `specus.peer-mesh.public-stun-servers` | `SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS` | （空） | 额外公共 STUN 服务器，多个地址用英文逗号分隔，支持 `host:port` / `stun:host:port` |
| `specus.peer-mesh.session-ttl-seconds` | `SPECUS_PEER_MESH_SESSION_TTL_SECONDS` | `3600` | peer session 授权有效期 |
| `specus.peer-mesh.allocation-ttl-seconds` | `SPECUS_PEER_MESH_ALLOCATION_TTL_SECONDS` | `300` | relay allocation TTL |
| `specus.peer-mesh.relay-min-port` | `SPECUS_PEER_MESH_RELAY_MIN_PORT` | `49152` | TURN relay 分配端口范围下限 |
| `specus.peer-mesh.relay-max-port` | `SPECUS_PEER_MESH_RELAY_MAX_PORT` | `65535` | TURN relay 分配端口范围上限 |
| `specus.peer-mesh.relay-worker-threads` | `SPECUS_PEER_MESH_RELAY_WORKER_THREADS` | `0` | relay 数据帧工作线程数，`0` 表示按 CPU 自动选择 |
| `specus.peer-mesh.relay-worker-queue-capacity` | `SPECUS_PEER_MESH_RELAY_WORKER_QUEUE_CAPACITY` | `10000` | relay 工作队列上限，队列满时丢弃新的 relay 数据帧以保护服务端 |
| `specus.peer-mesh.udp-receive-buffer-bytes` | `SPECUS_PEER_MESH_UDP_RECEIVE_BUFFER_BYTES` | `4194304` | STUN/TURN 与 allocation socket 请求的 UDP 接收缓冲区字节数 |
| `specus.peer-mesh.udp-send-buffer-bytes` | `SPECUS_PEER_MESH_UDP_SEND_BUFFER_BYTES` | `4194304` | STUN/TURN 与 allocation socket 请求的 UDP 发送缓冲区字节数 |
| `specus.peer-mesh.udp-traffic-class` | `SPECUS_PEER_MESH_UDP_TRAFFIC_CLASS` | `16` | UDP socket 请求的 IP_TOS/Traffic Class，取值 `0..255` |
| `specus.peer-mesh.relay-traffic-flush-interval-ms` | `SPECUS_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS` | `5000` | relay 流量聚合入库间隔 |
| `specus.peer-mesh.turn-auth-required` | `SPECUS_PEER_MESH_TURN_AUTH_REQUIRED` | `true` | 是否要求 Allocate/Refresh/CreatePermission 携带长期凭证认证 |
| `specus.peer-mesh.turn-realm` | `SPECUS_PEER_MESH_TURN_REALM` | `specus` | TURN realm；参与 MESSAGE-INTEGRITY key 派生 |
| `specus.peer-mesh.turn-shared-secret` | `SPECUS_PEER_MESH_TURN_SHARED_SECRET` | （空） | 临时 credential HMAC-SHA1 密钥；为空时使用进程内随机密钥，重启后旧凭证失效 |
| `specus.peer-mesh.turn-credential-ttl-seconds` | `SPECUS_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS` | `3600` | 临时 TURN credential 有效期，最小 60 秒 |

公网安全组 / 防火墙需要放行 `3478/udp`、`3479/udp` 和 relay 分配端口范围（默认 `49152-65535/udp`）。完整 RFC 5780 模式要在 A1、A2 两个公网 IP 上同时放行两个 STUN 端口；TURN 仍只在 A1:P1 处理。独立部署说明见 [`deploy/stun-server/systemd`](deploy/stun-server/systemd/README.md)。如果不希望开放完整高端口范围，可以把 `relay-min-port` / `relay-max-port` 收窄到可控区间，并同步开放该区间。

客户端侧 `peerMeshDevice` 决定虚拟网卡实现：`linux-tun` 使用 `/dev/net/tun`，需要 root 或 `CAP_NET_ADMIN`；`windows-wintun` / `wintun` 使用随客户端分发的 Wintun 动态库；Java / Go / .NET 客户端均支持 `utun` 接入 macOS utun，其中 Java 可使用 `mac-utun` / `utun`，`auto` 会按系统选择；`noop` 只保留控制面，不创建虚拟网卡。更完整的信令、加密帧和 NAT 探测说明见 [protocol/spec/peer-mesh.md](protocol/spec/peer-mesh.md)。

管理后台的「私有组网」页面展示设备虚拟 IP、在线状态、虚拟网卡状态、NAT 类型、候选 Endpoint、链路和活跃会话，并支持启停设备、配置 ACL、分页查看会话、清理活跃会话和链路。路径统计同时展示 NAT 行为探测设备数、完整分类率，以及映射行为、过滤行为和探测方式分布。公开的浏览器 NAT 检测页会调用 `/api/public/peer-mesh/stun-config` 获取自建 STUN，再结合配置的公共 STUN 进行 WebRTC 探测。

## 公共互传与对象存储

公共发现信令使用 `/ws/public-transfer/discovery`；附件使用 Aliyun OSS V4 签名，浏览器直接 PUT/GET 私有 OSS，业务服务只保存元数据。可选上传回调由 OSS 在 PUT 成功后签名通知服务端，客户端 complete 保留为 HEAD 兜底。下载申请返回只能消费一次的站内授权，首次访问并成功领取跳转时按附件大小扣除月用量，再 `302` 到 30 秒 OSS 地址；未访问不扣，再次访问返回 `410`。对象存储默认关闭，新 presign 在通过来源 IP/房间配额检查后返回 `409`，不会返回占位 URL。完整 payload、隔离和错误语义见 [public-transfer.md](protocol/spec/public-transfer.md)。

| 配置 | 环境变量 | 默认 | 说明 |
| --- | --- | --- | --- |
| `specus.object-storage.provider` | `SPECUS_OBJECT_STORAGE_PROVIDER` | `disabled` | `disabled` 或 `aliyun-oss` |
| `specus.object-storage.endpoint` / `.bucket` | `SPECUS_OBJECT_STORAGE_ENDPOINT` / `SPECUS_OBJECT_STORAGE_BUCKET` | （空） | OSS endpoint 与私有 bucket |
| `specus.object-storage.region` | `SPECUS_OBJECT_STORAGE_REGION` | （自动） | OSS V4 region；标准 `oss-<region>` endpoint 可自动推导，CNAME 必须显式配置 |
| `specus.object-storage.access-key-id` / `.access-key-secret` | `SPECUS_OBJECT_STORAGE_ACCESS_KEY_ID` / `SPECUS_OBJECT_STORAGE_ACCESS_KEY_SECRET` | （空） | OSS 访问凭证 |
| `specus.object-storage.object-prefix` | `SPECUS_OBJECT_STORAGE_PREFIX` | `specus/attachments` | object key 前缀 |
| `specus.object-storage.upload-callback-url` | `SPECUS_OBJECT_STORAGE_UPLOAD_CALLBACK_URL` | （空） | OSS 上传成功回调地址；例如 `https://specus.devshuai.com/api/public/transfer/oss-callback` |
| `specus.object-storage.upload-url-ttl-seconds` | `SPECUS_OBJECT_STORAGE_UPLOAD_URL_TTL_SECONDS` | `900` | 上传预签名 URL TTL |
| `specus.object-storage.download-url-ttl-seconds` | `SPECUS_OBJECT_STORAGE_DOWNLOAD_URL_TTL_SECONDS` | `600` | 一次性下载授权领取期限 |
| `specus.object-storage.download-object-url-ttl-seconds` | `SPECUS_OBJECT_STORAGE_DOWNLOAD_OBJECT_URL_TTL_SECONDS` | `30` | 首次消费后签发的 OSS V4 直达 URL TTL |
| `specus.object-storage.retention-hours` | `SPECUS_OBJECT_STORAGE_RETENTION_HOURS` | `72` | 附件保留小时数；实现最小按 1 小时处理 |
| `specus.object-storage.max-attachment-bytes` | `SPECUS_OBJECT_STORAGE_MAX_ATTACHMENT_BYTES` | `536870912` | 声明与 HEAD 实际大小上限 |
| `specus.object-storage.per-user-storage-quota-bytes` | `SPECUS_OBJECT_STORAGE_PER_USER_STORAGE_QUOTA_BYTES` | `1073741824` | 每个登录账号的有效附件存储额度（1 GiB） |
| `specus.object-storage.per-user-monthly-download-quota-bytes` | `SPECUS_OBJECT_STORAGE_PER_USER_MONTHLY_DOWNLOAD_QUOTA_BYTES` | `1073741824` | 每个登录账号按 UTC 自然月计算的下载跳转流量额度（1 GiB） |
| `specus.object-storage.expiration-scan-interval-ms` | `SPECUS_OBJECT_STORAGE_EXPIRATION_SCAN_INTERVAL_MS` | `3600000` | 过期扫描间隔 |
| `specus.public-transfer.presign-rate-limit-per-ip` | `SPECUS_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_PER_IP` | `30` | 单来源 IP 每窗口公开 presign-upload 次数 |
| `specus.public-transfer.presign-rate-limit-window-seconds` | `SPECUS_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_WINDOW_SECONDS` | `300` | presign 固定窗口秒数 |
| `specus.public-transfer.max-pending-uploads-per-room` | `SPECUS_PUBLIC_TRANSFER_MAX_PENDING_UPLOADS_PER_ROOM` | `50` | 同 roomToken 哈希下 PENDING 上限 |
| `specus.public-transfer.max-discovery-peers-per-room` | `SPECUS_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM` | `32` | 单发现房间在线 peer 上限 |
| `specus.public-transfer.discovery-message-rate-limit-per-connection` | `SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_PER_CONNECTION` | `360` | 单发现连接每窗口消息数 |
| `specus.public-transfer.discovery-message-rate-limit-window-seconds` | `SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_WINDOW_SECONDS` | `60` | 发现消息限流窗口秒数 |
| `specus.public-transfer.cluster-enabled` | `SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED` | `false` | 启用 Redis 多实例 presence、Pub/Sub、房间修订和共享限流 |
| `specus.public-transfer.redis-uri` | `SPECUS_PUBLIC_TRANSFER_REDIS_URI` | 空 | 集群模式必填，例如 `redis://user:password@redis.internal:6379/0` |
| `specus.public-transfer.redis-key-prefix` | `SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX` | `specus:v2:public-transfer` | Redis key 与频道前缀；环境之间必须隔离 |
| `specus.public-transfer.presence-lease-seconds` | `SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS` | `30` | discovery presence 租约 TTL |
| `specus.public-transfer.presence-refresh-interval-ms` | `SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS` | `10000` | 租约刷新间隔，必须小于 TTL 一半 |
| `specus.public-transfer.redis-command-timeout-ms` | `SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS` | `2000` | Redis 命令超时；故障时不回退本地状态 |

## Control/Data 连接 TLS

本地开发默认可使用明文 TCP（`SPECUS_TLS_MODE=disabled`）。生产 profile 或启用 `SPECUS_TLS_REQUIRE_ENCRYPTION=true` 后，公网 control/data 监听必须使用受信 TLS；只有 TLS 已由受信 L4 上游终止且进程绑定 loopback/私网地址时，才能显式设置 `SPECUS_TLS_TERMINATED_UPSTREAM=true`：

| `SPECUS_TLS_MODE` | 说明 |
| --- | --- |
| `disabled` | 仅限本地开发；生产公网绑定会被启动门禁拒绝 |
| `file` | 生产环境。从磁盘加载真实的 keystore（JKS / PKCS12）签发服务端证书 |
| `self-signed` | 仅开发/测试。启动时生成一次性自签名证书，控制连接已加密但不校验 CA |

服务端：

```bash
# 生产：使用磁盘上的 keystore
SPECUS_TLS_MODE=file \
SPECUS_TLS_KEYSTORE=/path/to/server.p12 \
SPECUS_TLS_KEYSTORE_PASSWORD=changeit \
SPECUS_TLS_KEY_PASSWORD=changeit \
mvn org.springframework.boot:spring-boot-maven-plugin:run

# 开发/测试：一次性自签名证书
SPECUS_TLS_MODE=self-signed \
mvn org.springframework.boot:spring-boot-maven-plugin:run
```

Java、Go、.NET 服务端会在 HTTP 登录响应中返回 `nettyTls`，Java、Go、.NET、Android 客户端默认据此选择 control/data
连接的明文或 TLS 模式。该信号描述原始 TCP 端点，不能用 `serverBaseUrl` 是否为 HTTPS 推断：管理 HTTPS 可能已由
OpenResty 终止，而 `7010/TCP` 仍为明文。旧服务端未返回该字段时按 `false` 兼容。

客户端可在 `client.jsonc` 中覆盖或补充信任配置：

```jsonc
"controlTls": {
  // 省略/null：跟随 nettyTls；true/false：显式覆盖
  // "enabled": true,
  // "caCertificatePath": "./control-ca.pem",
  // "serverName": "control.example.com",
  "insecureSkipVerify": false
}
```

配置 CA、`serverName` 或 `insecureSkipVerify` 也会启用 TLS；`enabled=false` 时不得配置这些附加项。
`insecureSkipVerify=true` 会关闭证书链和主机名校验，仅可用于本地开发。

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `SPECUS_TLS_MODE` | `disabled` | TLS 模式：`disabled` / `file` / `self-signed` |
| `SPECUS_TLS_KEYSTORE` | （空） | 服务端 keystore 路径，仅 `mode=file` 时使用 |
| `SPECUS_TLS_KEYSTORE_PASSWORD` | （空） | keystore 密码 |
| `SPECUS_TLS_KEY_PASSWORD` | （空） | key 密码，留空时回退到 keystore 密码 |
| `SPECUS_TLS_REQUIRE_ENCRYPTION` | `false` | 强制 control/data 连接加密；生产 profile 自动执行同等门禁 |
| `SPECUS_TLS_TERMINATED_UPSTREAM` | `false` | 声明 TLS 已由受信 L4 上游终止；仅允许进程绑定 loopback/私网地址 |

## 数据库切换

默认配置使用 SQLite：

```bash
SPECUS_DB_URL=jdbc:sqlite:./specus.db \
SPECUS_DB_DRIVER=org.sqlite.JDBC \
SPECUS_DB_DIALECT=org.hibernate.community.dialect.SQLiteDialect \
mvn org.springframework.boot:spring-boot-maven-plugin:run
```

切换至 MySQL：

```bash
SPECUS_DB_URL=jdbc:mysql://127.0.0.1:3306/specus \
SPECUS_DB_DRIVER=com.mysql.cj.jdbc.Driver \
SPECUS_DB_DIALECT=org.hibernate.dialect.MySQLDialect \
SPECUS_DB_USERNAME=root \
SPECUS_DB_PASSWORD=your-password \
SPECUS_DB_POOL_SIZE=8 \
mvn org.springframework.boot:spring-boot-maven-plugin:run
```

切换至 PostgreSQL：

```bash
SPECUS_DB_URL=jdbc:postgresql://127.0.0.1:5432/specus \
SPECUS_DB_DRIVER=org.postgresql.Driver \
SPECUS_DB_DIALECT=org.hibernate.dialect.PostgreSQLDialect \
SPECUS_DB_USERNAME=postgres \
SPECUS_DB_PASSWORD=your-password \
SPECUS_DB_POOL_SIZE=8 \
mvn org.springframework.boot:spring-boot-maven-plugin:run
```

### 连接池、批量写入与连接记录归档

面向大量客户端的场景，服务端做了以下数据库工程化处理：

- **连接池**：HikariCP 连接池大小由 `SPECUS_DB_POOL_SIZE` 控制。默认 `1` 适配单写者的 SQLite；切换到 MySQL/PostgreSQL 时应调大（建议 `16`–`32`）。
- **批量写入**：Hibernate 启用 `batch_size`（默认 `50`，由 `SPECUS_DB_BATCH_SIZE` 调整），合并流量聚合的更新与归档时的批量删除。
- **登录链路**：鉴权、连接记录写入和 `NAT_CONTROL` 下发都在独立的有界线程池中执行，不占用 Netty I/O 事件循环（见 `specus.login.executor.*`）。
- **流量聚合**：上下行字节先在内存中按客户端累加，每 `SPECUS_TRAFFIC_FLUSH_INTERVAL_MS` 毫秒按「客户端 + UTC 日期」批量 upsert 一行，而非每个数据包写库。
- **索引**：连接记录表对 `(client_id, connected_at)` 建复合索引（服务每次登录的频率限制查询），并对 `connected_at` 建索引（服务归档扫描）。
- **连接记录归档**：连接记录是逐次登录追加的日志，会无限增长。后台定时任务把**早于保留窗口的明细按自然月汇总成总量**（连接数 / 成功数 / 失败数，保存在 `specus_connection_stat` 表，长期保留），**汇总完成后**才删除原始明细——数据不会丢失。明细默认保留**最近 60 天（滚动窗口）**。跨越截止点的月份会随天数滚出窗口而逐步汇总，计数采用累加且在同一事务内删除已汇总明细，因此不会重复计数。归档后的月度总量可通过 `GET /api/admin/connection-stats?clientName=...` 查询。

| 配置 | 环境变量 | 默认 | 说明 |
| --- | --- | --- | --- |
| `specus.connection-record.detail-retention-days` | `SPECUS_CONNECTION_DETAIL_RETENTION_DAYS` | `60` | 保留最近多少天的连接明细（滚动窗口）；更早的明细按自然月汇总后删除。`0` 关闭归档 |
| `specus.connection-record.archive-interval-ms` | `SPECUS_CONNECTION_ARCHIVE_INTERVAL_MS` | `3600000` | 归档任务执行间隔（毫秒） |
| `spring.jpa.properties.hibernate.jdbc.batch_size` | `SPECUS_DB_BATCH_SIZE` | `50` | Hibernate JDBC 批量大小 |

Go server 与 .NET server 也兼容 `SPECUS_CONNECTION_DETAIL_RETENTION_DAYS` 和 `SPECUS_CONNECTION_ARCHIVE_INTERVAL_MS`，用于对齐 Java 的连接明细归档策略。

> 月度归档总量（`specus_connection_stat`）与每日流量（`specus_traffic_usage`）都长期保留，只有连接明细会被汇总后清理。对于超大规模部署，建议进一步在数据库层对明细表按 `connected_at` 做时间分区（如 PostgreSQL 声明式分区）；JPA 的 `ddl-auto` 不会自动建立分区，需要在数据库侧维护。首次归档历史积压较大时，单次事务会汇总并删除全部过期明细，必要时可分批执行。

### 流量明细存储

Java 参考实现中，HTTP 协议记录和 TCP payload 记录默认写入业务数据库；配置 Elasticsearch 后会自动切换到 ES 存储，管理页查询同一套接口。明细采集由全局总开关和通道开关共同控制，全局总开关默认关闭，每条 HTTP 路由 / TCP 映射新建时也默认关闭明细采集，需要在管理页单独打开。写入时会保留完整 HTTP body 与 TCP 二进制 payload，压缩 HTTP Body 的解压预览有独立大小上限，页面按分页读取；HTTP 与 TCP 索引都可通过体积上限自动清理最旧记录。管理查询默认不强制 flush，避免读请求放大写入压力。

| 配置 | 环境变量 | 默认 | 说明 |
| --- | --- | --- | --- |
| `specus.elasticsearch.uris` | `SPECUS_ELASTICSEARCH_URIS` | （空） | ES 地址，多个节点用逗号分隔；为空时继续使用数据库存储流量明细 |
| `specus.elasticsearch.username` | `SPECUS_ELASTICSEARCH_USERNAME` | （空） | ES 用户名 |
| `specus.elasticsearch.password` | `SPECUS_ELASTICSEARCH_PASSWORD` | （空） | ES 密码 |
| `specus.elasticsearch.api-key` | `SPECUS_ELASTICSEARCH_API_KEY` | （空） | ES API Key；设置后优先于用户名密码 |
| `specus.elasticsearch.http-index` | `SPECUS_ELASTICSEARCH_HTTP_INDEX` | `specus-http-traffic` | HTTP 流量索引 |
| `specus.elasticsearch.tcp-index` | `SPECUS_ELASTICSEARCH_TCP_INDEX` | `specus-tcp-traffic` | TCP 流量索引 |
| `specus.elasticsearch.http-max-store-size` | `SPECUS_ELASTICSEARCH_HTTP_MAX_STORE_SIZE` | `100GB` | HTTP 明细索引最大存储体积，超过后删除最旧记录 |
| `specus.elasticsearch.tcp-max-store-size` | `SPECUS_ELASTICSEARCH_TCP_MAX_STORE_SIZE` | `10GB` | TCP payload 索引最大存储体积 |

HTTP 流量入库前会根据 `Content-Encoding` 对 `gzip`、`deflate`、`br` 响应体做解压，管理页再按 `Content-Type` 提供对应预览；如果历史记录只保存了已损坏的压缩文本，页面会提示缺少可还原的原始压缩字节。

Go server 和 .NET server 已补齐数据库版资源级流量聚合、HTTP/TCP 明细采集、分页查询、字段搜索和 TCP 串流查询，并已兼容 `gzip`、`deflate` 的 zlib / raw deflate 以及 `br` Brotli 响应预览解码；同时支持 Java 风格 Elasticsearch 可选存储与 HTTP 100GB / TCP 10GB 索引容量治理。

## 当前状态

已实现：

- 客户端启动登录（基于 apiKey/secret 的 **HMAC-SHA256** 签名，canonical message 覆盖 apiKey、时间戳、nonce、`machineFingerprint` 与 `osUser`，并校验 60 秒时间窗）、运行时 token control/data 双通道登录与心跳保活；`(apiKey, nonce)` 通过数据库唯一键原子去重并按 TTL 清理
- 基于 Spring Data JPA 和 Hibernate 的 SQLite、MySQL 和 PostgreSQL 持久化与初始化
- 客户端账号分配、连接记录、连接频率限制（默认每分钟 `30` 次，`0` 表示不限）和流量统计
- 内置管理 API 和管理页面，支持用户名/密码与 OIDC（授权码 + PKCE）两种登录，后端统一校验 Bearer JWT
- 多租户管理用户：内置 admin 来自配置，其它用户保存到数据库；admin 可管理用户和查看租户内全部资源，普通用户只能看到自己创建的客户端、凭证、映射、连接和流量
- 端口映射的持久化管理，以及通过 `NAT_CONTROL` 完成登录自动下发和在线快照同步
- 基于客户端 route 白名单的 HTTP 请求直接转发
- HTTP / TCP 流量明细观测，支持通道级采集开关（默认关闭）、分页搜索、Header 说明、HTTP Body 类型化预览、压缩响应解码，以及 DB / Elasticsearch 存储切换
- 控制连接断开后的指数退避重连
- TCP 公网端口监听和双向数据转发
- 服务端通过专用数据连接以 NAT stream 转发 HTTP/WebSocket，支持首部先达、流式 body、SSE、trailers、取消传播与窗口流控
- Peer Mesh：虚拟 IP 分配、Linux TUN / Windows Wintun / macOS utun、同用户默认互通、`PEER_CONTROL` 信令、标准 STUN/TURN、公共 STUN 候选补充、UDP direct、server relay、NAT 类型探测、链路和会话展示
- 可选的 control/data 连接 TLS（`file` 加载 keystore / `self-signed` 自签名）
- 免登录房间互传：匿名用户可使用 WebRTC Direct 和认证 TURN，登录用户额外支持 OSS 预签名兜底、云端下载与分享链接；Token 房间支持 OWNER/EDITOR/VIEWER 角色邀请、撤销和只读限制；专业流程图基于 maxGraph + Yjs，支持多页面、分类图形库与模板、动态泳池/泳道、容器与组合、智能参考线、小地图、自动布局、格式刷、高级样式、评论、协作光标和服务端版本历史；支持 `.stdg`、多页 `.drawio`、Mermaid、PlantUML、Visio `.vsdx` 导入，以及 `.stdg`、`.drawio`、Mermaid、PlantUML、Visio `.vdx`、SVG、PNG、全页 PDF 导出；文件接收默认关闭“接收前确认”，收到文件元数据后自动开始接收；仅在会话内开启该开关后才显示接收/拒绝，拒绝后发送端不会绕过拒绝回退 OSS
- 使用统一 v2 线协议的 Go 客户端，支持 control/data 双连接、登录、心跳、自动重连、TCP 映射和 HTTP/WebSocket 流式直转
- Go/.NET server 已同步 Java 管理用户与租户/owner 权限基础，并已对齐 TCP 映射 / HTTP 路由的通道级 `detailCaptureEnabled`、HTTP 路由 `pathRewriteEnabled`、逐 route Basic 入口认证及 `/http/**` WebSocket SWS2 隧道；C server 的 SQLite 管理路由也使用同一认证字段与数据面校验语义
- Go/.NET server 已补齐数据库版资源级流量聚合和 HTTP/TCP 明细观测，包括资源流量表、明细表、热路径采集写入、资源列表、HTTP 分页与字段搜索、TCP 分页、单帧详情和按 channel 串流查询；同时已支持 Java 风格 Elasticsearch 可选存储与 HTTP 100GB / TCP 10GB 索引容量治理
- Go/.NET server 已对齐 Java 公共互传与客户端消息主路径：`/ws/public-transfer/discovery`、6 个公共/管理附件接口、Aliyun OSS 预签名与 HEAD 完成校验、过期清理、来源 IP/房间限流、`/ws/client-messages`、消息能力持久化和 client/admin fallback；TURN 临时 credential、MESSAGE-INTEGRITY 及 401/438 challenge 也已补齐，Java/Go/.NET/Android 客户端会更新 challenge、换新 transaction 并最多重试一次
- Go/.NET server 已对齐 Java 的 HTTP route 媒体采集与播放：逐 route 开关、RustFS/S3 multipart、HLS/DASH 清单改写、Range 去重和中断区间保留、跨对象回放、短期 tenant 绑定播放票据及过期清理；真实 RustFS 仍需在部署环境验收
- Go/.NET server 已对齐 Java 的持久化互传房间角色、配对码、WebSocket room role/discoverable、附件角色授权、公共流程图版本和登录用户云端流程图；.NET 的 SQLite/MySQL/PostgreSQL migration 同步覆盖这些实体与媒体采集实体
- Go/.NET client 已同步 `PEER_CONTROL` 枚举、客户端 HTTP 登录里的 `peerMesh` 配置、`peerPublicKey` 环境字段，并已接入 Linux TUN、Windows Wintun、macOS utun、UDP direct/relay、X25519/HKDF/AES-GCM 数据帧和 token 快过期主动刷新；Java client 也已支持 macOS utun；C server 提供明确列出的轻量子集
- .NET Windows 桌面客户端已接入同一套 .NET 客户端运行时，支持保存连接配置、启动/停止客户端、查看 TCP/HTTP 路由和 Peer Mesh 状态、活跃 session、运行日志，以及跟随系统/浅色/深色主题
- Android 客户端已提供原生运行控制台、JSONC 配置编辑与摘要、前台服务、HTTP 登录、control/data TLS、严格 TCP 半关闭、全双工 HTTP/trailers、Java 兼容的 WebSocket SWS2 frame 规范化、VpnService TUN 生命周期、客户端文本消息，以及 Peer Mesh 数据面（X25519/HKDF/AES-GCM、候选交换、session 授权/刷新、全地址 STUN、TURN、同 nonce burst、自适应端口预测、UPnP/NAT-PMP/PCP、direct-stale relay fallback、链路/流量/设备上报和 IPv4 包收发）；JVM 测试覆盖帧边界、登录、重连、流状态、真实测试证书 TLS、HTTP early response/trailers、probe 防护和端口映射 wire
- 面向规模化的数据库工程：有界登录线程池、批量流量聚合、复合索引、连接级 O(1) 数据路由，以及连接明细按自然月汇总归档（明细滚动保留 60 天，汇总后再清理）

实现边界：

- 公网 UDP 端口映射尚未实现；目前 UDP 数据面只用于 Peer Mesh direct / relay。
- Peer Mesh 的 Go/.NET 数据面已对齐协议和核心能力，跨平台运行仍以 Java 基准实现为准；C server 只实现 v2 控制/NAT stream 与管理面的轻量子集，不包含 TLS 控制连接、HTTPS OIDC token exchange、ES 明细、live client-message/公共发现、对象存储或 Peer Mesh 数据面。C 的附件路径会明确返回 `409 OBJECT_STORAGE_DISABLED`，公共 ICE 仅描述显式配置的外部 STUN/TURN 服务。
- Android Peer Mesh 的源码能力已覆盖 direct UDP、全地址 STUN、TURN relay、session 刷新、同 nonce burst、自适应端口预测、UPnP/NAT-PMP/PCP 显式映射和链路/流量/设备上报；Peer 授权与 Java client 一样由服务端 roster/session grant 执行，不存在需要复制的客户端本地 ACL 镜像。完整真机端到端矩阵仍待环境验收。Direct HTTP 已改用受保护的 Netty transport，不再存在 `HttpURLConnection` 的 request trailer、带 body GET/HEAD 或 early response 能力差异。
- Java、Go、.NET、Android 客户端已支持登录响应驱动的 control/data TLS 与显式 CA/主机名覆盖；真实生产证书和 L4 TLS 终止仍需在目标部署环境验收。
- 自动化测试仍需要补充真实 MySQL、PostgreSQL 和端到端隧道覆盖。

## 开发入口

服务端下发 `NAT_CONTROL` 的管理接口见[下发端口映射](#3-下发端口映射)，客户端启动登录使用基于 apiKey/secret 的 HMAC-SHA256（secret 明文不上线）。协议字段和跨语言实现入口优先查看 [protocol/spec](protocol/spec/README.md)；Java 基准实现的服务端、客户端和公共协议分别位于 `implementations/java/server`、`implementations/java/client` 和 `implementations/java/common`。

## 许可证

本项目采用 [MIT License](LICENSE)。
