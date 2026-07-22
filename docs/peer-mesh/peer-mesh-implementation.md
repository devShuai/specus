# Peer Mesh 私有组网落地说明

本文记录当前跨语言 peer mesh 实现状态、部署开关、客户端启用方式和验收步骤。peer mesh 是并行能力，不改变现有公网 TCP 映射、HTTP route 和流量观测语义。

## 当前实现状态

已完成：

* 默认关闭：`TUNNEL_PEER_MESH_ENABLED=false`。
* 服务端按租户 / 用户 / 客户端维护 peer device、peer ACL、peer session。
* 默认 ACL：同一 `tenantId + ownerUsername` 的客户端互通；跨用户默认拒绝，admin 可配置显式 ACL。
* 客户端登录响应下发 `peerMesh` 配置，包括虚拟 IP、CIDR、标准 STUN/TURN 地址、公共 STUN 列表、会话 TTL 和设备公钥相关信息。
* v2 `control` 长连接承载 `PEER_CONTROL` JSON 信令；TCP/HTTP/WebSocket 数据只走独立 `data` 长连接。
* Java / Go / .NET 服务端内置标准 UDP STUN/TURN：支持 Binding、Allocate、Refresh、CreatePermission、Send Indication 和 Data Indication；relay 转发使用独立 UDP allocation 端口。
* Java STUN 核心支持 RFC 5780 四端点、`CHANGE-REQUEST`、`RESPONSE-PORT`、`PADDING`、标准 `MAPPED-ADDRESS` / `XOR-MAPPED-ADDRESS`、`RESPONSE-ORIGIN` 和 `OTHER-ADDRESS`；同一核心可由独立 `stun-server.jar` 部署，也可把 A1/A2 拆到两台内网互通的服务器，通过 HMAC 鉴权控制通道协同回包。
* Go 提供 `cmd/shuai-stun-server`，.NET 提供 `ShuaiTunnel.StunServer`；两者与 Java 使用同一套四端点、限流、防放大和 Prometheus 指标契约，可脱离业务 server 独立部署。
* Java / Go / .NET / Android 客户端可使用独立 STUN 入口执行 RFC 5780 映射与过滤行为探测，并上报 `natMappingBehavior`、`natFilteringBehavior` 和探测模式。
* relay 转发前会校验 session 是否存在、是否 ACTIVE、是否过期、source/target 是否匹配，拒绝未授权 relay frame。
* 客户端已实现 UDP host candidate、relay candidate、connectivity check、path nominated、direct 优先、relay fallback。
* 客户端数据面固定使用 `SPM2`：X25519 + 方向 HKDF + AES-GCM，36 字节外层开销；server relay 不解密业务明文。
* 客户端 replay 保护使用 4096 位滑动窗口，允许乱序并拒绝重复包和窗口外旧包。
* `SPMTU2` 在认证数据面上执行每路径探测、三次确认和二分搜索，结果缓存 10 分钟；IPv4 TCP SYN 会按路径 MTU clamp MSS，超大 IPv4 包向本地 TUN 注入 ICMP Fragmentation Needed。
* Linux TUN：支持 `/dev/net/tun`，配置虚拟 IP、MTU，并只为当前 roster 中的在线 peer 同步 `/32` host route。
* Windows Wintun：Java / Go / .NET 客户端均支持随包携带 `wintun.dll`，配置虚拟 IP、MTU，并同步在线 peer 的 `/32` host route。
* macOS utun：Java / Go / .NET 客户端均可创建 utun，并同步在线 peer 的 `/32` host route。
* 管理页“私有组网”展示设备、虚拟 IP、在线状态、NAT 类型、ACL、active session、direct/relay 路径、RTT 和流量；路径统计还展示 NAT 行为完整分类率及映射、过滤、探测方式分布。

多语言实现当前状态：

* Java client 是完整参考实现，Linux TUN、随包 Wintun 与 macOS utun 均已支持。
* Go server 已实现标准 STUN/TURN UDP relay：Binding、alternate port NAT 探测、Allocate/Refresh、CreatePermission、ChannelBind、Send/Data Indication、ChannelData、`SPM2` session 授权和 relay 字节计量；过期 allocation 会清理并由新 Allocate 重建。
* .NET server 已实现同一套 STUN/TURN 与 `SPM2` relay 规则，并提供公开 `/api/public/peer-mesh/stun-config` 用于 NAT 检测页面和外部探测。
* Go client 已支持 Linux TUN、随包 Windows Wintun、macOS utun、v2 X25519/HKDF/AES-GCM frame、direct UDP、标准 TURN relay、ChannelData 与路径 MTU 探测。
* .NET client 已支持 X25519 key 上报、v2 AES-GCM frame codec、4096 位 replay window、标准 STUN/TURN UDP 控制面、公共 STUN 候选、路径 MTU 探测，以及随包 Windows Wintun / Linux TUN / macOS utun packet 读写；Go / .NET / Android 均已补齐 RFC 5780 行为探测与设备上报，当前仍需要真实 Windows/Linux/macOS/Android 双机环境做 ping、HTTP 和 relay fallback 手工验收。

需要真实环境手工验收：

* 两台 Linux / Windows / macOS 客户端创建真实 TUN/Wintun/utun 后互 ping 虚拟 IP。
* 访问对端 TCP 服务，例如 `curl http://100.96.x.y:8080` 或 SSH 到对端虚拟 IP。
* 屏蔽 UDP direct 后确认自动切到 relay，恢复后确认回到 direct。
* 控制连接断开后确认新 session 不再创建，已建立 direct session 在密钥有效期内继续转发。

## 服务端配置

systemd 环境变量示例已在 `deploy/java-server/systemd/tunnel-server.env.example` 中维护。核心配置如下：

```env
TUNNEL_PEER_MESH_ENABLED=false
TUNNEL_PEER_MESH_CIDR=100.96.0.0/11
TUNNEL_PEER_MESH_PUBLIC_ADDRESS=tunnel.example.com
TUNNEL_PEER_MESH_STUN_TURN_PORT=3478
TUNNEL_PEER_MESH_STANDALONE_STUN_ADDRESS=stun1.tunnel.devshuai.com
TUNNEL_PEER_MESH_STANDALONE_STUN_PORT=34780
TUNNEL_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS=stun2.tunnel.devshuai.com
TUNNEL_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT=34781
TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT=3479
#TUNNEL_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS=10.0.0.10
#TUNNEL_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS=10.0.0.11
#TUNNEL_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS=203.0.113.11
#TUNNEL_PEER_MESH_STUN_BEHAVIOR_STRICT=true
TUNNEL_PEER_MESH_SESSION_TTL_SECONDS=3600
TUNNEL_PEER_MESH_ALLOCATION_TTL_SECONDS=300
```

说明：

* `TUNNEL_PEER_MESH_ENABLED`：总开关，生产默认保持 `false`，需要灰度时再启用。
* `TUNNEL_PEER_MESH_CIDR`：mesh 虚拟网段，默认 `100.96.0.0/11`。
* `TUNNEL_PEER_MESH_PUBLIC_ADDRESS`：UDP 探测和 relay 对外地址。完整 RFC 5780 模式下必须填写主公网 IP A1。
* `TUNNEL_PEER_MESH_STUN_TURN_PORT`：内置标准 STUN/TURN UDP 主端口，默认 `3478`。
* `TUNNEL_PEER_MESH_STANDALONE_STUN_ADDRESS`：可选独立 STUN 主域名或 IP；配置后客户端 STUN 探测优先使用该地址，认证 TURN 仍使用 `PUBLIC_ADDRESS`。
* `TUNNEL_PEER_MESH_STANDALONE_STUN_PORT`：独立 STUN 入口端口，默认 `3478`。
* `TUNNEL_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS`：独立 RFC 5780 拓扑的第二公网地址 A2；A2:P1 自动作为客户端备用 STUN，下发给网页和已登录客户端。
* `TUNNEL_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT`：独立 RFC 5780 拓扑的第二 UDP 端口 P2。示例双节点部署使用 `34781`。
* `TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT`：第二个 STUN UDP 端口 P2，默认 `3479`。备用端口只用于 Binding，不承载 TURN allocation。
* `TUNNEL_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS`：主地址 A1 的本机绑定 IP。
* `TUNNEL_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS`：备用地址 A2 的本机绑定 IP。
* `TUNNEL_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS`：与 A2 对应的备用公网 IP。
* `TUNNEL_PEER_MESH_STUN_BEHAVIOR_STRICT`：开启后必须提供完整 A1/A2 和 P1/P2 配置，否则内置 STUN/TURN 不启动。
* `TUNNEL_PEER_MESH_SESSION_TTL_SECONDS`：peer session 授权有效期。
* `TUNNEL_PEER_MESH_ALLOCATION_TTL_SECONDS`：relay allocation 有效期，客户端会提前 refresh。

启用后需要放行 UDP：

```bash
sudo firewall-cmd --add-port=3478/udp --permanent
sudo firewall-cmd --add-port=3479/udp --permanent
sudo firewall-cmd --reload
```

NAT 行为探测说明：

* 完整模式监听 A1:P1、A1:P2、A2:P1、A2:P2。Binding Success 同时返回 `MAPPED-ADDRESS` 和 `XOR-MAPPED-ADDRESS`。
* `RESPONSE-ORIGIN` 表示实际回包端点；`OTHER-ADDRESS` 始终表示相对请求目标的另一 IP + 另一端口。
* `CHANGE-REQUEST(change IP/change port)` 决定回包源端点，可用于探测 Endpoint-Independent、Address-Dependent 与 Address-and-Port-Dependent Filtering。
* `RESPONSE-PORT` 可把响应发往请求源 IP 的另一个 UDP 端口；`PADDING` 用于分片行为探测。两者同时出现时返回 `400`，PADDING 回包受配置上限约束以避免放大。
* 客户端分别向 A1:P1、A2:P1 和 A2:P2 发起 Binding，可比较映射地址，区分 Endpoint-Independent、Address-Dependent 与 Address-and-Port-Dependent Mapping。
* 只有一个公网 IP 时，服务端不返回标准 `OTHER-ADDRESS`，收到 `CHANGE-REQUEST` 返回 `420 Unknown Attribute`；此时只能做普通 Binding 和保守分类。

网页通过无需登录的 `GET /api/public/peer-mesh/nat-probe-config` 获取探测拓扑。完整配置会返回：

```json
{
  "available": true,
  "protocol": "RFC8489",
  "discoveryMethod": "RFC5780",
  "endpoints": [
    { "id": "A1P1", "url": "stun:stun1.tunnel.devshuai.com:34780" },
    { "id": "A1P2", "url": "stun:stun1.tunnel.devshuai.com:34781" },
    { "id": "A2P1", "url": "stun:stun2.tunnel.devshuai.com:34780" },
    { "id": "A2P2", "url": "stun:stun2.tunnel.devshuai.com:34781" }
  ],
  "capabilities": {
    "binding": true,
    "changeRequest": true,
    "responseOrigin": true,
    "otherAddress": true,
    "responsePort": true,
    "padding": true,
    "browserMappingObservation": true,
    "browserFilteringObservation": false
  }
}
```

网页先分别预检四端点，再让同一个 WebRTC ICE socket 访问四端点并比较公网映射。
浏览器 API 不能构造 `CHANGE-REQUEST`，因此网页只报告映射行为；EIF / ADF / APDF
过滤行为必须由 Java / Go / .NET / Android 原生探针补全。若 A2/P2 未配置或任一端点
预检失败，页面会降级到基础多 STUN 模式，不会把超时误判为过滤类型。

生产环境中，`stun1.tunnel.devshuai.com` 必须只解析到 A1（ali2，
`47.103.154.117`），`stun2.tunnel.devshuai.com` 必须只解析到 A2（ali，
`101.133.236.111`）。两个域名解析到同一公网 IP 时不能完成 RFC 5780 跨地址探测。

如果 STUN 不应与业务服务共进程，可选择 Java
[`implementations/java/stun-server`](../../implementations/java/stun-server)、Go
`implementations/go/server/cmd/shuai-stun-server` 或 .NET
`implementations/csharp/server/src/ShuaiTunnel.StunServer`。systemd、限流、指标、DNS 和双公网 IP
示例见 [`deploy/stun-server/systemd`](../../deploy/stun-server/systemd/README.md)。Java
实现还支持两台单公网 IP 服务器组成完整 RFC 5780 拓扑；部署入口见
[`deploy/stun-server/remote`](../../deploy/stun-server/remote/README.md)。独立服务不包含 TURN，
tunnel-server 的认证 TURN 仍可单独作为直连失败后的备用通道。

## 客户端配置

客户端仍使用 HTTP 登录配置文件 `client.jsonc`（JSONC）。peer mesh 虚拟网卡由客户端配置控制，默认 `noop` 不接管本机路由。

```json
{
  "serverBaseUrl": "http://127.0.0.1:8088",
  "apiKey": "YOUR_CLIENT_API_KEY",
  "secret": "YOUR_CLIENT_SECRET",
  "peerMeshDevice": "noop",
  "peerMeshTunName": "shuai0",
  "peerMeshMtu": 1280
}
```

`peerMeshDevice` 可选值：

* `noop`：默认值，只做控制面、候选交换、UDP 探测、加密 frame 数据面，不创建虚拟网卡。
* `linux-tun`：Linux 使用 `/dev/net/tun` 创建 TUN。
* `windows-wintun` 或 `wintun`：Windows 使用 Wintun。
* `mac-utun` 或 `utun`：Java 客户端可在 macOS 使用 utun；配置 `peerMeshTunName=utun5` 时会尽量请求固定编号，否则由系统自动分配 `utunN`。
* `utun`、`macos-utun` 或 `darwin-utun`：Go / .NET 客户端可在 macOS 使用 utun。
* `auto`：Java 参考客户端会按当前操作系统选择 Linux TUN、Windows Wintun 或 macOS utun；Go / .NET 客户端也会在 macOS 选择 utun，不支持的平台回退 noop。

`peerMeshMtu` 与 Java 参考实现保持一致，客户端会归一化到 `576..1280`。示例使用 `1280`，为 UDP 封装、AES-GCM tag 和公网路径预留空间，降低分片导致的丢包概率。

Linux 启动条件：

```bash
sudo modprobe tun
sudo java -jar tunnel-client.jar
```

如果不想用 root，可给 Java 运行文件授予能力，实际命令按发行版和 Java 路径调整：

```bash
sudo setcap cap_net_admin+ep /path/to/java
```

Windows 启动条件：

* 使用管理员权限运行客户端。
* Java / Go / .NET 客户端发布包会携带 `native/windows/<arch>/wintun.dll`。
* 如果要覆盖随包版本，Java 可使用系统属性显式指定：

```powershell
java -Dshuai.peerMesh.wintunDll=C:\path\to\wintun.dll -jar tunnel-client.jar
```

Go / .NET 客户端可使用环境变量覆盖：

```powershell
$env:SHUAI_PEER_MESH_WINTUN_DLL="C:\path\to\wintun.dll"
```

## 验收步骤

### 1. 服务端启用

```env
TUNNEL_PEER_MESH_ENABLED=true
TUNNEL_PEER_MESH_PUBLIC_ADDRESS=你的公网IP或域名
TUNNEL_PEER_MESH_STUN_TURN_PORT=3478
```

重启后检查日志：

```bash
journalctl -u tunnel-server -f
```

期望看到标准 STUN/TURN UDP server 监听成功。

### 2. 启动两个同用户客户端

两个客户端使用同一用户下不同客户端凭证登录。管理页“私有组网”应看到：

* 两个设备在线。
* 每个设备分配了不同虚拟 IP。
* ACL 默认允许同用户互访。

### 3. 验证 direct

在客户端 A：

```bash
ping 100.96.x.y
```

其中 `100.96.x.y` 是客户端 B 的虚拟 IP。管理页 active session 应显示：

* `pathType=DIRECT`
* RTT 有值
* direct bytes 增加

### 4. 验证 relay fallback

临时屏蔽两端之间 UDP direct，只保留到 server `3478/udp` 的连通性，再次访问对端虚拟 IP。管理页应显示：

* `pathType=RELAY`
* relay bytes 增加
* 业务不中断或自动恢复

### 5. 验证跨用户隔离

使用另一个用户的客户端尝试访问当前用户虚拟 IP，默认应失败。admin 添加显式 ACL 后再测试，应能创建 session 并访问。

## 常见问题

### 管理页看到设备但 ping 不通

先确认客户端没有使用 `peerMeshDevice=noop`。noop 模式不会创建虚拟网卡，也不会安装在线 peer 的 `/32` host route，因此系统 `ping` / `curl` 不会把虚拟 IP 流量交给 peer mesh。

### Linux 创建 TUN 失败

确认：

* 进程有 root 或 `CAP_NET_ADMIN`。
* `/dev/net/tun` 存在。
* 系统有 `ip` 命令。
* `peerMeshTunName` 没有和现有网卡冲突。

### Windows Wintun 加载失败

确认：

* 管理员权限启动。
* `wintun.dll` 位数和当前进程架构一致。
* 发布包内存在 `native/windows/<arch>/wintun.dll`。Go 客户端会先把内置资源解压到本地缓存再加载；.NET 客户端会在 build / publish 输出目录带上该 native 目录。
* 如果需要覆盖，Java 通过 `-Dshuai.peerMesh.wintunDll=完整路径` 指定，Go / .NET 通过 `SHUAI_PEER_MESH_WINTUN_DLL` 指定。

### 一直走 relay

说明 direct candidate 没有通过 connectivity check，常见原因是两端 NAT / 防火墙阻断 UDP。只要 server UDP relay 可达，业务仍可转发，但延迟和服务端带宽成本会上升。

### relay 被拒绝

服务端会拒绝未授权、过期、source/target 不匹配或非 ACTIVE session 的 relay frame。检查客户端是否重新登录、session 是否过期、ACL 是否允许。

## 后续可增强

* 真实 macOS / Windows / Linux 多端互通和 relay fallback 压测。
* .NET server / .NET client 继续做真实跨 NAT 压测，验证 direct 失败后的标准 TURN relay fallback、relay 计量和管理展示。
* 客户端侧更细粒度的 direct / relay 统计签名上报。
* 管理页拓扑图动画和 session 时间线。

## 相关记录

* Java 客户端打洞审计与修复(2026-07,含 roster 候选保留、keepalive burst、endpoint 粘滞、广播去重、`/api/admin/peer-mesh/stats` 聚合统计):`docs/peer-mesh/peer-mesh-java-client-audit-fixes.md`
