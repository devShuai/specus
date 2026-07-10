# Peer Mesh 私有组网落地说明

本文记录当前 Java `tunnel-server` / `tunnel-client` 的 peer mesh 实现状态、部署开关、客户端启用方式和验收步骤。peer mesh 是并行能力，不改变现有公网 TCP 映射、HTTP route 和流量观测语义。

## 当前实现状态

已完成：

* 默认关闭：`TUNNEL_PEER_MESH_ENABLED=false`。
* 服务端按租户 / 用户 / 客户端维护 peer device、peer ACL、peer session。
* 默认 ACL：同一 `tenantId + ownerUsername` 的客户端互通；跨用户默认拒绝，admin 可配置显式 ACL。
* 客户端登录响应下发 `peerMesh` 配置，包括虚拟 IP、CIDR、标准 STUN/TURN 地址、公共 STUN 列表、会话 TTL 和设备公钥相关信息。
* 控制协议通过现有控制长连接承载 `PEER_CONTROL` JSON 信令，不破坏现有 NAT / HTTP 协议。
* Java / Go / .NET 服务端内置标准 UDP STUN/TURN：支持 Binding、Allocate、Refresh、CreatePermission、Send Indication 和 Data Indication；relay 转发使用独立 UDP allocation 端口。
* relay 转发前会校验 session 是否存在、是否 ACTIVE、是否过期、source/target 是否匹配，拒绝未授权 relay frame。
* 客户端已实现 UDP host candidate、relay candidate、connectivity check、path nominated、direct 优先、relay fallback。
* 客户端数据面使用 X25519 + HKDF + AES-GCM，加密后的 IP packet 通过 UDP frame 传输；server relay 不解密业务明文。
* 客户端 replay 保护使用滑动窗口，允许小范围乱序，拒绝重复包和窗口外旧包。
* Linux TUN：支持 `/dev/net/tun`，配置虚拟 IP、MTU，并只为当前 roster 中的在线 peer 同步 `/32` host route。
* Windows Wintun：Java / Go / .NET 客户端均支持随包携带 `wintun.dll`，配置虚拟 IP、MTU，并同步在线 peer 的 `/32` host route。
* macOS utun：Java / Go / .NET 客户端均可创建 utun，并同步在线 peer 的 `/32` host route。
* 管理页“私有组网”展示设备、虚拟 IP、在线状态、NAT 类型、ACL、active session、direct/relay 路径、RTT 和流量。

多语言实现当前状态：

* Java client 是完整参考实现，Linux TUN、随包 Wintun 与 macOS utun 均已支持。
* Go server 已补齐 Java 兼容标准 STUN/TURN UDP relay：Binding、alternate port NAT 探测、Allocate/Refresh、CreatePermission、Send/Data Indication、`SPM1` frame relay 授权和 relay 字节计量；过期 allocation 按 Java 语义清理并由新 Allocate 重建。
* .NET server 已补齐 Java 兼容标准 STUN/TURN UDP relay：Binding、alternate port NAT 探测、Allocate/Refresh、CreatePermission、Send/Data Indication、`SPM1` frame relay 授权和 relay 字节计量；同时提供公开 `/api/public/peer-mesh/stun-config` 用于 NAT 检测页面和外部探测。
* Go client 已支持 Linux TUN、随包 Windows Wintun、macOS utun、Java 兼容 X25519/HKDF/AES-GCM frame、direct UDP 与标准 TURN relay data indication。
* .NET client 已补 X25519 key 上报、Java 兼容 AES-GCM frame codec、replay window、标准 STUN/TURN UDP 控制面、公共 STUN 候选，以及随包 Windows Wintun / Linux TUN / macOS utun packet 读写；当前仍需要真实 Windows/Linux/macOS 双机环境做 ping、HTTP 和 relay fallback 手工验收。

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
TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT=0
TUNNEL_PEER_MESH_SESSION_TTL_SECONDS=3600
TUNNEL_PEER_MESH_ALLOCATION_TTL_SECONDS=300
```

说明：

* `TUNNEL_PEER_MESH_ENABLED`：总开关，生产默认保持 `false`，需要灰度时再启用。
* `TUNNEL_PEER_MESH_CIDR`：mesh 虚拟网段，默认 `100.96.0.0/11`。
* `TUNNEL_PEER_MESH_PUBLIC_ADDRESS`：UDP 探测和 relay 对外地址。服务器在 NAT 后面时必须显式配置。
* `TUNNEL_PEER_MESH_STUN_TURN_PORT`：内置标准 STUN/TURN UDP 主端口，默认 `3478`。
* `TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT`：NAT 类型辅助探测 UDP 端口。默认 `0` 表示使用 `STUN/TURN 端口 + 1`，即 `3479`。备用端口只用于 Binding 探测，不承载 relay allocation。
* `TUNNEL_PEER_MESH_SESSION_TTL_SECONDS`：peer session 授权有效期。
* `TUNNEL_PEER_MESH_ALLOCATION_TTL_SECONDS`：relay allocation 有效期，客户端会提前 refresh。

启用后需要放行 UDP：

```bash
sudo firewall-cmd --add-port=3478/udp --permanent
sudo firewall-cmd --add-port=3479/udp --permanent
sudo firewall-cmd --reload
```

NAT 类型探测说明：

* 客户端先向主端口发送 binding，服务端返回映射地址和备用探测端口。
* 服务端会从备用端口向同一个客户端映射主动回包，客户端也会主动向备用端口再发送一次 binding。
* 如果主端口和备用端口看到的映射端点不同，页面展示为 `Symmetric NAT`。
* 如果映射端点相同且能收到备用端口主动回包，页面展示为 `Full cone / Restricted NAT`。在只有一个公网 IP 的部署里，无法严格拆分 Full Cone 与 Address-Restricted NAT。
* 如果映射端点相同但收不到备用端口主动回包，页面展示为 `Port Restricted NAT` 或更保守的 `NAT`。

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
