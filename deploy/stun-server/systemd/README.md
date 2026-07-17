# 独立 RFC 5780 STUN Server 部署

独立服务提供 Java、Go、.NET 三种运行时，只处理 UDP STUN Binding 与 RFC 5780
行为探测，不启动 tunnel-server、数据库、业务 HTTP、WebSocket 或 TURN。三种
实现共用单机四端点、限流、防放大和 Prometheus 指标契约。Java 另外支持把 A1/A2
拆到两台内网互通、各只有一个公网 IP 的服务器。

## 1. 网络拓扑

### 1.1 单机四端点

完整区分 NAT 映射和过滤行为需要四个端点：

| 端点 | 本地绑定 | 对外地址 |
| --- | --- | --- |
| A1:P1 | `10.0.0.10:3478` | `203.0.113.10:3478` |
| A1:P2 | `10.0.0.10:3479` | `203.0.113.10:3479` |
| A2:P1 | `10.0.0.11:3478` | `203.0.113.11:3478` |
| A2:P2 | `10.0.0.11:3479` | `203.0.113.11:3479` |

两张本地地址必须同时存在于运行服务的主机。云环境可以给两张私网 IP
分别绑定一个 EIP，要求出站源地址也保持对应的 1:1 映射。两个公网 IP
都要放行 `3478/udp` 和 `3479/udp`。

### 1.2 Java 双节点四端点

两台服务器各有一个公网 IP 且内网互通时，可把地址槽拆开：

| 节点 | 本地职责 | 公网端点 | 内网控制端点 |
| --- | --- | --- | --- |
| A1 节点 | `primary` 地址槽 | A1:P1、A1:P2 | `10.0.0.10:3480` |
| A2 节点 | `alternate` 地址槽 | A2:P1、A2:P2 | `10.0.1.10:3480` |

收到请求的节点仍在本地完成 STUN 解析、限流和 Binding Response 构造。如果
`CHANGE-REQUEST` 指定的源地址属于另一节点，本机通过私网控制通道发送完整响应和
目标地址，对端再从正确的 P1/P2 socket 回包。控制报文使用 HMAC-SHA256、时间戳、
nonce 防重放、固定对端地址校验、长度限制和独立 token bucket。

公网只开放两台机器各自的 `3478/udp`、`3479/udp`。内网 `3480/udp` 必须只允许
另一台节点的私网 IP，禁止公网访问。两台机器还必须保持时钟同步；默认允许 30 秒
偏差。Java 一键部署示例见
[`deploy/stun-server/remote`](../remote/README.md)。

端口号可以配置。若独立服务与 `tunnel-server` 同机，必须避开后者已有的
STUN/TURN 端口，例如让独立 STUN 使用 `34780/udp`、`34781/udp`，继续保留
`3478/udp` 给认证 TURN。安装和更新脚本会在替换文件前检查端口占用。

## 2. 构建

### Java JAR

```bash
mvn -pl :stun-server -am clean package
```

产物：

```text
implementations/java/stun-server/target/stun-server.jar
```

该 JAR 已包含运行需要的共享 STUN 类，可以脱离 tunnel-server 单独运行。

### Go 单文件

```bash
cd implementations/go/server
go test ./internal/stunserver
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
  -o shuai-stun-server ./cmd/shuai-stun-server
```

产物为不依赖 Java/.NET runtime 的 `shuai-stun-server`。

### .NET

Framework-dependent 发布：

```bash
dotnet publish \
  implementations/csharp/server/src/ShuaiTunnel.StunServer/ShuaiTunnel.StunServer.csproj \
  -c Release -o out/stun-dotnet
```

Linux x64 自包含单文件：

```bash
dotnet publish \
  implementations/csharp/server/src/ShuaiTunnel.StunServer/ShuaiTunnel.StunServer.csproj \
  -c Release -r linux-x64 --self-contained true \
  -p:PublishSingleFile=true -p:PublishTrimmed=false \
  -o out/stun-dotnet-linux-x64
```

## 3. 安装

### Java

```bash
sudo bash deploy/stun-server/systemd/install.sh \
  implementations/java/stun-server/target/stun-server.jar
sudo vim /etc/shuai-stun-server/stun-server.env
```

填写真实地址后先校验配置：

```bash
sudo -u stun bash -c '
  set -a
  source /etc/shuai-stun-server/stun-server.env
  set +a
  java $JAVA_OPTS -jar /opt/shuai-stun-server/stun-server.jar --check-config
'
```

再启动：

```bash
sudo systemctl start stun-server
sudo systemctl status stun-server
sudo journalctl -u stun-server -f
sudo ss -lunp | grep -E ':(3478|3479)\b'
```

若已经准备好节点环境文件，可把它作为第二个参数传入。脚本会在安装前校验配置，
安装后直接 enable/start，并检查 systemd 和 Prometheus 指标：

```bash
sudo bash deploy/stun-server/systemd/install.sh \
  /tmp/stun-server.jar /tmp/stun-server.env
```

`ExecStartPre` 每次启动都会执行一次 `--check-config`。如果四端点缺失、两个
公网 IP 相同、端口重复、地址族不一致，或者双节点控制配置不完整，systemd 会在
监听前直接失败。

双节点模式的 A1 环境文件核心配置：

```env
STUN_PRIMARY_PUBLIC_ADDRESS=203.0.113.10
STUN_ALTERNATE_PUBLIC_ADDRESS=198.51.100.10
STUN_PRIMARY_PORT=3478
STUN_ALTERNATE_PORT=3479
STUN_DISTRIBUTED_ENABLED=true
STUN_DISTRIBUTED_LOCAL_ADDRESS_SLOT=primary
STUN_DISTRIBUTED_STUN_BIND_ADDRESS=0.0.0.0
STUN_DISTRIBUTED_CONTROL_BIND_ADDRESS=10.0.0.10
STUN_DISTRIBUTED_CONTROL_PORT=3480
STUN_DISTRIBUTED_PEER_CONTROL_ADDRESS=10.0.1.10
STUN_DISTRIBUTED_PEER_CONTROL_PORT=3480
STUN_DISTRIBUTED_SHARED_SECRET=BASE64_SECRET_AT_LEAST_32_BYTES
```

A2 使用相同公网地址、端口和密钥，把 `LOCAL_ADDRESS_SLOT` 改为 `alternate`，
并交换本机/对端控制地址。此模式目前仅由 Java 独立 STUN 二进制实现。

### Go

```bash
sudo install -d -m 0755 /opt/shuai-stun-server
sudo install -m 0755 implementations/go/server/shuai-stun-server \
  /opt/shuai-stun-server/shuai-stun-server
sudo install -m 0644 deploy/stun-server/systemd/stun-server-go.service \
  /etc/systemd/system/stun-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now stun-server
```

### .NET

把 framework-dependent publish 目录复制到
`/opt/shuai-stun-server/dotnet/`，并安装
`stun-server-dotnet.service`。若使用自包含单文件，把 unit 中的
`/usr/bin/dotnet ...dll` 替换为发布出的可执行文件路径。

任一运行时都使用 `/etc/shuai-stun-server/stun-server.env`。同一台机器只应
启用一个 `stun-server.service`，避免四个 UDP 端点和 `9108/tcp` 指标端口冲突。

## 4. 同一个 STUN 域名

最简单的配置是让域名只指向入口 A1：

```dns
stun.example.com. 300 IN A 203.0.113.10
_stun-behavior._udp.example.com. 300 IN SRV 0 0 3478 stun.example.com.
```

客户端先访问 `stun.example.com:3478`，服务端通过标准
`OTHER-ADDRESS` 告知 A2:P2，因此不需要为第二个公网 IP 单独配置客户端域名。
也可以让同一域名同时返回 A1/A2；服务对四个端点均可接收请求，并会以请求
实际到达的 IP/端口为基准计算 `OTHER-ADDRESS`。

双节点模式下通常仍让域名只指向 A1。A2 不是休眠备用机，而是完整行为探测必须
在线的第二地址槽。任一节点故障时，存活节点仍可提供普通 Binding，但无法完成
跨地址的完整映射和过滤行为分类。

在 tunnel-server 中把原生客户端和公开 NAT 检测页指向该独立入口：

```env
TUNNEL_PEER_MESH_STANDALONE_STUN_ADDRESS=stun1.tunnel.devshuai.com
TUNNEL_PEER_MESH_STANDALONE_STUN_PORT=34780
TUNNEL_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS=stun2.tunnel.devshuai.com
TUNNEL_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT=34781
```

主地址和主端口替换登录配置中的 `stunHost/stunPort`；备用地址会以主端口 P1
自动加入登录配置和公开 ICE 配置的备用 STUN 列表。四个变量共同为
`GET /api/public/peer-mesh/nat-probe-config` 生成 A1:P1、A1:P2、A2:P1、A2:P2，
供网页执行端点预检和共享 ICE 映射观测。认证 TURN 继续使用
`TUNNEL_PEER_MESH_PUBLIC_ADDRESS:TUNNEL_PEER_MESH_STUN_TURN_PORT`，
因此 STUN 与 TURN 可以独立扩容、独立部署和独立维护。

生产域名 `stun1.tunnel.devshuai.com` 解析到 A1（ali2，`47.103.154.117`），
`stun2.tunnel.devshuai.com` 解析到 A2（ali，`101.133.236.111`）。两个域名必须
解析到不同公网 IP。STUN 响应中的 `RESPONSE-ORIGIN`、`OTHER-ADDRESS` 以及
双节点服务自身配置仍使用 A1/A2 的真实公网 IP。

## 5. 单公网 IP 兼容模式

不配置 `STUN_ALTERNATE_BIND_ADDRESS` 和
`STUN_ALTERNATE_PUBLIC_ADDRESS` 时，服务仍可作为普通 STUN Binding
server 使用。此模式不会返回 `OTHER-ADDRESS`，收到 `CHANGE-REQUEST`
会按 RFC 5780 返回 `420 Unknown Attribute`，因此不能完整区分 NAT
映射与过滤行为。

`STUN_LEGACY_SINGLE_IP_OTHER_ADDRESS=true` 仅用于兼容 shuai-tunnel
旧版单 IP / 双端口探测，不应作为公开 RFC 5780 服务配置。

## 6. Java 脚本更新

```bash
sudo bash deploy/stun-server/systemd/update.sh /tmp/stun-server.jar
```

只传 JAR 时继续复用服务器现有配置。需要让程序和配置作为同一个版本更新时：

```bash
sudo bash deploy/stun-server/systemd/update.sh \
  /tmp/stun-server.jar /tmp/stun-server.env
```

脚本默认保留最近 5 个完整备份；每个备份同时包含 JAR、环境文件和 systemd
unit。新进程不能通过配置校验、无法绑定 UDP 端点或指标检查失败时，会恢复整套
上一版。可通过 `STUN_BACKUP_KEEP` 和 `STUN_ACTIVE_TIMEOUT_SEC` 调整保留数量与
启动等待时间。

首次安装和更新也可统一调用：

```bash
sudo bash deploy/stun-server/systemd/deploy.sh \
  /tmp/stun-server.jar /tmp/stun-server.env
```

Windows 本地一键构建并部署 `ali2` 主节点和 `ali` 备用节点，见
[`deploy/stun-server/remote`](../remote/README.md)。

Go 和 .NET 建议采用相同流程：先运行新产物的 `--check-config`，停止服务，
原子替换产物，启动后检查 systemd active 状态和 `/metrics`，失败则恢复备份。

## 7. RESPONSE-PORT 与 PADDING

三种独立服务均实现：

* `RESPONSE-PORT (0x0027)`：Binding Response 发往请求源 IP 和属性指定端口。
  属性长度必须为 2，端口 0 因无法作为 UDP 目的端口而返回 `400`。
* `PADDING (0x0026)`：Binding Response 必定包含 PADDING；返回长度不超过请求
  PADDING、收到的数据报和 `STUN_MAX_PADDING_RESPONSE_BYTES` 三者的最小值。
* 同时携带 `RESPONSE-PORT` 与 `PADDING` 的请求返回 `400`，防止定向放大。
* 单个 UDP 响应不会超过 65507 字节；解析器不会按报文声明值分配超过实际收到
  数据报的属性内存。

## 8. 应用与内核防护

应用层默认启用两级 token bucket：

| 环境变量 | 默认 | 说明 |
| --- | ---: | --- |
| `STUN_RATE_LIMIT_PER_SECOND` | 100 | 单源 IP 持续请求数/秒 |
| `STUN_RATE_LIMIT_BURST` | 200 | 单源 IP 突发 token |
| `STUN_GLOBAL_RATE_LIMIT_PER_SECOND` | 10000 | 进程全局持续请求数/秒 |
| `STUN_GLOBAL_RATE_LIMIT_BURST` | 20000 | 进程全局突发 token |
| `STUN_MAX_TRACKED_SOURCES` | 65536 | 来源 IP 状态表硬上限 |
| `STUN_SOURCE_IDLE_SECONDS` | 300 | 来源状态空闲回收时间 |
| `STUN_MAX_PACKET_BYTES` | 65507 | 接受的 UDP payload 上限 |
| `STUN_MAX_PADDING_RESPONSE_BYTES` | 1472 | PADDING 回包值上限 |

来源按 IP 而不是 `IP:port` 计数，攻击者轮换源端口不会绕过单源限流。来源表满后
拒绝新来源，不再无界扩容。应用限流之前建议继续使用云安全组、DDoS 防护和内核
包过滤；[`nftables-stun-protection.example.nft`](nftables-stun-protection.example.nft)
提供了 invalid packet、单源和全局 UDP 速率模板。内核阈值应高于应用阈值，避免
正常突发在进入应用前被误杀。

## 9. 指标与告警

默认在 `127.0.0.1:9108/metrics` 提供 Prometheus 文本指标，设置
`STUN_METRICS_PORT=0` 可关闭。主要指标：

* `stun_packets_received_total`、`stun_requests_accepted_total`
* `stun_packets_dropped_total{reason=...}`
* `stun_responses_total{code="200|400|420"}`
* `stun_feature_requests_total{feature="change_request|response_port|padding"}`
* `stun_bytes_received_total`、`stun_bytes_sent_total`
* `stun_tracked_sources`、`stun_uptime_seconds`
* `stun_distributed_forward_total{event="sent|received|..."}`，仅 Java 双节点模式

不要直接把指标端口暴露到公网；由本机 Prometheus agent 抓取，或经认证反向代理
访问。可直接加载 [`prometheus-rules.yml`](prometheus-rules.yml) 监控服务失联、
有请求无成功响应、限流比例、畸形报文、来源表容量、控制报文拒绝和节点间转发
中断。

业务侧 `/api/admin/peer-mesh/stats` 额外返回
`natBehaviorDevices`、`natBehaviorClassifiedDevices`、
`natBehaviorSuccessRatio`、映射/过滤行为和探测方式分布。管理后台“私有组网”
页面会展示完整分类率及分类结果，用于区分“STUN 服务正常但客户端环境无法完整
探测”和“服务端无响应”两类故障。
