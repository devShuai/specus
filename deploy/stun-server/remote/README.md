# 双节点分布式 STUN 部署

此目录用于从 Windows 本地一次构建 Java 独立 STUN server，并部署到两台
内网互通、各有一个公网 IP 的服务器：

| 地址槽 | 部署角色 | SSH 别名 | 公网 IP | 内网控制 IP |
| --- | --- | --- | --- | --- |
| A1 | `primary` | `ali2` | `primaryPublicAddress` | 本机 `distributedControlBindAddress` |
| A2 | `standby` | `ali` | `alternatePublicAddress` | 本机 `distributedControlBindAddress` |

`standby` 是部署角色名称，不表示服务处于休眠状态。完整 RFC 5780 探测期间，
A1 和 A2 都持续提供服务。每台机器监听自己公网地址对应的 P1/P2 UDP 端口；
需要从另一公网地址回包时，通过内网 `3480/udp` 把已生成的 STUN
响应交给对端发送。

控制报文包含 HMAC-SHA256、`keyId`、时间戳、发送进程 epoch 和单调 sequence，
并校验来源 IP/端口、滑动重放窗口、最大报文和独立限速。`3480/udp` 只允许两台机器的内网 IP 互访，不能
暴露到公网。

## 1. 准备配置

真实配置文件为：

```text
deploy/stun-server/remote/stun-deploy.config.json
```

它已加入 `.gitignore`，用于保存服务器地址和共享密钥。新环境可从示例复制：

```powershell
Copy-Item `
  .\deploy\stun-server\remote\stun-deploy.config.example.json `
  .\deploy\stun-server\remote\stun-deploy.config.json
```

示例中的公网和内网地址都是文档占位值。共享密钥必须是至少 32 字节随机数据的
标准 Base64，可以这样生成：

```powershell
$bytes = New-Object byte[] 48
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($bytes)
    [Convert]::ToBase64String($bytes)
} finally {
    $rng.Dispose()
}
```

两节点必须配置完全相同的公网 A1/A2、端口、共享密钥和控制通道安全参数，只交换
以下三项：

```json
{
  "distributedLocalAddressSlot": "primary",
  "distributedControlBindAddress": "本机内网 IP",
  "distributedPeerControlAddress": "对端内网 IP"
}
```

当前本地配置已按两台服务器的实际公网和内网地址准备完成。SSH 用户、端口和
密钥继续放在 `~/.ssh/config` 的 `ali2`、`ali` 别名中。

客户端主入口使用 `stun1.tunnel.devshuai.com:34780`，解析到 A1（ali2，
`47.103.154.117`）；备用入口使用 `stun2.tunnel.devshuai.com:34780`，解析到
A2（ali，`101.133.236.111`）。两个域名必须解析到不同公网 IP。
`primaryPublicAddress` 和 `alternatePublicAddress` 必须继续填写真实公网 IP，
因为 RFC 5780 响应属性需要编码 IP 地址，不能改成域名。

## 2. 网络要求

两台服务器都需要：

```text
公网入站: primaryPort/udp, alternatePort/udp
内网入站: 3480/udp，仅允许另一台服务器的内网 IP
指标端口: 127.0.0.1:9108，仅本机
```

若独立 STUN 与现有 `tunnel-server` 部署在同一台机器，P1/P2 不能与其
STUN/TURN 监听端口冲突。本项目生产配置使用 `34780/udp`、`34781/udp`，保留
`3478/udp` 给现有认证 TURN。部署脚本会在上传 JAR 前检查 UDP 业务端口、内网
控制端口和指标端口，并打印冲突监听进程。

此外应满足：

- 两台服务器的内网路由双向可达。
- 主机防火墙和云安全组都允许对端访问 `3480/udp`。
- 两台机器启用 NTP/chrony，系统时钟差小于
  `distributedMaxClockSkewSeconds`，默认 30 秒。
- 两个公网 IP 的出站 SNAT 保持各自地址，不能统一从同一个 NAT 地址出站。

主域名只需指向 A1：

```dns
stun.example.com. 300 IN A 203.0.113.10
_stun-behavior._udp.example.com. 300 IN SRV 0 0 P1 stun.example.com.
```

客户端从 A1 的响应中读取标准 `OTHER-ADDRESS`，再访问 A2。也可以把 A2 作为
客户端的备用普通 STUN 地址；任一节点离线时仍可做基础 Binding，但完整映射和
过滤行为分类要求两台节点都在线。

## 3. 校验与预演

只校验 JSON、角色、地址、端口、成对关系和安全约束：

```powershell
.\deploy\stun-server\remote\deploy.ps1 -ValidateOnly
```

使用示例配置校验：

```powershell
.\deploy\stun-server\remote\deploy.ps1 `
  -ConfigPath .\deploy\stun-server\remote\stun-deploy.config.example.json `
  -ValidateOnly
```

打印构建、上传和远端执行命令，但不连接服务器：

```powershell
.\deploy\stun-server\remote\deploy.ps1 -DryRun
```

脚本会拒绝：

- 缺少或重复的 `primary` / `standby` 角色；
- 非法 SSH 别名、IP 字面量、端口或 JVM 参数；
- A1/A2 公网 IP 相同、地址族不一致或两个节点配置不一致；
- 控制通道使用公网、回环、通配地址或 STUN 业务端口；
- 控制地址没有互相指向；
- 共享密钥不是 32 到 256 字节的标准 Base64；
- 真实部署仍使用示例公网地址或公开示例密钥；
- Prometheus 指标绑定到非回环地址。

## 4. 执行部署

首次部署或需要同步程序与配置时，优先一次部署两台节点：

```powershell
.\deploy\stun-server\remote\deploy.ps1 -Target All
```

自动化执行：

```powershell
.\deploy\stun-server\remote\deploy.ps1 -Target All -Yes
```

只修复其中一台：

```powershell
.\deploy\stun-server\remote\deploy.ps1 -Target Primary -Yes
.\deploy\stun-server\remote\deploy.ps1 -Target Standby -Yes
```

只修改配置并复用现有 JAR：

```powershell
.\deploy\stun-server\remote\deploy.ps1 -Target Standby -SkipBuild -Yes
```

`-NoClean` 仅用于 Maven `clean` 因本地文件锁失败时显式回退到 `package`。
`-KeepRemoteTemp` 会保留成功部署后的远端 `/tmp/shuai-stun-deploy-*` 文件。

## 5. 部署行为

脚本按以下顺序工作：

1. 校验整对配置，并为 A1/A2 生成不同的无 BOM systemd 环境文件。
2. 运行 `mvn -pl :stun-server -am -Dmaven.test.skip=true clean package`。
3. 部署 A1，先检查端口占用，再检查配置、systemd active 和 Prometheus 指标。
4. 部署 A2，执行同样检查。
5. 更新失败时，在失败节点恢复旧 JAR、环境文件和 systemd unit。
6. 每台机器保留最近 `deployment.backupKeep` 个完整备份。

单节点本地健康检查不能证明对端控制通道已经可用。部署完成后应检查两台机器：

```bash
systemctl is-active stun-server
ss -lunp | grep -E ':(34780|34781|3480)\b'
curl --noproxy '*' -fsS http://127.0.0.1:9108/metrics \
  | grep stun_distributed_forward_total
```

执行一次包含 `CHANGE-REQUEST(change IP)` 的公网探测后，预期一侧出现
`event="sent"`，另一侧出现 `event="received"`。若只有 `sent`，优先检查
`3480/udp` 安全组、主机防火墙、内网路由、时钟同步和共享密钥。

## 6. 配置字段

`defaults` 中的值可由节点使用同名字段覆盖。

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `primaryPublicAddress` | 必填 | A1 公网 IP |
| `alternatePublicAddress` | 必填 | A2 公网 IP |
| `primaryPort` / `alternatePort` | `3478` / `3479` | P1/P2 公网 UDP 端口 |
| `distributedEnabled` | `false` | 启用 Java 双节点模式 |
| `distributedStunBindAddress` | `0.0.0.0` | 本机 P1/P2 绑定地址 |
| `distributedLocalAddressSlot` | 节点必填 | A1 使用 `primary`，A2 使用 `alternate` |
| `distributedControlBindAddress` | 节点必填 | 本机内网控制 IP |
| `distributedPeerControlAddress` | 节点必填 | 对端内网控制 IP |
| `distributedControlPort` | `3480` | 本机控制 UDP 端口 |
| `distributedPeerControlPort` | 同本机端口 | 对端控制 UDP 端口 |
| `distributedCurrentKeyId` | 必填 | 当前 HMAC 密钥的正整数 ID |
| `distributedCurrentSecret` | 必填 | 当前 32 到 256 字节 Base64 HMAC 密钥 |
| `distributedPreviousKeyId` / `distributedPreviousSecret` | 空 | 轮换期间临时保留的上一把密钥；必须成对配置 |
| `distributedMaxClockSkewSeconds` | `30` | 控制报文允许的最大时钟偏差 |
| `distributedReplayWindowSize` | `4096` | 每个发送 epoch 的乱序/防重放序列窗口 |
| `distributedMaxForwardPacketBytes` | `4096` | 控制报文最大长度 |
| `distributedForwardRatePerSecond` | `10000` | 控制通道持续限速 |
| `distributedForwardBurst` | `20000` | 控制通道突发上限 |
| `rateLimitPerSecond` / `rateLimitBurst` | `100` / `200` | 公网单来源 IP 限速 |
| `globalRateLimitPerSecond` / `globalRateLimitBurst` | `10000` / `20000` | 公网进程全局限速 |
| `metricsBindAddress` / `metricsPort` | `127.0.0.1` / `9108` | Prometheus 端点 |

`deployment` 控制 SSH 超时、服务启动超时、远端临时目录和备份保留数量。
