# 出口分流使用说明

让一台设备（消费端）把**指定目标**的流量经另一台设备（出口）访问：消费端按规则把这些目标的流量引进虚拟网卡，经已授权的 Peer Mesh 通道交给出口，出口用普通 socket 连接目标并把响应送回。应用不需要逐个配置代理，未命中规则的流量照常从本机出去。

关联 [#42](https://github.com/devShuai/specus/issues/42)。线协议与语义见 [peer-egress.md](../../protocol/spec/peer-egress.md)；本文只讲怎么用、怎么确认生效、怎么排查。

> **一期状态。** 下面描述的是当前实现的行为。三端单元测试、共享向量与 CLI 进程矩阵覆盖了规则、路由接管、状态与登录声明；**跨平台真机验收（P7，[#50](https://github.com/devShuai/specus/issues/50)）尚未完成**，吞吐也还没有实测数据。生产使用前请先在自己的网络里验证，并阅读文末的限制。

## 先看它不做什么

- **只支持 IPv4 地址与 CIDR 规则。** 域名规则二期提供；写域名会被拒绝，不会在启动时解析成 IP。
- **不支持 IPv6 规则**，IPv6 目标随二期一起提供。
- **不转发 ICMP。** 命中出口规则的目标 ping 不通——消费端会丢掉这些包，而不是让它从本机地址出去。
- **不支持多跳出口链。** 出口自己也是消费端时，它转发的流量不会再经过第二个出口。
- **目标看到的是出口所在网络的公网出口地址**，不保证等于出口设备自身的地址。
- **不改任何持久的系统配置**：不改 DNS、不写持久路由、不改防火墙和内核转发参数。运行期间只向内存路由表添加规则需要的条目，退出时撤回，重启后不存在。准确的清单见规范的[对系统的改动](../../protocol/spec/peer-egress.md#对系统的改动)。
- **不接管默认路由**：`0.0.0.0/0` 规则会被拒绝。
- **拥塞控制不完整**：出口到消费端方向目前没有发送侧流控，慢链路或丢包链路上下行吞吐会明显变差，详见文末。

## 前提

| 项目 | 要求 |
| --- | --- |
| 服务端 | 包含出口管理接口的版本（Java、Go、.NET、C 四个服务端路径一致）。租户级开关默认关闭 |
| 客户端 | 包含 P8 修复的版本：登录时声明出口能力。更早的客户端登录不声明能力，服务端不会给它下发出口策略 |
| 消费端网卡 | `peerMeshDevice` 必须是创建虚拟网卡的模式（`auto`，或 `linux-tun`、`wintun`、`utun` 等），**不能是默认的 `noop`**。消费端靠虚拟网卡捕获流量，`noop` 没有网卡，规则无从生效 |
| 出口端网卡 | 按设计不依赖虚拟网卡，数据经 Peer Mesh 会话进出；`noop` 与 `auto` 都可以（尚未真机验收） |
| 消费端权限 | 改路由表需要特权：Linux 需要 root 或 `CAP_NET_ADMIN`；Windows 需要管理员；macOS 需要 root |
| 消费端平台 | Linux、Windows、macOS。其他平台登录时声明 `consumerCapable: false`，配了规则也不会接管路由 |

## 一、服务端：把一台设备设为出口

出口由两级开关控制，**两者都打开**这台设备才会作为出口：租户级总开关，与这台设备自己的出口策略。策略变更会立即推送给在线设备，不必等它重新登录。

管理后台目前**没有**出口分流页面，请通过管理接口操作。所有请求都需要管理员登录后的 Bearer 令牌。

打开租户开关：

```http
PUT /api/admin/peer-mesh/egress/switch
Content-Type: application/json

{"enabled": true}
```

为出口设备写策略（按 `egressClientId` 新增或更新，省略的字段保持原值）：

```http
POST /api/admin/peer-mesh/egress/policies
Content-Type: application/json

{
  "egressClientId": 2,
  "enabled": true,
  "scope": "PUBLIC",
  "allowedConsumerClientIds": [5, 7],
  "destinationRules": [
    {"cidr": "203.0.113.0/24", "protocols": ["tcp"], "portRanges": [[443, 443]]}
  ],
  "maxConcurrentFlows": 256,
  "maxFlowsPerConsumer": 64,
  "idleTimeoutSeconds": 60
}
```

几点要注意：

- **`destinationRules` 为空等于全部拒绝**，没有「不配置即放行」。
- `scope` 取 `PUBLIC`（公网地址）或 `LAN`（RFC 1918 私有地址与 RFC 6598 共享地址），两者互不隐含。
- 实际允许的消费端是 `allowedConsumerClientIds` 与基础 Peer ACL 的**交集**，出口在每次建立连接前还会再校验一次。
- 回环、链路本地与云元数据地址、组播广播、Peer Mesh 网段、本部署的控制与 STUN/TURN 端点、出口本机虚拟网卡网段**永远拒绝**，写 `0.0.0.0/0` 也不会放行它们。

其余接口：`GET /api/admin/peer-mesh/egress/switch` 查看开关，`GET /api/admin/peer-mesh/egress/policies` 列出策略（含与 ACL 取交集后的实际消费端），`DELETE /api/admin/peer-mesh/egress/policies/{id}` 删除策略。`GET /api/admin/peer-mesh/egress/activity` 设计为展示出口上报的计数，但客户端目前还不上报，**这个接口现在总是空的**；出口侧计数请在出口设备上用 `specus-client egress` 查看。

## 二、消费端：写规则

在消费端的 `client.jsonc` 里加 `peerEgressRules`，三端共用这个字段。列表非空即启用，没有单独的开关。

```jsonc
{
  "serverBaseUrl": "https://your-server.example",
  "apiKey": "env:SPECUS_API_KEY",
  "secret": "env:SPECUS_SECRET",
  "peerMeshDevice": "auto",
  "peerEgressRules": [
    // 这个网段经 2 号设备访问
    {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 2},
    // 其中这一台仍然本地直连
    {"match": "203.0.113.10", "action": "direct"},
    // 这个网段一律不通
    {"match": "198.51.100.0/24", "action": "block"}
  ]
}
```

| `action` | 行为 |
| --- | --- |
| `egress` | 经 `egressClientId` 指定的出口访问，`egressClientId` 必须是正整数 |
| `direct` | 本地直连。不安装路由，与未匹配的流量走同一个机制 |
| `block` | 阻断。会安装路由把包捕获下来再丢弃 |

- **前缀更长的规则优先**，同样长时先写的优先。单个地址等于 `/32`。
- **未匹配即本地直连。**
- **命中 `egress` 规则但出口不可用时阻断**，不会改走本机。出口离线、授权被撤、建连失败都属于这一类。
- 规则变更后，不再匹配或不再指向出口的已建连接会立即断开。

以下规则会被拒绝，**被拒的规则不生效，其余规则照常生效**：

| 错误码 | 原因 |
| --- | --- |
| `EGRESS_RULE_MALFORMED` | `match` 为空、不是合法 IPv4 地址或前缀、主机位非零（如 `203.0.113.1/24`），或 `action` 不认识 |
| `EGRESS_RULE_DOMAIN_UNSUPPORTED` | `match` 是域名，一期不支持 |
| `EGRESS_RULE_IPV6_UNSUPPORTED` | `match` 是 IPv6，一期不支持 |
| `EGRESS_RULE_DEFAULT_ROUTE` | `0.0.0.0/0`，一期不接管默认路由 |
| `EGRESS_RULE_MESH_OVERLAP` | 与 Peer Mesh 虚拟网段重叠 |
| `EGRESS_RULE_PORT_UNSUPPORTED` | 规则里写了 `port`。端口限制只在出口策略里配置 |
| `EGRESS_RULE_MISSING_TARGET` | `action` 是 `egress` 但没有有效的 `egressClientId` |

## 三、确认规则生效

**连接之前**，离线校验会列出不会生效的规则：

```sh
specus-client config validate --config ./client.jsonc
```

```text
Warning: peerEgressRules[1] is not in force: EGRESS_RULE_DEFAULT_ROUTE
Configuration valid: /path/client.jsonc (offline; connectivity not tested)
```

告警只给规则序号（从 0 开始）和错误码，不打印规则内容。离线校验按默认组网网段 `100.96.0.0/11` 判断重叠；服务端若配置了别的网段，与之重叠的规则要到连上之后才会被发现。

**运行中**，另开一个终端查看出口分流状态：

```sh
specus-client egress --config ./client.jsonc
specus-client egress --config ./client.jsonc --json
```

```text
PID 12345 | ready
  consumer: 3 rules (1 not in force) | 2 routes (1 not installed) | 0 flows | 1 egress peers (1 offline)
    rule 1 "0.0.0.0/0": NOT IN FORCE (EGRESS_RULE_DEFAULT_ROUTE)
    route 203.0.113.0/24 (rule:203.0.113.0/24): NOT INSTALLED, already present: 203.0.113.0/24 via 192.0.2.1 dev eth0
    egress peer 2: offline, so its rules have nowhere to send
  egress: not serving (no policy has enabled it)
```

输出只逐条列出**有问题**的部分，其余只计数：没生效的规则、没装上的路由、离线的出口设备。一个一切正常的节点只输出两行。Java 使用 `java -jar specus-client-exec.jar egress --config ...`。

本地管理页（`specus-client ui --config ./client.jsonc`）的「连接与服务」页有同样内容的「出口分流」面板。管理服务不可达时面板会清空并注明状态已过期，不会继续显示上一次的「正常」。

## 四、排查

| 现象 | 看哪里 | 原因与处理 |
| --- | --- | --- |
| 规则写了但流量照常走本机 | `egress` 里的 `NOT IN FORCE` | 规则被拒，按错误码修正。也检查 `peerMeshDevice` 是否还是默认的 `noop` |
| 规则生效但流量仍走本机 | `egress` 里的 `NOT INSTALLED` | 该前缀已被本功能之外的路由占用。本功能不抢占，删掉或调整那条路由后重新连接 |
| `route install failed`，Windows 带 `needs administrator rights`、macOS 带 `needs root`、Linux 带 `Operation not permitted` | `egress` 里的 `route install failed` | 消费端没有改路由表的权限。以管理员或 root 运行，Linux 也可授予 `CAP_NET_ADMIN` |
| 命中规则的目标不通，状态里出口离线 | `egress peer N: offline`，拦截计数 `egress-unavailable` | 出口设备不在线、服务端未打开租户开关或出口策略、或这台消费端不在允许列表里。出口设备上 `egress` 显示 `not serving` 说明它没收到策略 |
| 出口在线但特定目标不通 | 拦截计数 `rejected-egress_dest_denied` 等；出口上的 `refused` | 出口策略拒绝了这个目标，检查 `destinationRules`、`scope`、协议与端口 |
| ping 不通但 TCP 正常 | 拦截计数 `unsupported-protocol` | 一期不转发 ICMP，符合预期 |
| 出口设备收不到策略 | 出口上 `egress: not serving` | 确认客户端版本包含登录能力声明；更早的客户端服务端不会下发策略 |
| 大文件下载很慢或断流 | — | 已知限制：出口到消费端方向没有发送侧流控，见下文 |

拦截计数的原因名：

| 原因 | 含义 |
| --- | --- |
| `rule` | 命中 `block` 规则 |
| `unsupported-protocol` | 命中出口规则但协议不承载，如 ICMP |
| `egress-unavailable` | 指向的出口当前不可用 |
| `send-failed` | 交给出口的帧没能发出 |
| `return-mesh-source` / `return-no-flow` | 回程包来源异常，被拒收 |
| `rejected-<错误码>` | 出口拒绝了这个连接 |

**macOS 注意：** 虚拟网卡必须先配好 IPv4 地址，路由才能指向它；这由网卡启动完成。

**出口的转发流量不会走进本机隧道。** 一台设备同时是出口和消费端时，它为自己的规则装的隧道路由可能覆盖别人托它访问的目标。Windows 与 macOS 上，出口在连接目标前会把 socket 绑定到「没有隧道路由时系统本来会选的接口」（`IP_UNICAST_IF` / `IP_BOUND_IF`），按目标逐个选择，另一个 VPN 或第二块网卡上的路由照常生效，不需要任何配置。除了隧道之外没有路由通往目标时，这个连接会被拒绝，日志里是 `no route outside the tunnel`。Java 客户端用 `java -jar` 启动即可；自己拼 classpath 或用服务包装器启动时，要加上 `--add-exports java.base/sun.nio.ch=ALL-UNNAMED`，否则 Windows 与 macOS 上所有出口连接都会被拒绝，日志会写明缺这个选项。

Linux 上若本机隧道接管了默认路由，Go 与 .NET 出口会给出站 socket 打 `SO_MARK 0x5350`，需要运维自行添加策略路由，把带这个标记的流量交给一张以物理网关为默认路由的独立路由表，才能把转发流量固定在物理接口上。例如（网关、网卡与表号按实际环境替换）：

```sh
ip route add default via 192.0.2.1 dev eth0 table 100
ip rule add fwmark 0x5350 table 100
```

不要让它查主路由表：主表里正是隧道的路由。Java 出口在 Linux 上目前不打标记。

## 五、已知限制

完整列表见规范的[当前限制](../../protocol/spec/peer-egress.md#当前限制)。影响使用的几条：

- **出口到消费端方向没有发送侧流控。** 出口从目标读到多少就立刻发给消费端，不看消费端的接收窗口，没有拥塞窗口，靠超时重传恢复丢包。消费端或链路比目标服务器慢、或链路丢包时，下行吞吐会明显退化。**目前没有实测数据**，测量与修复单独跟进。
- **客户端不处理服务端下发的出口目录，也不上报出口计数。** 出口是否可用取自组网在线状态；管理接口的活动页现在总是空的。
- **遇到版本过旧的对端时没有专门提示**，只会表现为出口离线。
- **出口侧没有字节速率限制**，只有并发数与空闲超时上限。
- **Go、.NET 客户端崩溃后若删光规则再启动，残留路由不会被撤回**，这些目标会一直不通到重启。先恢复一条规则启动一次再删，或重启机器。
- **Java 客户端应用规则的时机过早**，控制端点与对端端点的旁路保护在 Java 上没有生效。在修复前，消费端建议使用 Go 或 .NET 客户端。
- **Windows 的路由安装与撤销尚未在真机上执行过**；macOS 的安装路径在 CI 真机上验证过，但指向的是回环接口而不是 utun。
- **桌面图形界面没有出口分流页面。**
