# 出口分流使用说明

让一台设备（消费端）把**指定目标**的流量经另一台设备（出口）访问：消费端按规则把这些目标的流量引进虚拟网卡，经已授权的 Peer Mesh 通道交给出口，出口用普通 socket 连接目标并把响应送回。应用不需要逐个配置代理，未命中规则的流量照常从本机出去。

关联 [#42](https://github.com/devShuai/specus/issues/42)。线协议与语义见 [peer-egress.md](../../protocol/spec/peer-egress.md)；本文只讲怎么用、怎么确认生效、怎么排查。

> **一期状态。** 下面描述的是当前实现的行为。三端单元测试、共享向量与 CLI 进程矩阵覆盖了规则、路由接管、状态与登录声明；**跨平台真机验收（P7，[#50](https://github.com/devShuai/specus/issues/50)）尚未完成**，吞吐也还没有实测数据。生产使用前请先在自己的网络里验证，并阅读文末的限制。

## 先看它不做什么

- **默认只支持 IPv4 地址与 CIDR 规则。** 域名规则要打开二期的 `peerEgressDnsTakeover`（见[第五节](#五二期域名规则与系统-dns-接管)）；不打开时写域名会被拒绝，不会在启动时解析成 IP。
- **不支持 IPv6 规则**，IPv6 目标随二期一起提供。
- **不转发 ICMP。** 命中出口规则的目标 ping 不通——消费端会丢掉这些包，而不是让它从本机地址出去。
- **不支持多跳出口链。** 出口自己也是消费端时，它转发的流量不会再经过第二个出口。
- **目标看到的是出口所在网络的公网出口地址**，不保证等于出口设备自身的地址。
- **不改任何持久的系统配置**：不改 DNS（打开二期的 `peerEgressDnsTakeover` 时除外，它在运行期间把系统 DNS 指向本机，退出时改回，见第五节）、不写持久路由、不改防火墙和内核转发参数。运行期间只向内存路由表添加规则需要的条目，退出时撤回，重启后不存在。准确的清单见规范的[对系统的改动](../../protocol/spec/peer-egress.md#对系统的改动)。
- **出口不可用时立刻失败，不挂起**：命中规则而出口离线时，TCP 连接立即被拒绝，UDP 收到主机不可达；出口离线或规则改动时已建立的 TCP 连接立即被复位。应用照常重试，出口回来后就通。`block` 规则仍是静默丢弃。
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

管理后台「私有组网 → 出口分流」页提供这些操作：总开关（开关前说明影响）、为设备新增或编辑出口策略（目标范围、授权的消费设备、目的规则、限额、启用）、启停与删除。页面保存前按出口的解析规则校验目的规则——网段必须主机位为零、协议只认小写 `tcp`/`udp`、端口不能为空（全部端口写「全部」）——并提示强制拒绝的地址、与目标范围不符的网段；列表逐条说明策略为什么没有生效（总开关关闭、设备未启用组网、Peer ACL 未放行、没有目的规则），并标出已存下但出口永远不会匹配的规则。

也可以直接调用管理接口，下文给出请求形状。所有请求都需要管理员登录后的 Bearer 令牌。服务端保存策略时按出口的读法校验目的规则，出口读不懂的规则整个请求以 400 拒绝（规则见[规范](../../protocol/spec/peer-egress.md#出口授权模型)）；非 ADMIN 修改为 403，设备或策略不存在为 404。在此之前保存的策略里可能仍有无效规则，管理后台会在列表里标出。

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

在消费端的 `client.jsonc` 里加 `peerEgressRules`，三端共用这个字段。**规则写好只是保存，还要把 `peerEgressEnabled` 设为 `true` 才会接管流量**：保存规则与启用系统接管是两步，默认关闭。

开关关闭而规则不为空时，`config validate` 和每次启动都会提示 `peerEgressRules has <N> rule(s) but peerEgressEnabled is false: none is in force`，`specus-client egress` 显示 `consumer: takeover off`，每条规则的状态是 `EGRESS_CONSUMER_DISABLED`。启用前请确认：客户端需要创建虚拟网卡与安装路由的权限（`peerMeshDevice` 不能是 `noop`）；只有命中规则的目标会被接管，其余流量保持本地直连；命中 `egress` 规则而出口不可用时流量被阻断，不会改走本机。

```jsonc
{
  "serverBaseUrl": "https://your-server.example",
  "apiKey": "env:SPECUS_API_KEY",
  "secret": "env:SPECUS_SECRET",
  "peerMeshDevice": "auto",
  // 启用系统接管；不写或写 false 时规则只保存、不生效
  "peerEgressEnabled": true,
  "peerEgressRules": [
    // 这个网段经 2 号设备访问
    {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 2},
    // 其中这一台仍然本地直连
    {"match": "203.0.113.10", "action": "direct"},
    // 这个网段一律不通
    {"match": "198.51.100.0/24", "action": "block"},
    // 暂时停用的规则：留在列表里，不参与匹配
    {"match": "192.0.2.0/24", "action": "egress", "egressClientId": 2, "enabled": false}
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

规则写 `"enabled": false` 即停用：它留在列表里但不参与匹配、不安装路由，状态里显示 `EGRESS_RULE_DISABLED`。停用是用户的选择，`config validate` 不为它告警。

### 用命令编辑规则

不想手改 JSONC 时，三端都提供同一组编辑命令（Java 为 `java -jar specus-client-exec.jar egress ...`）。它们只改配置文件、不碰正在运行的客户端，运行中的客户端**重启后**才应用；每次写入都会提示这一点。

```bash
specus-client egress rules --config client.jsonc
specus-client egress rule add --config client.jsonc --match 203.0.113.0/24 --action egress --egress-client-id 2
specus-client egress rule add --config client.jsonc --match 203.0.113.10 --action direct --at 0
specus-client egress rule disable --config client.jsonc --index 1
specus-client egress rule move --config client.jsonc --index 1 --to 0
specus-client egress enable --config client.jsonc --yes
specus-client egress test 203.0.113.5 --config client.jsonc
```

- `egress rules` 列出开关状态与每条规则，形如 `[0] on 203.0.113.0/24 egress 2`；规则本身会被拒绝时在行尾写明错误码与原因。
- `egress rule add` 会先按上表校验，会被拒绝的规则不写入（`Rule not added: EGRESS_RULE_DOMAIN_UNSUPPORTED (...)`，退出码 2）。`--at` 指定插入位置，`--disabled` 以停用状态加入。
- `egress rule remove|enable|disable --index N` 与 `egress rule move --index N --to M` 按 `egress rules` 显示的序号操作。
- `egress enable` 每次都先说明接管意味着什么（需要创建虚拟网卡与安装路由的权限、只接管命中规则的目标、出口不可用时阻断而不改走本机），不加 `--yes` 时不做任何修改、退出码 2。`peerMeshDevice` 为 `noop` 时另有一行提醒。`egress disable` 直接关闭。
- `egress test ADDRESS` 只根据配置预演该 IPv4 地址会命中哪条规则、结果是经哪个出口、阻断还是本地直连，**不建立任何连接**；开关关闭时同时给出"开启后会怎样"。加 `--connect PORT` 才会做一次 5 秒内的 TCP 连接测试，它只说明地址可达，不说明走的是哪条路径。
- `egress test NAME` 预演一个域名（二期，见第五节）：命中哪条域名规则、DNS 查询会被回 fake-IP 还是转发给系统原来的 DNS、最后经哪个出口或阻断；DNS 接管没开时说明名字由系统 DNS 解析、开启后会怎样。预演不查询 DNS；`--connect` 只接受 IPv4 地址，因为名字在本机解析的结果不代表出口那边。

编辑只替换 `peerEgressRules` 或 `peerEgressEnabled` 这一个值，文件里其他内容与注释原样保留，换行风格（LF/CRLF）跟随原文件；写入是原子的，文件在读取后被别处改过则拒绝写入。`peerEgressRules` 列表内部的注释在编辑后不保留，因为整个列表会按每行一条规则重写。所有子命令都支持 `--json`。

本地管理页（`specus-client ui`）的「出口规则」页提供同样的编辑：列表中逐条启用/停用、上移/下移、删除，表单添加规则，开关开启前弹出同样的影响说明，另可预演地址或域名的去向。页面与命令走同一段逻辑，写出的文件相同。

### 用 Windows 桌面端编辑规则

桌面端（`specus-desktop`）的「出口分流」页提供同一组操作：添加规则（目标、动作、出口设备可从在线设备中选或填 ID，可放在最前、可先停用）、逐条启用/停用、上移/下移、删除，以及系统接管开关——开启前每次弹出与 `egress enable` 相同的影响说明。规则的校验与上面的命令、本地管理页是同一段逻辑，被拒绝的规则同样不写入，并给出原因与错误码。

- 桌面端的规则与开关保存在桌面端自己的设置里（与连接设置同一个文件），不读写 `client.jsonc`；**断开后重新连接**才会应用到正在运行的连接。
- 「规则测试」分成两个按钮：「按配置预演」只按已保存的规则判断去向，不建立连接；「连通测试」真实连接一次指定端口，只说明能否连上，不说明走了哪条路径。
- 「运行状态」与本地管理页的状态卡片一致：只列出不起作用的规则、没装上的路由、离线或尚无路径的出口设备、路由下发失败，其余只计数；并显示本机作为出口时的流数与拒绝计数。

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
| `route install failed` 带 `no route outside the tunnel` | `egress` 里的 `route install failed` | 某条规则覆盖了控制服务器、STUN/TURN 或某个对端的地址，而除了隧道之外路由表里没有能到达它的路由（或者到它的路由是黑洞）。这条旁路没装上，经过它的连接会走进隧道。检查规则前缀是否写得过宽，或者本机的路由表 |
| 日志有 `routes not installed: virtual device is NOOP`（或 `ERROR`） | 日志 | 消费端的虚拟网卡没起来，路由不会装。`peerMeshDevice` 还是默认的 `noop`，或网卡创建失败（看同一段日志里的原因，通常是权限）。网卡起来后自动装上，不用重启 |
| 日志有 `took back N routes left by a previous run` | 日志 | 上一次进程没有正常退出，留下的路由已在这次启动时收回，随后按当前规则重装。只是说明，不需要处理 |
| 日志有 `route X put back, it was missing`（或 `moved`） | 日志 | 路由表里本功能的路由不见了或指错了网关（切网、休眠恢复、别的工具改了表），已经补回。只是说明；频繁出现时查是什么在反复改路由表 |
| 日志有 `route X lost to another route, not taken back` | 日志；`egress` 里的 `NOT INSTALLED` | 本功能的路由不在了，而同一前缀上出现了别人的路由。本功能不抢占：这条前缀从此按冲突处理，每 60 秒查一次，对方撤了就装回。删掉或调整那条路由 |
| 日志有 `bypass host X did not resolve` | 日志 | 服务端、STUN 或 TURN 的主机名解析失败，它的旁路没装。若某条规则的前缀覆盖了它的地址，去它的连接会走进隧道。检查 DNS；解析恢复后一分钟内自动补上 |
| 命中规则的目标连接立刻被拒绝（TCP `connection refused` / UDP 报主机不可达），状态里出口离线 | `egress peer N: offline`，拦截计数 `egress-unavailable` | 出口设备不在线、服务端未打开租户开关或出口策略、或这台消费端不在允许列表里。出口设备上 `egress` 显示 `not serving` 说明它没收到策略 |
| 同样立刻被拒绝，但出口在线 | `egress peer N: not offered to this device by the server's egress catalog`，拦截计数 `egress-not-offered` | 服务端的出口目录没有把这台出口提供给本机：它不是出口、出口策略未启用、没有允许本机，或基础 ACL、租户开关不允许。请管理员在出口策略里启用它并允许本机 |
| 同样立刻被拒绝，出口在线 | `egress peer N: online, but its client does not support peer egress`，拦截计数 `egress-unsupported` | 出口设备的客户端版本太旧，登录时没有声明出口能力，发给它的流量不会被处理。升级那台设备的客户端 |
| `egress` 里有 `server: sent no egress catalog` | 状态里 `catalog` 为 `none` | 控制连接认证后 30 秒内没收到出口目录，服务端可能太旧、不支持出口，升级服务端。在此之前出口能否接流以出口的拒绝为准 |
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
| `egress-not-offered` | 指向的出口在线，但服务端的出口目录没有向本机提供它 |
| `egress-unsupported` | 指向的出口在线，但它的客户端不支持出口（旧版本） |
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

## 五、二期：域名规则与系统 DNS 接管

二期让规则可以按**域名**写。它靠 fake-IP 生效：命中域名规则的 DNS 查询不在本地解析，而是从专用地址池分配一个假地址返回；应用连到这个假地址时，消费端把**域名**交给出口，由出口在自己的网络里解析、授权并连接。完整规则见规范 [peer-egress-dns.md](../../protocol/spec/peer-egress-dns.md)。

**可识别边界：** 应用自带 DoH/DoT、使用系统缓存、或直接硬编码 IP 时，域名规则**不会**命中，这类流量只能靠 IP/CIDR 规则覆盖。

> **二期状态。** 下面描述的是当前实现的行为。单元测试与共享向量覆盖了规则、地址池、应答者与接管命令；Linux 命名空间实验室（`scripts/peer-egress-lab/lab.py`，CI 里三种消费端 × 三种出口）以 `/etc/resolv.conf` 方式完整跑通了接管、经出口访问、池内无映射与强杀后恢复。Windows 与 macOS 的真机验收（NRPT、networksetup）尚未完成，见 #50。

### 打开二期

要让应用的查询到达本功能，只能修改系统 DNS 设置，**这是整个功能里唯一修改用户系统配置的地方**，所以默认关闭，需要同时打开两个开关。可以用命令设置，开启时每次先说明这一改动，确认后才写入：

```sh
specus-client egress enable --config ./client.jsonc --yes
specus-client egress dns enable --config ./client.jsonc --yes
specus-client egress dns disable --config ./client.jsonc
```

与 `egress enable` 一样只改配置文件里的这一个值，注释与换行风格保留，运行中的客户端重启后生效。也可以直接编辑配置：

```jsonc
{
  "peerMeshDevice": "auto",
  "peerEgressEnabled": true,
  // 二期总开关：域名规则生效，运行期间系统 DNS 指向本机的应答者，退出时改回
  "peerEgressDnsTakeover": true,
  // fake-IP 地址池，可省略；必须是 IPv4、前缀 /8 到 /24，不能与组网网段或本机网段重叠
  "peerEgressFakeIpCidr": "198.18.0.0/15",
  "peerEgressRules": [
    // 只匹配 example.com 本身
    {"match": "example.com", "action": "egress", "egressClientId": 2},
    // 匹配 example.com 的任意子域，不含 example.com 本身
    {"match": "*.example.org", "action": "egress", "egressClientId": 2},
    // 这个名字本地解析、本地直连
    {"match": "intranet.example.org", "action": "direct"},
    // 这个名字一律不通
    {"match": "*.ads.example", "action": "block"}
  ]
}
```

- 名字比较前去掉末尾的 `.`、转小写；中文等国际化域名要写成 punycode（`xn--` 开头），写成 Unicode 会被拒绝。
- 多条域名规则都匹配时，**精确匹配优先于 `*.` 后缀**，后缀之间标签多的优先，再相同则先写的优先。IP/CIDR 规则与域名规则互不竞争。
- 命中 `direct` 的名字不接管，查询原样交给原来的 DNS；命中 `egress` 或 `block` 的名字得到一个 fake-IP，之后到这个地址的流量按该规则发往出口或阻断。
- 指向的出口在线却不支持域名（旧版本客户端）时，规则状态是 `EGRESS_RULE_EGRESS_NO_DOMAIN`，这些名字的流量被阻断，不会改为本地解析。
- `peerEgressDnsTakeover` 打开而地址池不可用时，`config validate` 与启动时提示 `peerEgressFakeIpCidr is not usable: EGRESS_FAKE_IP_POOL_INVALID; domain rules are not in force`，一期照常运行。

新增的错误码：

| 错误码 | 原因 |
| --- | --- |
| `EGRESS_RULE_FAKE_IP_OVERLAP` | IP/CIDR 规则与 fake-IP 池重叠；池内地址只能由域名规则分配 |
| `EGRESS_FAKE_IP_POOL_INVALID` | `peerEgressFakeIpCidr` 不合法，或与组网网段、本机网段重叠。二期不启动，一期照常 |
| `EGRESS_RULE_EGRESS_NO_DOMAIN` | 域名规则指向的出口在线，却没有声明支持域名 |
| `EGRESS_DNS_TAKEOVER_REFUSED` | 开启前检查不通过，没有改系统 DNS，原因见 `reason` |
| `EGRESS_DNS_TAKEOVER_FAILED` | 改系统 DNS 的命令失败，已经改回，失败命令的输出见 `error`；或系统 DNS 正由本机另一个仍在运行的客户端接管，`error` 写明它的 PID，那个客户端退出后本客户端在一分钟内接管 |

### 系统 DNS 怎么被接管

应答者在 fake-IP 池的第一个地址（默认 `198.18.0.1`）的 53 端口上应答，它不占用系统的 53 端口，只回答本机发出的查询。接管时按平台做下面的改动，**改动之前先把原值写进事务日志**，退出时按日志改回：

| 平台 | 接管 | 改回 |
| --- | --- | --- |
| Linux，应用经 systemd-resolved 的 stub（`127.0.0.53`） | 对本机虚拟网卡的链路执行 `resolvectl dns` 与 `resolvectl domain <网卡> '~.'` | `resolvectl revert <网卡>` |
| Linux，其他 | 把 `/etc/resolv.conf` 改写为只指向应答者 | 文件仍是本功能写的内容时写回原文；别人改过则保留别人的版本并在日志里告警 |
| macOS | 每个启用的网络服务 `networksetup -setdnsservers <服务> 198.18.0.1` | 仍只指向应答者的服务写回原值（原来是 DHCP 的写回 `Empty`）；别人改过的保留并告警 |
| Windows | 添加命名空间为 `.`、注释为 `specus-peer-egress` 的 NRPT 规则，不改网卡 DNS | 删除注释为 `specus-peer-egress` 的 NRPT 规则 |

改动需要管理员或 root 权限，与装路由相同。应答者转发不认识的查询时，用的是接管前系统原来的 DNS 服务器。

以下情况**不接管**（`EGRESS_DNS_TAKEOVER_REFUSED`），数据面与应答者照常运行，一期不受影响：

| `reason` | 何时 |
| --- | --- |
| `pool-route-not-installed` | fake-IP 池的路由没装上（被别的路由占用，或虚拟网卡没起来） |
| `system-dns-loopback` | 系统 DNS 里有回环地址，多半已有别的接管者 |
| `system-dns-virtual` | 系统 DNS 落在 fake-IP 池、组网网段或本机某个隧道类网卡（别的 VPN）上 |
| `no-upstream` | 去掉 IPv6 与 `0.0.0.0` 后没有可转发的上游 |
| `resolv-conf-managed` | Linux 没经 systemd-resolved 的 stub，而 `/etc/resolv.conf` 是符号链接，归别的程序管理 |
| `nrpt-root-occupied` | Windows 上已有别人的、命名空间为 `.` 的 NRPT 规则 |
| `unsupported-platform` | 不是 Linux、macOS、Windows |

切换网络（默认路由所在网卡或本机地址变化）后，客户端在 10 秒内先改回、再按新网络重新检查并接管，新网络经 DHCP 下发的 DNS 会被读成新的上游。新网络的地址落进 fake-IP 池时，二期整体停止并告警。

### 查看与恢复

```sh
specus-client egress dns status --config ./client.jsonc
specus-client egress dns restore
```

- `egress dns status`：二期是否在运行、系统 DNS 是否已接管（不接管时给出原因）、转发的上游、事务日志状态、映射数与池使用率。读状态文件与事务日志，客户端没在运行也能用。
- `egress dns restore`：按事务日志把系统 DNS 改回，客户端不需要在运行。客户端被强杀、断电之后用它恢复网络；下次正常启动客户端也会先按日志改回。
  - 没有事务日志时说明无需恢复，以 0 退出；改回成功以 0 退出。
  - 日志里记录的客户端还在运行时拒绝并以 1 退出：先停止客户端，或把 `peerEgressDnsTakeover` 改为 `false` 后重启它。「还在运行」指它仍在往状态目录（`SPECUS_CLI_STATE_DIR`，默认 `~/.specus-cli`）发布状态；只是进程号在运行不算，断电重启后进程号常被别的程序占用。`--force` 跳过这一检查（那个进程号如今属于另一个客户端时用）。
  - 某一步失败以 1 退出并说明是哪一步，事务日志保留，修正后再运行一次。

事务日志在 `~/.specus/egress-dns-journal.json`，与路由安装记录在同一目录。客户端启动时、以及每次接管之前，按同一个判定处理找到的日志：属于另一个仍在运行的客户端就不动它（自己也不接管），否则先按日志改回。桌面应用不发布状态，认不出来，所以一台机器上只应有一个客户端开启 `peerEgressDnsTakeover`。

同一台机器上只让一个客户端开启 `peerEgressDnsTakeover`。客户端启动时，不论日志里记录的进程此刻是否在运行，都先按日志改回：断电重启之后那个进程号多半已被别的程序占用，按它判断会让系统 DNS 一直指着一个没人应答的地址。

运行状态（`egress --config ... --json`）里 `consumer.dns` 一节给出同样的信息：`active` 是二期是否在运行，`takeover` 是系统 DNS 此刻是否指向应答者，`journal` 是 `none`、`pending` 或 `committed`，`queries` 是应答、转发与失败的累计数。拦截计数增加四个原因：

| 原因 | 含义 |
| --- | --- |
| `fake-ip-unmapped` | 发往 fake-IP 池内、却没有映射的地址 |
| `fake-ip-stale` | 地址映射的名字已没有规则认领，或改由 `direct` 认领；应用重新查询即可 |
| `egress-no-domain` | 域名规则指向的出口在线，却不支持域名 |
| `dns-not-local` | 发往应答者的查询不是本机发出的，不予回答 |

## 六、已知限制

完整列表见规范的[当前限制](../../protocol/spec/peer-egress.md#当前限制)。影响使用的几条：

- **下行只有有界发送窗口，没有自适应拥塞控制。** 此前经出口下载大响应会被复位的问题已修复（#74）：出口按消费端通告的窗口发送，并对目标 socket 施加背压。Linux 上三种语言两两组合的 9 种组合在每次 PR 上用真 TUN 验证 8 MiB 上下行、64 条并发流与 2% 丢包下的完整性（见[真机实验室](../../scripts/peer-egress-lab/README.md)）；Windows 与 macOS 的真 TUN 验收仍在 #50 中进行。
- **客户端不上报出口计数**，管理接口的活动页现在总是空的。出口是否在线取自组网在线状态，出口目录只用来判断出口是否提供给本机、能否接流与能否解析域名。
- **出口侧没有字节速率限制**，只有并发数与空闲超时上限。
- **切网或休眠恢复后，路由最多在 5 秒内补回；这 5 秒内命中规则的目标会从本机直连出去，而不是被阻断。** 日志里的 `route … put back` 说明发生过一次补回；如果它频繁出现，说明有别的东西在反复改路由表。Linux 上只对照主表，另一个 VPN 用策略路由把流量导走时发现不了。
- **控制连接断开重连时路由保持不变**，不再有窗口。断开期间客户端只挂起：路由与虚拟网卡都留着，命中规则的流量仍然被接管，由出口承载或被拒绝；已建立的对端流量走 UDP，不受影响。只有真正退出时才撤回路由。
- **Windows 的路由安装与撤销尚未在真机上执行过**；macOS 的安装路径在 CI 真机上验证过，但指向的是回环接口而不是 utun。
