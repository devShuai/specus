# Peer 出口分流协议

消费设备按规则把指定目标的流量送进虚拟网卡，经已授权的 Peer 通道交给出口设备，由出口设备连接目标并把响应送回。用户无需逐个应用配置代理。目标通常看到出口设备所在网络的公网出口 IP，**不承诺等于出口设备自身地址**。

设计取舍与推演过程见 [docs/peer-mesh/peer-egress-split-routing-plan.md](../../docs/peer-mesh/peer-egress-split-routing-plan.md)。本文只定义线协议与语义。

关联 [#42](https://github.com/devShuai/specus/issues/42)。

## 一期边界

本规范当前定义的是一期范围。以下能力**明确不在本版本内**，实现必须拒绝而不是静默降级：

| 不支持 | 行为 |
| --- | --- |
| 域名与域名后缀规则 | 配置校验阶段拒绝，返回 `EGRESS_RULE_DOMAIN_UNSUPPORTED`。不得忽略，更不得在启动时解析成静态 IP |
| IPv6 单地址与 CIDR 规则 | 配置校验阶段拒绝，返回 `EGRESS_RULE_IPV6_UNSUPPORTED` |
| IPv6 数据面 | `SPEG1` 收到 IPv6 packet 拒绝，返回 `EGRESS_IPV6_UNSUPPORTED` |
| DNS 接管 | 不实现。一期不修改任何用户系统 DNS 配置 |
| ICMP | 出口不代发。代 ping 需要 raw socket 权限，与「出口零特权」前提冲突。消费端对命中 `egress` 规则的 ICMP 包**丢弃**并计入 `unsupported-protocol`，不改走本机：规则说了这个目标不许从本地出去，ping 不通好过从本机地址 ping 通 |
| 多跳出口链 | `SPEG1` 的 hop 标记已置位时拒绝，返回 `EGRESS_HOP_NOT_ALLOWED` |
| 默认路由接管 | 规则不接受 `0.0.0.0/0`，返回 `EGRESS_RULE_DEFAULT_ROUTE` |

「拒绝而非降级」是防泄漏要求。静默忽略一条不支持的规则，等于让本应经出口的流量走本地，与命中规则后静默回退本地是同一类问题。

## 数据面形态

线上传输的是**原始 IPv4 packet**，出口侧用用户态连接栈终结后再用普通 socket 连接目标。消费端不解析 TCP。

由此得到两条贯穿全文的约束：

- **消费端规则只能按目的地址匹配。** 消费端靠安装路由把流量引入 TUN，而路由只能选目的地址。端口与协议限制只存在于出口策略，在出口侧建流时执行。规则里出现 `port` 字段返回 `EGRESS_RULE_PORT_UNSUPPORTED`。
- **可靠性由应用自己的 TCP 提供。** TCP 的另一端在出口的用户态栈上，peer 链路上的丢包与乱序就是普通网络丢包，由应用端到端重传兜住。数据面不额外提供可靠有序流。

## 配置

消费端在客户端配置文件（`client.jsonc`）里写规则，三端共用同一个字段：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `peerEgressRules` | 空 | 有序规则列表，语义见下节。**没有单独的总开关**：列表非空即启用消费端，空或缺省即不启用 |

设计阶段写过 `egressEnabled` 与 `egressRules` 两个字段，实现时没有采用：多一个开关就多一种「规则写了但没打开」的状态，而那恰好是本功能要防的静默不生效。

出口端不在客户端本地配置授权。出口由服务端两级开关控制——租户级总开关与每台设备的出口策略，**两者都开**这台设备才会作为出口——持久化后通过 `egress-config` 下发，避免出口设备本地被改写后绕过租户策略。管理接口见 [出口分流使用说明](../../docs/peer-mesh/peer-egress-usage.md)。客户端本地只保留一个只读的当前生效视图。

## 规则语义

规则有序，每条包含 `match`（IPv4 单地址或 CIDR）与 `action`。

| `action` | 说明 |
| --- | --- |
| `egress` | 经 `egressClientId` 指定的出口设备访问。该字段缺失或不是正整数返回 `EGRESS_RULE_MISSING_TARGET` |
| `direct` | 本地直连 |
| `block` | 阻断 |

匹配规则：

- **优先级**：前缀更长者优先；前缀长度相同时按配置顺序，先匹配者胜。
- **默认动作**：未匹配即本地直连。这是路由表本身的结果——没有安装路由的目标根本不会进入 TUN，实现**不得**再加一条兜底放行分支。
- **单地址**等价于 `/32`。
- **主机位非零**（如 `203.0.113.1/24`）一律拒绝，返回 `EGRESS_RULE_MALFORMED`。不做隐式掩码归一化：各语言的归一化行为不一致，拒绝比兼容更安全。
- 规则**不得覆盖 Peer Mesh 虚拟网段**，返回 `EGRESS_RULE_MESH_OVERLAP`，否则组网自身流量会被卷进出口。
- **校验失败的规则不参与匹配**。匹配前必须先跳过它们，不能只依赖调用方预先过滤。一条被拒的长前缀规则若仍参与匹配，会压过合法的短前缀规则，运维读到的「已拒绝」与流量实际走向不符。

配置校验顺序固定，实现必须按此顺序返回第一个命中的错误码。一条规则可能同时违反多项，顺序不固定则各语言会对同一条规则报出不同的码，而共享向量目前没有同时违反两项的用例，无法靠它兜住：

1. `EGRESS_RULE_MALFORMED` —— `match` 为空
2. `EGRESS_RULE_IPV6_UNSUPPORTED` —— `match` 含冒号
3. `EGRESS_RULE_DOMAIN_UNSUPPORTED` —— `match` 是域名或域名后缀
4. `EGRESS_RULE_MALFORMED` —— 不是合法的 IPv4 地址或前缀，前缀长度越界，或主机位非零
5. `EGRESS_RULE_DEFAULT_ROUTE` —— 前缀长度为 0
6. `EGRESS_RULE_MESH_OVERLAP` —— 与 Peer Mesh 网段任一方向重叠
7. `EGRESS_RULE_PORT_UNSUPPORTED` —— 携带端口维度
8. `EGRESS_RULE_MALFORMED` —— `action` 不是 `egress` / `direct` / `block`
9. `EGRESS_RULE_MISSING_TARGET` —— `action=egress` 而 `egressClientId` 缺失、为 `0` 或为负

`egressClientId` 必须是正整数，字段在场不等于字段有效：`0` 是本项目里「没有消费端」的哨兵值，接受它等于让规则过校验、路由照常安装，然后每个包都找不到出口对端——一个配置期就能报出的错被推迟成运行期的黑洞。

`match` 是规则的主体：先判断它是什么、是否合法、作为前缀是否被策略拒绝，最后才轮到 `action` 与它需要的字段。冒号是无歧义的信号，所以 IPv6 排在域名之前。

规则变更对已建立连接：已建流不受影响，除非规则从 `egress` 变为 `direct` / `block` 或不再匹配。此时消费端立即断开该流，并向出口发送 `flow-purge` 控制消息关闭对端侧的对应连接。

命中出口规则但出口离线、授权失效或建链失败时**阻断**，不静默回退本地直连。

**被拒的规则在两处报告，都不中断其余规则。** 离线：`config validate` 与每次启动加载配置时，对每条不会生效的规则写一条告警 `peerEgressRules[<序号>] is not in force: <错误码>`，三端逐字一致；告警只打序号不打 `match`，与其他配置告警不打印配置值的约定一致。运行时：连上之后应用规则，被拒的规则跳过、写日志，并在状态查询里以 `inForce: false` 列出。

离线校验按**默认 Peer Mesh 网段** `100.96.0.0/11` 判断重叠：真实网段在登录时由服务端下发，一条只与自定义网段重叠的规则要到应用规则时才被发现。

固定向量：`protocol/test-vectors/peer-egress-rules-v1.json`。

## 路由接管

消费端靠安装路由把流量引进 TUN。计划是纯函数，只说应该存在哪些路由；执行与回滚由安装器负责。分开是为了让回滚、冲突拒绝与归属判定都能脱离真实路由表被测试。

### 计划

- 只安装**精确前缀**，计划器不会自己造出 `0.0.0.0/0` 或它的两个 `/1` 半区。
- `action=direct` **不安装路由**。流量靠「没有路由」留在本地，与未匹配流量是同一个机制，而不是两处需要彼此保持一致的行为。
- `action=block` **要安装**：包必须先被捕获，数据面才谈得上丢弃它。
- **旁路条目排在最前**，安装也按此顺序。控制连接、登录用的服务端地址、STUN 与 TURN、中继、对端 UDP 端点必须继续走物理网络；某条规则的前缀若覆盖了它们，承载隧道的传输就会被送进隧道自身。旁路先入表，因此同地址的规则不会把它顶掉。
- **旁路只为被规则路由覆盖的地址安装 `/32`。** 没被任何 `egress`/`block` 规则前缀覆盖的地址，系统自己的路由本来就送得到，多装一条只是多一条要随对端来去而维护的东西；被拒的规则和 `direct` 规则不装路由，它们覆盖的地址同样不需要旁路。
- 旁路里的主机名（服务端 URL、STUN/TURN 主机、公共 STUN 列表）在消费端**解析后逐个地址安装**，解析结果缓存 60 秒，解析失败的主机跳过并记一次日志。这与出口侧强制拒绝清单只收字面地址的做法相反，原因也相反：拒绝清单的失败形态是「看起来拒绝了其实没有」，旁路的失败形态是「少一条路由，控制连接被卷进隧道」，多一条 `/32` 则没有代价。
- 同一前缀只产生一条路由。引擎按包决定用哪条规则，装两次会让撤销失去定论。
- **被拒的规则逐条返回**，不静默跳过：运维写了一条而本功能忽略了它，他们没有任何途径发现这个泄漏。
- 旁路列表来自运行期发现的对端与端点，不是用户配置，因此读不出的条目跳过即可；整体拒绝会因为一个失联对端停掉全部分流。
- 撤销先于新增。同一前缀改变了种类时必须先撤旧的再装新的，否则平台要么拒绝重复条目，要么静默保留先看到的那条。

### 冲突

安装前先查这条精确前缀上是否已有别人的路由。有就**拒绝这一条并把原样的那一行报给运维**，其余照常安装：一个有争议的前缀不该让所有规则失效。一期**不抢占、不比较 metric**，把选择权留给运维，好过悄悄赢下一场与他们自己路由的争论。

### 运行期

规则在进程生命周期内不变，但规则需要的路由会变：旁路是为被覆盖的地址装的，而这些地址随对端连上与断开、中继重新分配、控制连接重建而变。所以计划不是应用一次，而是**随组网自己的节拍重算**，三端一致：

- **虚拟网卡就绪之后才应用**，之后每 5 秒重算一次（组网的保活节拍）。路由指向虚拟网卡，网卡还没起来时装上的是一条指向空处的路由——比「没有路由、流量走本机」更糟，所以网卡未就绪（未创建、`noop`、启动失败）时计划为空，网卡失效后计划也清空、路由撤回，网卡恢复后重装。
- **计划与上次应用的相同就不动**。每 5 秒重写一次安装记录、重配一次消费端只会打断自己的流。比较的是集合，顺序不算变化；消费端只在规则、组网网段或本机虚拟地址变化时重配。
- **上次应用留下了没做完的事**（有前缀被别人占用、或安装失败回滚）**且计划没变时，60 秒后再试一次**；计划变了立刻应用。冲突与失败只在变化时记日志，同一条冲突不会每分钟刷一行。判定用例见 `peer-egress-routes-v1.json` 的 `reconcile`。
- **网卡被替换或关闭时先撤回**：三个平台上，接口消失时内核会连带删掉经它的路由；本功能在关闭前自己撤回，新网卡起来后由下一次重算重装。
- **规则为空也走一遍**：不建消费端（状态里消费端为未启用），但安装记录照读，上一次进程留下的路由照收。
- **计划没变的每一拍都对照真实路由表**（Linux `ip -4 route show table main`，Windows 原生转发表，macOS `netstat -rn`），与安装记录比对。指向隧道的路由不见了就重装；旁路的行不见了、或它的接口/网关与「去掉隧道和本功能自己的路由之后，表现在会把该地址送去哪」不同，就先撤再装、重新解析下一跳；旁路还在而隧道之外已无更好的路可走就保留。隧道路由的前缀出现在别的接口上是别人的路由：报冲突、从安装记录里放弃、不抢占，计划 60 秒后重新申请。重装失败的路由仍归本功能所有，60 秒后再试。比对用例见 `peer-egress-socket-binding-v1.json` 的 `drift`。

### 旁路的下一跳

旁路路由要指向「隧道之外本来会走的那一跳」。三个平台都先问系统：Linux 用 `ip route get`，Windows 用 `Find-NetRoute`，macOS 用 `route -n get`。先问系统，是因为它知道读表读不出来的东西，Linux 的策略路由（例如另一个 VPN 的规则和路由表）尤其如此。

但只要某条规则的路由已经覆盖了这个地址，系统就只会回答「走隧道」。这正是需要旁路的时候：网卡起来之后才出现的对端、中继地址都属于这种情况。实测：在一个把 `203.0.113.0/24` 路由进 `specus0` 的网络命名空间里，`ip route get 203.0.113.9` 的回答是 `dev specus0`。所以**系统回答隧道时，改为读路由表**，按与[出站 socket](#出站-socket) 相同的规则选：

- 候选里去掉隧道接口上的路由，以及本功能自己拥有的旁路前缀；
- 取包含该地址的最长前缀，等长取度量小的，再相同取表里靠前的；
- 选中的路由若不通往任何地方（Linux 的 `blackhole`、`unreachable`、`prohibit`、`throw`），视为**没有下一跳**，不去找下一条路由：表里明确不让到达的地址，不能借旁路绕过去；
- 没有下一跳就拒绝安装这条旁路，错误为 `no route outside the tunnel`。

各平台读的表：

| 平台 | 表 | 网关 |
| --- | --- | --- |
| Linux | `ip -4 route show table main` | `via` 后的地址。多路径路由取第一个 `nexthop`；带 `dead` 的路由不可用 |
| Windows | `GetIpForwardTable2` 与 `GetIpInterfaceTable`（与出站 socket 相同） | 行内的 `NextHop`，`0.0.0.0` 表示直连 |
| macOS | `netstat -rn -f inet`（与冲突检查相同） | 只有 Flags 含 `G` 时 Gateway 列才是网关；否则那一列写的是 `link#N`、MAC 地址、接口名或回环/点对点的对端地址，都按直连处理 |

Linux 回退时只读主路由表，不考虑策略路由。某些机器上，如果没有本功能的路由，这个地址本来会被别的规则送去另一张表（例如 wg-quick 用 `suppress_prefixlength 0` 把默认路由让给 WireGuard 表），回退得到的仍是主表里的那一跳。这种情况只在「规则覆盖了控制或对端地址」与「机器上另有策略路由」同时成立时出现。

固定向量：`protocol/test-vectors/peer-egress-socket-binding-v1.json` 的 `linux` 与 `hops`。Linux 的表是在 WSL 2（iproute2 6.1.0）里用 `unshare -rn` 建的网络命名空间中抓取的，TUN、虚拟网卡与路由都是真的。真机测试：

- Go 在 Linux runner 上以 root 在独立网络命名空间里先装规则路由、再装被它覆盖的旁路，断言旁路经物理网关；再断言黑洞后面的地址被拒绝（`peer-egress-linux.yml`）。
- macOS runner 上以 lo0 充当隧道做同样的事（`peer-egress-macos.yml`）。
- 两处都先断言系统查询确实回答了隧道，所以不经过回退就过不了。

### 安装记录

安装记录（journal）落盘，用来区分「本功能装的」与「用户或别的工具装的」，跨越正常退出、崩溃与重启。**先写记录再安装**：为一条没装成的路由留下记录，代价是清理时一次无害的删除尝试；而没有记录的已装路由，没有人会再去收回它。

写入走临时文件加改名。被崩溃截断的记录会比实际安装的少，少掉的那部分就是会被留在路由表里的东西。

格式在三个客户端实现之间共享——同一台机器上换实现之后，上一次装下的路由要被收回：

```json
{
  "version": 1,
  "routes": [
    { "cidr": "198.51.100.7/32", "kind": "bypass", "origin": "bypass" },
    { "cidr": "203.0.113.0/24", "kind": "tun", "origin": "rule:203.0.113.0/24" }
  ]
}
```

`kind` 取 `tun` 或 `bypass`。`origin` 是运维会读到的字符串：旁路为 `bypass`，规则为 `rule:` 加上规则里原样的 `match`。

读取规则：

- **文件不存在**即空集合。这是正常的首次运行，拒绝启动没有任何收益，而空集合之外的选择是去猜机器上哪些路由曾经是自己的。
- **文件存在但读不出**（版本不认识、`kind` 不认识、根本不是 JSON）一律**失败并报错**，不得当作空集合。当作空集合意味着它描述的那些路由永远不会被收回。
- **启动时读到的条目先全部收回，再按当前计划重装**，而不是逐条比对后保留。记录比写它的进程活得久，而那个进程的接口已经随它消失，记录描述的路由要么已经不在，要么指向空处；仍然需要的由紧接着的应用装回来。规则已经删空时同样读记录、同样收回。
- 全部撤销之后删除该文件。

### 平台

未实现接管的平台必须**返回失败而不是静默什么都不做**：装不上任何路由却报告规则已生效的消费端，会把每个目标都送去本地直连，正是本功能要防的泄漏。

#### Linux

`ip route`。输出不带翻译，因此可以直接解析文本。

#### Windows

路由表通过 **PowerShell 的 `Get-NetRoute` / `Find-NetRoute` / `New-NetRoute` / `Remove-NetRoute`** 读写，**不解析 `netsh` 与 `route print`**：它们的输出是本地化的。同一条 `netsh interface ipv4 show route` 在同一台机器上，一个控制台代码页下打印英文表头，另一个下打印中文表头（`发布  类型  跃点数  前缀  索引  网关/接口名称`）。照英文表头写的解析器在中文机器上一条路由都读不出来，而「读不出路由」恰好等于「没有冲突，装吧」——失败方向是覆盖掉运维自己的路由。

调用 `powershell.exe`（Windows PowerShell 5.1）而不是 `pwsh`：前者随系统存在，后者不一定装。

PowerShell 那一层**只把对象转成 JSON，不做判断**。挑哪个对象、缺失的下一跳是什么意思、失败是不是权限问题，全部在解析器里，由共享向量钉住三端；写进 PowerShell 字符串里的过滤逻辑是三份各自嵌的片段，没有任何测试覆盖得到。据此固定下来的读法：

- **序列化用 `ConvertTo-Json -InputObject @(...)`，不用管道。** 管道给单个对象时输出的是 JSON 对象而不是单元素数组，而「只有一条路由」正是最常见的情况——只测过多条的解析器会在生产上读不出东西。
- **`Find-NetRoute` 返回两个对象**：先是它会使用的源地址，然后才是路由。只有后者带 `DestinationPrefix`，靠这个把它挑出来。取 `[0]` 会拿到接口索引却没有下一跳，等于把一条经网关的路由读成直连。
- **直连在 Windows 上写作 `NextHop = 0.0.0.0`**，Linux 是省略 `via`。两者都归一成空网关，安装器不需要知道是哪个平台回答的。照 `0.0.0.0` 原样安装会装出一条指向空处的路由。
- **`InterfaceIndex` 为 0 的条目跳过**，继续找下一条。0 不是接口。
- **只用接口索引，不用接口名**：接口名是本地化的（中文系统上默认网卡叫「以太网」），索引是数字。
- **权限不足认 `FullyQualifiedErrorId` 里的错误号 5**（`Windows System Error 5`），不认消息文本：消息在中文系统上是「拒绝访问」。这一类失败要明确告诉运维需要提权，重试到天亮也不会成功。
- 查不到前缀时 `Get-NetRoute` 是**报错**而不是输出空，因此查询带 `-ErrorAction SilentlyContinue`，把它压成空数组。

**每次进程启动约 175 ms，第一次调用 NetTCPIP cmdlet 再加约 380 ms，之后同一进程内的查询几乎免费**（实测：一次查询 559 ms，五次 564 ms）。因此平台查询要在一个进程里批量做完，逐条调用会让二十条规则花掉十一秒。Linux 的 `ip` 是毫秒级，没有这个约束。

批量的输出形状：**每个被问的前缀输出一行压缩 JSON，行序即入参序**，空结果也占一行。因此逐行喂给单条的解析器即可，不需要为批量再写一套读法。

发出去的脚本本身也被固定，不只是收回来的输出——三端各自嵌一份 PowerShell 字符串，正是其中两端查了 `ActiveStore` 而第三端查了 `PersistentStore` 的方式，而解析结果看不出任何差别。

- **`PolicyStore` 用 `ActiveStore`，不用 `PersistentStore`。** ActiveStore 的路由不跨重启存在，这正是本功能要的，也与 Linux 的 `ip route add` 一致。真正会留下残留的是持久化路由：重启之后它还在表里，而安装记录可能已经对不上了。
- **`Remove-NetRoute` 必须带 `-Confirm:$false`**，否则在非交互进程里等一个没人回答的确认。
- **删除一条表里没有的前缀不算失败**（`CmdletizationQuery_NotFound`）：要的结果已经成立。这一条在 Windows 上比在 Linux 上更要紧，因为 ActiveStore 的路由不跨重启，所以**每次重启后的第一次清理，走过的整本安装记录都是这个状态**——把它报成失败会让真正的失败淹在噪音里。
- **安装不带 `-NextHop` 即直连**，与写 `-NextHop '0.0.0.0'` 等价，取前者。

### 参数拼接

Linux 侧前缀与地址作为 argv 条目传给 `ip`，从来没有 shell 看见它们。Windows 侧它们被拼进**一个命令字符串**，因此：

**只接受点分十进制的地址与 CIDR，其余一律拒绝到构造脚本之前。** 不做转义——白名单里没有引号，一道到不了的转义读起来像第二道防线，而到不了的防线比没有更糟：它会让第一道被放松。

一条写着 `10.0.0.0/8';Remove-NetRoute -DestinationPrefix '0.0.0.0/0` 的前缀就是两条命令，第二条会删掉默认路由。

**接口名是唯一不能白名单的参数**：TUN 适配器名来自配置，空格与非 ASCII 字符都是合法的（采样机上默认网卡就叫「以太网」）。因此这一处**转义才是防线**，不是到不了的代码——PowerShell 单引号字符串里，一个引号写成两个。

### 输出编码

**子进程的 stdout 用控制台代码页写出，采样机上是 936，不是 UTF-8。** GBK 双字节字符的低字节可能是 `0x5C`，也就是反斜杠——把一个中文适配器名回显进 JSON 就可能吐出一个裸反斜杠，整份文档就坏了。

因此**脚本一律不 `Select` 任何名字字段**。索引、前缀、下一跳、跃点数都是 ASCII，无论代码页是什么都读得出来。这是要求，不是巧合：查接口索引的脚本把名字**传进去**，但只把索引**取回来**。

同理，**子进程的 stdout 与 stderr 不合并**。Linux 侧合并是无害的，`ip` 要么成功要么在 stderr 上说话；Windows 侧脚本把自己的失败 catch 成 stdout 上的 JSON，而 PowerShell 自己未捕获的错误走 stderr。合并会把非 JSON 文本插进 JSON，于是每个解析器都只看到「读不出来」——而那正是「没有冲突，装吧」的那个答案。

### 冲突检查的整表缓存

冲突检查按前缀逐条被问，但答案全部来自**一次整表读取**。逐条查是每条 419 ms；一次读完是一次。

缓存带**生存期**，一期定为 5 秒。这个数只需要覆盖一次下发的时长：**一次下发内缓存有效，跨下发必然失效**。一次下发跑得比生存期长，代价是多读一次表，那是变慢而不是答错；而不设生存期的缓存最终会漏掉别人几小时前装的路由，把一条本该被拒绝的冲突变成一次失败的安装，进而回滚整份计划。

前缀是**精确字符串比较**，不是最长前缀查找。问的是「这条精确前缀上有没有别人的路由」，不是「这个地址能不能被路由」——有默认路由时后者永远是能，把它当冲突会在任何一台有默认路由的机器上拒绝掉每一条规则。

### 参数在起进程之前就被拒

安装与撤销在构造脚本**之前**先校验前缀。顺序是刻意的：一个脚本构造器本来就会拒绝的参数，不该先花半秒去查接口索引；而在这个平台上，那道拒绝正是「一条前缀不会变成第二条命令」的保证。

平台选择住在自己的地方（Go 按 build tag 分派，Java 与 .NET 各有一个 `PeerEgressRouteCommanders`），不挂在某一个平台的类上：三个平台都实现之后，一个叫 Linux 的类去决定要不要构造另外两个就说不通了。

#### macOS

读路由表用 `netstat -rn -f inet`，改路由表用 `route`。下面每一条都是真机采样出来的，其中三条改了设计而不是确认了设计。

**`route` 失败也返回 0。** 前缀已存在、前缀不在表里、接口没有 IPv4 地址、参数不完整——采样到的失败里除了地址不合法之外全部退出 0，而且 stdout 第一行的开头与成功一模一样（`add net 203.0.113.0: gateway 192.168.64.1` 后面跟一个 `: File exists`）。信退出码的实现会把失败的安装报成成功，于是一条规则被认为已生效，而它要捕获的流量照旧从物理网卡出去。

分开成功与失败的是 **stderr**：采样到的每一次成功修改 stderr 都是空的，每一次失败都有 `route: writing to routing socket: <errno 的 strerror>`。所以分类按「stderr 非空即失败」来做，不按错误文本列表——那些文本是路由套接字返回值的 strerror，列不完，而没认出来的错误会被当成成功。stderr 上的噪声往另一个方向错：安装被报成失败，安装器把自己刚装的那条撤掉，什么都不会漏。权限失败是唯一一条 stdout 完全为空的失败（`route: must be root to alter routing table`，退出码 77），这也是「必须读 stderr」的那一条载荷。

**`route -n add -net 203.0.113.0/33 <网关>` 会被接受。** 它打印成功行、退出 0，装进表里的是 `128.0/1`——半个 IPv4 地址空间指向网关。输出里没有任何地方说得出这件事，只有路由表说得出。Windows 上同样的参数会被 `New-NetRoute` 拒绝，所以那边「起进程之前先校验前缀」是多一层防线；这边它是唯一一层。八位组和长度也都不接受前导零：`route` 用 inet_aton 解析地址，前导零按八进制读，`010.0.0.1` 对它是 `8.0.0.1`——同一段文本被读成两个前缀，意味着冲突检查问的是一条、装进去的是另一条。

**读表很便宜，所以不缓存。** `netstat -rn -f inet` 中位数 25 ms，`route -n get` 26 ms，`/usr/bin/true` 3 ms。Windows 那边缓存整表五秒，因为一次 PowerShell 查询 419 ms、二十条前缀的计划要花八秒去问；这边二十次读表是半秒。缓存换来的是一个本来不存在的节省，代价是一个答案可能过期的窗口，所以 macOS 每次冲突检查都重读整表。**同一个问题，两个平台两个答案，分开它们的是测量。**

仍然读整表而不是逐条查，因为逐条查这件事不存在：`route -n get` 做最长前缀匹配，任何有默认路由的机器上，它对每一条没人占的前缀都回答「能路由」。前缀是精确比较，理由与 Windows 相同。

**netstat 的 Destination 列是缩写过的，而缩写方式猜不出来。** `0.0.0.0/0` 写成 `default`，`127.0.0.0/8` 写成 `127`，`203.0.113.0/24` 写成 `203.0.113`，`100.64.0.0/10` 写成 `100.64/10`，`198.51.100.0/26` 写成 `198.51.100/26`，主机路由写成裸地址。读回来的规则是：没带长度的按每个八位组八位算，带长度的把缺的八位组补零；补完之后按长度掩掉主机位，因为同一条前缀的两种写法必须比较相等。

**按段落切分是必需的，不是整洁。** `netstat -rn` 的 `Internet6:` 段里也有 `default`——采样机上有四条，每个 utun 一条——而 `default` 是唯一一个 IPv6 写法与 IPv4 写法长得一样的目的地。不切分的话，问「有没有人占着 0.0.0.0/0」会在任何开了 IPv6 的机器上找到幽灵路由，而那条前缀正是全隧道规则要的那条。

**内核生成的条目（flags 里带 `W`）不算冲突。** BSD 把地址解析放在路由表里，所以最近通信过的每一台主机都有一条自己的 `/32`，子网广播地址和加入过的每个组播组也都有。把它们算成冲突会拒掉旁路路由——旁路是控制端点、STUN、TURN 与对端地址的 `/32`，恰好是最可能已经通信过的那些地址——而被拒的旁路路由正是本功能要防的那种泄漏。

**参数拼接：没有 shell。** 这些是直接 exec 的 argv 数组，所以这边没有引号问题：一条带引号或分号的前缀不会变成第二条命令，只会是一条 `route` 读不懂的前缀。要防的是「读起来像选项的值」和「读起来像合法前缀但不是的值」。接口名因此是白名单而不是转义——与 Windows 上同一个值的处理正好相反，那边它作为脚本的一部分进入 PowerShell，必须转义，因为运维真的会用带空格和非 ASCII 的适配器名；这边它是 argv 的一个元素，没什么可转义的，唯一会出错的是 `route` 把接口名当地址读，而它确实会：接口不存在时报的是 `route: bad address: utun99`。

**TUN 必须先有 IPv4 地址，路由才能指过去。** 同一条 `route -n add -net ... -interface utun3`，在只有链路本地 IPv6 地址的接口上报 `Network is unreachable`（退出码仍然是 0），`ifconfig` 配上地址之后成功。Linux 上 `ip route add ... dev tun0` 不需要地址，所以这是一个平台差异，也是对调用顺序的要求：先配地址，再下发路由。

**同一条前缀上可以有多条路由。** 第二次普通 `add` 报 `File exists`，但 `-ifscope` 限定作用域的可以与未限定的并存，采样机上同时有三条。所以冲突描述里的「+N more」是真的会发生的，不是摆设。安装与撤销都不带 `-ifscope`：不带它的撤销只删未限定的那一条，限定的留着——这是对的方向，本功能只装未限定的路由，同一前缀上限定作用域的那条属于别人。

**输出不本地化**，这是在 zh_CN、ja_JP、de_DE 三个 locale 下采样比对出来的，与 C 区域逐字节相同，不是「BSD 工具没有消息目录」这个说法。所以这边按键名解析是安全的，Windows 那边不是。

固定向量：`protocol/test-vectors/peer-egress-routes-v1.json`（计划、差异、安装记录与 `ip route` 输出解析）、`protocol/test-vectors/peer-egress-windows-routes-v1.json`（Windows 三个解析器）、`protocol/test-vectors/peer-egress-macos-routes-v1.json`（macOS 的读表、归一、分类与参数）。后两者标了 `sampled` 的用例都是真机抓下来的原样输出：Windows 侧为 Windows 11 26200、Windows PowerShell 5.1.26100.9444、系统区域 zh-CN；macOS 侧为 macOS 26.6.2（Darwin 25.6.0，arm64）。

## 出口授权模型

服务端实体 `peer_egress_policy`，与 `peer_mesh_acl` 正交。基础组网授权**不自动**等于出口授权。

| 字段 | 说明 |
| --- | --- |
| `egressClientId` | 出口设备的稳定标识，不使用易变的名称或 IP |
| `enabled` | 出口设备总开关，默认 `false` |
| `allowedConsumerClientIds` | 允许使用该出口的设备 |
| `destinationRules[]` | `cidr` + `protocols[]` + `portRanges[][]`。**默认空 = 全拒绝**，不存在「未配置即放行」 |
| `scope` | `PUBLIC` 或 `LAN`。公网访问与对端局域网访问分开授权，互不隐含 |
| `limits` | `maxConcurrentFlows`、`maxFlowsPerConsumer`、`idleTimeoutSeconds` 等 |

`allowed = 基础 Peer ACL ∩ 出口策略`。服务端下发时取交集，出口端在实际 `connect()` 前**再完整校验一次**。目录不可见与数据面不可访问必须同时成立，与 Peer 服务共享的既有口径一致。

### 强制拒绝清单

以下目标**不受任何宽泛公网规则影响**，即使策略里存在 `0.0.0.0/0` 条目也必须拒绝：

- `0.0.0.0/8`、`127.0.0.0/8`（回环）
- `169.254.0.0/16`（链路本地），含 `169.254.169.254` 与 `100.100.100.200` 等云元数据端点
- `224.0.0.0/4`（组播）、`240.0.0.0/4`、`255.255.255.255/32`（广播）
- Peer Mesh 虚拟网段
- 本部署的控制连接、STUN 与 TURN 端点地址
- **出口本机任何 TUN 或虚拟接口的网段**

最后一项是防回环规则的延伸：消费端发来的是地址，若该地址落在出口自己的虚拟接口网段内，转发就会绕回出口自身的接管路径。二期引入 fake-IP 后，出口本机的池段同样加入此清单。

### 判定顺序

按固定顺序执行，各实现返回的错误码必须逐条一致，而不只是 allow/deny 一致：

```text
hop → enabled → peerAcl → consumer → forcedDeny → scope
    → destination → protocol → port → limits
```

`scope` 分类：`LAN` 为 RFC 1918 私有地址与 RFC 6598 共享地址空间；其余可路由地址为 `PUBLIC`。

授权撤销、出口关闭或设备停用时，**立即拒绝新流并清理受影响的已有流**，不等待空闲超时。

固定向量：`protocol/test-vectors/peer-egress-authz-v1.json`。

## 出站 socket

出口替消费端连接目标用的是普通 socket。这台设备若同时是消费端，本机隧道为它自己的规则装的路由会覆盖一部分目标；socket 跟着这些路由走，转发流量就回到 mesh 里，而不是从本机出去。强制拒绝清单挡的是「目标落在本机虚拟接口网段」，挡不住「目标是公网地址、本机路由表却把它指进隧道」。

所以出站 socket 在 connect 之前绑定到**假如没有隧道的路由、系统本来会选的那个接口**：

| 平台 | 做法 |
| --- | --- |
| Windows | `IP_UNICAST_IF`（`IPPROTO_IP`，31）。值为接口索引的**网络字节序**，传主机序时 setsockopt 直接报错；读回时却是主机序 |
| macOS | `IP_BOUND_IF`（`IPPROTO_IP`，25）。值为接口索引的主机序 |
| Linux | 不绑定接口。Go 与 .NET 给 socket 打 `SO_MARK 0x5350`，由运维添加策略路由，见[对系统的改动](#对系统的改动)；Java 不打，见当前限制 |

这两个选项都不需要提权，也都由协议栈强制执行：绑到一个没有路由通往目标的接口上，流量不会换个接口出去，而是失败。失败发生在哪一步因平台和协议而异，都是实测的：

| | TCP | UDP |
| --- | --- | --- |
| Windows | connect 失败：目标经别的接口才到达时报 `WSAENETUNREACH`，目标是回环地址时报 `WSAEADDRNOTAVAIL` | 同 TCP，connect 时失败 |
| macOS | connect 失败，`EADDRNOTAVAIL`（`can't assign requested address`） | **connect 成功**，第一次发送时失败，同样是 `EADDRNOTAVAIL`。macOS 上连接 UDP socket 只是记下对端，不查路由 |

**接口按目标逐个选。** 统一绑到默认路由所在的接口，会让经第二块网卡或另一个 VPN 才能到达的目标全部不通。选法：

1. 候选是 IPv4 路由表里的全部路由，去掉本机 TUN 接口上的路由（按接口精确比较：`utun30` 不是 `utun3`），再去掉系统不会给未绑定 socket 使用的路由——Windows 上所在接口未连接的路由、所在接口设置了 `DisableDefaultRoutes` 的 `0.0.0.0/0`、接口表里找不到其接口的路由；macOS 上带 `I` 标志（限定作用域）的路由。
2. 取包含目标的最长前缀；等长时取度量小的，Windows 的度量是路由度量加接口度量，macOS 一律为 0；再相同取表里靠前的。
3. 没有候选时**拒绝建流**，不退回不绑定：不绑定的 socket 正是会跟着隧道路由走的那个。TCP 流给消费端回 RST，UDP 会话直接不建，日志记为 `connect failed ... no route outside the tunnel`。

没有 TUN 的节点（虚拟网卡为 `noop`）没有路由要去掉，按同样的规则选出来的就是系统自己的选择。TUN 名在系统里找不到对应接口时同样视为没有路由要去掉：不存在的接口上不会有路由。

**读表。** Windows 每次 connect 用 `GetIpForwardTable2` 与 `GetIpInterfaceTable` 原生读取，不经 PowerShell：一次 `Get-NetRoute` 要 419 ms，这两个调用是微秒级，不需要缓存，切网之后下一次 connect 就能看到。macOS 读 `netstat -rn -f inet`，与路由接管同一套读取与归一，25 ms 一次，结果保留 2 秒：隧道自己的路由本来就不参与选择，缓存能错过的只有物理网络的变化，而错过的后果是 connect 失败，不是泄漏。

**Java 的前提。** JDK 不提供这两个选项，也不暴露 socket 句柄。Java 客户端经 `sun.nio.ch.SelChImpl.getFDVal()` 取句柄，再用 JNA 调 setsockopt，这要求 JVM 带 `--add-exports java.base/sun.nio.ch=ALL-UNNAMED`。发布的 jar 在清单里声明了 `Add-Exports`，`java -jar` 启动时自动生效，Spring Boot 嵌套加载的类同样适用；以其他方式启动又缺这个选项时，Windows 与 macOS 上的每次出口建流都会被拒绝，日志写明缺的是哪个选项。

固定向量：`protocol/test-vectors/peer-egress-socket-binding-v1.json`，覆盖接口选择、Windows 两张表的二进制布局、macOS 的候选路由与两个选项的编码。Windows 表布局按 SDK 结构体用 ctypes 生成，偏移在 Windows 11 26200 上与 `Get-NetRoute`、`Get-NetIPInterface` 逐行比对过，三端测试在每次 Windows CI 上重做这一比对。三端另有真实 socket 测试：连 127.0.0.1 时读回绑定的是回环接口；把回环接口当作隧道时拒绝建流；给绑定器一张声称 `127.0.0.0/8` 在物理接口上的表时，TCP 连不上、UDP 数据报送不到。UDP 那一半真的发包并在监听端等待，先用正确绑定发一次、必须收到，因为 macOS 上错误绑定的 UDP socket 能连接成功，只看 connect 会误判。最后这条在不设选项时会通过，所以它证明的是选项真的起了作用。Windows 部分在 CLI 矩阵的 windows runner 上运行，macOS 部分在 `peer-egress-macos.yml` 的 macOS runner 上运行。

## 能力协商

登录 `environment.clientEgressCapabilities`：

| 字段 | 说明 |
| --- | --- |
| `version` | 当前为 `1`。`0` 或缺省表示不支持出口 |
| `consumerCapable` / `egressCapable` | 该客户端能否作为消费端 / 出口端 |
| `domainTargetCapable` | 是否支持域名目标。一期固定为 `false` |
| `ipv6TargetCapable` | 是否支持 IPv6 目标。一期固定为 `false` |

服务端**不得**向 `version` 为 `0` 或缺省的客户端下发 `egress-config` 或 `egress-catalog`。四个服务端都按这条门控。

设计稿里这个字段叫 `egressVersion`，四个服务端实现与 Java 共享模型读的都是 `version`，以实现为准。三个客户端上报 `version: 1`、`egressCapable: true`（出口只需要普通 socket）、`consumerCapable` 按本平台能否接管路由（Linux、Windows、macOS 为 `true`），`domainTargetCapable` 与 `ipv6TargetCapable` 为 `false`。

> 在 P8 审计之前，三个客户端**都没有上报**这个对象（Java 上报了但 `version` 为默认的 `0`），于是没有任何服务端向任何客户端下发过 `egress-config`：真实部署里没有设备能被启用为出口，出口数据面只在直接喂策略的测试里跑过。修复见 `fix(peer-egress): make the feature reachable outside its own tests`。

`domainTargetCapable` 与 `ipv6TargetCapable` 独立于 `egressVersion`，这样二期上线时新旧客户端可以共存，不必靠版本号一刀切。

消费端遇到不支持出口的对端或旧服务端时，**不降级、不静默直连**：出口侧不可用时命中规则的流量被阻断，状态查询里对应出口显示离线、拦截计数里记为 `egress-unavailable`。设计稿要求的「明确提示能力不支持」这一句提示尚未实现，见当前限制。升级默认关闭，不改变现有组网与服务共享行为。

## 控制信令

复用控制连接的 `MESSAGE_REQUEST` / `MESSAGE_RESPONSE`，`messageType=PEER_CONTROL`。

### `egress-config`

服务端下发给出口设备。开关或策略变更后立即下发，不等下次登录。

```json
{
  "type": "egress-config",
  "enabled": true,
  "revision": 7,
  "scope": "PUBLIC",
  "allowedConsumerClientIds": [1, 5],
  "destinationRules": [
    {"cidr": "203.0.113.0/24", "protocols": ["tcp"], "portRanges": [[80, 80], [443, 443]]}
  ],
  "limits": {"maxConcurrentFlows": 256, "maxFlowsPerConsumer": 64, "idleTimeoutSeconds": 60}
}
```

`revision` 在同一控制 session 内单调递增，小于或等于上次接受值的快照幂等忽略。`enabled` 转为 `false` 时出口必须立即停止接受新流并关闭全部已建流。

客户端读取这条消息时：

- `type` 不是 `egress-config` 的消息**不属于**这个解码器。把目录当成策略读会给节点装上一份它没有收到过的策略。
- `scope` 在存下来之前**去空白并转大写**。判定层拿自己算出的 `PUBLIC` 或 `LAN` 做相等比较，一条写着小写 `public` 的推送在不归一化的实现里会被判成不匹配，整条策略静默失效。
- `scope` **缺失即拒绝**，不得回落到 `PUBLIC`：消息照常接受并记下空 `scope`，此后判定一律返回 `EGRESS_SCOPE_DENIED`（向量用例 `enabled-without-scope-denies`）。把缺失的授权字段默认成许可值就是「未配置即放行」，这一点对 `destinationRules` 已经写明，`scope` 没有理由例外。
- `limits` 缺失时三个字段都为 `0`，由使用方按自己的默认值兜底；解码器不替它编造数值。关闭出口的推送不带 `limits`，这是服务端逐字发出的形状。
- **不认识的键一律忽略。** 服务端已经会带上 `createdAtMillis`，日后还会带别的；旧客户端拒绝整条消息等于一次协议升级就让所有旧设备停止接受配置。

固定向量：`protocol/test-vectors/peer-egress-control-v1.json`。

### `egress-catalog`

服务端下发给消费设备，列出当前可用的出口及其能力。

```json
{
  "type": "egress-catalog",
  "revision": 4,
  "egresses": [
    {
      "clientId": 2,
      "clientName": "office-gateway",
      "online": true,
      "scope": "PUBLIC",
      "protocols": ["tcp", "udp"],
      "domainTargetCapable": false,
      "ipv6TargetCapable": false
    }
  ]
}
```

目录**不包含**出口的目标白名单细节：消费端不需要它，泄露出去等于把出口的内网拓扑告诉每个对端。消费端配了不被允许的目标时，由出口在建流阶段拒绝并通过 `flow-reject` 说明。

出口下线、设备停用、ACL 撤销或总开关关闭时立即下发 `egresses: []`。`egress-catalog` 只能由服务端发出；客户端上报该类型必须拒绝。

**客户端目前不处理这条消息。** 四个服务端都会下发，三个客户端都没有解码器。消费端判断出口是否可用，用的是 Peer Mesh 自己的对端在线状态，而不是目录；因此目录里的 `scope`、`protocols` 等能力信息目前不影响消费端行为，被出口拒绝的目标由 `flow-reject` 与状态里的 `rejected-<错误码>` 计数体现。

### `egress-report`

出口设备上报给服务端，仅用于管理端展示。

```json
{
  "type": "egress-report",
  "revision": 12,
  "activeFlows": 18,
  "totalFlows": 2140,
  "rejectedFlows": {"EGRESS_DEST_DENIED": 4, "EGRESS_PORT_DENIED": 1},
  "bytesIn": 10485760,
  "bytesOut": 2097152
}
```

服务端从已认证的当前控制连接绑定上报者身份与 session，**不信任消息体里的 source 身份**。客户端必须省略全部 `sourceClient*`、`targetClient*`、`sessionId` 与 `token` 字段；显式发送 `null` 同样属于协议违规。

上报不含目标地址、域名或请求内容。拒绝计数按错误码聚合，不逐条记录目标。

**客户端目前不发送这条消息。** 服务端能接收并在管理接口 `GET /api/admin/peer-mesh/egress/activity` 展示，但三个客户端都没有发送方，所以该接口目前总是空的。出口侧的计数在本机状态查询（`specus-client egress`）里可以看到。

## SPEG1 数据面帧

`SPEG1` 是 SPM2 解密后的**第三种明文类型**，与裸 IPv4 packet 和 `STMSG2` 应用消息并列。出口路径与 mesh 内部路径在解密后第一时间分流，两套校验互不削弱。

| 明文类型 | 校验规则 |
| --- | --- |
| 裸 IPv4 packet | 源 = 对端虚拟 IP，目标 = 本机虚拟 IP |
| `STMSG2` 应用消息 | 见 `peer-mesh.md` |
| `SPEG1` 出口帧 | 见下 |

**不得通过放宽裸 IPv4 packet 的既有校验来承载出口流量。**

### 帧头

固定 8 字节：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| `magic` | 5 | ASCII `SPEG1`，`0x5350454731` |
| `type` | 1 | `1` = ip-packet，`2` = control |
| `flags` | 1 | bit0 = hop；其余位保留，必须为 `0` |
| `reserved` | 1 | 必须为 `0` |

`type=1` 的 body 是完整 IPv4 packet。`type=2` 的 body 是 UTF-8 JSON object，无空白，键序按本文给出的顺序。

hop 标记由出口设备在**自己作为消费端**转发流量时置位。出口收到已置位的帧一律拒绝——不支持多跳出口链。

### 接收方校验

消费端 → 出口（`type=1`）：

- IP 版本必须为 4；IPv6 返回 `EGRESS_IPV6_UNSUPPORTED`
- IPv4 `totalLength` 精确等于 body 长度，尾随字节拒绝
- **源地址等于该已认证 session 对端获分配的虚拟 IP**。不得仅信任包内源地址，否则对端可伪造其他获授权虚拟 IP
- 目标地址**不在** Peer Mesh 虚拟网段内
- 目标通过完整的出口授权判定

出口 → 消费端（`type=1`）：

- 目标地址等于本机会话获分配的虚拟 IP
- **源地址必须对应一个本机发起过、且当前存活的出口流**。否则对端可以借回程路径注入任意源地址的包
- 源地址**不在** Peer Mesh 虚拟网段内。否则出口可以伪造成其他 mesh peer

### 控制消息

`type=2`，一期定义两种。控制消息只用于诊断与撤销，**不承载业务数据**；丢失不得影响数据面正确性。

`flow-reject`，出口 → 消费端：

```json
{"type":"flow-reject","protocol":"tcp","sourceIp":"100.96.0.1","sourcePort":54321,"destinationIp":"203.0.113.9","destinationPort":22,"code":"EGRESS_DEST_DENIED"}
```

应用侧以出口用户态栈生成的 TCP RST 为准，本消息只为界面提供可读的阻断原因。

`flow-purge`，消费端 → 出口：

```json
{"type":"flow-purge","destinations":["203.0.113.0/24","198.51.100.50/32"],"code":"EGRESS_RULE_REVOKED"}
```

出口关闭匹配这些目标的全部已建流。

`name-bind` 为二期域名分流保留。一期收到必须拒绝，返回 `EGRESS_CONTROL_UNSUPPORTED`，不得当作已实现。

固定向量：`protocol/test-vectors/peer-egress-frame-v1.json`。

## 错误码

| 错误码 | 触发点 |
| --- | --- |
| `EGRESS_ALLOWED` | 授权通过 |
| `EGRESS_HOP_NOT_ALLOWED` | hop 标记已置位，不支持多跳出口链 |
| `EGRESS_DISABLED` | 出口总开关关闭 |
| `EGRESS_PEER_ACL_DENIED` | 基础 Peer ACL 不允许 |
| `EGRESS_CONSUMER_DENIED` | 消费设备不在出口允许列表内 |
| `EGRESS_FORBIDDEN_DESTINATION` | 命中强制拒绝清单 |
| `EGRESS_SCOPE_DENIED` | 目标的 scope 与授权 scope 不符 |
| `EGRESS_DEST_DENIED` | 目标地址不在任何允许网段内 |
| `EGRESS_PROTOCOL_DENIED` | 地址命中但协议未授权 |
| `EGRESS_PORT_DENIED` | 地址与协议命中但端口未授权 |
| `EGRESS_LIMIT_EXCEEDED` | 并发或配额上限 |
| `EGRESS_RULE_DOMAIN_UNSUPPORTED` | 配置校验：一期不支持域名规则 |
| `EGRESS_RULE_IPV6_UNSUPPORTED` | 配置校验：一期不支持 IPv6 规则 |
| `EGRESS_RULE_MALFORMED` | 配置校验：前缀非法或主机位非零 |
| `EGRESS_RULE_MISSING_TARGET` | 配置校验：`action=egress` 缺少 `egressClientId` |
| `EGRESS_RULE_MESH_OVERLAP` | 配置校验：规则覆盖 Peer Mesh 虚拟网段 |
| `EGRESS_RULE_DEFAULT_ROUTE` | 配置校验：一期不接管默认路由 |
| `EGRESS_RULE_PORT_UNSUPPORTED` | 配置校验：消费端规则不支持端口维度 |
| `EGRESS_FRAME_BAD_MAGIC` | 帧 magic 不是 `SPEG1` |
| `EGRESS_FRAME_UNKNOWN_TYPE` | 未定义的 `type` |
| `EGRESS_FRAME_RESERVED_SET` | `reserved` 字节或保留 flag 位非零 |
| `EGRESS_FRAME_TRUNCATED` | 帧短于固定头，或 body 不足以构成 IPv4 packet |
| `EGRESS_FRAME_TRAILING_BYTES` | IPv4 `totalLength` 与 body 长度不符 |
| `EGRESS_IPV6_UNSUPPORTED` | 数据面收到 IPv6 packet |
| `EGRESS_FRAME_MALFORMED_CONTROL` | `type=2` 的 body 不是 UTF-8 JSON object |
| `EGRESS_CONTROL_UNSUPPORTED` | 控制消息类型未在本版本实现 |

## 状态查询

本功能必须能说出自己在做什么。在此之前做不到：一条运维写下、而本功能拒掉的规则，只在被拒的那一刻写进日志一次，此后无处可查——路由规划器自己的注释把这种情况叫做「运维没有任何办法注意到的泄漏」。路由因为前缀已被别人占用而没装上，同样如此：流量从物理网卡出去，而每一个面板看上去都是健康的。

运行中的进程把一份状态快照发布到本地状态文件里（与 `peers`、`services` 同一份文件、同一套私有目录校验），一次性命令读它。三端写的是同一份形状，因为任一端的 CLI 都要能读另一端写的文件。

快照里 `egress` 一节的形状：

```json
{
  "consumer": {
    "active": true,
    "appliedAtUnixMs": 1757000000000,
    "rules": [
      {"index": 0, "match": "203.0.113.0/24", "action": "egress", "egressClientId": 42,
       "inForce": true},
      {"index": 1, "match": "0.0.0.0/0", "action": "egress", "egressClientId": 42,
       "inForce": false, "code": "EGRESS_RULE_DEFAULT_ROUTE"}
    ],
    "routes": [
      {"cidr": "203.0.113.0/24", "kind": "tun", "origin": "rule:203.0.113.0/24",
       "installed": false, "conflict": "203.0.113.0/24 via 192.0.2.1 dev eth0"}
    ],
    "peers": [{"clientId": 42, "online": true}],
    "flows": 3,
    "blocked": {"egress-unavailable": 7},
    "routeError": "",
    "rolledBack": false
  },
  "egress": {"active": true, "flows": 5, "totalFlows": 11,
             "bytesIn": 900, "bytesOut": 1200,
             "refused": {"EGRESS_DEST_DENIED": 4}, "revision": 3}
}
```

几条要求：

**`inForce` 是这一节存在的理由。** 一条配置了但被拒的规则读出来是 `false` 并带着它的错误码。这是「这条规则在保护我」和「这条规则是文件里的一段文字」之间的区别。被拒的规则**必须列出来**，不能省掉：只列生效规则的状态，会让写下那条规则的人无从发现它没生效。

**没装上的路由必须列出来**，带 `installed: false` 和占用者的描述。省掉它会让状态看起来干干净净，而它本该捕获的流量正从物理网卡出去。

**两个字段是现算的，两个是记下来的。** 规则是否生效每次取快照时用与 `matchEgressRules` 相同的校验重算，这样状态不会与真正的导流决定漂移；路由是否装上算不出来——那个答案来自下发那一刻的系统路由表——所以记下来。记下来的只有冲突：已装的在安装记录里，而安装记录才是重启后被接管的东西。

**被拒的规则不贡献 `peers` 条目。** 否则状态会报告一个本节点永远不会发往的出口，看起来像一条生效规则有个健康的目的地。

**`refused` 用的是一份不会被清零的累计计数。** 周期性 egress-report 也按错误码计数，但那一份是 drain 的——为的是让连续两次报告描述连续的两个区间。状态若读同一份，回答的就是「上次报告发出之后」，那不是任何人问的问题，而且报告一旦接上就会无声地改变含义（目前三端都还没有调用方）。所以两份计数：报告一份，状态一份，代价是一个 map。

`blocked` 的原因名三端一致：

| 原因 | 含义 |
| --- | --- |
| `rule` | 命中 `action=block` 的规则 |
| `unsupported-protocol` | 命中 `egress` 规则但协议不承载，如 ICMP |
| `egress-unavailable` | 规则指向的出口当前不可用（离线或尚未在线） |
| `send-failed` | 交给出口的帧没能发出 |
| `return-mesh-source` | 回程包的源地址落在 Peer Mesh 网段内，拒收 |
| `return-no-flow` | 回程包找不到本机发起过的存活流，拒收 |
| `rejected-<错误码小写>` | 出口用 `flow-reject` 拒绝了这个流，如 `rejected-egress_dest_denied` |

**`blocked` 与 `refused` 按原因/错误码分别计数，不汇总。** 「没有出口在线」与「被出口拒绝」数字一样大，却是完全不同的两个问题。计数为零的不输出：一排零会把真正发生过的那一条埋掉。

**这一节不受控制面认证状态影响**，与 `peers`、`services` 不同。后两者描述的是服务端告诉我们的东西，在服务端开口之前不予发布；这一节描述的是本机自己的配置和本机自己的路由表，无论如何都是关于这台机器的事实。恰恰在运维正想弄清楚「为什么什么都不通」的时候把它藏起来，是最糟的时机。

**面向人的输出打印问题、计数其余。** 一个健康节点输出两行，一个有问题的节点输出那两行加上确切哪里不对。把生效的规则也逐条列出来，会在任何有真实规则集的节点上把唯一重要的那一行挤出屏幕。

**状态文件可能是另一个运行时写的**，所以读取一侧对缺失字段和类型不符必须给出一行输出而不是崩掉。因为某个字段拼法不同就崩掉的状态命令，比打印一个零更糟。

快照里不含任何机密：规则的 match 与前缀是运维自己的配置，客户端 ID 已经出现在 peer 列表里；令牌、密钥与从其他对端学到的地址不在其中。

## 资源上限

出口不得成为开放代理。上限四端取一致口径，并在成功、失败、超时和取消路径全部释放：

- 全进程活动流上限、每出口策略上限、每消费设备上限
- TCP connect timeout、双向 idle timeout
- UDP 来源映射 idle TTL
- 速率限制——**尚未实现**，见当前限制

拒绝日志按相同主体和原因限频，审计缓存设进程级硬上限。日志默认不记录请求正文、凭据或完整访问历史，诊断信息脱敏。

## 对系统的改动

「一期不修改任何用户系统配置」要说准确：本功能**不写任何持久的系统配置**，但运行期间会改动内存中的路由表。

| 对象 | 是否改动 |
| --- | --- |
| DNS 设置 | 不改 |
| 持久路由（Windows PersistentStore、Linux 与 macOS 的开机配置） | 不写 |
| 运行期路由表 | 会添加：规则需要的前缀与旁路条目。Windows 写入 ActiveStore，Linux 用 `ip route add`，macOS 用 `route add`，三者都不跨重启存在。正常退出时撤回；崩溃后，下次启动时按安装记录先全部收回，再按当前计划重装，规则已删空也照样收回 |
| 防火墙、NAT、`ip_forward` 等内核参数 | 不改。出口用用户态栈终结连接、用普通 socket 连目标，不做内核转发 |
| Linux 策略路由规则 | 不装。Go 与 .NET 出口给出站 socket 打 `SO_MARK 0x5350`，但把这个标记接到物理接口的 `ip rule` 由运维按需自己添加；没有这条规则时，只要隧道没有接管默认路由，行为照常 |
| 出站 socket 的接口绑定（Windows、macOS） | 不改系统配置。`IP_UNICAST_IF` 与 `IP_BOUND_IF` 是单个 socket 的选项，随 socket 关闭消失，见[出站 socket](#出站-socket) |
| 本机文件 | 路由安装记录 `~/.specus/egress-routes.json` 与 CLI 状态文件，均在当前用户目录下 |

## 当前限制

- **出口到消费端方向没有发送侧流控。** 出口的用户态 TCP 栈对外通告固定的 65535 字节接收窗口，不做窗口缩放；发送方向不看消费端通告的窗口，没有拥塞窗口，也不对真实 socket 施加背压——从目标读到多少就立即切段发给消费端。RTT 估算只用来计算重传超时（初始 1 s，下限 200 ms，上限 60 s，单段最多重传 6 次）。Peer Mesh 发送队列满时丢帧，靠超时重传恢复。所以在消费端或对端链路比目标服务器慢、或链路丢包时，下行吞吐会退化为超时驱动的重传。设计稿与本文此前写的「保守固定窗口加基于 RTT/PMTU 观测的限速」对接收方向成立，对发送方向不成立，已更正。**尚无实测数据**：吞吐测量与发送侧流控作为独立工作跟进，P7 真机验收之前不给数字。
- 分片 IPv4 packet 不在出口重组；超过有效路径 MTU 的包沿用 Peer Mesh 既有处理，向本地虚拟网卡回注 ICMP Destination Unreachable code 4。
- 出口使用普通 socket 连接目标，因此不保留原始源地址；目标看到的是出口所在网络的出口地址。
- 出口与消费端角色可以同时启用，但不构成出口链：hop 标记保证一跳即止。
- 校验只拒绝 `/0`。运维手写 `0.0.0.0/1` 与 `128.0.0.0/1` 两条规则仍然可以覆盖全部地址，其中下半区目前只是因为覆盖 Peer Mesh 网段才被拒。堵住它需要定一个最小前缀长度，属于策略决定。
- **macOS 的安装路径在 CI 的真机上跑，但指向的是 lo0 而不是 TUN。** GitHub 的 macos runner 给免密 sudo，所以 `peer-egress-macos.yml` 里有一条用例真的装一条文档保留前缀、在整表里查到它、再撤销并确认它不在了。指向的接口是 lo0：真正的 utun 必须先配上 IPv4 地址（见上），而在 CI 里造一个带地址的 utun 要另外一个进程把它持住。argv 形态、输出分类、读表与撤销都是真的，「装进 TUN」这一步与真机的差别只有接口名。
- **macOS 的旁路下一跳同样是逐条解析的，没有批量。** 与 Windows 同一个原因：批量需要改三端共享的安装器接口。这边代价更小，一次 `route -n get` 是 26 ms。
- **Windows 的安装与撤销路径没有在真机上执行过。** 改路由表要管理员权限，开发机上跑不到。查询侧是跑通了的：三端各有一条用例真的启动 PowerShell、读回整张路由表、解析出默认路由并报告为冲突，每次 CI 在 windows runner 上都会跑。安装、撤销、回滚与旁路下一跳解析只有固定向量的覆盖。
- **Windows 的旁路下一跳是逐条解析的，没有批量。** 冲突检查靠整表读取批量化了，旁路没有：批量需要安装器把即将到来的路由告诉命令执行器，而那是三端共享接口的改动。旁路条目是控制端点、STUN、TURN 与对端地址，实践中是个位数，每条解析一次之后缓存。如果这个列表将来随 mesh 规模增长，这里要重做。
- **客户端不处理 `egress-catalog`，也不发送 `egress-report`。** 出口可用性取自 Peer Mesh 对端在线状态；管理接口的出口活动页目前总是空的。
- **遇到不支持出口的对端或旧服务端时，没有专门的「能力不支持」提示。** 流量照样被阻断而不是走本地，状态里表现为出口离线与 `egress-unavailable` 计数，但不会说明原因是对端版本太旧。
- **路由表被改后最多滞后一拍（5 秒）才补回，这 5 秒内命中规则的目标会从本机直连出去，而不是被阻断。** 路由不在时内核按普通路由送出，这是一期唯一会「静默直连」的窗口；切网与休眠恢复正是路由消失的场景。缩短它需要监听路由表变化事件（Linux netlink、Windows `NotifyRouteChange2`、macOS `PF_ROUTE`），三端各不相同，未做。
- **漂移修复只看路由表，不看策略路由。** Linux 只读主表：另一个 VPN 用 `ip rule` 把流量导去别的表时，本功能的路由在主表里看起来完好，实际路径可能已变，修复发现不了。
- **对端端点变化后旁路最多晚 5 秒跟上。** 旁路随组网的保活节拍重算，不随会话建立事件立即应用；这 5 秒内一条覆盖了新端点的规则会把该对端的传输送进隧道，对端会话会因此重建。
- **出口侧没有速率限制。** 并发流数、每消费端流数与空闲超时有上限，字节速率没有。
- **消费端桌面图形界面没有出口分流页面。** 状态可以通过 `specus-client egress` 与本地管理页查看。
- **Java 出口端在 Linux 上不给出站 socket 打标记。** Go 与 .NET 在 Linux 上用 `SO_MARK`（`0x5350`）让策略路由把转发流量固定在物理接口上。Java 在 Windows 与 macOS 上已经能拿到 socket 句柄来绑定接口（见[出站 socket](#出站-socket)），同一个句柄在 Linux 上也能打标记，但这一步没有做，单独跟进。在那之前，Java 出口端在 Linux 上靠强制拒绝清单挡住回环——本机 TUN 与虚拟接口网段在 connect 前就被拒绝——但那挡的是回环，不是路由：如果这台机器的隧道抢走了默认路由，Java 出口会把转发流量送进隧道而不是物理接口。一期不接管默认路由，所以这个状态不会由本功能自己造成，但运维用别的方式抢了默认路由就会看到。
- **Java 客户端不经 `java -jar` 启动时需要自己带 `--add-exports java.base/sun.nio.ch=ALL-UNNAMED`**，否则 Windows 与 macOS 上的出口建流全部被拒绝。jar 清单里的声明只对 `java -jar` 生效。
