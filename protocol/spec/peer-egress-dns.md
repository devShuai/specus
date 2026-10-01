# 出口分流二期：域名规则与 DNS 接管

本文是 [peer-egress.md](peer-egress.md) 的二期部分，对应 #52。设计依据见
[分流方案第八节](../../docs/peer-mesh/peer-egress-split-routing-plan.md#八二期域名分流设计已完成不在一期实现)。
**默认关闭**：不开 `peerEgressDnsTakeover`，一期行为不变，域名规则仍以 `EGRESS_RULE_DOMAIN_UNSUPPORTED` 拒绝。

状态：规范定稿，按下文「实现分期」逐步交付；未交付的部分，客户端仍按一期拒绝。

## 一、它做什么，不做什么

域名规则靠 fake-IP 生效：命中域名规则的 DNS 查询**不在本地解析**，而是从专用池分配一个假地址返回；
流量到达假地址时，消费端把**域名**告诉出口，由出口在自己的网络里解析、授权并连接。

要让应用的查询到达本功能，只能修改系统 DNS 设置。**这是整个功能里唯一修改用户系统配置的地方**，所以：

- 默认关闭，开启时每次说明这一改动（与 `egress enable` 同一方式）；
- 改动前记录原值并落盘事务日志，退出、异常终止、重启后都能完整回滚，且只撤销本功能写入的部分；
- 提供显式的「恢复网络设置」命令。

**可识别边界**，文档、页面与 CLI 帮助都必须出现这句话：应用自带 DoH/DoT、使用系统缓存、或直接硬编码 IP 时，
域名规则**不会**命中，这类流量只能靠 IP/CIDR 规则覆盖。

明确不做：DNS 学习路由（把出口解析出的真实 IP 反向加进路由）；TLS SNI 嗅探兜底。原因见设计文档。

## 二、配置

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `peerEgressDnsTakeover` | `false` | 二期总开关。开启需同时 `peerEgressEnabled: true` |
| `peerEgressFakeIpCidr` | `198.18.0.0/15` | fake-IP 池。必须是 IPv4、前缀长度 `/8`–`/24` |

`peerEgressDnsTakeover` 关闭时，域名规则仍报 `EGRESS_RULE_DOMAIN_UNSUPPORTED`，与一期逐字一致。

池的校验见共享向量的 `poolConfig` 用例；与本机接口地址的重叠在启动时检查，不入向量。

**二期何时运行**（向量 `phaseTwo`）：`peerEgressEnabled` 与 `peerEgressDnsTakeover` 都为 `true`，且池可用。
池不可用只停二期：一期照常运行，规则按接管关闭来校验（域名规则报 `EGRESS_RULE_DOMAIN_UNSUPPORTED`），
状态的 `dns` 一节写明 `EGRESS_FAKE_IP_POOL_INVALID`。二期运行时，池段作为一条 TUN 路由安装，
`origin` 为 `fake-ip-pool`，与规则路由一样记录冲突、一样由安装器回滚；这条路由不看有没有规则，
一条规则都没有时也装，状态里的 `consumer` 一节也因此出现。

离线校验（`config validate` 与每次启动加载配置）按「总开关为开」、默认 mesh 网段判断池：`peerEgressDnsTakeover`
为 `true` 而池不可用时，写一条告警 `peerEgressFakeIpCidr is not usable: EGRESS_FAKE_IP_POOL_INVALID; domain rules are not in force`，
三端逐字一致，与一期的规则告警同一处输出。本机接口网段的重叠要到启动二期时才查得到，不在离线校验里。

### 域名规则的写法与校验

| `match` 写法 | 含义 |
| --- | --- |
| `example.com` | 只匹配 `example.com` 这一个名字 |
| `*.example.com` | 匹配 `example.com` 的任意子域（`a.example.com`、`a.b.example.com`），**不含** `example.com` 本身 |

名字比较前统一：去掉末尾的 `.`、转小写；IDN 必须写成 punycode（`xn--`），写成 Unicode 的规则报 `EGRESS_RULE_MALFORMED`。
每个标签 1–63 字节、只含 `a-z0-9-` 且不以 `-` 开头或结尾，总长不超过 253 字节；`*` 只能作为最左整个标签出现一次。
其余校验顺序与一期相同（`enabled: false` 第一，`port` 仍拒绝，`egress` 需要 `egressClientId`）。

新增错误码：

| 错误码 | 何时 |
| --- | --- |
| `EGRESS_RULE_FAKE_IP_OVERLAP` | IP/CIDR 规则与 fake-IP 池重叠。池内地址只能由域名规则分配 |
| `EGRESS_FAKE_IP_POOL_INVALID` | `peerEgressFakeIpCidr` 不合法，或与 Peer Mesh 网段、本机接口地址重叠。整个二期拒绝启动 |

### 规则裁决

- IP/CIDR 规则只看地址，域名规则只看 DNS 查询的名字，两者**不互相竞争**：池内地址不会命中 IP 规则（重叠已在校验时拒绝），
  池外地址不会命中域名规则。
- 多条域名规则同时命中一个名字时：**精确匹配优先于后缀**；后缀之间标签更多者优先；再相同则靠前者优先。
  被拒（不在生效中）的规则不参与，与一期一致。唯一的例外是 `EGRESS_RULE_EGRESS_NO_DOMAIN`（见「能力协商」）：
  它是出口此刻的状况，不是规则写错了，所以这条规则照样认领它匹配的名字，名字不会因此落回本地解析。
- 命中 `direct` 的名字**不接管**：查询原样转发给原上游，应用拿到真实地址，之后照常受 IP/CIDR 规则约束。
- 命中 `egress` 或 `block` 的名字返回 fake-IP；之后到达该地址的流量按该规则处理：`egress` 发往出口，`block` 本地阻断。

## 三、消费端 DNS 应答

应答者占用 fake-IP 池的第一个可用地址（默认 `198.18.0.1`，下称**监听地址**）的 UDP 与 TCP 53 端口。
**它不开系统 socket**：池段路由把发往监听地址的包送进 TUN，消费端在读包路径上直接处理，把应答写回 TUN。
这样既不占系统的 53 端口、也不必给 TUN 另加地址，systemd-resolved 按链路发出的查询、Windows NRPT、
macOS 网络服务的 DNS 设置都经路由到达。发往监听地址其他端口或协议的包，照「池内流量」按无映射阻断。

**只答本机**：查询的源地址必须是本机的 Peer Mesh 虚拟地址，或本机某个接口的地址；否则丢弃不答，
计入 `blocked` 的 `dns-not-local`。本机发往池段的包，源地址由系统按 TUN 选出，就是虚拟地址；
别的源地址意味着这台机器在替别人转发，二期不替别人解析。

| 查询 | 应答 |
| --- | --- |
| 名字命中 `egress`/`block` 域名规则，类型 `A` | 一条 A 记录：该名字的 fake-IP，TTL 1 秒 |
| 同上，类型 `AAAA`、`HTTPS`（65）、`SVCB`（64）、`ANY`（255） | `NOERROR`、无答案（NODATA）。不让应用拿到绕过 fake-IP 的地址或端点 |
| 同上，其他类型 | 原样转发给原上游 |
| 名字未命中，或命中 `direct` | 原样转发给原上游，**不改写、不缓存**，应答原样返回 |
| 反向查询 `in-addr.arpa` 落在池内 | 有映射：类型 `PTR` 返回该地址映射的名字，其他类型 NODATA；无映射 `NXDOMAIN`。不刷新映射。只认四段、不带前导零的十进制写法，其他写法原样转发 |

### 报文

共享向量 `wire` 给出查询的字节与应得的结果：丢弃、原样转发、或自己构造的应答的**逐字节**内容。

- **只解释一种消息**：QR 为 0、opcode 为 0（QUERY）、恰好一个问题、类为 IN，且名字的每个标签都是可打印 ASCII、不含 `.`。
  QR 为 1 或不足 12 字节的**丢弃**；opcode 不为 0、问题数不为 1、类不为 IN、名字不可用的**原样转发**。
  头部完整而问题读不出（越界，或问题里出现压缩指针）时回 `FORMERR`，问题节为空。
  不认识的东西交给上游，而不是自己编一个答案：上游对它的回答至少是真实的。
- **自己构造的应答**：ID、opcode、RD、CD 照抄；QR、RA 置位；AA、TC、AD 清零。问题节**逐字节照抄**查询里的，
  保留应用的大小写（有的解析器用大小写随机化防投毒）。A 与 PTR 记录的名字写成指向问题的压缩指针 `C00C`，TTL 1 秒。
- 查询的附加节里有 OPT（EDNS）时，应答也附一条 OPT：载荷 1232 字节，扩展 RCODE、版本、标志全为 0（不回 DO）。
  不附的话，systemd-resolved 这类解析器会把这台上游降级为不带 EDNS，之后转发出去的查询也跟着不带。
- NODATA 是 `NOERROR`、无答案，不附 SOA。池满回 `SERVFAIL`，日志记「fake-IP 池耗尽」。

### 转发

- 转发的查询**逐字节原样**发往上游，应答逐字节原样交回，含 TC 位；不改写、不缓存。UDP 应答不论多大都原样写回 TUN，
  不做 IPv4 分片：只有应用自己通告的 EDNS 载荷大于 TUN 的 MTU 时才会遇到。
- UDP 查询按上游列表的顺序，每个等 2 秒，超时或不可达换下一个；应答按 ID 与来源地址配对。全部失败回 `SERVFAIL`（自己构造，规则同上）。
  不自行解析：自己解析就是在规则之外再开一条出网的路。
- 转发的查询不一定读得出问题（问题数不为 1、问题里有压缩指针等）。这样的查询失败时，`SERVFAIL` 只有头部，问题数为 0；
  读得出唯一一个问题的照抄问题节，查询带 OPT 的照附 OPT。
- 同时在途的转发最多 256 个；再来的查询不转发，直接回 `SERVFAIL`，计入 `failed`。一个不停发查询的应用
  不应该让客户端为它开出无限多的 socket。
- TCP 查询同样的顺序，对每个上游走 TCP，连接加等应答合计 2 秒。
- 上游列表取第五步记录的原值。第四步单独交付时由调用方传入，为空时所有转发都回 `SERVFAIL`。
- 发往上游的包按系统路由走。上游地址若落在某条出口规则里，转发就经出口出去，这正是那条规则要的。

### TUN 里的 TCP

应答截断（TC）后应用会改用 TCP，所以监听地址的 TCP 53 也在读包路径上应答，只做 RFC 7766 需要的最小子集：

- 收到 SYN 回 SYN-ACK，MSS 取对方 MSS 与 1360 的较小者，SYN-ACK 里通告的也是这个值；不做窗口缩放、SACK、时间戳，
  也不看对方通告的窗口（同机应用的接收窗口远大于一条 DNS 应答）。同时存在的连接上限 64，超出的 SYN 回 RST。
  没有连接的非 SYN 段回 RST。收到 RST 立即丢弃连接。
- 按序接收；乱序的段丢弃，并重发当前的 ACK。字节流按 2 字节长度前缀切出查询，**按到达顺序**逐个应答；
  转发出去的查询等上游回来再写，排在它后面的应答跟着等。
- 应答按 MSS 切段发出。未确认的段 1 秒后重发，同一段重发 3 次仍未确认则回 RST 关闭。
- 对方 FIN：写完已排队的应答后回 FIN。连接 10 秒既没有新查询也没有未答的查询，主动 FIN。

## 四、fake-IP 映射

- 同一个名字在映射存活期内始终得到同一个地址；不同名字得到不同地址。CDN 共享 IP、同 IP 多域名因此互不污染。
- 可分配地址是池内除网络地址、广播地址与应答者地址以外的全部地址。分配从游标处开始按地址顺序循环查找第一个
  未被占用、也不在隔离期的地址，取用后游标移到它的下一个。游标从应答者地址的下一个开始。
- 查询命中已有映射，或有流量发往映射地址，都刷新该映射的最近使用时间。
- **映射寿命与 DNS TTL 无关。** 应答 TTL 是 1 秒，映射按最近使用时间保留：最近 **6 小时**内用过的映射不回收。
  应用缓存了多久由不得我们，TTL 到期就回收会把长缓存的应用推进下一条的「池内无映射」。
- 池满（找不到空闲地址）时，淘汰**所有**已闲置满 6 小时的映射，每个淘汰记一行日志，然后重新查找；
  被淘汰的地址进入 **30 分钟**隔离期，期间不分配给别的名字，避免旧连接打到新名字上。
  仍找不到时，该查询应答 `SERVFAIL` 并记日志「fake-IP 池耗尽」，已有映射一个不动。
- **到达池内但没有映射的地址一律阻断**，计入 `blocked` 的 `fake-ip-unmapped`。这是 fake-IP 方案唯一真正的泄漏点：
  放行到出口或回退本地，都会让流量去向与规则不符。

### 池内流量怎么走

二期运行时，消费端对每个发往池内地址的包按下面的顺序决定（向量 `steering`）；池外地址仍按一期的地址规则。
应答者地址的 53 端口归应答者处理（第四步），其余发往应答者地址、网络地址、广播地址的包都按「无映射」处理。

1. 地址没有映射：阻断，`fake-ip-unmapped`。
2. 有映射：先刷新这个映射的最近使用时间，再用映射的**名字**选域名规则（与应答时同一套选择）。
   没有规则认领这个名字，或认领它的是 `direct`：阻断，`fake-ip-stale`。名字是在另一套规则下发出去的，
   它的真实地址这里不知道，放行只能靠猜；阻断并应答，应用会重新查询，新查询按现在的规则走。
3. 规则是 `block`：阻断，`rule`，与一期相同。
4. 规则是 `egress`：协议不承载（如 ICMP）阻断，`unsupported-protocol`；出口不在线阻断，`egress-unavailable`；
   出口在线却没有声明 `domainTargetCapable`，阻断，`egress-no-domain`。都通过则发往该出口。

`fake-ip-unmapped`、`fake-ip-stale`、`egress-unavailable`、`egress-no-domain` 四种阻断都**应答**应用，
方式与一期的 `egress-unavailable` 相同（TCP 回 RST，UDP 回 ICMP 不可达，见失败向量）：应用立刻失败并重试，
而不是等到自己超时。`rule` 与 `unsupported-protocol` 与一期一样静默丢弃。

发往池内地址的流也登记进消费端流表（键里是 fake-IP），回程包的源地址是同一个 fake-IP，照常按流表放行。
规则变更、出口离线、目录里出口的能力变化时，已建的 fake-IP 流用同一套判定重算（**不刷新**映射：规则变了不是流量）；
不再发往原出口的流立即断开，向原出口发送 `flow-purge`，目标写 `<fake-IP>/32`。出口的流键保留的就是 fake-IP，
所以按这个目标能关到对应连接。

共享向量 `peer-egress-dns-v1.json` 的 `pool` 用例给出一串带时间的查询与流量事件，以及每一步应得的映射，
三端逐步比对。

## 五、`name-bind` 与出口侧解析

### 消费端 → 出口：`name-bind`

一期保留的控制消息，二期启用：

```json
{"type":"name-bind","address":"198.18.0.5","name":"example.com"}
```

- 消费端在向出口发出发往 fake-IP 的包之前，满足下面任一条时先发送该地址的 `name-bind`（向量 `steering`）：
  这个包在流表里登记了一条新流；它是 TCP 的 SYN（不带 ACK），**包括重传的 SYN**；它属于一条还没收到过出口回包的 UDP 流。
  其他包不再发送。控制消息不可靠，所以不只发一次：TCP 靠应用自己重传的 SYN 补发，UDP 没有重传，
  就在出口回话之前每个数据报都带一条。`name-bind` 本身发送失败时，随后的 IP 包也不发，计 `send-failed`：
  一个明知出口无从知道名字的包，发出去只会建一条连向 fake-IP 的流。
- 出口按 `(消费端, address)` 登记，登记本身按最近使用保留、上限与流表同级，不另设 TTL。
- 出口收到发往某地址的新流、但该 `(消费端, address)` 没有登记时，按一期的地址流处理（通常因目标不可达而失败）；
  不得猜测名字。
- 出口收到 `name-bind` 时，关闭该消费端发往这个地址、却不是按这个名字建立的全部流（向量 `nameBindClosesFlows`）。
  名字到达之前建立的流连向的是 fake-IP 本身，永远不会通，而新到的 SYN 重传或数据报又会被当成这条流的后续包；
  关掉它，下一个包才会按名字重新建流。控制消息的丢失因此只让建流慢一个重传周期。
  这类流**静默关闭**：只关出口这一侧的 socket 与状态，不向消费端回 RST，也不发 `flow-reject`。紧跟在后面的通常就是
  应用自己重传的 SYN，此刻回一个 RST，应用会把连接判为被拒，`name-bind` 要救的正是这条连接；`flow-reject`
  则会让消费端删掉刚按名字重建的流，回程包被当成 `return-no-flow` 挡掉。
  同一名字重复绑定不关任何流；地址改绑到另一个名字时，旧名字的流一并关闭，这些是真连到过别处的连接，
  按撤销授权关闭（TCP 回 RST，不发 `flow-reject`），向量里列在 `reset`。

### 出口：先解析，再授权，最后用已授权的地址连接

1. 用出口本机的系统解析器解析名字。先要 A；没有 A 而出口声明了 `ipv6TargetCapable` 时再要 AAAA。解析失败返回 `EGRESS_NAME_UNRESOLVED`。
2. 对**每一个**解析出的地址做一期的完整授权判定（强制拒绝清单、scope、目的规则、协议与端口）。
   取第一个通过的地址；全部不通过时返回第一个地址的拒绝码。**DNS 重绑定**在这里被挡住：
   名字解析到回环、私有网段或 mesh 网段时，由强制拒绝清单与 scope 拒绝。
3. 用这个已授权的地址建连，解析与连接之间不再有第二次解析，不留窗口。
4. 回程包的源地址仍写 fake-IP：消费端看到的始终是它分配出去的那个地址。

出口的强制拒绝清单增加一项：出口**本机**配置的 fake-IP 池段（当它自己也开着二期时）。

新增错误码：

| 错误码 | 何时 |
| --- | --- |
| `EGRESS_NAME_UNRESOLVED` | 出口解析名字失败或没有可用地址 |
| `EGRESS_NAME_UNSUPPORTED` | 出口不支持域名目标（未声明 `domainTargetCapable`）却收到 `name-bind` |

### 能力协商

出口的能力上报把 `domainTargetCapable` 置为 `true`（只在它实现了本节时）。服务端把它转进 `egress-catalog`
（[peer-egress.md](peer-egress.md#egress-catalog)），消费端从目录里读。消费端只对声明了该能力的出口使用域名规则：
指向不支持的出口的域名规则不在生效中，报 `EGRESS_RULE_EGRESS_NO_DOMAIN`，不降级为本地解析。
共享向量的 `egressCapability` 用例给出规则与出口能力的组合，`nameBindAtEgress` 给出出口对 `name-bind` 的答复，
`egressChoice` 给出解析结果与逐地址授权下应拨的地址。

**消费端读目录**（向量 `catalog`）：只读每个出口的 `domainTargetCapable`，别的字段目前不影响行为。
`revision` 与 `egress-config` 同规则：同一控制 session 内单调递增，小于或等于上次接受值的忽略，新 session 重新计。
`type` 不是 `egress-catalog`、`revision` 不是正整数、`egresses` 存在却不是数组的消息整条拒收，已知的能力不变。
`egresses` 缺失按空数组处理。接受的目录**整体替换**已知能力：没列出的出口视为不能解析域名。
`clientId` 不是正整数的条目跳过；`domainTargetCapable` 只有 JSON `true` 算数，字符串 `"true"`、数字 `1` 都是否。
不认识的键忽略。新 session 只重置 `revision` 的下限，已知能力保留到下一份目录替换它。

**只对在线的出口判能力**（向量 `ruleStatus`）：服务端对不在线的出口一律写 `false`，这时规则是对的、在等出口，
状态里仍算生效，流量按一期计 `egress-unavailable`；出口在线而目录说它不能解析域名，才报 `EGRESS_RULE_EGRESS_NO_DOMAIN`。
出口刚上线、新目录还没到的那一小段时间里，规则会短暂显示 `EGRESS_RULE_EGRESS_NO_DOMAIN`、流量计 `egress-no-domain`，
目录一到即恢复。

`EGRESS_RULE_EGRESS_NO_DOMAIN` 的规则不贡献状态里的 `peers` 条目，与其他被拒的规则一致；
但它仍认领匹配的名字（见「规则裁决」），落到它名下的流量阻断并计 `egress-no-domain`。

## 六、系统 DNS 接管

### 共同要求

- **开启前检查，任一不满足即拒绝启动二期并说明原因**（一期照常运行）：
  - fake-IP 池段已被本功能以外的路由占用，或与 mesh 网段、本机任一接口地址重叠；
  - 系统 DNS 当前指向回环地址或某个 TUN/虚拟接口的地址（强烈暗示已有别的接管者在场）。
    这一条同时防住**回滚陷阱**：把这样的值记成「原值」，将来回滚会把用户指向一个已经不存在的接管者，直接断网。
- **事务日志**先落盘再改系统：记录改了哪里、原值是什么；改动成功后标记为已提交。
- 进程启动时若发现事务日志，**先按日志回滚**，再按当前配置决定是否重新接管。
- 正常退出回滚；被强杀后的回滚在下次启动时完成，或由显式命令完成。
- 网络切换（默认路由或接口地址变化）后重新做开启前检查；新网络落进池段时停止接管、回滚并告警，不静默继续。

### 各平台做法

| 平台 | 接管 | 记录的原值 | 回滚 |
| --- | --- | --- | --- |
| Linux，systemd-resolved 在运行 | 对 TUN 链路 `resolvectl dns <tun> 198.18.0.1`、`resolvectl domain <tun> '~.'`，使其成为所有名字的默认路由 | `resolvectl status` 中全局与各链路的 DNS 服务器（仅用于转发，不需要写回） | `resolvectl revert <tun>` |
| Linux，无 systemd-resolved | 备份 `/etc/resolv.conf` 后改写为 `nameserver 198.18.0.1` | 原 `resolv.conf` 的 `nameserver` 行 | 恢复备份；若文件在接管期间被别人改过，保留别人的版本并告警 |
| macOS | 对每个启用的网络服务 `networksetup -setdnsservers <service> 198.18.0.1` | 各服务原来的 DNS（`Empty` 表示用 DHCP 下发的） | 逐个服务写回原值（`Empty` 原样写回） |
| Windows | 添加 NRPT 规则 `Add-DnsClientNrptRule -Namespace "." -NameServers 198.18.0.1`，带本功能的注释标记 | 各启用接口的 DNS 服务器 | 删除带本功能标记的 NRPT 规则 |

Windows 不改网卡 DNS：多网卡时系统会同时问各网卡的 DNS 并取最先到的应答，改一张网卡挡不住别的网卡抢答；NRPT 规则优先于所有网卡。

转发用的原上游取自上表「记录的原值」；取不到（例如全部指向回环）时按开启前检查拒绝启动。

### 命令

- `egress dns status --config PATH`：是否接管、原上游、事务日志状态、映射数与池使用率。
- `egress dns restore`：按事务日志回滚，不需要客户端在运行；日志不存在时说明没有需要恢复的内容并以 0 退出。

## 七、状态查询增量

`consumer.dns`：

```json
{"takeover": true, "listen": "198.18.0.1", "pool": "198.18.0.0/15", "mappings": 42,
 "quarantined": 0, "upstreams": ["192.0.2.53"], "journal": "committed",
 "queries": {"answered": 120, "forwarded": 300, "failed": 2}}
```

- 开了 `peerEgressDnsTakeover` 这一节才出现。`takeover` 是二期此刻是否在运行；池不可用时为 `false`，
  并带 `"code": "EGRESS_FAKE_IP_POOL_INVALID"`。
- `mappings` 是存活的映射数，`quarantined` 是还在隔离期的地址数，都在取快照时按当时的时间现算。
- `listen`、`upstreams`、`queries` 由第四步填，`journal` 由第五步填；还没交付的字段不输出。
  `listen` 只在二期运行时输出；`upstreams`（没有时为 `[]`）与 `queries` 只要开了 `peerEgressDnsTakeover` 就输出。
  `queries` 是启动以来的累计：`answered` 自己构造的应答（含 NODATA、`NXDOMAIN`、`FORMERR`），
  `forwarded` 拿到上游应答并交回的，`failed` 因上游全部失败或池满而回 `SERVFAIL` 的。丢弃的查询不计。
- 与 fake-IP 有关的阻断计入 `consumer.blocked`，不在这里另记一份：`fake-ip-unmapped`、`fake-ip-stale`、`egress-no-domain`、`dns-not-local`。

规则条目增加 `kind`：`"cidr"` 或 `"domain"`。二期运行时，池段那条路由出现在 `consumer.routes` 里，`origin` 为 `fake-ip-pool`。

## 八、实现分期

1. 规范、共享向量（名字校验与匹配、DNS 应答判定、映射寿命与隔离、`name-bind` 编解码、出口解析后的授权）。已交付。
2. 出口侧：`name-bind` 登记、解析、逐地址授权、能力上报。三端，已交付。
   IPv6 目标连接暂不交付：出站 socket 绑定物理网卡的实现只有 IPv4，三端都不声明 `ipv6TargetCapable`，
   解析只取 A 记录；按上文规则，只有 AAAA 的名字报 `EGRESS_NAME_UNRESOLVED`。
3. 消费端数据面：二期开关与池校验、读 `egress-catalog`、带接管与能力的规则校验、fake-IP 池与映射、
   池内流量的判定与应答、`name-bind` 发送、fake-IP 流的清除、池段路由、状态。三端。
   出口侧补一条：收到 `name-bind` 时关闭名字到达之前按地址建立的流。
   四个服务端在 `egress-catalog` 里如实转发出口登录时声明的 `domainTargetCapable`（此前固定为 `false`，
   服务端只保存了能力的 `version`），消费端据此判定 `EGRESS_RULE_EGRESS_NO_DOMAIN`。
   这一步之后映射只能由第四步的应答者创建，所以单开这一步的开关，域名规则显示生效，却还没有流量会落进池里；
   用户文档在第五步交付之前不介绍这个开关。
4. 消费端 DNS 应答者：读包路径上的 UDP 与 TCP、报文（向量 `wire`）、反向查询、转发（上游由调用方传入）、状态。三端。
5. 系统 DNS 接管、事务日志、回滚与 `egress dns restore`，三平台。
6. 实验室：Linux 命名空间里完整跑通（resolv.conf 方式），并增加「池内无映射」与「接管后强杀再启动」用例。
