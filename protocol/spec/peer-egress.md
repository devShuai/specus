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
| ICMP | 出口不代发。代 ping 需要 raw socket 权限，与「出口零特权」前提冲突 |
| 多跳出口链 | `SPEG1` 的 hop 标记已置位时拒绝，返回 `EGRESS_HOP_NOT_ALLOWED` |
| 默认路由接管 | 规则不接受 `0.0.0.0/0`，返回 `EGRESS_RULE_DEFAULT_ROUTE` |

「拒绝而非降级」是防泄漏要求。静默忽略一条不支持的规则，等于让本应经出口的流量走本地，与命中规则后静默回退本地是同一类问题。

## 数据面形态

线上传输的是**原始 IPv4 packet**，出口侧用用户态连接栈终结后再用普通 socket 连接目标。消费端不解析 TCP。

由此得到两条贯穿全文的约束：

- **消费端规则只能按目的地址匹配。** 消费端靠安装路由把流量引入 TUN，而路由只能选目的地址。端口与协议限制只存在于出口策略，在出口侧建流时执行。规则里出现 `port` 字段返回 `EGRESS_RULE_PORT_UNSUPPORTED`。
- **可靠性由应用自己的 TCP 提供。** TCP 的另一端在出口的用户态栈上，peer 链路上的丢包与乱序就是普通网络丢包，由应用端到端重传兜住。数据面不额外提供可靠有序流。

## 配置

消费端配置：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `egressEnabled` | `false` | 消费端出口分流总开关 |
| `egressRules` | 空 | 有序规则列表，语义见下节 |

出口端不在客户端本地配置授权。出口开关与目标白名单由服务端持久化并通过 `egress-config` 下发，避免出口设备本地被改写后绕过租户策略。客户端本地只保留一个只读的当前生效视图。

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

固定向量：`protocol/test-vectors/peer-egress-rules-v1.json`。

## 路由接管

消费端靠安装路由把流量引进 TUN。计划是纯函数，只说应该存在哪些路由；执行与回滚由安装器负责。分开是为了让回滚、冲突拒绝与归属判定都能脱离真实路由表被测试。

### 计划

- 只安装**精确前缀**，计划器不会自己造出 `0.0.0.0/0` 或它的两个 `/1` 半区。
- `action=direct` **不安装路由**。流量靠「没有路由」留在本地，与未匹配流量是同一个机制，而不是两处需要彼此保持一致的行为。
- `action=block` **要安装**：包必须先被捕获，数据面才谈得上丢弃它。
- **旁路条目排在最前**，安装也按此顺序。控制连接、STUN 与 TURN、对端 UDP 端点、出口对端自身地址必须继续走物理网络；某条规则的前缀若覆盖了它们，承载隧道的传输就会被送进隧道自身。旁路先入表，因此同地址的规则不会把它顶掉。
- 同一前缀只产生一条路由。引擎按包决定用哪条规则，装两次会让撤销失去定论。
- **被拒的规则逐条返回**，不静默跳过：运维写了一条而本功能忽略了它，他们没有任何途径发现这个泄漏。
- 旁路列表来自运行期发现的对端与端点，不是用户配置，因此读不出的条目跳过即可；整体拒绝会因为一个失联对端停掉全部分流。
- 撤销先于新增。同一前缀改变了种类时必须先撤旧的再装新的，否则平台要么拒绝重复条目，要么静默保留先看到的那条。

### 冲突

安装前先查这条精确前缀上是否已有别人的路由。有就**拒绝这一条并把原样的那一行报给运维**，其余照常安装：一个有争议的前缀不该让所有规则失效。一期**不抢占、不比较 metric**，把选择权留给运维，好过悄悄赢下一场与他们自己路由的争论。

### 安装记录

安装记录（journal）落盘，用来区分「本功能装的」与「用户或别的工具装的」，跨越正常退出、崩溃与重启。**先写记录再安装**：为一条没装成的路由留下记录，代价是清理时一次无害的删除尝试；而没有记录的已装路由，没有人会再去收回它。

写入走临时文件加改名。被崩溃截断的记录会比实际安装的少，少掉的那部分就是会被留在路由表里的东西。

格式在三个客户端实现之间共享——同一台机器上换实现之后，上一次装下的路由要被接管并撤销：

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
- 全部撤销之后删除该文件。

### 平台

一期只实现 Linux（`ip route`）。其它平台的接管留给 P5，在那之前必须**返回失败而不是静默什么都不做**：装不上任何路由却报告规则已生效的消费端，会把每个目标都送去本地直连，正是本功能要防的泄漏。

固定向量：`protocol/test-vectors/peer-egress-routes-v1.json`，含计划、差异、安装记录与 `ip route` 输出解析。

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

## 能力协商

登录 `environment.clientEgressCapabilities`：

| 字段 | 说明 |
| --- | --- |
| `egressVersion` | 当前为 `1`。`0` 或缺省表示不支持出口 |
| `consumerCapable` / `egressCapable` | 该客户端能否作为消费端 / 出口端 |
| `domainTargetCapable` | 是否支持域名目标。一期固定为 `false` |
| `ipv6TargetCapable` | 是否支持 IPv6 目标。一期固定为 `false` |

服务端**不得**向 `egressVersion` 为 `0` 或缺省的客户端下发 `egress-config` 或 `egress-catalog`。

`domainTargetCapable` 与 `ipv6TargetCapable` 独立于 `egressVersion`，这样二期上线时新旧客户端可以共存，不必靠版本号一刀切。

消费端遇到不支持出口的对端或旧服务端时，明确提示能力不支持，**不降级、不静默直连**。升级默认关闭，不改变现有组网与服务共享行为。

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

## 资源上限

出口不得成为开放代理。上限四端取一致口径，并在成功、失败、超时和取消路径全部释放：

- 全进程活动流上限、每出口策略上限、每消费设备上限
- TCP connect timeout、双向 idle timeout
- UDP 来源映射 idle TTL
- 速率限制

拒绝日志按相同主体和原因限频，审计缓存设进程级硬上限。日志默认不记录请求正文、凭据或完整访问历史，诊断信息脱敏。

## 当前限制

- 出口的用户态 TCP 栈一期采用保守固定窗口加基于 RTT/PMTU 观测的限速，不是完整拥塞控制。高丢包链路下的表现须以实测数据说明。
- 分片 IPv4 packet 不在出口重组；超过有效路径 MTU 的包沿用 Peer Mesh 既有处理，向本地虚拟网卡回注 ICMP Destination Unreachable code 4。
- 出口使用普通 socket 连接目标，因此不保留原始源地址；目标看到的是出口所在网络的出口地址。
- 出口与消费端角色可以同时启用，但不构成出口链：hop 标记保证一跳即止。
- 校验只拒绝 `/0`。运维手写 `0.0.0.0/1` 与 `128.0.0.0/1` 两条规则仍然可以覆盖全部地址，其中下半区目前只是因为覆盖 Peer Mesh 网段才被拒。堵住它需要定一个最小前缀长度，属于策略决定。
