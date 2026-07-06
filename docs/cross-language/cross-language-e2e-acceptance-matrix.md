# 跨语言端到端验收矩阵

## 1. 目标

本文用于验收 Java、Go、C# 三套 `server / client` 实现是否在真实运行环境下保持协议、功能和观测行为一致。

验收重点不是单元测试覆盖率，而是回答下面几个问题：

1. 任意语言 server 能否接入任意语言 client。
2. TCP 映射、HTTP 路由、管理 API、流量观测是否行为一致。
3. Peer Mesh 在同 LAN、普通 NAT、复杂 NAT、UDP 受限场景下能否直连或自动 fallback relay。
4. 管理页面看到的连接、会话、链路、流量是否和真实数据面一致。

## 2. 语言组合矩阵

所有 P0 用例至少覆盖下表 9 个组合。

| 编号 | Server | Client A | Client B | 说明 |
| --- | --- | --- | --- | --- |
| L-01 | Java | Java | Java | 基准组合 |
| L-02 | Java | Go | Go | Java server + Go client |
| L-03 | Java | C# | C# | Java server + C# client |
| L-04 | Go | Java | Java | Go server 接 Java client |
| L-05 | Go | Go | Go | Go 自闭环 |
| L-06 | Go | C# | C# | Go server 接 C# client |
| L-07 | C# | Java | Java | C# server 接 Java client |
| L-08 | C# | Go | Go | C# server 接 Go client |
| L-09 | C# | C# | C# | C# 自闭环 |

混合客户端组合用于 Peer Mesh 互通：

| 编号 | Server | Client A | Client B | 必测内容 |
| --- | --- | --- | --- | --- |
| M-01 | Java | Java | Go | 虚拟 IP ping、HTTP over mesh、relay fallback |
| M-02 | Java | Java | C# | 虚拟 IP ping、HTTP over mesh、relay fallback |
| M-03 | Java | Go | C# | 虚拟 IP ping、HTTP over mesh、relay fallback |
| M-04 | Go | Java | Go | 虚拟 IP ping、HTTP over mesh、relay fallback |
| M-05 | Go | Java | C# | 虚拟 IP ping、HTTP over mesh、relay fallback |
| M-06 | Go | Go | C# | 虚拟 IP ping、HTTP over mesh、relay fallback |
| M-07 | C# | Java | Go | 虚拟 IP ping、HTTP over mesh、relay fallback |
| M-08 | C# | Java | C# | 虚拟 IP ping、HTTP over mesh、relay fallback |
| M-09 | C# | Go | C# | 虚拟 IP ping、HTTP over mesh、relay fallback |

## 3. 运行环境矩阵

| 编号 | Client OS | 虚拟网卡 | 必测项 |
| --- | --- | --- | --- |
| O-01 | Windows | Wintun | 启动创建 `shuai0`、路由注入、重启恢复、退出清理 |
| O-02 | Linux | `/dev/net/tun` | `CAP_NET_ADMIN` / root 创建 `shuai0`、路由注入、退出清理 |
| O-03 | macOS | utun | utun 创建、路由注入、退出清理 |
| O-04 | 任意 OS | noop | 无 TUN 权限时不影响 TCP/HTTP 映射，Peer Mesh 状态明确显示不可用或 noop |

## 4. 网络类型矩阵

| 编号 | 网络场景 | 预期路径 | 通过标准 |
| --- | --- | --- | --- |
| N-01 | 同一 LAN | direct host candidate | 30 秒内 direct，ping 丢包率 0%，HTTP 成功 |
| N-02 | 普通家庭 NAT + UPnP 可用 | direct srflx 或 port mapping | 60 秒内 direct，管理页显示 NAT / endpoint / path |
| N-03 | Port Restricted NAT 双端 | direct 优先，失败 relay | direct 成功则记录 direct；失败 60 秒内 relay 可用 |
| N-04 | Symmetric NAT 双端 | relay | 60 秒内 relay，业务不中断 |
| N-05 | 一端 UDP 受限 | relay 或失败原因明确 | 不允许无限空转；管理页显示 dropped / relay / failure 原因 |
| N-06 | 服务端 STUN 主端口不可达，备用端口可达 | STUN alternate port | NAT 类型仍能给出结论或明确降级 |
| N-07 | 公共 STUN 可达，自建 STUN 可达 | 多 srflx 候选 | 客户端上报多个 srflx 观测，端口预测使用观测集合 |
| N-08 | 公共 STUN 不可达，自建 STUN 可达 | 自建 STUN | NAT 检测和 Peer Mesh 候选不被公共 STUN 失败阻断 |
| N-09 | 已建立 direct 后路径 stale | fallback relay | stale 后主动切 relay，ping/HTTP 最多短暂抖动，不永久断流 |
| N-10 | 服务端关闭 peer session | session closed | 客户端停止使用旧 session，新业务重新申请或明确失败 |

## 5. P0 核心功能用例

| 用例 | 覆盖组合 | 步骤 | 通过标准 |
| --- | --- | --- | --- |
| P0-01 客户端登录 | L-01 到 L-09 | client 使用 HTTP 登录获取 token，再建立控制连接 | 登录成功，服务端生成 client session，管理页在线 |
| P0-02 token 主动刷新 | L-01 到 L-09 | 缩短 token TTL，保持客户端在线超过 2 个 TTL | 不因过期断联；如断开，刷新后自动恢复 |
| P0-03 TCP 端口映射 | L-01 到 L-09 | 映射公网端口到客户端本地 TCP echo / ssh / http 服务 | 连接成功，数据双向完整，断开无异常刷屏 |
| P0-04 HTTP 路由 GET/POST | L-01 到 L-09 | 通过 `/http/{client}/{route}` 访问本地 HTTP 服务 | method、path、query、headers、body 保真 |
| P0-05 HTTP 大响应与 Range | L-01 到 L-09 | 下载大文件、视频 Range 请求 | 响应完整，Range 状态码和 Content-Range 正确 |
| P0-06 HTTP WebSocket | L-01 到 L-09 | 通过 HTTP route 代理 WebSocket echo | 握手成功，双向消息完整 |
| P0-07 明细采集默认关闭 | L-01 到 L-09 | 默认配置启动并产生流量 | 不写 HTTP/TCP 明细；汇总流量仍更新 |
| P0-08 明细采集开启 | L-01 到 L-09 | 开启采集，产生 HTTP/TCP 流量 | HTTP/TCP 明细分页可查，body 不异常截断，解压预览受上限保护 |
| P0-09 查询默认不 flush | L-01 到 L-09 | 频繁刷新流量页面和明细接口 | 查询不强制 flush；显式 `flush=true` 才准实时刷新 |
| P0-10 ES 写入不 refresh | L-01 到 L-09 | 使用 ES 存储并压测明细写入 | 写入无 `refresh=true` 放大，查询符合最终一致性 |

## 6. P0 Peer Mesh 用例

| 用例 | 覆盖组合 | 步骤 | 通过标准 |
| --- | --- | --- | --- |
| PM-01 虚拟 IP 分配 | L-01 到 L-09 | 两个同用户 client 登录并启用组网 | 每个 client 有唯一 `/32` 虚拟 IP，CIDR 一致 |
| PM-02 TUN 创建 | O-01 到 O-03 | 启动客户端并启用 Peer Mesh | 系统可见 `shuai0`，只接管 mesh CIDR，不改默认路由 |
| PM-03 同用户互 ping | M-01 到 M-09 | A ping B 虚拟 IP，B ping A 虚拟 IP | 50 个包丢包率 0%，RTT 有管理页记录 |
| PM-04 HTTP over mesh | M-01 到 M-09 | B 本地启动 HTTP 服务，A 访问 B 虚拟 IP | HTTP 200，body checksum 一致 |
| PM-05 TCP over mesh | M-01 到 M-09 | B 本地启动 TCP echo，A 通过虚拟 IP 连接 | 双向 payload checksum 一致 |
| PM-06 direct path | N-01 / N-02 / N-03 | 放开 UDP，观察候选协商 | direct active，管理页逻辑链路和活跃会话一致 |
| PM-07 relay fallback | N-04 / N-05 / N-09 | 阻断直连或等待 stale | 自动切 relay，业务恢复，relay 流量增长 |
| PM-08 关闭会话 | L-01 到 L-09 | 管理页关闭单个 active session | 旧 session 不再 active，客户端重新协商或明确失败 |
| PM-09 禁用设备组网 | L-01 到 L-09 | 管理页关闭某 client 的组网启用 | 在线 client 收到控制消息并停用 Peer Mesh |
| PM-10 跨用户隔离 | L-01 到 L-09 | 不同用户 client 互访虚拟 IP | 默认拒绝；admin ACL 授权后才允许 |

## 7. P1 管理面与观测用例

| 用例 | 步骤 | 通过标准 |
| --- | --- | --- |
| P1-01 管理 API 权限 | admin 和普通用户分别登录 | admin 可看全量；普通用户只能看自己的 client、连接、流量、Peer Mesh 设备 |
| P1-02 客户端详情 | 调用 `GET /api/admin/clients/{id}` | 返回 client、TCP tunnels、HTTP routes，字段和 Java 契约一致 |
| P1-03 连接记录分页 | 产生多页连接记录 | 翻页不追加旧数据，筛选不乱跳 |
| P1-04 HTTP 明细搜索 | 按 method/status/route/contentType 搜索 | 字段过滤准确，例如 method=POST 不出现 GET |
| P1-05 TCP 明细分页和串流 | 产生多条 TCP frame，打开 stream view | frame 分页正确，按 channelId + direction 串联 |
| P1-06 Peer Mesh 拓扑 | 多客户端上线、下线、关 session | 离线设备不显示 active session；逻辑链路聚合不重复 |
| P1-07 NAT 检测页面 | 浏览器访问公开 NAT 检测页 | 给出明确 NAT 结论或明确不可判定原因，引用自建 STUN 和公共 STUN |

## 8. P2 稳定性与压测用例

| 用例 | 步骤 | 通过标准 |
| --- | --- | --- |
| P2-01 24 小时控制连接 | 每种 client 保持在线 24 小时 | 无内存持续增长，无异常重连风暴 |
| P2-02 TCP 长连接 | 建立 TCP 映射并持续传输 1 小时 | 无数据损坏，断开后资源释放 |
| P2-03 HTTP 并发 | 100 并发请求经过 HTTP route | 错误率低于 0.1%，延迟无明显长尾放大 |
| P2-04 Peer Mesh 长流量 | 虚拟 IP 双向传输 10 GB | direct/relay 计量误差小于 2%，无 nonce/replay 异常 |
| P2-05 server 重启 | 重启控制端 / server | client 按策略重连；旧 session 状态最终清理 |
| P2-06 ES 数据集限制 | 明细写入接近配置上限 | index rollover / 限制策略生效，不拖垮查询 |

## 9. 标准 STUN/TURN 验收

| 用例 | 步骤 | 通过标准 |
| --- | --- | --- |
| T-01 Binding | client 向主 STUN 端口发 Binding Request | 返回 XOR-MAPPED-ADDRESS 和 OTHER-ADDRESS |
| T-02 Alternate Binding | client 向备用 STUN 端口发 Binding Request | NAT 探测能比较不同 endpoint |
| T-03 Allocate | client 发 TURN Allocate UDP | 返回 relayed address，lifetime 为服务端授予值 |
| T-04 Refresh | client 发 Refresh 缩短/延长请求 | 响应 lifetime 语义和 Java 一致；过期 allocation 被拒绝 |
| T-05 CreatePermission | client 为 peer 创建 permission | permission TTL 生效，过期后拒绝 |
| T-06 Send/Data Indication | client 通过 relay 发 payload | 对端收到 Data Indication，payload 字节完全一致 |

说明：当前 Java、Go、C# 都未实现 TURN ChannelBind / ChannelData，统一使用 Send/Data Indication；这不是跨语言差异。

## 10. 验收数据记录

每次执行需要保存以下证据：

| 类型 | 内容 |
| --- | --- |
| 版本 | git commit、server 语言、client 语言、构建时间 |
| 环境 | server OS、client OS、JDK/.NET/Go 版本、是否管理员/root |
| 网络 | NAT 类型、内外网 IP、STUN/TURN 端口、防火墙策略 |
| 日志 | server 日志、client A 日志、client B 日志 |
| 接口快照 | `/api/admin/clients`、`/api/admin/peer-mesh/devices`、`/api/admin/peer-mesh/sessions`、`/api/admin/traffic/inspection-status` |
| 业务结果 | ping 统计、HTTP checksum、TCP checksum、吞吐、RTT、路径 direct/relay |
| 页面截图 | Peer Mesh 拓扑、活跃会话、流量使用、NAT 检测结果 |

## 11. 通过规则

1. P0 必须全部通过；任意 P0 失败都不能认为该语言实现和 Java 对齐。
2. P1 允许存在展示细节差异，但 API 字段、权限范围和分页语义必须一致。
3. P2 是发布质量门槛；如果只做功能联调，可以先记录为待验收。
4. Peer Mesh 场景下，direct 不是唯一通过标准；复杂 NAT 能稳定 fallback relay 也算通过。
5. 不允许出现无限重试、无限创建 session、离线设备仍长期 active、日志异常刷屏、明细查询拖垮写入路径。

## 12. 推荐执行顺序

1. 先跑 Java server + Java client，确认基准行为。
2. 再固定 Java server，分别接 Go / C# client。
3. 然后固定 Java client，分别接 Go / C# server。
4. 最后跑混合客户端 Peer Mesh 矩阵。
5. 功能通过后再进入真实复杂 NAT 和 24 小时稳定性验证。

