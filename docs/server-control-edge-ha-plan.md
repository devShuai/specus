# Server 控制端 / 连接端拆分与高可用方案

本文保存后续把 `tunnel-server` 拆成控制端和连接端的演进方案。当前代码仍是单体模式：Spring 管理 API、管理后台、Netty 控制连接、公网 TCP 端口监听、HTTP route 入口、peer relay 都运行在同一个 `tunnel-server` 进程中。

## 1. 结论

可行：

* 控制端单独重启，不影响连接端上已经建立的客户端控制连接和公网数据连接。
* 连接端多实例高可用，通过客户端重连、入口负载均衡、连接端 drain 实现滚动升级和故障恢复。
* port mapping 的后端是 HTTP 服务时，公网 HTTPS 推荐优先通过 HTTP Route 入口做 TLS 终止。

不作为 v1 目标：

* 已建立的单条 TCP 流跨连接端无感迁移。Java / Netty 进程已经持有的 socket 无法直接搬到另一进程或另一台机器。要做到“单流不掉”需要更复杂的四层代理、内核级连接迁移或自研可靠流层，成本和风险都高。

v1 推荐目标：

* 控制端可以独立重启。
* 连接端可以滚动 drain：停止接新连接，已有连接自然结束，超时后关闭。
* 连接端宕机时，客户端秒级重新登录并连接到健康连接端，新建公网连接恢复。

## 2. 当前实现约束

当前在线路由依赖进程内状态：

* `SessionUtil` 保存 `clientName -> Channel`，只在当前 JVM 内可见。
* `NatServerHandler` 绑定在客户端控制连接上，持有该客户端的公网监听端口和公网 socket 映射。
* `RemotePortServerManager` 在当前进程内动态监听公网 TCP 端口。
* HTTP route 和 WebSocket route 最终也需要通过当前进程内的客户端控制连接转发。

因此当前单体进程重启会导致：

* 客户端控制连接断开。
* 该进程上的公网监听端口关闭。
* 已建立公网 TCP / WebSocket / HTTP 等待请求中断。

要拆分高可用，核心不是简单把 Controller 拆出去，而是把“配置权威”和“在线连接归属”分开。

## 3. 目标架构

引入 server 运行角色：

* `all`：默认兼容模式，保持当前单体行为。
* `control`：控制端，只负责管理 API、管理 UI、认证、客户端 HTTP 登录、配置 CRUD、调度和审计。
* `edge`：连接端，只负责客户端 Netty 长连接、公网 TCP/HTTP/WS 入口、peer relay、流量采集和本地在线路由。

建议新增配置：

```yaml
tunnel:
  server:
    role: all # all | control | edge
    edge-id: edge-a
    edge-public-address: tunnel-a.example.com
    edge-internal-address: 10.0.0.11
```

部署形态：

```text
                +--------------------+
                | control x 1..N     |
                | 管理/认证/配置调度  |
                +---------+----------+
                          |
                          | DB / outbox / heartbeat
                          |
        +-----------------+-----------------+
        |                                   |
+-------+--------+                  +-------+--------+
| edge-a         |                  | edge-b         |
| Netty/公网入口 |                  | Netty/公网入口 |
+-------+--------+                  +-------+--------+
        ^                                   ^
        | L4 LB / VIP                       |
        +--------------- 公网访问者 --------+
```

## 4. 控制端职责

控制端作为配置和身份的权威来源：

* 管理用户、租户、客户端、凭证、权限。
* 管理 TCP port mapping、HTTP route、peer mesh ACL。
* 处理客户端 HTTP 登录，选择一个健康 edge，并返回 edge 的 Netty 地址。
* 维护 edge 注册表和健康状态。
* 提供管理页面查询，展示客户端在线归属、连接记录、流量统计。

控制端不能再直接依赖本进程的 `SessionUtil` 判断在线状态。在线状态应来自 edge 心跳和持久化表。

## 5. 连接端职责

连接端作为数据面入口：

* 接收客户端 Netty 控制连接，维护本地 `clientName -> Channel` 路由表。
* 按配置动态监听公网 TCP 端口。
* 接收 HTTP route / WebSocket route 的公网请求，并转发给本 edge 上的客户端。
* 运行 peer mesh UDP/STUN/TURN-lite relay。
* 上报在线客户端、连接数、端口监听状态、流量统计和错误状态。

edge 本地仍可以保留 `SessionUtil`，但它只表示“本 edge 当前进程持有哪些客户端连接”，不再代表全局在线状态。

## 6. 配置同步

推荐 v1 使用 DB outbox / config version，不强制引入 Redis、etcd 或 MQ。

流程：

1. control 写入 TCP/HTTP/peer 配置表。
2. control 写入 outbox 事件或递增客户端配置版本。
3. edge 周期拉取自己负责的客户端配置变更。
4. 如果目标客户端当前连接在本 edge，edge 下发 `NAT_CONTROL` 或 `PEER_CONTROL`。
5. edge 上报下发结果和当前生效版本。

这样 control 重启时：

* 已经下发到 edge 的配置继续生效。
* 已建立连接继续转发。
* 管理端短暂不可用，但数据面不受影响。

## 7. 连接端 HA 与重启转移

### 7.1 正常滚动升级

edge 进入 drain：

1. edge 标记 `DRAINING`，control 不再分配新客户端到该 edge。
2. 公网入口 LB 停止把新连接转到该 edge。
3. edge 通知已连接客户端重新登录或迁移到推荐 edge。
4. edge 保留已有公网 TCP 连接，等待自然结束。
5. 超过 drain timeout 后关闭剩余连接并退出。

这种模式不会保证长连接永远不断，但能避免升级时主动打断大多数短连接。

### 7.2 异常故障

edge 宕机：

1. control 通过 heartbeat 发现 edge 失联。
2. 客户端控制连接断开，客户端按现有重连机制重新 HTTP 登录。
3. control 选择健康 edge，客户端连接新 edge。
4. 新公网连接由 LB 进入健康 edge 后恢复。
5. 原 edge 上已经建立的公网 TCP 流会断开，这是 v1 可接受语义。

### 7.3 公网端口归属

有两种策略：

* 简单策略：每个 TCP 映射绑定到某个 owner edge，LB / 防火墙把该公网端口导向 owner edge。owner edge 故障后切换端口归属，新连接恢复。
* 统一入口策略：所有 edge 都可接收公网连接。如果连接落到非 owner edge，由该 edge 通过内部 edge-to-edge stream 转发给 owner edge。

v1 推荐先做简单策略。统一入口策略更灵活，但需要额外实现 edge 间数据转发和背压。

## 8. HTTPS 到内网 HTTP 服务

### 8.1 当前 port mapping 语义

当前 TCP port mapping 是纯 TCP 字节透传：

```text
公网 TCP socket -> server NAT DATA -> client -> 内网目标 TCP socket
```

server 不解析 HTTP，也不终止 TLS。因此：

* 如果公网用户用 `https://公网端口` 访问，而内网后端只是 HTTP，当前 port mapping 不会自动工作。
* 如果内网后端本身就是 HTTPS，当前 port mapping 可以透明透传 TLS。

### 8.2 推荐方案：HTTP Route 做 HTTPS 入口

公网 HTTPS 推荐走 HTTP Route：

```text
浏览器 HTTPS -> 反向代理/edge HTTP入口 TLS终止 -> HTTP Route -> client -> 内网 HTTP 服务
```

优点：

* 符合当前 HTTP Route 的设计方向。
* 可以复用现有 Header、Body、响应改写、HTTP 明细采集。
* 证书集中放在公网入口或 edge 上，不要求内网服务改 HTTPS。

### 8.3 可选增强：port mapping TLS 终止

如果希望继续使用 port mapping 暴露 HTTPS，但内网后端是 HTTP，可以新增映射模式：

* `TCP_PASSTHROUGH`：默认，纯 TCP 透传。
* `TLS_TERMINATE_HTTP`：server/edge 在公网端口终止 TLS，把解密后的 HTTP 字节转给客户端内网 HTTP 服务。

需要新增能力：

* 证书管理：`certRef`、证书链、私钥、过期时间。
* SNI 策略：同一端口多域名需要按 SNI 选择证书和后端。
* 协议限制：该模式只适合 HTTPS over HTTP/1.1 或后续明确支持的 HTTP/2，不适合任意 TCP 协议。
* 安全边界：TLS 在 edge 终止后，edge 能看到 HTTP 明文；如果要求端到端加密，应让后端服务自己提供 HTTPS，并使用 `TCP_PASSTHROUGH`。

v1 推荐先不做 port mapping TLS 终止，优先把 HTTPS 能力收敛到 HTTP Route。

## 9. 数据模型建议

新增或扩展：

* `edge_node`：`edgeId`、公网地址、内网地址、状态、是否 drain、最后心跳、版本。
* `client_online_presence`：客户端当前所在 edge、控制连接 ID、登录时间、最后心跳、配置版本。
* `config_outbox`：配置变更事件、目标客户端、配置类型、版本、状态。
* `port_binding_ownership`：公网端口、owner edge、状态、更新时间。

这些表服务于跨进程协调，不替代 edge 本地的高性能 Channel Map。

## 10. 分阶段落地

### P0：角色拆分开关

* 加 `all/control/edge` 角色。
* `all` 保持现状。
* `control` 不启动 Netty 控制服务和公网端口。
* `edge` 不提供管理写操作，只保留必要健康检查和内部接口。

### P1：edge 注册和在线归属

* edge 启动后注册心跳。
* 客户端 HTTP 登录时由 control 选择 edge。
* 登录响应返回选中 edge 的 Netty 地址。
* 管理页在线状态从 presence 表读取。

### P2：配置 outbox

* control 写配置后写 outbox。
* edge 消费 outbox 并下发给本机客户端。
* 增加配置版本和下发结果展示。

### P3：edge drain

* edge 支持 DRAINING 状态。
* control 不再把新客户端分配到 draining edge。
* edge 停止接新公网连接，已有连接自然结束。
* drain timeout 后关闭剩余连接。

### P4：公网入口 HA

* 简单策略：端口 owner edge + LB / 防火墙切换。
* 后续增强：非 owner edge 转发到 owner edge。

### P5：HTTPS 增强

* 先完善 HTTP Route 的 HTTPS 部署说明和反向代理模板。
* 如仍需要，再实现 `TLS_TERMINATE_HTTP` 类型的 TCP 映射。

## 11. 验收标准

控制端重启：

* 已连接客户端不断线。
* 已有 TCP port mapping 可以继续访问。
* HTTP Route 已发出的请求不因 control 重启中断。
* 管理 API 恢复后能正确看到 edge presence。

连接端 drain：

* drain 后不再分配新客户端。
* drain 后不接新公网连接。
* 已有短连接自然结束。
* 超时后剩余连接按原因记录为 `EDGE_DRAINED`。

连接端故障：

* 客户端断开后自动重新 HTTP 登录并连接新 edge。
* 新公网连接恢复。
* 旧连接断开原因可观测。

HTTPS：

* HTTP Route 可通过公网 HTTPS 访问内网 HTTP 服务。
* TCP passthrough 访问内网 HTTPS 服务正常。
* TCP passthrough 访问内网 HTTP 服务时，公网 HTTPS 失败属于预期。
