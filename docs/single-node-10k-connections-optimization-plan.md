# 单机代理 10k 连接优化清单

> 目标：让单台 `shuai-tunnel` 服务端稳定代理约 10k 条外部 TCP 连接。
>
> 当前文件只做优化点拆解和落点规划，不执行代码改造、不调整运行参数、不做压测。

## 0. 口径与前置假设

- 这里的 10k 连接优先按“外部访问者通过 NAT 隧道连接到服务端监听端口”的 TCP 连接数理解，不等同于 10k 个客户端控制连接。
- 如果 10k 连接大多空闲或低吞吐，重点是 fd、线程、堆外内存、心跳、连接映射和背压。
- 如果 10k 连接都在持续传输，单条客户端控制连接会成为吞吐和队头阻塞瓶颈，需要多路数据通道或分片。
- SQLite 默认配置适合轻量管理和本地演示，不适合作为高并发连接审计、登录风暴、统计写入的主存储。

## 1. 必须先做的代码优化

### 1.1 合并服务端外部监听的 EventLoopGroup

现状：

- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/NatServerHandler.java`
  - `processRegister` 每注册一个端口都会 new 一个 `TcpServer`。
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/server/TcpServer.java`
  - 每个 `TcpServer.bind` 都创建新的 boss/worker `MultiThreadIoEventLoopGroup`。

风险：

- 如果一个客户端注册多个端口，线程数会随端口数增长。
- 10k 连接不是 10k 线程，但当前“每端口一套 event loop”的模型会让资源不可控。

建议：

- 新增共享的 `RemotePortServerManager` 或 `TcpServerFactory`。
- 服务端进程内只保留一套外部端口 boss/worker group，由所有远端监听端口复用。
- `TcpServer` 只负责 bind/close channel，不拥有 event loop 生命周期。
- 将 boss/worker 线程数配置化，例如：
  - `tunnel.netty.remote-boss-threads`
  - `tunnel.netty.remote-worker-threads`

涉及文件：

- `tunnel-server/src/main/java/com/theshuai/tunnelserver/server/TcpServer.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/NatServerHandler.java`
- `tunnel-server/src/main/resources/application.yml`

优先级：P0。

### 1.2 Java 客户端本地连接复用 EventLoopGroup

现状：

- `tunnel-client/src/main/java/com/theshuai/tunnelclient/client/TcpConnection.java`
  - 每次连接本地服务都创建新的 `MultiThreadIoEventLoopGroup`。
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/handler/NatClientHandler.java`
  - 每个远端 CONNECTED 都 new 一个 `TcpConnection`。

风险：

- 10k 本地连接会导致大量 event loop group 和线程，Java 客户端基本撑不住。

建议：

- 将本地连接 `Bootstrap` 和 `EventLoopGroup` 提升为 `NettyClient` 或独立 `LocalConnectionManager` 生命周期对象。
- `TcpConnection.connect` 改为复用共享 group，连接关闭只关闭 channel，不关闭 group。
- 客户端退出时统一关闭 group。

涉及文件：

- `tunnel-client/src/main/java/com/theshuai/tunnelclient/client/TcpConnection.java`
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/client/NettyClient.java`
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/handler/NatClientHandler.java`

优先级：P0。

### 1.3 加入连接数预算和准入控制

现状：

- `NatServerHandler.externalChannels` 无上限。
- `NatClientHandler.channelHandlerMap` 和 `channelGroup` 无上限。
- 服务端没有单客户端、单端口、全局外部连接数限制。

风险：

- 慢客户端或恶意流量可以把内存、fd、控制连接写缓冲打满。

建议：

- 加入全局最大外部连接数、单客户端最大连接数、单端口最大连接数。
- 超限时服务端立即关闭新外部 channel，并记录一次轻量指标。
- 配置项示例：
  - `tunnel.netty.max-external-connections`
  - `tunnel.netty.max-external-connections-per-client`
  - `tunnel.netty.max-external-connections-per-port`

涉及文件：

- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/NatServerHandler.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/RemoteTunnelHandler.java`
- `tunnel-server/src/main/resources/application.yml`

优先级：P0。

### 1.4 增加 Netty 背压与写缓冲水位

现状：

- `RemoteTunnelHandler.channelRead` 直接 `tunnelHandler.getCtx().writeAndFlush(message)`。
- `NatServerHandler.processData` 直接 `target.writeAndFlush(data)`。
- `LocalTunnelHandler.channelRead` 和 `NatClientHandler.processData` 也直接写。
- 没有 `AUTO_READ` 切换、`channelWritabilityChanged`、高低水位控制。

风险：

- 下游慢读时，上游仍持续读入，最终积压在 Netty outbound buffer、堆外内存或 `byte[]` 上。
- 10k 连接下，少量慢连接就能拖垮整条控制连接。

建议：

- 配置 `WRITE_BUFFER_WATER_MARK`。
- 在通道不可写时暂停对端 `AUTO_READ`，恢复可写后再开启。
- 建立外部 channel 与本地 channel 的配对关系，统一封装 pause/resume。
- 将高频 `writeAndFlush` 改为适度批量 flush，降低 syscall 和 event loop 压力。

涉及文件：

- `tunnel-server/src/main/java/com/theshuai/tunnelserver/server/NettyServer.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/server/TcpServer.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/RemoteTunnelHandler.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/NatServerHandler.java`
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/handler/LocalTunnelHandler.java`
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/handler/NatClientHandler.java`

优先级：P0。

## 2. 协议与内存优化

### 2.1 限制最大帧大小

现状：

- `tunnel-common/src/main/java/com/theshuai/common/codec/Spliter.java`
  - `LengthFieldBasedFrameDecoder` 的最大帧是 `Integer.MAX_VALUE`。

风险：

- 单连接即可制造超大帧内存压力。
- 10k 连接下，最大帧不设限会放大堆外内存风险。

建议：

- 增加 `tunnel.netty.max-frame-size`，默认先按 16MB 或 32MB。
- 与 Go 客户端 `tunnel-client-go/internal/protocol/protocol.go` 中的 `maxFrameSize` 对齐。
- 对 NAT 数据帧和 HTTP 直连帧分别设上限。

涉及文件：

- `tunnel-common/src/main/java/com/theshuai/common/codec/Spliter.java`
- `tunnel-common/src/main/java/com/theshuai/common/protocol/PacketCodec.java`
- `tunnel-client-go/internal/protocol/protocol.go`
- `tunnel-server/src/main/resources/application.yml`

优先级：P0。

### 2.2 减少 NAT 数据帧复制和 JSON 元数据开销

现状：

- `PacketCodec.encode` 为 NAT 消息创建 `ByteArrayOutputStream`，每帧序列化 metadata。
- `PacketCodec.decode` 对 NAT payload 使用 `ByteBufUtil.getBytes(byteBuf)`，会复制。
- NAT 数据使用 `byte[]` 在 `ByteArrayDecoder`、`NatMessagePacket`、压缩封装之间多次复制。

风险：

- 10k 连接持续传输时，GC、堆外到堆复制、压缩尝试都会成为主要 CPU/内存成本。

建议：

- NAT DATA 帧使用更轻的二进制头：`type + channelId + payload`。
- CONNECTED/DISCONNECTED/REGISTER 等低频帧可保留 metadata，DATA 高频帧避免 JSON。
- channelId 从长字符串映射为 int/long，减少每帧 metadata 长度。
- 能用 `ByteBuf` 传递时避免落成 `byte[]`，谨慎处理引用计数。
- 对小包默认不压缩；对已经压缩或随机数据避免 deflate。

涉及文件：

- `tunnel-common/src/main/java/com/theshuai/common/protocol/PacketCodec.java`
- `tunnel-common/src/main/java/com/theshuai/common/protocol/NatMessagePacket.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/RemoteTunnelHandler.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/NatServerHandler.java`
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/handler/LocalTunnelHandler.java`
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/handler/NatClientHandler.java`
- `tunnel-client-go/internal/protocol/protocol.go`
- `tunnel-client-go/internal/client/nat.go`

优先级：P1。

### 2.3 单控制连接改为多数据通道

现状：

- 一个客户端登录后，所有 NAT 外部连接的数据都复用同一个控制 channel。

风险：

- 一个慢写、一个大包或一次 TLS/网络抖动，会影响同客户端下所有连接。
- 10k 活跃连接时，单 TCP 连接吞吐、拥塞窗口、写锁都会成为瓶颈。

建议：

- 保留控制连接用于登录、心跳、注册。
- 增加 N 条数据连接，按 channelId hash 分片。
- 可配置 `tunnel.client.data-lanes`，例如 4/8/16。
- CONNECTED 时服务端分配 lane，DATA/DISCONNECTED 在同 lane 内路由。

涉及文件：

- `tunnel-server/src/main/java/com/theshuai/tunnelserver/server/NettyServer.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/ManagedLoginRequestHandler.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/NatServerHandler.java`
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/client/NettyClient.java`
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/handler/NatClientHandler.java`
- `tunnel-client-go/internal/client/client.go`
- `tunnel-client-go/internal/client/nat.go`

优先级：P1。若 10k 多为空闲连接，可排在背压之后；若 10k 都活跃传输，应提前。

## 3. 服务端 Netty 配置优化

### 3.1 暴露核心 ChannelOption

现状：

- `NettyServer` 固定 `SO_BACKLOG=1024`，只设置 `SO_KEEPALIVE` 和 `TCP_NODELAY`。
- `TcpServer` 没有 backlog、reuseaddr、水位等配置。

建议：

- 配置化以下选项：
  - `SO_BACKLOG`
  - `SO_REUSEADDR`
  - `SO_KEEPALIVE`
  - `TCP_NODELAY`
  - `ALLOCATOR = PooledByteBufAllocator.DEFAULT`
  - `WRITE_BUFFER_WATER_MARK`
  - 可选 `SO_RCVBUF` / `SO_SNDBUF`
- 生产 Linux 可考虑 Netty native transport，例如 epoll；当前 Windows 开发环境仍保留 NIO。

涉及文件：

- `tunnel-server/src/main/java/com/theshuai/tunnelserver/server/NettyServer.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/server/TcpServer.java`
- `tunnel-server/pom.xml`
- `tunnel-server/src/main/resources/application.yml`

优先级：P0/P1。

### 3.2 心跳与空闲策略分层

现状：

- 控制连接已有 `SocketIdleStateHandler`。
- 外部 TCP 数据连接没有更细的 idle/half-close 策略。

建议：

- 控制连接继续保留心跳。
- 外部数据连接按业务配置 idle timeout，避免 10k 死连接长期占 fd。
- 对半关闭场景明确策略：是否支持 half-close，或统一双方 close。

涉及文件：

- `tunnel-common/src/main/java/com/theshuai/common/handler/SocketIdleStateHandler.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/RemoteTunnelHandler.java`
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/handler/LocalTunnelHandler.java`

优先级：P1。

## 4. 数据库与管理面优化

### 4.1 连接记录不要成为登录路径瓶颈

现状：

- `ClientManagementService.authenticate` 会查库并做连接频率统计。
- `recordConnection` 和 `recordDisconnect` 会写 `ConnectionRecord`。
- 默认数据库是 SQLite，Hikari pool 默认 1。

风险：

- 10k 控制连接或频繁重连时，登录线程池和 SQLite 写入会成为硬瓶颈。
- `hasExceededRateLimit` 每次登录查 DB 计数，不适合登录风暴。

建议：

- 生产 10k 场景迁移到 PostgreSQL/MySQL。
- 连接限频使用内存滑动窗口或令牌桶，异步落库。
- 连接记录改为队列批量写入，失败可降级丢弃或落本地文件。
- 登录成功路径只做必要认证，审计异步化。

涉及文件：

- `tunnel-server/src/main/java/com/theshuai/tunnelserver/management/service/ClientManagementService.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/ManagedLoginRequestHandler.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/config/ServerExecutorConfig.java`
- `tunnel-server/src/main/resources/application.yml`

优先级：P1。

### 4.2 流量统计减少 DB 往返

现状：

- `TrafficUsageService` 已用 `LongAdder` 聚合，这是好的。
- flush 时每个 client 会 `findClientByName`，再查当天 usage，再 save。

建议：

- 缓存 `clientName -> clientId`，减少 flush 周期内查 client 表。
- 数据库支持时使用 upsert，避免 find-then-save。
- 增加 flush 耗时、flush 失败、counter backlog 指标。

涉及文件：

- `tunnel-server/src/main/java/com/theshuai/tunnelserver/management/service/TrafficUsageService.java`
- `tunnel-server/src/main/java/com/theshuai/tunnelserver/management/repository/TrafficUsageRepository.java`

优先级：P2。

## 5. HTTP 直连链路单独优化

如果 10k 指的是 `/http/{clientName}/{route}/**` 的 HTTP 并发，而不是原始 TCP NAT 连接，需要单独处理。

现状：

- `HttpTunnelController` 使用 Spring MVC，同步等待 `DirectHttpFutureManager.forward`。
- 请求体和响应体都完整读入 `byte[]`。
- Java 客户端 `DirectHttpForwarder` 使用 Apache classic blocking client。
- `DirectHttpFutureManager.FUTURES` 无显式最大并发上限。

建议：

- 为 HTTP 直连增加最大 in-flight 请求数。
- 大响应使用流式转发，避免完整 body 常驻内存。
- 改为 WebFlux/Netty 或 servlet async，释放 Tomcat 工作线程。
- 客户端使用 async HTTP client 或 Netty HTTP client。

涉及文件：

- `tunnel-server/src/main/java/com/theshuai/tunnelserver/http/HttpTunnelController.java`
- `tunnel-common/src/main/java/com/theshuai/common/manager/DirectHttpFutureManager.java`
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/handler/DirectHttpRequestHandler.java`
- `tunnel-client/src/main/java/com/theshuai/tunnelclient/handler/DirectHttpForwarder.java`
- `tunnel-client-go/internal/client/http.go`

优先级：P2，除非 10k 目标就是 HTTP 并发。

## 6. Go 客户端优化点

现状：

- `tunnel-client-go/internal/client/client.go` 中所有写控制连接都走 `writeMu`。
- `tunnel-client-go/internal/client/nat.go` 每个本地连接一个 goroutine 读本地，再串行写同一控制连接。
- 协议层 `protocol.go` 会对 payload 做压缩尝试。

建议：

- 与 Java 客户端一样引入多数据通道，避免所有 DATA 串在一把 `writeMu` 后。
- 增加本地连接数量上限和 per-lane 写队列上限。
- 对 DATA 帧避免默认压缩或按阈值/内容类型判断。
- 加入读写 deadline 和慢连接清理策略。

涉及文件：

- `tunnel-client-go/internal/client/client.go`
- `tunnel-client-go/internal/client/nat.go`
- `tunnel-client-go/internal/protocol/protocol.go`

优先级：P1。

## 7. 操作系统与 JVM 参数

这些不是代码优化，但 10k 单机必须同时满足。

Linux 主机建议检查：

- `ulimit -n` 至少 100000，建议 200000 以上。
- `net.core.somaxconn` 大于服务端 backlog，例如 65535。
- `net.ipv4.ip_local_port_range` 足够大，尤其客户端和压测机在同机或同 NAT 时。
- `net.ipv4.tcp_tw_reuse`、`net.ipv4.tcp_fin_timeout` 根据内核版本和部署策略谨慎调整。
- `net.core.netdev_max_backlog`、`net.ipv4.tcp_max_syn_backlog` 按压测结果调。

JVM 建议检查：

- 设置足够堆和堆外内存，例如 `-Xms`/`-Xmx`、`-XX:MaxDirectMemorySize`。
- 生产关闭高开销 Netty leak detection，压测排查时短期开启。
- 观察 GC 暂停、direct memory、线程数、event loop pending tasks。

TLS：

- 如果 `tunnel.tls.mode` 开启，10k 连接下要单独压测握手 CPU。
- 生产可评估 OpenSSL/tcnative 或前置 TLS 终止。

优先级：P0。

## 8. 可观测性与压测验收

必须补充指标：

- 当前外部连接数、每 client 连接数、每端口连接数。
- 控制连接和数据连接 outbound buffer 字节数。
- event loop pending tasks、执行耗时、异常数。
- `externalChannels` / `channelHandlerMap` 大小。
- 登录线程池 active/queue/rejected。
- DB flush 耗时、失败次数、批量大小。
- direct memory、heap、GC、fd 数、线程数。
- NAT DATA 包大小分布、每秒包数、每秒字节数、p95/p99 转发延迟。

压测阶段：

1. 空闲 10k 连接保持 30 分钟，验证 fd、heap、direct memory、心跳稳定。
2. 10k 连接建立/断开风暴，验证 accept backlog、登录、清理、TIME_WAIT。
3. 1k/5k/10k 小包持续转发，验证 CPU、延迟、写缓冲。
4. 慢读客户端测试，验证背压不会拖垮其他连接。
5. 客户端断网和服务端重启，验证资源释放。

建议新增或扩展：

- `tunnel-server/src/test/java/com/theshuai/tunnelserver/integration/EndToEndTunnelIT.java`
- 新增独立压测工具目录，例如 `tools/loadtest/`，优先 Go 实现 raw TCP 压测。

优先级：P0。

## 9. 建议执行顺序

1. P0：共享服务端外部监听 event loop。
2. P0：共享 Java 客户端本地连接 event loop。
3. P0：最大帧、最大连接数、backlog、写缓冲水位配置化。
4. P0：实现背压，慢写暂停对端读取。
5. P0：补基础指标和 10k 空闲连接压测工具。
6. P1：NAT DATA 帧减少 JSON、复制和压缩开销。
7. P1：多数据通道，解决单控制连接队头阻塞。
8. P1：数据库从 SQLite 演进到生产数据库，登录审计异步/批量化。
9. P2：HTTP 直连链路按是否需要 10k 并发再重构。

## 10. 不建议只做的事情

- 只把 `SO_BACKLOG` 从 1024 调大。它只能改善排队，不能解决 event loop、背压、内存、fd。
- 只把管理台的 `connectionRateLimitPerMinute` 调到 10000。它限制的是控制连接登录频率，不是外部代理连接容量。
- 只调大 JVM 堆。当前链路存在大量堆外和 socket buffer 压力，堆不是唯一瓶颈。
- 在没有背压和连接预算前直接做高流量 10k 压测，容易把机器打到不可观测状态。
