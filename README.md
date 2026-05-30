# shuai-tunnel

`shuai-tunnel` 是一个基于 Spring Boot 和 Netty 的 Java 内网穿透实验项目。它在公网服务端和内网客户端之间维护一条控制连接，并在收到映射配置后，将公网 TCP 端口上的流量转发到客户端可访问的本地服务。

> 当前仓库适合用于学习和继续开发，不建议直接用于生产环境。端到端隧道映射还缺少一个服务端配置下发入口，详见[当前状态](#当前状态)。

## 工作原理

```mermaid
flowchart LR
    U[公网访问者] -->|访问公网映射端口| P[TcpServer]
    P --> R[RemoteTunnelHandler]
    R <-->|通过 7010 控制连接传输数据| N[NatServerHandler]
    N <-->|Netty 自定义协议| C[NatClientHandler]
    C --> L[LocalTunnelHandler]
    L -->|访问内网地址和端口| S[本地 TCP 服务]
```

核心流程：

1. `tunnel-server` 启动 Spring Boot 应用，并在 `7010` 端口监听客户端控制连接。
2. `tunnel-client` 读取工作目录下的 `tunnelClientConfig.json`，连接服务端并完成登录。
3. 服务端向客户端发送 `NAT_CONTROL` 消息后，客户端动态添加 `NatClientHandler` 并注册端口映射。
4. 服务端为每个公网映射端口创建一个 `TcpServer`。
5. 公网请求到达映射端口后，数据经控制连接转发至客户端，再由客户端连接目标内网服务。

## 模块结构

| 模块 | 说明 |
| --- | --- |
| `tunnel-common` | 公共协议、编解码器、登录鉴权、心跳、会话、消息和同步 HTTP 请求能力 |
| `tunnel-server` | 公网服务端，监听控制连接，并为已注册映射创建公网 TCP 监听端口 |
| `tunnel-client` | 内网客户端，连接服务端，并将隧道数据转发至目标内网服务 |

主要入口：

- 服务端：`tunnel-server/src/main/java/com/theshuai/tunnelserver/TunnelServerApplication.java`
- 客户端：`tunnel-client/src/main/java/com/theshuai/tunnelclient/TunnelClientApplication.java`
- 协议实现：`tunnel-common/src/main/java/com/theshuai/common/protocol/PacketCodec.java`

## 环境要求

- JDK 25
- Maven 3.x

根目录 `pom.xml` 将 Java 编译版本设置为 `25`。仓库中的 Maven Wrapper 脚本没有可执行权限，且未提交 `.mvn` 目录，因此建议使用本机安装的 Maven。

## 构建

在项目根目录执行：

```bash
mvn clean install -DskipTests
```

## 启动

### 1. 启动服务端

```bash
cd tunnel-server
mvn org.springframework.boot:spring-boot-maven-plugin:run
```

服务端会监听两个端口：

| 端口 | 用途 |
| --- | --- |
| `7010` | Netty 控制连接端口，定义在 `NettyServer` 中 |
| `8088` | Spring Boot Web 端口，定义在 `application.yml` 中；当前仓库尚未提供 HTTP Controller |

### 2. 配置并启动客户端

客户端从当前工作目录读取 `tunnelClientConfig.json`。在 `tunnel-client` 目录中创建或修改该文件：

```json
{
  "clientName": "Demo client",
  "remoteAddress": "127.0.0.1",
  "remotePort": 7010
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `clientName` | 客户端名称，也是服务端会话标识 |
| `remoteAddress` | 公网服务端地址 |
| `remotePort` | 服务端 Netty 控制连接端口，当前代码固定为 `7010` |

启动客户端：

```bash
cd tunnel-client
mvn org.springframework.boot:spring-boot-maven-plugin:run
```

客户端的 `application.yml` 也将 Spring Boot Web 端口设置为 `8088`。如果服务端和客户端在同一台机器上联调，需要为客户端覆盖该端口：

```bash
mvn org.springframework.boot:spring-boot-maven-plugin:run \
  -Dspring-boot.run.arguments=--server.port=8089
```

### 3. 下发端口映射

客户端收到 `NAT_CONTROL` 消息后，才会注册端口映射。消息体应为以下 JSON 结构：

```json
{
  "clientName": "Demo client",
  "remoteAddress": "127.0.0.1",
  "remotePort": 7010,
  "tunnelConfigList": [
    {
      "port": 9000,
      "tunnelAddress": "127.0.0.1",
      "tunnelPort": 8080
    }
  ]
}
```

该示例表示：访问服务端 `9000` 端口的 TCP 流量，将被转发到客户端网络中的 `127.0.0.1:8080`。

## 协议概览

控制连接使用自定义二进制协议：

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| `magic` | 4 字节 | 固定值 `0x14353565` |
| `version` | 1 字节 | 协议版本 |
| `serializer` | 1 字节 | 序列化算法 |
| `command` | 1 字节 | 消息指令 |
| `length` | 4 字节 | 消息体长度 |
| `body` | N 字节 | 消息体 |

当前已定义登录、退出、心跳、普通消息、同步 HTTP 请求和 NAT 隧道消息。NAT 隧道消息支持注册、连接建立、断开、数据转发和保活。

普通控制消息默认使用紧凑二进制序列化：省略字段名，使用变长整数、短类型标记，并在消息体较大且压缩后更小时启用 Deflate。NAT 数据帧保留已有的专用布局，但隧道字节流也会在确实能够缩小时启用 Deflate。由于默认序列化算法和 NAT 数据封装已经变更，服务端和客户端需要同步升级。

## 当前状态

已实现：

- 客户端登录、时间戳校验和心跳保活
- 控制连接断开后的重连逻辑
- TCP 公网端口监听和双向数据转发
- 服务端通过控制连接请求客户端发起 HTTP 请求，并同步等待响应

需要继续完善：

- 仓库中没有 Controller、命令行入口或管理界面用于向客户端发送 `NAT_CONTROL` 消息，因此仅启动服务端和客户端只能完成登录，不能直接创建端口映射。
- `tunnel-client/tunnelClientConfig.json` 中提交的示例 `remotePort` 为 `8081`，与服务端实际监听的 `7010` 不一致。
- 服务端和客户端的 Spring Boot Web 端口默认均为 `8088`，部署在同一台机器时需要覆盖其中一个端口。
- UDP 转发尚未实现，`UdpConnection` 当前为空。
- 登录密码和签名盐值写在代码中，MD5 签名仅适合演示。
- 自动化测试覆盖较少，服务端 POM 当前还配置了跳过测试。

## 开发建议

下一步可以优先增加一个服务端管理接口，用于选择在线客户端并下发 `NAT_CONTROL` 配置；随后将控制端口、登录凭据和签名配置迁移到配置文件，并补充端到端测试。
