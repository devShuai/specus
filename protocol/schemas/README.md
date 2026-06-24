# 协议 Schema

本目录用于保存跨语言共享的 JSON Schema。Schema 只描述线协议字段，不生成或存放任意语言的业务代码。

当前已有：

- [client-startup-config.schema.json](client-startup-config.schema.json)：客户端 `tunnelClientConfig.json` 启动配置。
- [client-auth-login.schema.json](client-auth-login.schema.json)：客户端 HTTP 登录请求和响应。
- [nat-control.schema.json](nat-control.schema.json)：`MessageType.NAT_CONTROL` 的 JSON 消息体。
- [peer-control.schema.json](peer-control.schema.json)：`MessageType.PEER_CONTROL` 的 JSON 信令。
- [peer-relay.schema.json](peer-relay.schema.json)：Peer Mesh STUN/TURN-lite UDP JSON 消息和 direct UDP check。

当前 Java 实现仍是字段来源；新增字段前应先更新 [protocol/spec](../spec/README.md)，再同步更新 Schema 和测试向量。
