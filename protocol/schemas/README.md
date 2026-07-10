# 协议 Schema

本目录用于保存跨语言共享的 JSON Schema。Schema 只描述线协议字段，不生成或存放任意语言的业务代码。

`protocol/schemas/` 是主副本；同名文件同步到 `apps/admin-web/public/schemas/`、
`implementations/csharp/server/src/ShuaiTunnel.Server/wwwroot/schemas/` 和
`implementations/java/server/src/main/resources/static/schemas/`，线上可通过
`https://tunnel.devshuai.com/schemas/<schema-file>` 访问。

当前已有：

- [client-startup-config.schema.json](client-startup-config.schema.json)：客户端 `client.jsonc` JSONC 启动配置。
- [client-auth-login.schema.json](client-auth-login.schema.json)：客户端 HTTP 登录请求和响应。
- [nat-control.schema.json](nat-control.schema.json)：`MessageType.NAT_CONTROL` 的 JSON 消息体。
- [peer-control.schema.json](peer-control.schema.json)：`MessageType.PEER_CONTROL` 的 JSON 信令。
- [peer-relay.schema.json](peer-relay.schema.json)：**历史文件名**；当前只描述 Peer Mesh 客户端间 direct UDP
  `check` / `check-response` JSON，并不描述 TURN relay。标准二进制 STUN/TURN 控制面见
  [peer-mesh.md](../spec/peer-mesh.md)。

权威顺序如下：

1. [protocol/spec](../spec/README.md) 是人可读的规范契约；
2. 本目录 Schema 约束其中的 JSON 消息，不能扩大或改写规范语义；
3. Java 参考实现和跨语言 fixtures 是当前已发布兼容行为的验证基线。

三者冲突时不得静默任选其一：先冻结既有 wire 行为并记录差异，再决定修正文档还是实现。新增行为必须先更新
`protocol/spec`，随后同步 Schema、测试向量和各语言实现。
