# implementations/csharp/protocol

shuai-tunnel 协议库的 .NET 实现,从 `implementations/csharp/server` 抽离为独立模块,供
**server** (`implementations/csharp/server`) 和 **client** (`implementations/csharp/client`) 共同复用。

## 内容

- 11 字节帧头 + CompactBinary + NAT_MESSAGE 编解码(双向)
- 所有命令包(`LoginRequestPacket`、`NatMessagePacket`、`DirectHttpRequest/Response` 等)
- HMAC-SHA256 登录签名 (`Security.HmacSigner`)
- 26 个 fixture 测试,与 Java / Go 实现字节兼容

## 引用方式

```xml
<ProjectReference Include="path/to/implementations/csharp/protocol/src/ShuaiTunnel.Protocol/ShuaiTunnel.Protocol.csproj" />
```

server 与 client 都通过相对路径 `ProjectReference`,无外部 NuGet 依赖。

## 构建

```bash
dotnet build implementations/csharp/protocol/ShuaiTunnel.Protocol.slnx
dotnet test  implementations/csharp/protocol/ShuaiTunnel.Protocol.slnx
```
