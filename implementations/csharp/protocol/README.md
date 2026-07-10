# implementations/csharp/protocol

shuai-tunnel 协议库的 .NET 实现,从 `implementations/csharp/server` 抽离为独立模块,供
**server** (`implementations/csharp/server`) 和 **client** (`implementations/csharp/client`) 共同复用。

## 内容

- 11 字节帧头 + CompactBinary + NAT_MESSAGE 编解码(双向)；默认 32 MiB 上限按完整帧（header + body）计算
- 所有命令包(`LoginRequestPacket`、`NatMessagePacket`、`DirectHttpRequest/Response` 等)
- HMAC-SHA256 登录签名 (`Security.HmacSigner`)
- 21 个仓库内二进制 fixture，并由 packet / NAT fixture 测试覆盖与 Java / Go 实现的字节兼容
- CompactBinary raw-deflate 解压要求流已正常 Finish（截断或仅 Flush 的流拒绝）；恰好 16 MiB 允许，超过 1 字节拒绝；完整帧边界同样覆盖等号与超限

## 引用方式

```xml
<ProjectReference Include="path/to/implementations/csharp/protocol/src/ShuaiTunnel.Protocol/ShuaiTunnel.Protocol.csproj" />
```

server 与 client 都通过相对路径 `ProjectReference` 引用本协议项目；协议项目自身无外部 NuGet 依赖（server / client 应用项目仍有各自的 NuGet 依赖）。

## 构建

```bash
dotnet build implementations/csharp/protocol/ShuaiTunnel.Protocol.slnx
dotnet test  implementations/csharp/protocol/ShuaiTunnel.Protocol.slnx
```

当前协议测试为 38/38；两份 21 个 fixture 副本按文件名逐一 SHA-256 一致。
