# 协议测试向量

本目录用于保存跨语言共用的二进制和 JSON fixture，目标是让 Java、Go、C#、C 实现可以用同一批样本证明线协议兼容。

## 当前状态

当前二进制 fixture 的主副本仍放在：

```text
implementations/csharp/protocol/tests/fixtures
```

- C# 协议测试直接读取该目录。
- C server 测试也直接读取该目录。
- Go server 当前另有一份同步副本：

  ```text
  implementations/go/server/internal/protocol/testdata/fixtures
  ```

两处当前各有 21 个 `.bin` fixture；按文件名逐一计算 SHA-256 无缺失、无内容差异。C 测试直接复用
C# 主副本，因此三种实现的 fixture 基线一致；这只证明样本字节一致，仍需各语言 codec 测试实际解码/编码通过。

Java 侧生成入口：

```text
implementations/java/common/src/test/java/com/theshuai/common/tools/WireFixtureGenerator.java
```

## 计划稿（尚未完成）

后续整理方向：

- 把 `LOGIN_REQUEST`、`LOGIN_RESPONSE`、`DIRECT_HTTP_*`、`NAT_MESSAGE` 等二进制 fixture 迁入本目录。
- 增加 `client-auth-login`、`nat-control`、`peer-control`、`peer-relay` JSON fixture。
- 每个语言实现的测试只引用本目录样本，不再各自维护一份。
