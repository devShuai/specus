# 协议测试向量

本目录用于保存跨语言共用的二进制和 JSON fixture，目标是让 Java、Go、C#、C 实现可以用同一批样本证明线协议兼容。

当前已有的二进制 fixture 暂时仍放在：

```text
implementations/csharp/protocol/tests/fixtures
```

Java 侧生成入口：

```text
implementations/java/common/src/test/java/com/theshuai/common/tools/WireFixtureGenerator.java
```

后续整理方向：

- 把 `LOGIN_REQUEST`、`LOGIN_RESPONSE`、`DIRECT_HTTP_*`、`NAT_MESSAGE` 等二进制 fixture 迁入本目录。
- 增加 `client-auth-login`、`nat-control`、`peer-control`、`peer-relay` JSON fixture。
- 每个语言实现的测试只引用本目录样本，不再各自维护一份。
