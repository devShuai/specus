# 跨语言对齐：安全差异

> 本文是从 `cross-language-java-alignment-plan.md` 拆分出来的四篇之一。索引与拆分理由见 [该文件](../cross-language-java-alignment-plan.md)。

本篇记录四端在安全上**必须一致的部分**、**故意不一致的部分**，以及后者的理由。前三篇关心"能不能互通"和"行为是否相同"；这一篇关心"哪些地方看起来该相同、实际不同，以及为什么那是对的"。

一条贯穿全篇的原则：差异本身不是问题，**没写下来的差异**才是。一个读者如果不知道某个检查只在三端存在，就会在第四端上做出错误假设。

## 必须逐字节一致

这些一旦分叉，同一份数据在不同实现上会得出不同结论，属于事实上的协议。

### 口令与密钥摘要格式

人类口令使用 PBKDF2-HMAC-SHA256，格式自描述、参数随哈希走：

```
$pbkdf2-sha256$v=1$i=<iterations>$<base64 salt>$<base64 key>
```

Java、Go、.NET 三端共用同一格式，并各自断言同一组由**独立实现**生成的向量，因此任一端写出的哈希都能被另外两端验证。选 PBKDF2 而不是 Argon2id，是因为它在三端标准库里都有——格式分叉意味着同一个账号在一端能登录、另一端不能，这个代价高于 Argon2id 多出的内存硬度。

默认 210,000 轮；低于 1,000 轮的存量哈希按损坏处理。旧的裸 SHA-256 仍可验证，并在验证成功的那一刻——明文唯一存在的那一刻——就地重写为新格式。

**高熵密钥不走这条路，而且不能走**：HMAC 登录流程直接使用凭据摘要的 32 字节原文作为 HMAC key，所以机器凭据的 SHA-256 摘要格式是协议的一部分。每路由 basic-auth 密钥同样保持摘要，因为它在每个被代理请求上都要校验一次，210k 轮迭代等于自我 DoS；它是闸门而不是账号。OIDC issuer+subject 索引键也是摘要——那是索引，不是凭据。

四类用途现在有各自的命名（`HashPassword` / `HashToken` / `DigestKey`），不再共用一个函数，因为共用正是当初把慢 KDF 用错地方、或把快摘要用在口令上的原因。

### 解压上限

绝对上限 64 MiB，膨胀比上限 100:1，两者同时生效；小于 64 KiB 的输入按固定额度处理。三端取同一组数值不是为了互通，而是为了同一份恶意载荷在任何一端都被同样拒绝——否则攻击者只需挑一个部署了最宽实现的节点。

## 一致的策略，不同的机制

这些在安全语义上一致，但落地手段随平台不同。差异是平台决定的，不是疏漏。

| 能力 | Java / Android | Go | .NET |
| --- | --- | --- | --- |
| 上游证书链校验 | Netty `SslContextBuilder` | `crypto/tls` 默认校验 | 平台默认校验（不设 callback） |
| 上游主机名校验 | **必须显式开启**：`SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` | `tls.Config.ServerName` 自动生效 | `SocketsHttpHandler` 按请求填入 TargetHost |
| 私钥文件权限 | POSIX mode / Windows ACL（`AclFileAttributeView`） | POSIX mode / `icacls` | POSIX `UnixFileMode` / `icacls` |
| 凭据文件权限拒绝 | `Files.getPosixFilePermissions` | `os.Stat` mode 位 | `File.GetUnixFileMode` |

**Netty 的主机名校验必须显式开启**，是这张表里最容易出事的一格。trust manager 只证明证书可信，不证明它属于正在连的那台主机；不设这一项的话，任意主机的有效证书对所有主机都成立。Go 和 .NET 的默认路径自带这项检查，Java 和 Android 不带。

## 故意不一致

### Android 不做凭据文件权限检查

Android 客户端的配置存放在应用私有目录，隔离由操作系统强制，比文件 mode 位更强。`env:` / `file:` 这种取值方式也不符合手机应用的配置形态——那是给命令行客户端准备的。在 Android 上加同样的旋钮是动作，不是保护。

### Windows 不做 ACL 宽松度判断

Unix mode 位在 Windows 上没有意义，而把 ACL 读到足以判断"过宽"，需要解析组成员关系和继承项——这个判断很容易在细节上出错，出错的后果要么是拒绝合法配置，要么是放行不合法的。因此客户端改为**在自己写出文件时**收紧 ACL，那是唯一能精确做到的时点；读取时只检查文件存在且是常规文件。

### 不加密凭据文件

密钥必须放在本进程无需协助就能拿到的地方，因此任何以该用户身份运行的人同样能解密，而读不到文件的人本来也读不到密钥。文件权限才是真正区分这两种情况的机制——OpenSSH 对权限过宽的私钥选择拒绝而不是默认加密，正是这个道理。这一条写下来，是为了下一个人不必重新推导，也不会误以为"加密存储"是被遗漏了。

### C server 不在安全门禁内

C server 按要求冻结为轻量兼容子集，缺少 TLS、对象存储、live discovery/client-message、HTTP 媒体采集和 Peer Mesh 数据面。它不纳入本篇任何一条结论，引用时必须显式排除。

## 拒绝而不是告警

以下情况四端一律拒绝启动或拒绝连接，而不是记一条日志继续跑：

- 凭据文件 group/other 可读（类 Unix）——一个每个本地账号都能读的凭据已经泄露了，告警只会滚过去
- 上游证书校验失败，且没有配置 CA、pin 或显式 `insecureSkipVerify`
- CA 文件不存在、文件里没有证书、pin 不是 64 位十六进制——静默降级回"信任一切"正是要消除的失效模式
- 生产环境（`SPECUS_ENV=prod`）下仍使用已知默认口令
- 解压超过字节数或膨胀比上限

## CI 门禁

四端各有一个依赖审计 job，产出 SCA 报告并在 High/Critical 上失败。阈值由 `tools/sca/fail_on_severity.py` 判定而不是扫描器退出码：后者对任何发现都非零退出，包括常常没有修复版本的低危项，卡在那些上面只会让人学会绕过门禁。另加每周定时运行，因为新通告不需要提交代码就会出现。

Go 用 `govulncheck`，它只报代码**可达**的漏洞，所以一次命中是一条调用路径而不是一次版本匹配。Java 和 Android 先生成解析后的 CycloneDX SBOM 再扫，因为扫描器读不了 pom 和 build.gradle；Android 的 SBOM 限定在实际打进 APK 的 classpath，否则会把 Android Gradle Plugin 自己的构建期依赖也算进来。

## 环境验收边界

本篇所有结论都来自源码与自动化测试。真实 CA、L4 TLS 终止、多平台证书存储、跨 NAT 直连/中继回落、真机 VPN 与长时间压力仍属发布验收，见 [环境验证](environment-verification.md)。
