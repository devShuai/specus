# 管理账号：登录名按租户唯一（v1）

本文规定管理后台账号（`specus_management_user`）的身份模型：登录名在租户内唯一，不同租户可以有同名账号；登录、token、每次请求的身份解析、OIDC 绑定和所有以账号为键的数据都以 **（租户，登录名）** 为身份。四个服务端按本文实现。

关联 [issue #183](https://github.com/devShuai/specus/issues/183)。参考实现是 Java server：`ManagementUser`、`ManagementUserService`、`ManagementUserSchemaMigrator`、`AuthController`、`ManagementContextResolver`、`LocalTokenService`，测试 `ManagementUserServiceTests`、`ManagementUserServiceIntegrationTests`、`ManagementUserSchemaMigratorTests`。

**状态：四个服务端已实现。** 第 11 节列出各端的书面差异。

## 1. 名词

| 名词 | 含义 |
| --- | --- |
| 租户 | `tenant_id`。外部输入去掉首尾空白，空值即**默认租户**（配置项，Java 为 `specus.auth.tenant-id`，缺省 `default`），超过 80 个字符视为无效。租户比较**区分大小写**，逐字相等 |
| 登录名 | 账号在租户内的名字，用于密码登录，也是管理 API 返回的 `username`。去掉首尾空白后 1–80 个字符，保存用户输入的写法 |
| 规范登录名 | `login_name_normalized`，登录名去空白后转小写（Java `toLowerCase(Locale.ROOT)`）。租户内唯一性和所有按名字查账号的比较都用它 |
| 账号键 | 主键列 `username`，不透明、不对外展示。旧账号保留原来的用户名作账号键；新建账号的账号键是随机 UUID（小写、带连字符的 36 个字符） |
| 内置管理员 | 配置里的管理员（Java `specus.auth.username`/`password`），没有账号行，只属于默认租户 |

## 2. 表结构

`specus_management_user`：

| 列 | 说明 |
| --- | --- |
| `username` | 主键，账号键 |
| `login_name` | 登录名，可空只为兼容迁移前的行；迁移后每行都有值 |
| `login_name_normalized` | 规范登录名，同上 |
| `tenant_id` | 非空 |
| `password_hash`、`role`、`enabled`、`created_at`、`updated_at` | 不变 |
| `oidc_issuer`、`oidc_subject`、`oidc_identity_key` | 不变 |

索引：

- `uq_management_user_tenant_login_name`：**唯一**，列恰好是 `(tenant_id, login_name_normalized)`，顺序也如此。
- `uq_management_user_oidc_identity_key`：唯一，不变。
- `idx_management_user_tenant`、`idx_management_user_role` 不变。

`username` 不再要求全局唯一的「名字」语义，只是主键。任何地方都不得再用「`lower(username) = lower(?)`」按名字找账号；按账号键查找的只有两处：第 4.1 节不带租户的兼容登录，与第 6 节不带 `tenant_id` 的旧 token。

邮件注册表 `specus_management_user_email` 的主键 `username` 存账号键（Java `RegistrationService` 写 `user.accountKey()`）。

## 3. 迁移

已有数据库启动时执行，必须幂等，可以重复运行（Java `ManagementUserSchemaMigrator.migrate`，每次启动运行一次）：

1. 缺 `login_name`、`login_name_normalized` 列时加列（`varchar(80)`，可空）。
2. 读出全部行，按行计算：登录名 = `login_name` 去空白后非空则用它，否则用账号键 `username`；登录名为空或超过 80 个字符则**启动失败**。租户 = `tenant_id` 去空白，空值按 `default`。
3. 任一（租户，规范登录名）出现两次，**启动失败**，错误信息含 `duplicate management login name` 与租户名。这一步在回填之前：失败时不写入任何行。
4. 回填：每行写入 `login_name` 与 `login_name_normalized`。
5. 缺唯一索引时创建；随后读回索引定义，名字对但不是唯一索引、或列不是恰好 `(tenant_id, login_name_normalized)` 的，**启动失败**，错误信息含 `must be unique on (tenant_id, login_name_normalized)`。

结果：旧账号的登录名就是原来的用户名，账号键不变，所以旧库里所有以用户名记录的归属（第 10 节）不需要改写，原账号照常登录。旧库里大小写不同的两个同名账号只要分属不同租户就能通过迁移；在同一租户则迁移拒绝启动，由运维先处理。

各端在一个事务里完成第 1–5 步的写入时，第 3 步之后的失败同样不能留下部分回填。

## 4. 密码登录

`POST /auth/login`，请求体 `{"username", "password", "turnstileToken", "tenantId"}`，`tenantId` 可省略。

### 4.1 租户怎样确定

**只看请求体的 `tenantId`。** 不按域名、Host 或其他请求头推断租户。管理前端的登录框有可选的「租户」输入（`apps/admin-web` 的 `AuthDialog`），留空时不发送该字段。

| 请求 | 查找 |
| --- | --- |
| 带 `tenantId`（去空白后非空） | 只在该租户按规范登录名查找。`tenantId` 无效（超过 80 个字符）视为登录失败 |
| 不带 `tenantId` | 先在默认租户按规范登录名查找；**找不到时**，再按账号键不区分大小写查找，恰好一行时用它（旧账号的兼容登录，见 4.2），零行或多行都视为失败 |

找到的账号必须已启用且口令正确，否则 `401 {"error":"用户名或密码错误"}`；各种失败的答复逐字节相同。口令成功校验后可以升级旧哈希（不变）。

### 4.2 同名账号在多个租户时

- 带 `tenantId` 时只会命中该租户的账号，其他租户的同名账号不参与。
- 不带 `tenantId` 时，默认租户里的同名账号优先。默认租户里没有时，旧账号（账号键等于原用户名）仍可不带租户登录，这样升级前的客户端和书签照常可用；新建账号的账号键是 UUID，不会被这一步命中，所以非默认租户的新账号**必须**带 `tenantId` 登录。
- 兼容查找匹配到多行（例如旧库里 tenant-a 有 `Alice`、tenant-b 有 `alice`）时失败关闭，答复与口令错误相同（Java `bareLegacyLoginFailsClosedWhenCaseInsensitiveAccountKeyIsAmbiguous`）。

### 4.3 内置管理员

用户名与内置管理员不区分大小写相等，且请求不带 `tenantId` 或 `tenantId` 等于默认租户时，按内置管理员校验（配置口令常量时间比较，关闭密码登录或未配置口令时失败）。带其他租户时按普通账号在该租户查找。

### 4.4 限流

登录限流的账号维度键是 `lower(trim(tenantId)) + "\0" + lower(trim(username))`（Java `AuthController.loginIdentity`）：不同租户的同名账号各自计数，成功登录只清除自己的计数。IP 维度不变。

## 5. Token

本地 HS256 token（`iss = "specus"`）的声明：

| 声明 | 值 |
| --- | --- |
| `sub` | 账号的**登录名**（内置管理员为配置中的写法） |
| `tenant_id` | 账号的租户 |
| `role` | `ADMIN` 或 `USER` |
| `iat`、`exp` | 不变 |

签发（登录、注册验证、OIDC 换取本地 token、续期）一律按上表。

## 6. 每次请求与续期的身份解析

每个需要鉴权的管理请求和 `POST /auth/refresh` 都按 token 重新读取账号（Java `ManagementUserService.resolveLocalTokenUser(sub, tenant_id)`）：

| token | 解析 |
| --- | --- |
| `sub` 与内置管理员不区分大小写相等，且 `tenant_id` 缺失或等于默认租户 | 内置管理员；关闭密码登录后不再解析 |
| 带 `tenant_id` | 在该租户按规范登录名查找 |
| 不带 `tenant_id`（只可能是更早版本签发的旧 token） | 按账号键**精确**查找 |

账号必须存在且已启用；租户、角色、是否管理员一律取自账号记录，不取 token 的声明。续期用读到的记录重新签发。解析不到时：普通请求按各端现状拒绝（Java `403`），续期 `401`。

两个租户各有一个 `alice` 时，各自登录得到各自租户的 token；tenant-a 的 token 在 tenant-b 里解析不到任何账号，也看不到 tenant-b 的任何数据。

OIDC 直连 Bearer（非本地 token）按已绑定的 issuer/subject 找账号，租户与角色取账号记录，不变。

## 7. 管理账号 API

调用者的租户 = 管理上下文的租户。

| 接口 | 规则 |
| --- | --- |
| `GET /api/admin/me` | `username` 为登录名，`tenantId` 为账号的租户 |
| `GET /api/admin/users` | 只列调用者租户的账号，按登录名排序，`username` 字段是登录名；内置管理员一行照旧排在最前 |
| `POST /api/admin/users` | 只在调用者租户检查规范登录名冲突。**其他租户已有同名账号不算冲突**，照常创建，账号键为新的 UUID。本租户冲突的状态码沿用各端现状（Java、Go、.NET `400`，C `409`），错误信息不含其他租户的任何信息。与内置管理员同名一律拒绝 |
| `PUT/DELETE /api/admin/users/{username}` | 路径参数是登录名，只在调用者租户按规范登录名查找；其他租户的账号与不存在的账号答复相同 |

创建冲突与跨租户目标都不能透露其他租户里是否存在该名字。

删除账号时，按（账号的租户，账号记录里的登录名）清理该身份的工作台行、产品指标进度与 HTTP 分享，时机与事务边界见各自的契约（[service-workbench.md](service-workbench.md)、[product-metrics.md](product-metrics.md)、[temporary-http-share.md](temporary-http-share.md)）。

## 8. 邮件注册

注册只开在默认租户：冲突检查是「默认租户里已有该规范登录名」，新账号的账号键是 UUID，邮箱记录指向账号键。注册挑战表的用户名唯一性不变。

## 9. OIDC 绑定

`resolveOrProvisionOidcUser(issuer, subject, preferred_username)`：

1. `preferred_username` 与内置管理员不区分大小写相等：拒绝。
2. 已有账号绑定该 issuer/subject（`oidc_identity_key`）：用它（任何租户），停用则拒绝。
3. 否则在**默认租户**按规范登录名找 `preferred_username`：找到且已启用、未绑定的，原子地绑定（条件更新以账号键为条件）后重读确认；已停用或已绑定其他身份的，拒绝。
4. 默认租户里没有这个登录名：在默认租户新建 USER，登录名为 `preferred_username`，账号键为 UUID，口令为无人知道的随机口令的哈希。**其他租户的同名账号不参与**，也不阻止新建。

## 10. 以账号为键的其他数据

这些列存的是**登录名**，与所在行的 `tenant_id` 一起构成身份；写入时取管理上下文的 `username`（登录名），比较时与上下文的租户和登录名比较：

| 数据 | 列 |
| --- | --- |
| 客户端、接入凭证 | `owner_username` |
| Peer Mesh ACL、Peer 出口策略、绘图文档、云端附件 | `owner_username` |
| 服务工作台 | `management_workbench_item.username` |
| 临时 HTTP 分享 | `created_by`、`revoked_by`、审计的 `actor` |
| 产品指标进度 | `product_metrics_onboarding_progress.username`；开关的 `updated_by` |
| 客户端消息订阅 | `admin:<username>` 与（租户，用户名）订阅 |
| 连接事件、连接与审计记录 | 按（租户，`owner_username`）过滤；审计里的执行人 |

迁移不改写这些列：旧账号的登录名等于原用户名，已有的值仍然指向同一个账号。凡是要从这些列找回账号的地方（例如 HTTP 分享重新读取创建者），都按（行的租户，规范登录名）查找，不得跨租户按名字查找。

## 11. 各端差异

| 实现 | 差异 |
| --- | --- |
| Java | 参考实现 |
| Go | 规范登录名用 `strings.ToLower`（Unicode 简单大小写映射），与 Java 的 `Locale.ROOT` 在少数字符上可能不同 |
| .NET | 规范登录名用 `ToLowerInvariant()`，同上 |
| C | 只用 SQLite。规范登录名只折叠 ASCII 字母（与既有的 SQLite `lower()` 一致），非 ASCII 字母区分大小写；token 的租户声明最长 63 字节；限流键的分隔符是 `\x1f` 而不是 `\0`（C 字符串不能含 `\0`），效果相同 |

MySQL 上（Java、Go、.NET）：库的默认排序规则（如 `utf8mb4_0900_ai_ci`）不区分大小写和重音，`tenant_id = ?` 与唯一索引在这种库上也就不区分，`Tenant-A` 与 `tenant-a`、`élise` 与 `elise` 会被当成同一个。这与第 1 节「租户区分大小写」不符，属于已知差异；需要严格语义的部署应为这两列使用二进制或区分大小写的排序规则。

## 12. 测试要求

每个服务端至少要有与以下 Java 测试对应的用例：

- `createsSameLoginNameInDifferentTenantWithoutGlobalLookup`、`tenantsCanCreateTheSameLoginNameWithoutEnumeration`：两个租户的管理员各自创建同名账号都成功，账号键不是登录名，各自的列表只看到自己租户的那个；跨租户同名创建不返回 `409`。
- `tenantQualifiedLoginAndRefreshResolveOnlyTheMatchingTenant`：两个租户各有 `alice`，各自带 `tenantId` 登录得到各自租户的 token，续期仍在本租户；用错租户或不带租户（`alice` 不在默认租户、也不是旧账号）登录失败；一方的 token 看不到另一方的数据。
- `bareLegacyLoginFailsClosedWhenCaseInsensitiveAccountKeyIsAmbiguous`。
- `ManagementUserSchemaMigratorTests` 的三项：回填并强制租户内唯一（可重复运行）；同租户重名在回填前失败；同名但定义不对的索引被拒绝。另外，**旧库升级后原账号照常可以登录**。
