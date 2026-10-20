# 管理账号：登录名按租户唯一（v1）

本文规定管理后台账号（`specus_management_user`）的身份模型：登录名在租户内唯一，不同租户可以有同名账号；登录、token、每次请求的身份解析、OIDC 绑定和所有以账号为键的数据都以 **（租户，登录名）** 为身份。四个服务端按本文实现。

关联 [issue #183](https://github.com/devShuai/specus/issues/183)；账号删除与 token 的账号键声明见 [issue #199](https://github.com/devShuai/specus/issues/199)，删除账号时按登录名记录的数据怎样处理见 [issue #225](https://github.com/devShuai/specus/issues/225)，账号的访问权变化时管理 WebSocket 怎样失效见 [issue #236](https://github.com/devShuai/specus/issues/236)。参考实现是 Java server：`ManagementUser`、`ManagementUserService`、`ManagementUserSchemaMigrator`、`AuthController`、`ManagementContextResolver`、`LocalTokenService`，测试 `ManagementUserServiceTests`、`ManagementUserServiceIntegrationTests`、`ManagementUserSchemaMigratorTests`。

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

邮件注册表 `specus_management_user_email` 的主键 `username` 存账号键（Java `RegistrationService` 写 `user.accountKey()`）。它是唯一按账号键引用账号的表：账号删除时它的邮箱记录在同一事务里删除（第 7 节），迁移清理指向已不存在账号的邮箱记录（第 3 节第 6 步）。其他以账号为键的数据按（租户，登录名）记录，见第 10 节。

## 3. 迁移

已有数据库启动时执行，必须幂等，可以重复运行（Java `ManagementUserSchemaMigrator.migrate`，每次启动运行一次）：

1. 缺 `login_name`、`login_name_normalized` 列时加列（`varchar(80)`，可空）。
2. 读出全部行，按行计算：登录名 = `login_name` 去空白后非空则用它，否则用账号键 `username`；登录名为空或超过 80 个字符则**启动失败**。租户 = `tenant_id` 去空白，空值按 `default`。
3. 任一（租户，规范登录名）出现两次，**启动失败**，错误信息含 `duplicate management login name` 与租户名。这一步在回填之前：失败时不写入任何行。
4. 回填：每行写入 `login_name` 与 `login_name_normalized`。
5. 缺唯一索引时创建；随后读回索引定义，名字对但不是唯一索引、或列不是恰好 `(tenant_id, login_name_normalized)` 的，**启动失败**，错误信息含 `must be unique on (tenant_id, login_name_normalized)`。
6. 邮件注册表存在时，删除 `username` 不是任何账号键的邮箱记录（`delete from specus_management_user_email where username not in (select username from specus_management_user)`）。在第 7 节的删除规则之前删掉的账号会留下这样的记录，它们让该邮箱一直无法再注册；本步骤把它们放出来。表不存在（尚未建表的新库）时跳过。

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
| `uid` | 账号的**账号键**，字符串，不透明；客户端不得解析或展示。内置管理员没有账号行，它的 token **不带** `uid` |
| `role` | `ADMIN` 或 `USER` |
| `iat`、`exp` | 不变 |

签发（登录、注册验证、OIDC 换取本地 token、续期）一律按上表：账号的 token 都带 `uid`，内置管理员的都不带。

`uid` 把 token 钉在签发时的那一行账号上。登录名可以复用：删除 tenant-a 的 `alice` 后再建一个 `alice`，新账号的账号键是新的 UUID，旧 `alice` 的 token 因 `uid` 不符而解析不到任何人（第 6 节），不会落到新账号上。

`uid` 缺失或是空字符串，视为不带该声明。

## 6. 每次请求与续期的身份解析

每个需要鉴权的管理请求和 `POST /auth/refresh` 都按 token 重新读取账号（Java `ManagementUserService.resolveLocalTokenUser(sub, tenant_id, uid)`）：

| token | 解析 |
| --- | --- |
| 不带 `uid`，`sub` 与内置管理员不区分大小写相等，且 `tenant_id` 缺失或等于默认租户 | 内置管理员；关闭密码登录后不再解析 |
| 带 `tenant_id` | 在该租户按规范登录名查找 |
| 不带 `tenant_id`（只可能是更早版本签发的旧 token） | 按账号键**精确**查找 |

带 `uid` 的 token 跳过第一行，只解析为账号行：按后两行找到账号后，账号键必须与 `uid` **逐字相等**（区分大小写），否则视为解析不到。所以带 `uid` 的 token 永远不是内置管理员。

不带 `uid` 的 token 按上表照旧解析，**直到过期**。这样的 token 只能是本版本之前签发的；升级时不让所有人重新登录，代价是：升级前签发、在过期前其账号被删除且同租户又建了同名账号的 token，仍会解析到新账号，与升级前相同。续期用读到的记录重新签发，新 token 带上 `uid`，所以升级后至多一个 token 有效期，所有在用的 token 都带 `uid`。

账号必须存在且已启用；租户、角色、是否管理员一律取自账号记录，不取 token 的声明。续期用读到的记录重新签发。解析不到时：普通请求按各端现状拒绝（Java `403`），续期 `401`。

两个租户各有一个 `alice` 时，各自登录得到各自租户的 token；tenant-a 的 token 在 tenant-b 里解析不到任何账号，也看不到 tenant-b 的任何数据。

OIDC 直连 Bearer（非本地 token）按已绑定的 issuer/subject 找账号，租户与角色取账号记录，不变。

## 7. 管理账号 API

调用者的租户 = 管理上下文的租户。

| 接口 | 规则 |
| --- | --- |
| `GET /api/admin/me` | `username` 为登录名，`tenantId` 为账号的租户 |
| `GET /api/admin/users` | 只列调用者租户的账号，按登录名排序，`username` 字段是登录名。内置管理员只属于默认租户：**只有调用者租户是默认租户时**列出它的一行（`builtIn: true`，`tenantId` 为默认租户），排在最前；其他租户的列表里没有这一行 |
| `POST /api/admin/users` | 只在调用者租户检查规范登录名冲突。**其他租户已有同名账号不算冲突**，照常创建，账号键为新的 UUID。本租户冲突答复 `400`，Java 与 C 的文案为 `用户名不可用`（Go、.NET 为 `用户名已存在: <登录名>`，见第 11 节），错误信息不含其他租户的任何信息。与内置管理员同名（Java `String.equalsIgnoreCase`）一律拒绝 |
| `PUT/DELETE /api/admin/users/{username}` | 路径参数是登录名，只在调用者租户按规范登录名查找；其他租户的账号与不存在的账号答复相同：`400` `{"error":"用户不存在: <登录名>"}`，登录名为路径参数去掉首尾空白后的原样（Go 为 `404`，见第 11 节） |

创建冲突与跨租户目标都不能透露其他租户里是否存在该名字。

这三个接口的拒绝都按 Java `ManagementUserService` 的检查顺序与文案答复，由 `GlobalExceptionHandler` 把 `IllegalArgumentException` 答成 `400` `{"error":"<文案>"}`；C 与 Java 逐项一致，只有第 11 节所列的两处登录名存储限制不同。Spring 绑定请求体失败的 `400` `{"error":"Bad Request"}` 在这些检查之前，非管理员的 `403` `{"error":"需要 admin 权限"}` 在绑定之后、这些检查之前：

| 接口 | 依次检查 | 文案 |
| --- | --- | --- |
| `POST` | 用户名为空（`StringUtils.hasText`，Unicode 空白也算空）；去掉首尾空白（`String.trim`）后超过 80 个字符（UTF-16 单元）；与内置管理员同名；本租户已有；口令为空；去掉首尾空白后超过 120 个字符 | `username cannot be blank`、`username is too long`、`内置 admin 用户不能重复创建`、`用户名不可用`、`password cannot be blank`、`password is too long` |
| `PUT` | 路径参数为空；超过 80 个字符；与内置管理员同名；本租户没有；口令有内容但去掉首尾空白后为空（口令为空白时不改，不限长度） | `username cannot be blank`、`username is too long`、`内置 admin 用户只能通过配置文件修改`、`用户不存在: <登录名>`、`password cannot be blank` |
| `DELETE` | 路径参数为空；超过 80 个字符；与内置管理员同名；本租户没有；仍拥有客户端或接入凭证（`409`，7.1 节） | `username cannot be blank`、`username is too long`、`内置 admin 用户不能删除`、`用户不存在: <登录名>` |

列表里的内置管理员一行是配置的写照，不是账号：其他租户的管理员看不到它，也不能创建、修改或删除与它同名的账号（这三项照旧拒绝，不论调用者在哪个租户）。

### 7.1 删除账号

账号的**身份**是（账号的租户，账号记录里的登录名），第 10 节的数据都按它记录归属；下文「该身份的行」指 `tenant_id` 等于账号的租户、归属列（`owner_username` 或 `username`）与登录名**逐字相等**的行，与各处的可见性判断相同。登录名可以复用，所以删除账号必须处理这些行，否则同租户里之后建的同名账号会直接拥有它们（[issue #225](https://github.com/devShuai/specus/issues/225)）。

`DELETE /api/admin/users/{username}` 先按第 7 节的规则拒绝非管理员、内置管理员与本租户里不存在的目标，然后在**一个事务**里：

1. **仍拥有客户端或接入凭证时拒绝。** 统计该身份的客户端（`specus_client_account`，C 为 `client_account`）与接入凭证（`specus_client_credential`）。任一不为零时答复 `409`，不改动任何数据：

   ```json
   {"error": "该账号仍拥有 2 个客户端、1 个接入凭证，需先转移或删除", "clients": 2, "credentials": 1}
   ```

   两个计数都给出，为零的也给；`error` 的措辞各端可以不同（C 与 Java 相同）。客户端带着在用的隧道，凭证会在客户端登录时派生新的客户端，这些不能被一次账号删除顺带删掉或交给别人，由管理员先删除，或把归属转给其他账号。目前没有修改 `owner_username` 的接口，转移只能直接改数据；转移客户端时它的 Peer Mesh 设备行要一起改（设备行的归属跟随客户端，客户端每次登录也会刷新）。
2. **个人数据随账号删除**，与账号行、邮箱记录同一事务：

   | 数据 | 处理 |
   | --- | --- |
   | 邮箱记录 `specus_management_user_email` | 删除 `username` 等于该账号**键**的行：删除提交后该邮箱可以再注册，删除失败则两者都保留 |
   | 服务工作台 | 删除该身份的两个列表（[service-workbench.md](service-workbench.md)） |
   | 绘图文档 `user_diagram_document` | 删除该身份的全部文档；文档只有作者本人能读写，管理员也看不到别人的 |
   | 云端附件 `transfer_attachment` | 该身份上传、状态不是 `EXPIRED` 且尚未过期的附件，`expires_at` 与 `upload_expires_at` 都改为删除时刻：之后不能再完成上传、签发或领取下载，也不再计入存储额度；下一次过期扫描（[public-transfer.md](public-transfer.md) 第 3.4 节）删除存储里的对象并标为 `EXPIRED`。不直接删行，因为行是删除对象的唯一依据 |
   | 附件下载授权 `transfer_attachment_download_grant`、下载用量 `transfer_attachment_download_usage` | 删除该身份（`tenant_id` + `username`）的全部行：未领取的授权失效，本月下载用量不会算到同名新账号头上 |
   | Peer Mesh 设备 `peer_mesh_device` | 删除该身份名下、所属客户端已不存在的行（删除客户端时设备行不随之删除，这些是残留）。所属客户端还在的行不动 |
   | 临时 HTTP 分享 | 该身份创建的有效分享以 `creator-lost-access` 结束（[temporary-http-share.md](temporary-http-share.md)） |

3. **租户策略保留，归属转给执行删除的管理员。** Peer Mesh ACL（`peer_mesh_acl`）与 Peer 出口策略（`peer_mesh_egress_policy`）决定租户里的客户端之间能否互通、谁能经哪个出口访问外部，管理员可以在别人的客户端之间建立它们，删掉会切断其他人在用的连接。该身份的这两类行保留，`owner_username` 改为调用者的登录名（内置管理员为配置中的写法），其他列不变。ACL 的 `owner_username` 决定普通用户能否在列表里看到、能否删除它，转走后同名新账号既看不到也删不了；出口策略只有租户管理员能管理，`owner_username` 只是记录。

删除提交之后：

- 结束该身份的管理 WebSocket：客户端消息（[client-messages.md](client-messages.md) 的 `(tenantId, username)` 订阅，即 `admin:<username>`）与连接事件，并作废它尚未使用的 ticket（7.2 节）。连接在握手时记下身份，之后不再重新解析账号；不关闭的话，被删账号已打开的页面仍能收发消息，同租户再建同名账号后还会收到发给新账号的消息与事件。
- 删除产品指标进度（[product-metrics.md](product-metrics.md)）。

不随账号删除的记录：连接记录、连接事件存档、流量统计、HTTP 访问审计、分享审计里的执行人、产品指标与各开关、共享设置的 `updated_by`。它们是历史与审计，不授予任何访问：普通用户只能按自己当前拥有的客户端看到连接与流量记录，删除账号前它的客户端已经转走或删除，同名新账号看不到。

### 7.2 管理 WebSocket 的身份失效

管理 WebSocket（`/ws/client-messages`、`/ws/connections`）用 `POST /api/admin/ws-tickets` 签发的一次性 ticket 握手（[client-messages.md](client-messages.md) 第 1 节，45 秒有效）。ticket 记下签发请求解析出的身份：租户、登录名、是否管理员，以及账号键（与 token 的 `uid` 相同；内置管理员没有）。连接之后按握手时的这份身份收发和过滤：普通用户只收到自己客户端的连接事件、只能给自己的客户端发消息，`admin:<username>` 的消息投给登录名相同的连接。连接不逐条重新解析账号，所以账号的访问权变化时，服务端要主动作废 ticket、关闭连接（[issue #236](https://github.com/devShuai/specus/issues/236)）。

**哪些变化使身份失效**

| 账号的变化 | 失效 |
| --- | --- |
| 删除（7.1 节） | 是 |
| 停用：`enabled` 由 `true` 改为 `false` | 是 |
| 角色改变：`ADMIN` 改为 `USER`（降级），或 `USER` 改为 `ADMIN` | 是 |
| 只改口令；提交与原来相同的角色或启用状态；启用已停用的账号 | 否。改口令不吊销已签发的 token（第 5、6 节），连接同样保留；已停用的账号在停用时就没有连接和 ticket 了 |
| 改名 | 不适用：没有修改登录名的接口，登录名创建后不变。以后增加时按失效处理 |

**降级一律关闭，不按新权限继续。** 客户端用 token 重新换 ticket、重新连接，理由：

- 连接的权限是握手时的快照，每条事件、每条消息都按它判断（Java `ConnectionEventsWebSocketHandler.canReceive`、`ClientMessagesWebSocketHandler.canAccess`，其他三端相同）。按新权限继续，要么每条消息都重新读账号，要么把新角色推到每个实例的每条连接上，多出一条比关闭更容易出错的路径。
- 管理前端每次建连后先用 REST 读一遍快照，再回放实时事件（[public-transfer-cluster.md](public-transfer-cluster.md) 5.1 节）。降级前以管理员身份读到的别人的连接留在页面上，只有重连才按新权限重读。
- 前端在关闭码不是 `4401` 时就重新签发 ticket 重连（`apps/admin-web` 的 `useConnectionsFeed`、`AdminMessagesPanel`），token 每次请求都按账号记录解析（第 6 节），新 ticket 自然带新角色，不需要改前端。账号被删除或停用时签发失败，前端按原有退避重试。

升级（`USER` 改为 `ADMIN`）同样关闭：握手检查要求角色与 ticket 一致（见下），连接与 ticket 用同一条规则；重连后才收到全部事件。

**失效时服务端做的事**

1. 删除该身份尚未使用的管理 ticket：scope 为 `connections` 或 `client-messages`，租户与登录名都与账号逐字相等。Java、Go、.NET 的 ticket 存在共享数据库的 `specus_websocket_ticket` 里，与账号的修改或删除在**同一事务**里删除，对所有实例都生效。C 的 ticket 在进程内存里，在 SQLite 提交成功后、关闭连接前删除；数据库操作回滚时不动 ticket 和连接。提交与内存失效之间的握手仍由下面的当前身份检查保护。
2. 提交之后，以 `1008` 关闭本实例上该身份（租户与登录名逐字相等）的 `/ws/client-messages` 与 `/ws/connections`，原因文本为 `account deleted`、`account disabled` 或 `account role changed`。其他身份的连接不受影响，另一租户的同名身份也不受影响。
3. 集群模式（Java、Go、.NET、C 的 `cluster-enabled=true`）：经公共互传协调的 Redis 事件频道发布 STCE kind 5（[public-transfer-cluster.md](public-transfer-cluster.md) 第 4 节与 5.2 节），各实例（含发布者自己）按第 2 步关闭本地连接。发布失败只记日志，账号的修改照常成功。 C 收到有效 kind 5 后还删除本实例的内存 ticket；Pub/Sub 漏收时远端 ticket 仍受当前数据库身份检查保护，但不能承诺远端内存 ticket 一定收到撤销。

**握手时再校验。** 消费 ticket 之后、升级之前，按第 6 节解析 ticket 记下的身份，等于解析一个 `sub` 为 ticket 的登录名、`tenant_id` 为 ticket 的租户、`uid` 为 ticket 的账号键（没有时不带）的 token。解析不到（账号不存在、已停用、账号键不符；内置管理员已关闭密码登录），或解析出的是否管理员与 ticket 记下的不同，都答复 `403`，`X-Auth-Reason: identity revoked`，ticket 照样算已消费。账号键不符覆盖「删除后又在同一租户建了同名账号」。本版本之前签发、不带账号键的 ticket（升级时至多 45 秒）按不带 `uid` 解析，与 token 相同。

连接登记之后再检查一次，不通过时以 `1008`（`identity revoked`）关闭。握手检查可能与另一个请求的失效交错：检查读到旧状态，第 2 步的关闭（或别的实例收到的 kind 5）又在登记之前跑完；登记之后的检查读到的是已提交的新状态。

已知限制：Redis Pub/Sub 不保证送达。发布失败、或某个实例当时与 Redis 断开时，该实例上已打开的连接要等断开才结束；新的握手仍被上面的检查拒绝。新旧版本混部时，旧版本实例把 kind 5 当作未知 kind 丢弃，它上面的连接同样不关闭。

## 8. 邮件注册

注册只开在默认租户：冲突检查是「默认租户里已有该规范登录名」，新账号的账号键是 UUID，邮箱记录指向账号键。注册挑战表的用户名唯一性不变。账号删除后它的邮箱不再算「已注册」（第 7 节）。

## 9. OIDC 绑定

`resolveOrProvisionOidcUser(issuer, subject, preferred_username)`：

1. `preferred_username` 与内置管理员不区分大小写相等：拒绝。
2. 已有账号绑定该 issuer/subject（`oidc_identity_key`）：用它（任何租户），停用则拒绝。
3. 否则在**默认租户**按规范登录名找 `preferred_username`：找到且已启用、未绑定的，原子地绑定（条件更新以账号键为条件）后重读确认；已停用或已绑定其他身份的，拒绝。
4. 默认租户里没有这个登录名：在默认租户新建 USER，登录名为 `preferred_username`，账号键为 UUID，口令为无人知道的随机口令的哈希。**其他租户的同名账号不参与**，也不阻止新建。

## 10. 以账号为键的其他数据

这些列存的是**登录名**，与所在行的 `tenant_id` 一起构成身份；写入时取管理上下文的 `username`（登录名），比较时与上下文的租户和登录名比较。删除账号时各自怎样处理见 7.1 节：

| 数据 | 列 | 删除账号时 |
| --- | --- | --- |
| 客户端、接入凭证 | `owner_username` | 还有就拒绝删除（`409`） |
| Peer Mesh ACL、Peer 出口策略 | `owner_username` | 保留，归属改为执行删除的管理员 |
| 绘图文档 | `owner_username` | 删除 |
| 云端附件 | `owner_username` | 立即过期，对象由过期扫描删除 |
| 附件下载授权、下载用量 | `username` | 删除 |
| Peer Mesh 设备 | `owner_username`（跟随客户端） | 删除客户端已不存在的残留行 |
| 服务工作台 | `management_workbench_item.username` | 删除 |
| 临时 HTTP 分享 | `created_by`、`revoked_by`、审计的 `actor` | 有效分享结束；审计保留 |
| 产品指标进度 | `product_metrics_onboarding_progress.username`；开关的 `updated_by` | 进度删除；`updated_by` 保留 |
| 客户端消息订阅 | `admin:<username>` 与（租户，用户名）订阅 | 提交后关闭连接，未用的 ticket 作废（7.2 节；停用与改角色同样如此） |
| 连接事件、连接与审计记录 | 按（租户，`owner_username`）过滤；审计里的执行人 | 订阅关闭（同上）；记录保留 |

迁移不改写这些列：旧账号的登录名等于原用户名，已有的值仍然指向同一个账号。凡是要从这些列找回账号的地方（例如 HTTP 分享重新读取创建者），都按（行的租户，规范登录名）查找，不得跨租户按名字查找。

## 11. 各端差异

| 实现 | 差异 |
| --- | --- |
| Java | 参考实现 |
| Go | 规范登录名用 `strings.ToLower`（Unicode 简单大小写映射），与 Java 的 `Locale.ROOT` 在少数字符上可能不同；`PUT`/`DELETE /api/admin/users/{username}` 的目标在本租户不存在时答复 `404`（Java、.NET、C 为 `400` `用户不存在: <登录名>`）；本租户同名创建的文案是 `用户名已存在: <登录名>`（Java、C 为 `用户名不可用`） |
| .NET | 规范登录名用 `ToLowerInvariant()`，同上；本租户同名创建的文案是 `用户名已存在: <登录名>`（Java、C 为 `用户名不可用`） |
| C | 只用 SQLite。规范登录名只折叠 ASCII 字母（与既有的 SQLite `lower()` 一致），非 ASCII 字母区分大小写；token 的租户声明最长 63 字节；限流键的分隔符是 `\x1f` 而不是 `\0`（C 字符串不能含 `\0`），效果相同。登录名存成 80 字节：`POST /api/admin/users` 对超过 80 字节、但不超过 80 个字符的非 ASCII 用户名答复 `username is too long`（Java 接受），对去掉首尾空白后为空的用户名（只有控制字符，`hasText` 不算空）答复 `username cannot be blank`（Java 会建出没有登录名的账号）；管理用户三个接口的其余拒绝自 `fix/c-server-user-errors-as-java` 起与 Java 一致（第 7 节）。管理 WebSocket 的 ticket 在进程内存里；提交后删除本地 ticket 并关闭连接，启用公共互传集群时发布及接收 STCE kind 4/5，远端收到撤销后同样删除本地 ticket、关闭两类连接。仍只用 SQLite，事件协调不提供数据库 HA（[c-server-api-inventory.md](../../docs/cross-language/alignment/c-server-api-inventory.md) 第 8 节） |

MySQL 上（Java、Go、.NET）：库的默认排序规则（如 `utf8mb4_0900_ai_ci`）不区分大小写和重音，`tenant_id = ?` 与唯一索引在这种库上也就不区分，`Tenant-A` 与 `tenant-a`、`élise` 与 `elise` 会被当成同一个。这与第 1 节「租户区分大小写」不符，属于已知差异；需要严格语义的部署应为这两列使用二进制或区分大小写的排序规则。

## 12. 测试要求

每个服务端至少要有与以下 Java 测试对应的用例：

- `createsSameLoginNameInDifferentTenantWithoutGlobalLookup`、`tenantsCanCreateTheSameLoginNameWithoutEnumeration`：两个租户的管理员各自创建同名账号都成功，账号键不是登录名，各自的列表只看到自己租户的那个；跨租户同名创建不返回 `409`。
- `tenantQualifiedLoginAndRefreshResolveOnlyTheMatchingTenant`：两个租户各有 `alice`，各自带 `tenantId` 登录得到各自租户的 token，续期仍在本租户；用错租户或不带租户（`alice` 不在默认租户、也不是旧账号）登录失败；一方的 token 看不到另一方的数据。
- `bareLegacyLoginFailsClosedWhenCaseInsensitiveAccountKeyIsAmbiguous`。
- `ManagementUserSchemaMigratorTests` 的三项：回填并强制租户内唯一（可重复运行）；同租户重名在回填前失败；同名但定义不对的索引被拒绝。另外，**旧库升级后原账号照常可以登录**。

[issue #199](https://github.com/devShuai/specus/issues/199) 起另有：

- 共享向量 [`management-accounts-v1.json`](../test-vectors/management-accounts-v1.json)：按其中的账号键建好账号，把每个 `claims` 签成本地 token，逐条经 `GET /api/admin/me` 与 `POST /auth/refresh` 重放 `tokenResolution`（`expect` 为 `null` 时前者被拒、后者 `401`；否则前者答复 `username`、`tenantId`、`builtIn`，后者签发的新 token 的 `uid` 等于 `expect.uid`，`null` 表示不带），经 `GET /api/admin/users` 重放 `userLists`（逐项、按顺序比较 `username`、`tenantId`、`builtIn`）。Java `ManagementAccountsHttpTests.replaysTheTokenResolutionVector`、`replaysTheUserListVector`。
- 删除后重建同名账号：登录得到的 token 带 `uid`；删除该账号、在同一租户再建同名账号后，旧 token 的请求被拒、续期 `401`，新账号登录正常（Java `ManagementAccountsHttpTests.deletedAccountTokensDoNotResolveToARecreatedAccountOfTheSameName`）。
- 删除账号时邮箱记录同事务删除，删除后同一邮箱可以再注册；迁移清理指向不存在账号的邮箱记录且不动其他记录（Java `ManagementAccountsHttpTests.deletingAnAccountReleasesItsEmail`、`ManagementUserSchemaMigratorTests.removesEmailRecordsOfAccountsThatNoLongerExist`）。

[issue #225](https://github.com/devShuai/specus/issues/225) 起另有：

- 共享向量的 `accountDeletion`（7.1 节）：在单独的库里按其中的账号与行建好数据，逐步重放：仍拥有客户端或凭证时 `409` 且计数准确、什么都不改；客户端转走或删除、凭证删除后删除成功；个人数据删除、附件过期、ACL 与出口策略转给执行删除的管理员、另一租户的同名身份不受影响；同名新账号读到的绘图文档、ACL、设备都是空的（Java `ManagementAccountsHttpTests.replaysTheAccountDeletionVector`）。
- 删除账号后，该身份已打开的客户端消息与连接事件 WebSocket 被关闭，其他身份的不受影响（Java `ManagementAccountsHttpTests.deletingAnAccountClosesItsManagementWebSockets`）。

[issue #236](https://github.com/devShuai/specus/issues/236) 起另有（7.2 节）：

- 共享向量的 `webSocketRevocation`：停用、降级、升级、删除后，目标已打开的两种连接以 `1008` 关闭、它未用的 ticket 握手得 `403`；只改口令、提交相同角色与启用状态时连接保留、ticket 可用；旁观者（执行操作的管理员、另一租户的同名账号）的连接始终保留（Java `ManagementAccountsHttpTests.replaysTheWebSocketRevocationVector`）。
- 握手再校验：签发 ticket 后直接在库里停用账号、改角色、删除后重建同名账号，握手都得 `403`；账号不变时照常连接（Java `ManagementAccountsHttpTests.aTicketWhoseAccountChangedIsRefusedAtTheHandshake`）。
- 集群：两个连到同一 Redis 的实例，一个发布 kind 5，另一个关闭该身份的本地连接、不动其他身份（Java `PublicTransferCoordinationRedisIT.managementRevocationClosesTheIdentityOnAnotherInstance`）；STCE kind 5 的编码与共享向量 `canonicalManagementRevocation` 逐字节一致（各端 `PublicTransferClusterFrameTests`）。

.NET 的 `ManagementWebSocketRevocationTests.cs` 重放共享向量，并用真实 Redis 的两个服务实例验证撤销；另有 ticket 删除失败回滚与握手检查后、登记前撤销的确定性测试。C 的 `client_messages_tests` 在真实服务进程上重放共享向量、账号变化后的 ticket 与失败回滚；`oidc_tests` 和 .NET `Phase5SecurityTests` 验证直接使用外部 OIDC bearer 签发的 ticket 同样绑定原账号键，不能被同名替代账号继承。

其他三端的对应：Go `internal/management/management_accounts_test.go` 与 `internal/store/management_user_schema_test.go`；.NET `ManagementAccountLifecycleTests` 与 `ManagementLoginNameMigrationTests.StartupStepRemovesEmailRecordsOfDeletedAccounts`；C ctest `management_accounts_tests`（`tests/management_accounts_tests.c`）。关闭 WebSocket 的用例：Go `internal/server/client_messages_ws_test.go` 的 `TestDeletingAnAccountClosesItsManagementWebSockets`，.NET `ManagementAccountLifecycleTests.DeletingAnAccountClosesItsManagementWebSockets`，C ctest `client_messages_tests`。
