# 临时 HTTP 分享（v1）

route 的所有者或租户管理员，可以为**一条已有、受保护的 HTTP route** 签发一个临时分享：它有强制的有效期，可以随时撤销，可以把访问收窄到某个路径前缀和只读方法，并且**不会改变 route 本身**。route 自己的 `/http/{clientName}/{route}/` 入口照旧要求 Basic 认证。访客通过分享自己的路径 `/http-share/{shareId}/` 访问。分享令牌只在链接的 URL fragment 里出现一次，随后放进只对该路径有效的 HttpOnly cookie；服务端只保存令牌的 SHA-256。

关联 [issue #38](https://github.com/devShuai/specus/issues/38) 的待办「临时 HTTP 分享：有效期、撤销、访问范围与权限变更审计；各 server 实现保持一致，禁止把长期公开路由当作临时邀请」，见 [docs/issues/product-followups.md](../../docs/issues/product-followups.md)。

**状态：契约已定（第 15 节各项采用建议默认值）；Java、Go、.NET、C 四个服务端与管理前端已实现，尚未部署。** 共享向量 `protocol/test-vectors/temporary-http-share-v1.json` 由 `tools/protocol/generate_temporary_share_vectors.py` 生成。

## 1. 现状

以下是 2026-10-06 `main` 上四个服务端与管理前端的情况，契约的形状由它决定。

### 1.1 route 今天怎样被访问

公网入口只有一种：`ANY /http/{clientName}/{route}/**`，见 [http-route.md](http-route.md)。四个服务端都只按路径路由，没有按 Host 或子域名路由的能力。访问方式只有两种：公开，或者 route 级 HTTP Basic（密码以无盐 SHA-256 保存，常量时间比较）。没有登录后访问、没有 cookie，也没有任何临时凭据。

| 服务端 | 入口判定顺序 | route 记录不存在时 | 是否检查客户端已启用 | 缓存 |
| --- | --- | --- | --- | --- |
| Java | 请求体上限 → `HttpRouteAuthenticationService`（停用 404、Basic 401、读取失败 503）→ 数据连接（502） | 视为公开（「legacy client-local compatibility」） | 否，只靠停用时踢掉连接 | 客户端名 60 s（仅本实例失效）；改写、明细 2 s |
| Go | 策略读取（503）→ 停用 404 → Basic 401 → 413 → 在线（502，3 s 重连宽限） | 视为公开 | 否 | route 策略 2 s |
| .NET | 策略读取（503）→ 停用 404 → Basic 401 → 413 → 在线（503/502） | 视为公开 | 否 | 每请求读库 |
| C | Basic 门（读库）→ 413 → 会话内存中的 route 表（404）→ 在线（502） | 视为公开，按会话内存中的旧 route 表转发 | 否 | 每请求开 SQLite |

需要特别注意的两点：

- **「记录不存在就当公开」**。四端都这样处理没有服务端记录的 route，用来兼容客户端本地配置。再加上删除最后一条托管 route 时 `NAT_CONTROL` 会省略 `httpSpecusConfigList`，客户端因此保留旧列表，一条受 Basic 保护的 route 被删除后，可能在客户端重连之前变成公开可访问（见第 16 节）。分享路径绝不能沿用这条兜底规则。（之后已修复：四端入口在没有服务端记录时 fail closed，见 [http-route.md](http-route.md) 第 1、2 节。）
- **改变不会立刻到处生效。** route 配置推送、停用客户端时踢连接，都只作用于本实例持有的会话；已经建立的 HTTP 流和 WebSocket 在 route 停用或删除后照常运行。

### 1.2 谁能管理 route

四端规则一致：同一租户，并且调用者是管理员，或者其用户名等于该客户端的 `owner_username`。没有按 route 单独设的 ACL。对不可见的 route，各端分别返回 `400`（Java）、`403`（Go、.NET）、`404`（C）。

- route 可以改名（URL 随之改变），客户端也可以改名；route id 稳定。
- 没有任何服务端提供修改客户端所有者的接口。
- 删除用户只删用户行，其客户端与 route 保留，`owner_username` 悬空；Java 中新建的同名用户会「继承」这些客户端。
- Java、Go、.NET 每个管理请求都从库里重读用户，停用或删除立即生效。**C 只在登录时检查 `enabled`**，bearer 校验不读库，`/auth/refresh` 也不读库。
- 删除客户端时，Go 与 C 删除其 route 行，Java 与 .NET 留下孤立的 route 行。

### 1.3 同一个源

管理 SPA、公共互传页面、每一条 `/http/**` 上的内网应用，都在**同一个源**上：Go 用一个 mux 同时提供它们，OpenResty 用一个 `server_name` 反代它们。门户 CSP 对 `/http/**` 特意不生效，以免影响目标应用。

- 管理 token 存在 `sessionStorage`，按标签页隔离；主题、互传偏好存在 `localStorage`，同源的任何页面都能读写。
- 服务端从不读写 cookie。请求的 `Cookie` 原样转给设备，上游的 `Set-Cookie` 原样回给浏览器，不改 `Path`、不去 `Domain`。所以上游 A 用 `Path=/` 设置的会话 cookie，会被浏览器带到同源下的其他 route，也就是别的设备。
- 客户端把 `Origin`/`Referer` 改写为目标的源（Java 保留原始路径与 query），并把 `Sec-Fetch-Site: cross-site` 改为 `same-origin`。上游自己的 CSRF 判断因此看不到跨站请求，**挡住跨站写请求只能靠入口这一侧**。

### 1.4 已有的令牌与撤销模式

| 机制 | 令牌 | 存储 | 生命周期 | 能否借鉴 |
| --- | --- | --- | --- | --- |
| 互传房间邀请 | `st-<role>-` + 32 字节 base64url | SHA-256，唯一索引 | `expiresInSeconds` 300..604800，`revoked_at` 软撤销，每房间最多 20 个 | 最接近：哈希保存、有效期范围、上限与撤销语义都沿用 |
| 互传邀请链接 | 令牌放在页面 URL **fragment**，页面读取后立即清除 | — | — | 沿用：fragment 不发给服务器，不进反代访问日志 |
| WebSocket ticket | 32 字节 base64url | SHA-256，表 `specus_websocket_ticket` | 45 s，一次性，条件删除 | 只有一次性语义可借鉴 |
| 附件下载授权 | 32 字节 base64url，放在 URL 路径 | SHA-256 | 600 s，一次性；响应 `private, no-store` + `Referrer-Policy: no-referrer` | 响应头做法可借鉴 |
| 媒体回放 ticket | 32 字节 base64url，放在 URL 路径 | **明文，进程内存** | 900 s，不可撤销，不跨实例 | 反例 |

所有随机令牌都来自 CSPRNG（`SecureRandom`、`crypto/rand`、`RandomNumberGenerator`、`/dev/urandom` 或 `RAND_bytes`）。但 Java/.NET 的 route、客户端 id 生成器不是 CSPRNG，C 的 `build_prefixed_token` 用时间、pid 与计数器做 SHA-256，**这些都不能用来生成分享令牌**。唯一的服务端级密钥是 JWT 密钥；未配置时每个进程随机生成，跨实例不一致。

### 1.5 审计、限流与多实例

- **没有通用的审计或操作日志表。** Peer 服务审计在 Java、Go、.NET 中是进程内最近 80 条；C 把它落了库（`peer_mesh_service_audit`，每租户保留 80 行，没有操作者列）。流量明细 `specus_http_traffic_exchange` 记录的是公网请求本身，默认关闭。
- **`/http/**` 上没有任何限流**，Basic 认证也没有尝试次数限制。已有的限流器都是进程内固定窗口；公共互传集群模式下有基于 Redis 的共享计数。
- **多实例只共享数据库**（以及集群模式下互传用的 Redis）。控制与数据连接都在单个进程内；公网请求必须落到持有设备 `data` 连接的那个实例，否则得到 `502`/`503`。route 变更没有跨实例事件总线。

### 1.6 由此得到的约束

1. **分享不能复用 `/http/{clientName}/{route}/`。** 那里有 Basic 门和「记录不存在就当公开」的兜底；而且这个 URL 会把设备名和 route 名暴露给访客。分享使用独立前缀 `/http-share/{shareId}/`，按 route id 绑定，永远不走兜底。
2. **每个分享请求都必须从数据库读出分享、route、客户端和创建者的当前状态。** 推送、踢连接和缓存都是按实例的，不能用来保证撤销立即生效。
3. **令牌不能出现在路径或 query 中。** OpenResty 的访问日志会记录请求行；Java 把 `Referer` 的原始路径和 query 转给上游并写入流量明细；`raw_query` 原样入库；上游页面的 JS 能读到 `location`。令牌只能放在 fragment 和 HttpOnly cookie 里。
4. **cookie 只是同源下的一道弱边界。** 分享 cookie 必须 HttpOnly、按分享路径限定、`SameSite=Strict`；上游的 `Set-Cookie` 必须限定到分享路径；分享 cookie 绝不能转给设备。
5. **审计需要新表。** 现有存储里没有能记录「谁在何时改了谁的访问权限」的地方。

## 2. 模型与范围

一个分享是一行记录：

| 字段 | 说明 |
| --- | --- |
| `shareId` | 16 个 base64url 字符，随机生成，公开（出现在分享路径中），不可枚举 |
| `routeId` | 所属 route。绑定 id，不绑定名字：route 或客户端改名不影响分享 |
| `createdBy` | 创建者用户名。分享只在创建者**此刻**仍能管理该 route 时有效 |
| `access` | `read`（只读）或 `full`（完整） |
| `pathPrefix` | 规范化的路径前缀，`/` 表示整条 route |
| `label` | 可选，仅供所有者辨认，最多 60 个 Unicode 码点 |
| `createdAt`、`expiresAt` | UTC，精确到秒。`expiresAt - createdAt` 在 300..604800 秒之间 |
| `revokedAt`、`revokedBy`、`revokeReason` | 撤销信息；`revokedBy` 为空表示由系统撤销 |
| `tokenSha256` | 令牌的 SHA-256，不出现在任何接口响应中 |

**只能为「已启用、受 Basic 保护、所属客户端已启用」的 route 创建分享。** 公开 route 本来就人人可访问，在它上面建分享，会让所有者误以为「撤销分享就能停止访问」，这正是 issue 禁止的「把长期公开路由当作临时邀请」。route 之后被改成公开时，它的分享一并撤销（第 7 节）。

分享不改变 route 的任何字段，也不使用 route 的 Basic 凭据：访客永远拿不到 Basic 密码，所有者更换密码也不影响分享。

v1 不包含以下内容：

| 不包含 | 原因 |
| --- | --- |
| TCP 端口映射、Peer 服务 | 没有能放 cookie 的应用层；Peer 数据面端到端加密，服务端不在路径上 |
| 修改分享（延期、改范围） | 分享不可变，只能撤销后重建。这样审计里每个分享只有「创建、结束」两件事，没有「权限被悄悄放宽」的情形 |
| 使用次数上限 / 一次性链接 | 需要按访客区分会话，见第 15 节 |
| 记录访客 | 审计不含访客的地址、路径或内容；访问计数也不记录，见第 15 节 |
| 永久分享 | 长期访问应该用 route 自己的访问密码 |

## 3. 令牌与链接

### 3.1 令牌

```text
hs1.<shareId>.<secret>
```

- `shareId`：12 字节 CSPRNG 输出的 base64url（无填充），16 个字符；
- `secret`：32 字节 CSPRNG 输出的 base64url（无填充），43 个字符；
- 整个令牌固定 64 个字符，匹配 `hs1\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{43})`，必须整串匹配（大小写敏感，不容忍首尾空白或换行）。前缀 `hs1.` 便于日志清洗和密钥扫描识别。

服务端只保存 `tokenSha256 = lowercase_hex(SHA-256(UTF-8(整个令牌字符串)))`。比对时先按 `shareId` 取行，再对哈希做常量时间比较。令牌的熵来自 256 位的 `secret`，所以不需要慢哈希，也不需要服务端密钥。`shareId` 冲突时重新生成（主键约束保证）。令牌明文只出现在创建接口的响应里，之后任何接口都不再返回。

### 3.2 链接

```text
<origin>/#/http-share/<token>
```

管理前端用 `window.location.origin` 加上创建接口返回的 `linkPath` 拼出链接，与现有访问链接的拼法一致。令牌在 fragment 里：浏览器不会把它发给服务器，所以它不会进入 OpenResty 或服务端的访问日志，也不会出现在 `Referer` 里。`/` 在四个服务端上都返回管理 SPA（.NET 重定向到 `/index.html`，fragment 随重定向保留），所以落地页不需要服务端新增 HTML。

### 3.3 分享路径

```text
ANY /http-share/{shareId}/**
```

`shareId` 不是秘密，它出现在地址栏、`Referer` 和流量明细里都没有关系。只凭 `shareId` 什么也访问不了。

## 4. 管理接口

所有管理接口的鉴权方式与 route 管理接口相同；身份和租户只从已认证的会话取得。**创建与撤销必须从库里重新读取调用者**（启用状态、角色、租户），不能只信任 token 里的声明（C 目前不读库，见 1.2）。调用者不能管理的 route、不存在的 route、其他租户的 route，一律返回 `404`。所有响应都带 `Cache-Control: private, no-store`，非 2xx 的响应体为 `{"code": "<码>"}`，可以附带 `message`。

### 4.1 创建

```http
POST /api/admin/http-routes/{routeId}/shares
Content-Type: application/json

{"expiresInSeconds": 86400, "access": "read", "pathPrefix": "/docs/", "label": "周报评审"}
```

| 字段 | 必需 | 规则 |
| --- | --- | --- |
| `expiresInSeconds` | 是 | JSON 整数（不能是字符串、布尔或带小数的数），`300..604800`。**没有缺省值** |
| `access` | 否 | `read`（缺省）或 `full` |
| `pathPrefix` | 否 | 缺省 `/`，规范化规则见 6.3 |
| `label` | 否 | 字符串；去掉首尾 U+0020 后最多 60 个码点，不得含控制字符；为空则视为没有 |

其他字段一律拒绝（例如 `maxUses`），避免客户端以为某项限制生效了而实际没有。

| 顺序 | 情形 | HTTP | `code` |
| ---: | --- | ---: | --- |
| 1 | 没有有效的管理会话 | `401` | — |
| 2 | 请求体不合法 | `400` | `SHARE_REQUEST_INVALID` |
| 3 | 读取 route、客户端、用户或分享失败 | `503` | `SHARE_UNAVAILABLE` |
| 4 | route 不存在，或调用者此刻不能管理它 | `404` | `SHARE_ROUTE_NOT_FOUND` |
| 5 | route 已停用 | `409` | `SHARE_ROUTE_DISABLED` |
| 6 | 所属客户端已停用 | `409` | `SHARE_CLIENT_DISABLED` |
| 7 | route 是公开的 | `409` | `SHARE_ROUTE_PUBLIC` |
| 8 | 该 route 已有 20 个有效分享 | `409` | `SHARE_LIMIT_REACHED` |
| 9 | 创建成功 | `201` | — |

第 8 步只统计有效（未撤销、未过期）的分享。计数、插入与审计记录在同一个事务里完成。

```json
{
  "share": {
    "shareId": "WlpaWlpaWlpaWlpa",
    "routeId": 42,
    "label": "周报评审",
    "access": "read",
    "pathPrefix": "/docs/",
    "sharePath": "/http-share/WlpaWlpaWlpaWlpa/",
    "createdAt": "2026-10-06T08:00:00Z",
    "createdBy": "alice",
    "expiresAt": "2026-10-07T08:00:00Z",
    "status": "active",
    "revokedAt": null,
    "revokedBy": null,
    "revokeReason": null
  },
  "token": "hs1.WlpaWlpaWlpaWlpa.ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8",
  "linkPath": "/#/http-share/hs1.WlpaWlpaWlpaWlpa.ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8"
}
```

`expiresAt` 等于创建时刻（截断到整秒）加上 `expiresInSeconds`。

### 4.2 列表与查看

```text
GET /api/admin/http-routes/{routeId}/shares
GET /api/admin/http-routes/{routeId}/shares/{shareId}
```

可见性与创建相同。列表返回 `{"shares": [...]}`，包含保留期（第 7.5 节）内的全部分享，按 `createdAt` 倒序；元素即 4.1 中的 `share` 对象。`status` 在读取时计算：`revoked`、`expired` 或 `active`。读取时如果发现某个仍在有效期内的分享已经失效（第 7.2 节），必须先把它撤销，再返回撤销后的状态，所以列表永远不会把一个实际上无法访问的分享显示为 `active`。分享不属于该 route 时返回 `404 SHARE_NOT_FOUND`。

### 4.3 撤销

```text
POST /api/admin/http-routes/{routeId}/shares/{shareId}/revoke
```

请求体为空或 `{}`。对有效分享，写入 `revokedAt`、`revokedBy`（调用者）、`revokeReason = revoked-by-user`，在同一事务中写审计，返回 `200` 和撤销后的 `share` 对象。**撤销是幂等的**：对已撤销或已过期的分享返回 `200` 和当前状态，不写任何东西。调用者不能管理该 route 时返回 `404 SHARE_ROUTE_NOT_FOUND`；分享不存在或不属于该 route 时返回 `404 SHARE_NOT_FOUND`。撤销用 `POST`，不用 `DELETE`，因为记录保留到保留期结束。

### 4.4 审计读取

```text
GET /api/admin/http-routes/{routeId}/access-audit?limit=50&before=<auditId>
GET /api/admin/http-access-audit?routeId=<id>&limit=50&before=<auditId>
```

第一个接口对能管理该 route 的人开放；第二个只对租户管理员开放，可以查看已删除 route 的记录。`limit` 为 1..200，缺省 50；按 `auditId` 倒序分页。返回 `{"entries": [...], "nextBefore": <auditId 或 null>}`，元素格式见第 8 节。

## 5. 访客进入：落地页与兑换

### 5.1 落地页

落地页是管理 SPA 的公开 hash 路由 `#/http-share/<token>`，与 `#/transfer` 等公开页面同级，受门户 CSP 约束，不需要新增内联脚本。它必须：

1. 读出 fragment 中的令牌，**立即**用 `history.replaceState` 把地址栏换成不含令牌的地址，然后再发任何请求；
2. 令牌只保存在内存中，不写 `localStorage`、`sessionStorage` 或 IndexedDB；
3. 用 `fetch` 以 JSON 调用兑换接口（5.2）；
4. 成功后执行 `location.replace(body.location)`，这样带令牌的历史记录会被替换掉；
5. 失败时按 `code` 显示「链接无效」「分享已过期」「分享已被撤销」「请稍后再试」，不显示 route、设备或目标地址。

统计脚本不得上报 query 或 fragment。今天 `index.html` 内联的 gtag 配置只上报 `origin + pathname`，满足这一点；以后改动统计配置时必须保持。

### 5.2 兑换接口

```http
POST /api/public/http-shares/exchange
Content-Type: application/json

{"token": "hs1.H4s8XX6aCyxNbo8Q.o8Xn-QsdL0psjgstT2qMDitNb4oMLkttjwosTmuNDyo"}
```

| 顺序 | 情形 | HTTP | `code` |
| ---: | --- | ---: | --- |
| 1 | `Content-Type` 不是 `application/json`（允许带参数） | `415` | `SHARE_REQUEST_INVALID` |
| 2 | 请求体不是只含字符串 `token` 的对象 | `400` | `SHARE_REQUEST_INVALID` |
| 3 | 来源地址限流（第 9 节） | `429` | `SHARE_RATE_LIMITED` |
| 4 | 令牌格式不对 | `404` | `SHARE_NOT_FOUND` |
| 5 | 读取失败 | `503` | `SHARE_UNAVAILABLE` |
| 6 | 分享不存在或哈希不符 | `404` | `SHARE_NOT_FOUND` |
| 7 | 已撤销 | `410` | `SHARE_REVOKED` |
| 8 | 已过期（`now >= expiresAt`） | `410` | `SHARE_EXPIRED` |
| 9 | 仍在有效期内但已失效（7.2），就地撤销（7.4） | `410` | `SHARE_REVOKED` |
| 10 | 成功 | `200` | — |

从第 3 步起，每次请求都计入限流，不论结果。只接受 JSON：跨站页面无法用普通表单或无预检的请求提交它，浏览器的 CORS 预检也不会通过（服务端不提供 CORS）。

成功响应：

```json
{"shareId": "H4s8XX6aCyxNbo8Q", "location": "/http-share/H4s8XX6aCyxNbo8Q/docs/", "expiresAt": "2026-10-07T07:00:00Z", "access": "read", "pathPrefix": "/docs/"}
```

`location` 是分享路径加上前缀。响应不回显令牌，带 `Cache-Control: no-store` 和 `Referrer-Policy: no-referrer`，并设置 cookie：

```text
Set-Cookie: __Secure-specus_http_share=<token>; Path=/http-share/<shareId>/; Max-Age=<剩余整秒>; HttpOnly; Secure; SameSite=Strict
```

- `Max-Age` 等于 `expiresAt - now` 的整秒数，cookie 和分享同时到期；
- 不带 `Domain`，只对当前主机有效；
- `Path` 以 `/` 结尾，`/http-share/AB…/` 不会匹配 `/http-share/AB…X/`；
- `HttpOnly` 让上游页面的 JS 读不到；`__Secure-` 前缀与 `Secure` 让浏览器只在 HTTPS 上接受它（`localhost` 除外），见第 15 节；
- `SameSite=Strict`：跨站页面发起的任何请求，包括顶层 GET 导航，都不会带上它。落地页的跳转是同源发起的，所以不受影响。

非浏览器的调用方可以先调用兑换接口，再带上 cookie，例如 `curl -b '__Secure-specus_http_share=<token>' https://host/http-share/<shareId>/`。分享不接受其他任何形式的凭据。

**cookie 的值就是令牌本身**，而不是另发一个会话 id。这样服务端不需要会话表，也不需要签名密钥（未配置的 JWT 密钥在各实例上不同）；撤销与过期只看分享行。代价是不能逐个踢出访客，也做不了使用次数上限，见第 15 节。

## 6. 经分享访问

### 6.1 处理顺序

| 顺序 | 情形 | HTTP | `code` |
| ---: | --- | ---: | --- |
| 1 | `shareId` 不是 16 个 base64url 字符 | `404` | `SHARE_NOT_FOUND` |
| 2 | 路径是 `/http-share/{shareId}`，没有结尾斜杠 | `308` → `/http-share/{shareId}/`（保留 query） | — |
| 3 | 读取分享、route、客户端或用户失败 | `503` | `SHARE_UNAVAILABLE` |
| 4 | 分享不存在，或没有一个候选 cookie 与它的哈希相符 | `404` | `SHARE_NOT_FOUND` |
| 5 | 已撤销 | `410` | `SHARE_REVOKED` |
| 6 | 已过期 | `410` | `SHARE_EXPIRED` |
| 7 | 仍在有效期内但已失效（7.2），就地撤销（7.4） | `410` | `SHARE_REVOKED` |
| 8 | 方法不在 `read` 分享允许的范围内 | `405`，`Allow: GET, HEAD` | `SHARE_METHOD_NOT_ALLOWED` |
| 9 | `read` 分享上的 WebSocket Upgrade，或路径不在前缀内 | `403` | `SHARE_SCOPE_DENIED` |
| 10 | 本实例上该分享的在途流已达 64 | `429`，`Retry-After: 1` | `SHARE_BUSY` |
| 11 | 分享限流（第 9 节） | `429` | `SHARE_RATE_LIMITED` |
| 12 | 按 route 语义转发（6.4） | 目标的响应，或 [http-route.md](http-route.md) 的 `413`/`502`/`503`/`504` | — |

- 所有判定都在读取请求体、创建 NAT stream 和返回 `101` 之前完成。
- 第 1–11 步的响应体为 `{"code": "..."}`，带 `Cache-Control: no-store`。第 5–7 步同时清除 cookie（同名、同 Path、`Max-Age=0`），让浏览器不再出示它。
- 第 4 步把「分享不存在」「没有 cookie」「cookie 不对」合成同一个回答，持有 `shareId` 的人得不到任何信息。只有出示了正确令牌的人，才能从第 5–7 步知道分享已经结束。
- 第 10、11 步的额度只在凭据和范围都通过之后才消耗。知道 `shareId` 的第三方无法耗尽合法访客的额度。
- route 不存在、停用、改为公开，客户端不存在或停用，创建者失去管理权：都在第 7 步按第 7.2 节处理。**分享路径从不把「记录不存在」当作公开。**

### 6.2 凭据

凭据只取自 `Cookie` 头（HTTP/2 下可能有多个 `Cookie` 头，按出现顺序合并）。取所有名为 `__Secure-specus_http_share`（大小写敏感）、并且值的格式内含当前 `shareId` 的 cookie，最多按顺序取前 4 个，逐个计算哈希比对，任一相符即通过。之所以要试多个：同源页面可以用 JS 种下一个同名、`Path` 更长的 cookie，浏览器会把它排在前面发送。`Authorization` 头不是分享凭据，原样属于目标应用。

### 6.3 范围

**方法。** `read` 只允许 `GET` 和 `HEAD`，并且不允许 WebSocket Upgrade（WebSocket 可以向目标发送数据）。`OPTIONS` 也被拒绝：同源请求不需要预检，跨源预检本来就不带 cookie。`full` 允许任何方法和 WebSocket。只读是按方法过滤，**不能保证上游的 GET 没有副作用**，管理前端必须如实说明。

**路径前缀。** 创建时的规范化（不合格返回 `400`）：

1. 以 `/` 开头、不以 `//` 开头，只含 RFC 3986 `pchar`（**不含 `;`**）、`/` 和合法的 `%XX`，全部为 ASCII；
2. 解码代表非保留字符（`A-Z a-z 0-9 - . _ ~`）的 `%XX`，其他 `%XX` 的十六进制改为大写；
3. 拒绝：任何 `.` 或 `..` 路径段（包括由 `%2E` 组成的）、`%2F`、`%5C`、`%00`..`%1F`、`%7F`、反斜杠、空路径段；
4. 补上结尾的 `/`；结果不超过 256 字节。

例如 `/docs` → `/docs/`，`/%e6%96%87` → `/%E6%96%87/`，`/%7Euser/` → `/~user/`；`/a/../b`、`/a%2Fb/`、`/a;b/`、`/a//b/`、`/文档/`（未编码）都被拒绝。

请求时：前缀为 `/` 时，分享覆盖整条 route，不附加任何路径规则（与 route 自身完全一致）。否则把 `/http-share/{shareId}` 之后的原始路径 `relativePath` 按同样的第 1–2 步规范化；不合格、含第 3 步列出的任何成分，或者既不等于前缀去掉结尾斜杠、也不以前缀开头，就返回 `403 SHARE_SCOPE_DENIED`。所以 `/docs/` 覆盖 `/docs`、`/docs/`、`/docs/a`，不覆盖 `/docsecret`；`/docs/%2e%2E/admin`、`/docs/..%2Fadmin`、`/docs/..;/admin` 都被拒绝（最后一种针对 servlet 容器会先去掉 `;` 参数再规范化的行为）。规范化只用于判定，**转发的仍是原始路径**。

拒绝 `.`/`..` 段可能会误伤：浏览器在发送前已经去掉了点段，只有手工构造的请求会带它们；拒绝比猜测目标会怎样解码更安全。

### 6.4 转发

范围通过后，请求按 [http-route.md](http-route.md) 的语义转给 route 所属客户端，区别只有以下几点：

- NAT `OPEN` 的 `route` 取该 route **当前**的名字；`relativePath` 是 `/http-share/{shareId}` 之后的**原始**路径（保留百分号编码，为空时为 `/`）；`rawQuery` 原样。
- 不经过 route 的 Basic 门。`Authorization` 原样转发（与公开 route 相同），因为分享的凭据在 cookie 里，而不在这个头里。
- 从 `Cookie` 中删除所有名为 `__Secure-specus_http_share` 的项，其他 cookie 按原顺序合并成一个 `Cookie` 头；一项都不剩时不发 `Cookie` 头。令牌因此永远不会到达设备：它不在路径里，不在 query 里，也不在任何 header 里。
- 客户端照旧改写 `Origin`/`Referer`。`Referer` 中最多带有 `shareId`，它不是秘密。
- route 开启 `pathRewriteEnabled` 时，改写前缀与运行时脚本的 `data-specus-prefix` 都是 `/http-share/{shareId}`，**不是** route 自己的 `/http/{clientName}/{route}`；否则访客会被带到 route 的 Basic 入口，设备名与 route 名也会暴露。
- route 开启了流量明细时，分享请求按该 route 的请求记录，记录的是删除分享 cookie 之后的转发头。v1 不新增列来区分分享请求。管理前端在创建分享时，如果该 route 开启了明细采集，要提示所有者「访客的请求内容会被记录」。
- 与 route 一样，只有持有设备 `data` 连接的实例才能转发；其他实例返回 [http-route.md](http-route.md) 的离线响应。客户端 RST 也按 [http-route.md](http-route.md) 第 1 节返回固定文本的 `502`。

### 6.5 响应

在 route 自身的响应规则之后，分享响应再做以下改写：

- **`Set-Cookie` 限定到分享路径**：丢弃名为 `__Secure-specus_http_share` 的项，丢弃名字以 `__Host-` 开头（不分大小写）的项（这类 cookie 必须 `Path=/`）；删除 `Domain` 属性；`Path` 以 `/` 开头时改为 `/http-share/{shareId}` 加上原值；`Path` 缺省或不以 `/` 开头时保持原样（浏览器会取请求所在目录，它已经在分享路径下）。否则目标 A 的会话 cookie 会被浏览器带到同源下其他所有者的 route 与分享。
- **丢弃 `Clear-Site-Data`**：它会清空整个源的数据，包括管理后台和访客打开的其他分享。
- **缓存头**：删除上游的 `Cache-Control`、`CDN-Cache-Control`、`Surrogate-Control`、`Expires`、`Pragma`；上游的 `Cache-Control` 含 `no-store` 时追加 `Cache-Control: private, no-store`，否则追加 `Cache-Control: private, no-cache`。这样共享缓存不会留存副本，浏览器每次复用缓存都要回源验证：分享被撤销后，连浏览器缓存里的内容也无法继续使用。
- `101` 响应只执行 `Set-Cookie` 与 `Clear-Site-Data` 两条规则。
- 与 `/http/**` 一样，分享响应不附加门户的 CSP、`X-Frame-Options` 和 `Referrer-Policy`。`SameSite=Strict` 已经保证跨站框架里拿不到内容。

`Location` 头不改写，这与 route 现状相同（第 15 节）。

### 6.6 在途的流

已经开始的长响应、SSE 和 WebSocket 不能在分享结束后继续：

- 每个实例维护本实例上「分享 → 在途流」的登记（这同时用于 6.1 第 10 步的并发上限）；
- 在本实例上撤销分享（或者在本实例上因级联而撤销）时，立即对它的在途流发送 NAT `RST`，并关闭公网连接：HTTP 直接中断响应，WebSocket 以关闭码 `1008` 关闭；
- 每个流在 `expiresAt` 时被关闭，误差不超过 1 秒；
- 每个实例至少每 5 秒重新检查一次本实例上有在途流的分享（每个分享一次查询），发现已结束就按上面的方式关闭。所以在别的实例上发生的撤销，最迟 5 秒后切断这里的在途流。

route 今天在停用或删除后不切断在途流，这是 route 自己的问题（第 16 节）；分享不继承这个行为。

## 7. 结束：过期、撤销与级联

### 7.1 状态

`active` → `expired`（`now >= expiresAt`），或 `active` → `revoked`。两者都是终态，**分享永远不会复活**：route 重新启用、重新设为受保护，用户恢复启用，都不会让已经撤销的分享恢复。已过期的分享不再被撤销；已撤销的分享不再记录过期。时刻一律按 instant 比较；存储建议用整数 epoch 秒或毫秒，不要用字符串比较（今天 C 与 Java 部分代码按字符串比较时刻，整秒与带小数的格式会排错序）。

### 7.2 失效条件

一个仍在有效期内、尚未撤销的分享，在以下任一情况下**失效**，按表中顺序取第一条作为撤销原因：

| 条件 | `revokeReason` |
| --- | --- |
| route 不存在，或已不属于分享的租户 | `route-deleted` |
| 所属客户端不存在 | `client-deleted` |
| 所属客户端已停用 | `client-disabled` |
| route 已停用 | `route-disabled` |
| route 不再要求 Basic 认证 | `route-made-public` |
| 创建者不存在、已停用、不在该租户，或者既不是管理员也不是该客户端的所有者 | `creator-lost-access` |

最后一条意味着：管理员创建的分享不依赖所有者的账号；所有者创建的分享在所有者被停用或删除时结束；管理员被降为普通用户且不拥有该客户端时，他创建的分享全部结束。

### 7.3 主动撤销（钩子）

以下操作必须在**同一个事务**里撤销受影响的有效分享（`revokedBy` 为执行该操作的用户），并写入审计：

| 操作 | 受影响的分享 | `revokeReason` |
| --- | --- | --- |
| 停用 route | 该 route 的 | `route-disabled` |
| 关闭 route 的认证 | 该 route 的 | `route-made-public` |
| 删除 route | 该 route 的 | `route-deleted` |
| 停用客户端 | 其所有 route 的 | `client-disabled` |
| 删除客户端 | 其所有 route 的（并先为每条 route 写 `route.deleted`） | `client-deleted` |
| 停用、删除用户，或修改其角色 | 因此满足 `creator-lost-access` 的 | `creator-lost-access` |

删除客户端必须同时删除它的 route 行（Java 与 .NET 目前留下孤立行）。删除用户必须在同一事务里撤销其分享：分享按用户名记录创建者，Java 中新建的同名用户会继承原用户名。更换 Basic 密码或用户名不影响分享，只记审计。route 改名、客户端改名、修改 `targetBaseUrl` 等字段都不影响分享。

### 7.4 读取时撤销（兜底）

钩子可能被绕过：直接改库、滚动升级时的旧实例、某个遗漏的代码路径。所以**任何读到分享的路径**（访客请求、兑换、管理列表、清扫）在发现第 7.2 节的失效条件时，都必须先以条件更新把它撤销（`revokedBy = null`），再按撤销后的状态处理：

```text
UPDATE ... SET revoked_at = ?, revoked_by = NULL, revoke_reason = ?
WHERE share_id = ? AND revoked_at IS NULL AND expires_at > ?
```

只有更新影响一行时才写审计，所以并发的多个实例只会写一条。更新失败时请求仍按已结束拒绝。剩下的窗口是：失效条件出现后又在一个清扫周期内被恢复，而期间没有任何请求读到该分享。这种情况下分享继续有效，向量 `missed-hook-undone-before-sweep` 固定了这一点。

### 7.5 清扫

每个实例至少每 60 秒运行一次（多实例同时运行是安全的）：

1. 对已过期、未撤销、尚未记录过期的分享，用条件更新置位 `expiry_recorded`，成功者按 `expiresAt` 的顺序写 `share.expired`，`at` 等于 `expiresAt` 而不是清扫时刻；
2. 按 7.4 撤销失效的有效分享；
3. 删除结束（撤销或过期）超过 30 天的分享行，删除超过 180 天的审计行。

## 8. 审计

新表（建议名 `http_access_audit`），每行：

| 字段 | 说明 |
| --- | --- |
| `auditId` | 自增，用于分页 |
| `tenantId` | 租户 |
| `at` | UTC，精确到秒 |
| `actor` | 执行操作的用户名；系统动作（清扫、读取时撤销、到期）为 `null` |
| `action` | 见下表 |
| `routeId` | 相关 route |
| `shareId` | 相关分享；route 事件为 `null` |
| `detail` | 小 JSON 对象，见下表 |

| `action` | 何时写 | `detail` |
| --- | --- | --- |
| `share.created` | 4.1 成功 | `access`、`pathPrefix`、`expiresAt` |
| `share.revoked` | 4.3、7.3、7.4 | `reason` |
| `share.expired` | 7.5 | `{}`，`at` 为 `expiresAt` |
| `route.created` | 创建 route | `exposure` |
| `route.exposure-changed` | 修改 route 后其暴露状态改变 | `from`、`to` |
| `route.credentials-changed` | Basic 用户名改变，或设置了新密码 | `{}` |
| `route.deleted` | 删除 route（包括随客户端删除） | 删除前的 `exposure` |

`exposure` 取 `disabled`（`enabled = false`）、`protected`（启用且要求 Basic）或 `public`。首次开启认证并设置密码时，同时写 `route.exposure-changed` 和 `route.credentials-changed`。route 事件由 route 管理接口写入，所以本契约也要求四个服务端在 route 的创建、修改、删除中加入审计写入。

- 审计行与它描述的变更在**同一个事务**中提交；审计写入失败，变更也失败。
- **审计从不包含**：令牌、令牌哈希、label、Basic 用户名或密码、目标地址，以及任何访客信息（地址、路径、query、header、正文）。label 可能含有人名，审计的保留期比分享长，所以不写入。
- 返回给前端的元素格式：`{"auditId": 9, "at": "...", "actor": "alice", "action": "share.revoked", "routeId": 42, "shareId": "...", "detail": {"reason": "revoked-by-user"}}`。

## 9. 限流与并发

两个限流器都用 GCRA（generic cell rate algorithm），与服务连通性检查草案相同：每个键只存一个整数「理论到达时刻」TAT（毫秒），容差 `tolerance = (burst - 1) × interval`；`now >= TAT - tolerance` 时放行，放行后 `TAT = max(TAT, now) + interval`；被拒时等待 `TAT - tolerance - now`，`Retry-After` 取它向上取整的秒数，至少为 1。被拒的请求不消耗额度。

| 限流 | 键 | interval | burst | 何时计入 |
| --- | --- | ---: | ---: | --- |
| 兑换 | 来源地址（按 `trusted-proxies` 解析） | 6 000 ms | 10 | 5.2 第 3 步起的每次请求 |
| 分享请求 | `shareId` | 50 ms | 200 | 6.1 第 1–10 步都通过之后 |

- 每个分享在每个实例上最多 64 个在途流（HTTP 请求与 WebSocket 合计），超出时返回 `429 SHARE_BUSY`。
- 每条 route 最多 20 个有效分享。
- 状态都在进程内存里，按实例计算，与现有限流器的口径一致。键数上限建议 10 000：TAT 不晚于 `now` 的条目可以随时淘汰；全部条目都仍然有效而又需要新增时，拒绝新键（`429`），不淘汰仍有效的条目。

为什么这样设：令牌有 256 位熵，猜测不可行，兑换限流保护的是数据库和日志，不是密钥。分享请求的限流保护的是设备和目标服务：一个泄露出去的链接，在所有者撤销之前，最多以每秒 20 个请求的速度消耗设备，突发 200 个足够一次页面加载。`/http/**` 今天没有任何限流，这一点不因分享而改变。

## 10. 多实例

- **数据库是唯一的事实来源。** 授权判定不缓存，每个请求都读分享行以及它的 route、客户端与创建者（一次带索引的联表查询，与 .NET、Java 今天的 route 查询代价相当）。撤销与过期因此对所有实例上的新请求**立即**生效；在途流最迟 5 秒被切断（6.6）。
- 不需要跨实例事件，也不需要共享密钥：分享只依赖数据库里的哈希。
- 访客请求必须落到持有设备 `data` 连接的实例，这与 route 相同。
- 清扫、读取时撤销、撤销接口都用条件更新，多个实例同时运行时，每个结束事件只写一条审计。
- 过期按各实例的时钟判定，实例之间需要时间同步（NTP）；契约不为时钟偏差留余量。
- 限流与并发上限按实例计算。

## 11. 管理前端约束

- 「分享」入口只出现在已启用、受保护且客户端已启用的 route 上。公开 route 上要说明「公开路由无需分享，也不能用作临时邀请；需要临时访问请先开启访问认证」。
- 创建对话框必须让用户**明确选择**有效期（例如 1 小时、24 小时、7 天，或 5 分钟..7 天的自定义值），不提供「永久」，也不预先选中。访问方式缺省为只读，选「完整」时要说明访客可以提交、修改和建立 WebSocket。
- 对话框要写明：分享不改变 route 的访问认证；route 自己的访问链接仍需密码；route 被停用、改为公开或删除时，分享立即失效且不会恢复。
- 链接只在创建成功后显示一次，提供复制；不写入任何浏览器存储，关闭对话框后清除。复制失败时提示手动复制。
- 分享列表显示 label、访问方式、前缀、创建者、到期时间与状态（`expiresAt` 用服务端返回的值，到期倒计时用本地时钟只作提示），对有效分享提供撤销（需确认）。审计按 route 展示。
- 落地页按 5.1 实现。

## 12. 部署与实现入口（待实现）

- OpenResty：新增 `location ^~ /http-share/`，配置与 `location ^~ /http/` 相同（反代、WebSocket、超时、只透传上游 CSP）。否则 `/http-share/` 会落到 `location /` 的 SPA 回退。兑换接口在 `/api/` 下，已经覆盖。
- 四个服务端的门户安全头中间件都要像 `/http/` 一样豁免 `/http-share/`。
- 存储：新增分享表与审计表（Go 三种方言的 schema 与 `ensureCompatibleColumns`、Java 实体、.NET 三套 EF 迁移、C 的 `st_storage_init`）。分享表建议列：`share_id` 主键、`tenant_id`、`route_id`（索引）、`token_sha256`、`access`、`path_prefix`、`label`、`created_by`（与 `tenant_id` 联合索引）、`created_at`、`expires_at`（索引）、`revoked_at`、`revoked_by`、`revoke_reason`、`expiry_recorded`。

| 实现 | 服务端 |
| --- | --- |
| Java | `HttpRouteResource`/`HttpRouteService` 增加分享端点与钩子；新增 `/http-share/**` 入口，复用 `HttpSpecusController` 的转发与 `WebSocketSpecusConfig`，`ResponseRewriter` 的前缀参数化；`SecurityConfig` 豁免并放行兑换接口；`ManagementUserService`、`ClientAccountService` 加钩子；删除客户端时删除 route 行 |
| Go | `internal/management` 增加端点（`requireClientAccess`）与钩子；`app.go` 注册 `/http-share/{shareId}/{rest...}` 并在 `securityHeaders` 中豁免；`directhttp` 的 `relativePath` 与 `response_rewriter.go` 前缀参数化；分享入口不使用 2 s route 策略缓存；清扫用 `launch(...)` |
| .NET | `AdminApiEndpoints` 与 `ManagementMutationService`、`ManagementUserService` 钩子；`DirectHttpEndpoints` 新映射；`ResponseRewriter` 前缀参数化；`ManagementPageSecurityHeaders` 豁免；`BackgroundService` 清扫；删除客户端时删除 route 行 |
| C | `admin_http.c` 增加端点（`admin_load_accessible_client`，创建与撤销时从库里重读调用者）与 `/http-share/` 分发；转发时使用**原始** `relativePath`（今天 `/http/` 入口会解码它，见第 16 节）；`storage.c` 新表；维护线程增加 `next_*` 清扫 |
| 管理前端 | `HttpRoutesPanel` 的分享对话框、列表与审计；`lib/publicRoute.ts` 增加 `http-share` 公开路由与落地页 |

## 13. 共享向量

`protocol/test-vectors/temporary-http-share-v1.json` 由 `python tools/protocol/generate_temporary_share_vectors.py` 生成。生成器内置参考实现，写文件之前用手写的期望表逐条断言，并且断言：转发出去的内容里永远不含令牌；结束的分享会清除 cookie，`404` 永远不设 cookie；创建审计不含令牌、哈希或 label；每个撤销原因、每种审计动作、每个错误码都至少被一条用例覆盖。

| 部分 | 内容 | 实现怎样用 |
| --- | --- | --- |
| `constants`、`codes` | 本文的全部数值、cookie 名、错误码表 | 与实现中的常量逐一比对 |
| `token` | 固定随机字节对应的 `shareId`、令牌、哈希、分享路径、链接；以及格式解析的接受/拒绝样例 | 注入同样的字节，比较生成结果；解析逐条断言 |
| `pathPrefix` | 前缀规范化的输入与结果（`null` 表示 `400`） | 逐条断言 |
| `create` | 创建接口：输入、`world` 上的改动、期望状态码与响应体、审计 | 新分享的随机字节取 `newShare` |
| `exchange` | 兑换接口：状态码、响应体、结构化的 `setCookie`、读取时撤销 | — |
| `access` | 分享路径上的每个判定：拒绝、`308`、清除 cookie、读取时撤销，以及转发时的 `route`、`method`、`relativePath`、`rawQuery`、`Cookie` | 用假的设备与时钟驱动真实处理代码 |
| `headers` | 请求 `Cookie` 的剥离与合并；响应头改写 | 逐条断言 |
| `lifecycle` | 管理事件序列（撤销、route/客户端/用户变更、清扫、绕过钩子的改动）之后的审计序列与分享终态 | 按顺序重放，审计逐字段比较（`auditId` 除外） |
| `rate` | 两个 GCRA 限流器的事件序列 | 用同一个限流器实例按时间顺序重放 |

只断言「语义相近」不算通过。在途流的关闭时限（6.6）没有放进向量，由各实现的集成测试覆盖。

## 14. 放弃的方案

| 方案 | 不采用的原因 |
| --- | --- |
| 给 route 加有效期，让它临时公开 | 这正是 issue 禁止的做法：撤销等于改 route，所有人共享同一个入口，没有范围，也看不出谁在何时开放了它 |
| 每个分享一组临时 Basic 账号密码 | 浏览器按源和 realm 缓存 Basic 凭据，无法注销；凭据要以明文转交；`Authorization` 被占用后，上游自己的 Bearer 认证就不能用了 |
| 在 `/http/{clientName}/{route}/` 上额外接受分享 cookie | 暴露设备名与 route 名；同一 route 的多个分享会争用同一个 cookie 路径；要与 Basic 门和「记录不存在就当公开」交织 |
| 令牌放在路径里（`/http-share/<token>/...`） | 每个请求都带着它：进入 OpenResty 访问日志、浏览器历史、流量明细，上游页面的 JS 也能从 `location` 读到 |
| 第一次用 query 带令牌，然后 `303` 设置 cookie | 请求行仍然进入反代访问日志，重定向前的 URL 也会进入浏览器历史 |
| 服务端签名的无状态 cookie（HMAC） | 撤销仍然要查库；唯一现成的密钥是 JWT 密钥，未配置时各实例各不相同，还要处理密钥轮换 |
| 按访客发会话（会话表） | 多一张表、多一层状态，只为了次数上限和逐个踢人；v1 不需要，见第 15 节 |
| 授权结果缓存几秒 | route 现有的缓存都是按实例的，撤销会在别的实例上延迟；每请求一次带索引的查询代价很小 |
| 每个分享一个子域名 | 隔离最好，但要泛域名 DNS 与证书，四个服务端都没有按 Host 路由的能力；可作为以后的方向 |
| `SameSite=Lax` | 会让跨站的顶层 GET 导航带上 cookie。上游的 CSRF 判断已经被客户端的 `Sec-Fetch-Site` 改写绕开，入口这一侧应当尽量严格；落地页的跳转是同源的，`Strict` 没有代价 |
| 允许修改分享（延期、放宽范围） | 「权限悄悄放宽」最难审计；撤销后重建一样方便 |
| 在审计中记录访客访问 | 访客内容不属于审计；需要时由所有者开启 route 的流量明细 |
| 复用现有的固定窗口限流器 | 窗口边界会放过双倍突发；GCRA 每键一个整数，容易写成跨语言一致的向量 |

## 15. 已定事项（采用建议默认值）

以下各项在草案阶段列为待定，维护者此前对同类问题的做法是采用建议默认值，这里按各条的建议值确定。

1. **最长有效期是否可配置。** 建议：固定为 7 天，与房间邀请一致；以后如需配置，只允许调低。
2. **次数上限、一次性链接。** 建议：v1 不做。需要时另起版本，引入按访客的会话表，cookie 改为会话 id，`maxUses` 计兑换次数。
3. **访问计数或最后访问时间。** 建议：v1 不记录。如果要做，只在兑换时更新计数，不在每个请求上写库。
4. **非 HTTPS 部署。** 建议：cookie 始终 `Secure` 且带 `__Secure-` 前缀，所以纯 HTTP 部署（`localhost` 除外）无法使用分享。管理前端在 `http:` 源上禁用分享入口并说明原因。
5. **访客看到的错误页。** 建议：v1 分享路径上的错误一律返回 JSON；首次进入的错误由落地页友好显示。cookie 过期后的直接访问看到的是 JSON，可以接受。
6. **`Set-Cookie` 作用域改写和 `Clear-Site-Data` 丢弃，是否同样用于普通 route。** 建议：本契约只约束分享；普通 route 存在同样的跨 route cookie 泄露，另开 issue 处理。
7. **`Location` 改写。** 建议：v1 不改写，与 route 相同。上游返回 `/login` 这样的绝对路径跳转时，访客会离开分享路径；需要时与 route 的改写一起解决。
8. **修改 `targetBaseUrl` 是否结束分享。** 建议：不结束，也不写审计（目标地址不进审计）。分享授予的是「这条 route」，而修改 route 的人本身就有管理权。
9. **保留期。** 建议：分享行在结束后保留 30 天，审计保留 180 天，且不按租户截断条数。
10. **限流与并发的数值。** 建议：固定为本文的值，不做配置项，由向量固定。
11. **完整访问的额外确认。** 建议：管理前端在选择 `full` 时要求勾选确认，服务端不做区分。

## 16. 附带发现（不属于本契约，需要另行处理）

调研中发现的现有问题，分享路径已经避开，但 route 本身仍受影响：

1. **删除最后一条托管 route 可能让它变成公开访问（已修复）。** 服务端把「记录不存在」当公开；删除最后一条托管 route 时 `NAT_CONTROL` 省略 `httpSpecusConfigList`，客户端因此保留旧列表。四个服务端都存在这一组合（C 在客户端删除、改名或推送失败时也会发生），在客户端重连之前，原本受 Basic 保护的 route 可以被匿名访问。现在入口只按服务端记录放行；每条 `NAT_CONTROL`（包括每次控制登录的推送）都带完整列表；客户端把缺省或 `null` 的列表当作空列表；停用、改名或删除客户端会关闭其在线连接。见 [http-route.md](http-route.md) 第 1、2 节与 `protocol/test-vectors/http-route-lifecycle-v1.json`。
2. 公网入口不检查客户端是否已启用，只依赖停用时踢掉连接；而这个动作只作用于本实例。（已修复：入口要求客户端账户存在且已启用，见 [http-route.md](http-route.md) 第 1 节。）
3. C 的 bearer 校验不读库，`/auth/refresh` 也不读库：被停用或删除的用户可以一直刷新 token，角色变更也不生效。
4. C 的 `build_prefixed_token`（`cs_`/`ck_`/`sk_` 凭据）用时间、pid 和计数器做 SHA-256，不是 CSPRNG；未配置 JWT 密钥时的回退密钥也是这样生成的。
5. C 的 `/http/` 入口会解码 `relativePath`（把 `%XX` 与 `+` 都解码），与 [http-route.md](http-route.md) 第 1 节「保留原始百分号编码」不符。
6. route 停用或删除后，已经建立的 HTTP 流和 WebSocket 不会被切断；Basic 认证没有尝试次数限制。
7. 上游 `Set-Cookie` 不限定路径，与管理后台和其他 route 共用一个 cookie 空间（见 15.6）。
8. 流量明细的 `remote_address` 记录的是套接字对端，而不是按可信代理解析的来源地址。
