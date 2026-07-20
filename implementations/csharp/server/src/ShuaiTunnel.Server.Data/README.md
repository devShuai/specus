# Persistence & multi-provider migrations

`ShuaiTunnel.Server.Data` holds the shared model: entities, `TunnelDbContext`, and value
converters. Timestamps are stored as ISO-8601 strings (`IsoDateTimeOffsetConverter`) so ordering
and the SPA's fetch shape behave identically on every database.

## Supported providers

Selected at runtime via `Tunnel:Database:Provider` (env `TUNNEL_DB_PROVIDER`) plus the
`ConnectionStrings:Tunnel` connection string (env `TUNNEL_CONNECTIONSTRINGS_TUNNEL`):

| Provider value            | EF package                                  | Migrations assembly                  |
|---------------------------|---------------------------------------------|--------------------------------------|
| `sqlite` (default)        | `Microsoft.EntityFrameworkCore.Sqlite`      | `ShuaiTunnel.Server.Data` (this proj)|
| `postgres`/`postgresql`   | `Npgsql.EntityFrameworkCore.PostgreSQL`     | `ShuaiTunnel.Server.Data.Postgres`   |
| `mysql`/`mariadb`         | `MySql.EntityFrameworkCore` (Oracle)        | `ShuaiTunnel.Server.Data.MySql`      |

> MySQL uses Oracle's official provider because Pomelo has no EF Core 10 build yet.

Connection string examples:

- PostgreSQL: `Host=...;Database=shuai;Username=...;Password=...`
- MySQL: `server=...;database=shuai;user=...;password=...`

`DatabaseInitializer.MigrateAsync()` applies the matching migration set on startup.

## EF Core migrations are provider-specific

Each provider keeps its own migrations + model snapshot in its own assembly. **Any model change
must be re-scaffolded for all three providers**, each using its own project as both `-p` and `-s`
(this avoids the multi `IDesignTimeDbContextFactory` ambiguity):

```bash
# from implementations/csharp/server/
dotnet ef migrations add <Name> -p src/ShuaiTunnel.Server.Data         -s src/ShuaiTunnel.Server.Data         -o Migrations
dotnet ef migrations add <Name> -p src/ShuaiTunnel.Server.Data.Postgres -s src/ShuaiTunnel.Server.Data.Postgres -o Migrations
dotnet ef migrations add <Name> -p src/ShuaiTunnel.Server.Data.MySql    -s src/ShuaiTunnel.Server.Data.MySql    -o Migrations
```

`MultiProviderModelTests` guards this: it fails (`HasPendingModelChanges`) if the model drifts from
any provider's committed migrations, and checks each provider emits DDL for the core tables.

## Traffic resource and detail tables

The model now contains Java-aligned resource traffic and HTTP/TCP detail entities:

- `tunnel_resource_traffic_usage`
- `tunnel_http_traffic_exchange`
- `tunnel_tcp_traffic_frame`

本轮消息/互传模型还为 `tunnel_client_session` 增加发送、接收、附件、媒体预览和附件大小能力字段，并新增
`transfer_attachment`（公开房间或管理消息作用域、tenant/owner/target、object key、上传/保留时间和状态）。
SQLite、PostgreSQL、MySQL 都有对应的 `AddClientMessagingAndTransfer` migration 与同步 snapshot；三种 provider
的 `HasPendingModelChanges` 检查均应保持无漂移。
`AddTransferAttachmentQuota` 进一步增加账号活跃附件索引和 `transfer_attachment_download_usage` 月度下载跳转
计费表，用于执行每账号 1 GiB 存储与 1 GiB/月下载流量额度；用量在一次性 grant 首次消费时写入。
`AddSingleUseDownloadGrant` 增加 `transfer_attachment_download_grant`，只持久化随机下载授权的 SHA-256，
并通过原子消费字段保证同一业务下载链接最多换取一次短期 OSS V4 地址。
Peer Mesh ACL 的 `direction` 由三套 `AddPeerMeshAclDirection` migration 补齐，缺省 `OUTBOUND`；启动兼容 SQL
也会为旧库幂等补列并回填空值，保证正向/反向 ACL 判定可直接使用。

Provider-specific EF migrations for these tables are committed for SQLite, PostgreSQL, and MySQL.
Runtime startup also creates the tables and Java-aligned query indexes idempotently so deployments
with older or incomplete migration history can read/write detailed traffic records without a
destructive upgrade. This raw-SQL path is retained as a compatibility layer rather than a substitute
for the committed migrations.

`tunnel_traffic_usage` now includes Java-aligned `tenant_id`. Startup adds the column and
`idx_tunnel_traffic_tenant` to existing databases, traffic flush writes the owning client's tenant,
and management queries keep old null/empty rows visible only through the current tenant's visible
client set until the next flush upgrades them.

`tunnel_connection_record` keeps `tenant_id` nullable in the EF model so old rows remain readable
while startup compatibility SQL backfills from `tunnel_client_account`. The current snapshots match
that compatibility shape.

`tunnel_connection_stat` now includes Java-aligned `tenant_id`. Startup adds the column and
`idx_tunnel_connection_stat_tenant` to existing databases, then backfills old monthly rows by
`client_id` first and by `client_name` as a fallback. New monthly archives and management queries are
tenant-scoped so same-name clients in different tenants do not share counts.

The .NET server also supports Java-compatible Elasticsearch detail storage. When
`Tunnel:Elasticsearch:Uris` / `TUNNEL_ELASTICSEARCH_URIS` is blank, detail records stay in the
database. When configured, HTTP/TCP detail records are indexed into
`shuai-tunnel-http-traffic` / `shuai-tunnel-tcp-traffic` by default, management queries read from
Elasticsearch, and the indexes are trimmed by oldest `id` when they exceed the configured
HTTP 100GB / TCP 10GB default limits.
