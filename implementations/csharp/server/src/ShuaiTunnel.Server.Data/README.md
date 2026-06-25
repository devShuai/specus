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
# from csharp/
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

Runtime startup creates these tables idempotently for SQLite, PostgreSQL, and MySQL so existing
deployments can read/write detailed traffic records without a destructive migration step. Startup
also creates the Java-aligned query indexes used by resource listing, paging, body-type filtering,
and TCP stream lookup. The next schema pass should scaffold provider-specific EF migrations for these tables,
then remove the temporary raw-SQL compatibility path.

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
