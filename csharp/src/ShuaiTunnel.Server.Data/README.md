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
any provider's committed migrations, and checks each provider emits DDL for all six tables.
