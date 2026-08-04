# Specus v1 naming migration

This package migrates an existing installation after the source, binaries,
protocol identifiers, environment variables, runtime paths and database table
prefix were renamed to `specus`.

The migration is intentionally one-way. Deploy the server and every client from
the same Specus release; old protocol field names and old API routes are not
accepted by the new binaries.

## What changes

| Area | Legacy | Specus |
| --- | --- | --- |
| Environment prefix | `TUNNEL_*` | `SPECUS_*` |
| Peer environment prefix | `SHUAI_PEER_*` | `SPECUS_PEER_*` |
| .NET connection string | `ConnectionStrings__Tunnel` | `ConnectionStrings__Specus` |
| Configuration root | `tunnel.*` / `Tunnel` | `specus.*` / `Specus` |
| Database table prefix | `tunnel_*` | `specus_*` |
| Java service | `tunnel-server` | `specus-server` |
| Go service | `tunnel-server-go` | `specus-server-go` |
| .NET service | `tunnel-server-csharp` | `specus-server-csharp` |
| Default SQLite file | `shuai-tunnel.db` / transitional `shuai-specus.db` | `specus.db` |
| Attachment object prefix | `shuai-tunnel/attachments` | `specus/attachments` |
| Media object prefix | `shuai-tunnel/http-media` | `specus/http-media` |
| Elasticsearch HTTP index | `shuai-tunnel-http-traffic` | `specus-http-traffic` |
| Elasticsearch TCP index | `shuai-tunnel-tcp-traffic` | `specus-tcp-traffic` |
| Redis coordination prefix | `shuai-tunnel:v2:public-transfer` | `specus:v2:public-transfer` |
| Peer protocol label | `shuai-peer-mesh` | `specus-peer-mesh` |
| Default virtual device | `shuai0` | `specus0` |
| Public hostname, optional | `tunnel.devshuai.com` | `specus.devshuai.com` |

The complete table mapping is in
[`database/table-map.json`](database/table-map.json). The migration directory
is the only source directory where legacy identifiers are expected to remain.

## Required order

1. Back up the database, object-storage buckets, Elasticsearch indices, and
   `/etc`, `/opt`, `/var/lib`, and `/var/log` service directories.
2. Stop every Specus/legacy server process that can access the database.
3. Run a migration plan and resolve every reported destination collision.
4. Copy object-storage prefixes and clone Elasticsearch indices.
5. Apply database and configuration migration. The database step changes
   stored object keys, so do not run it before the object copy is verified.
6. Install the new server artifact and deploy all clients together.
7. Verify login, port mappings, HTTP routes, peer transfer, media capture and
   management login before deleting backups.

Do not enable `--rewrite-domain` until DNS and the TLS certificate cover
`specus.devshuai.com`.

## Object storage

The database contains complete attachment and media object keys. Copy the
objects before running the database migration; the relational migration then
updates those stored keys to the new prefixes. Configure a MinIO Client alias
for each backend without putting credentials on the command line.

Aliyun OSS attachment plan and apply:

```bash
bash ./deploy/migrations/specus-v1/migrate_object_storage.sh \
  --remote aliyun/private-bucket \
  --from shuai-tunnel/attachments \
  --to specus/attachments

bash ./deploy/migrations/specus-v1/migrate_object_storage.sh \
  --remote aliyun/private-bucket \
  --from shuai-tunnel/attachments \
  --to specus/attachments \
  --apply
```

RustFS media plan and apply:

```bash
bash ./deploy/migrations/specus-v1/migrate_object_storage.sh \
  --remote rustfs/specus-media \
  --from shuai-tunnel/http-media \
  --to specus/http-media

bash ./deploy/migrations/specus-v1/migrate_object_storage.sh \
  --remote rustfs/specus-media \
  --from shuai-tunnel/http-media \
  --to specus/http-media \
  --apply
```

The script uses `mc mirror`, verifies the result with `mc diff`, and retains
the source prefix for rollback. A non-empty destination is rejected unless
`--resume` is explicitly supplied. `mc diff` validates object names and sizes;
retain the source prefix until application-level download/playback checks pass.

When `mc` is not installed but the host has `python3-boto3`, use the native
S3-compatible migrator. It reads the existing media credentials from
`SPECUS_MEDIA_CAPTURE_*`, performs server-side copies, verifies every
destination key and size, and retains the source:

```bash
python ./deploy/migrations/specus-v1/migrate_s3_prefix.py \
  --from shuai-tunnel/http-media \
  --to specus/http-media

python ./deploy/migrations/specus-v1/migrate_s3_prefix.py \
  --from shuai-tunnel/http-media \
  --to specus/http-media \
  --apply
```

Use `--resume` only after inspecting a partial destination left by an
interrupted migration.

## Elasticsearch

When traffic detail storage is enabled, clone both legacy indices while the
server is stopped:

```bash
export SPECUS_ELASTICSEARCH_URIS=https://127.0.0.1:9200
export SPECUS_ELASTICSEARCH_API_KEY=...
python ./deploy/migrations/specus-v1/migrate_elasticsearch.py
python ./deploy/migrations/specus-v1/migrate_elasticsearch.py --apply
```

Production installations often prepend an environment name. Pass the actual
index pairs explicitly. If the new server already auto-created empty
destination indices, `--replace-empty-destination` may remove only those
zero-document indices before cloning:

```bash
python ./deploy/migrations/specus-v1/migrate_elasticsearch.py \
  --index-rename \
    prod-shuai-tunnel-http-traffic=prod-specus-http-traffic \
  --index-rename \
    prod-shuai-tunnel-tcp-traffic=prod-specus-tcp-traffic \
  --replace-empty-destination
```

Stop every index writer, inspect the plan, then append `--apply`.

Basic authentication is also supported through
`SPECUS_ELASTICSEARCH_USERNAME` and `SPECUS_ELASTICSEARCH_PASSWORD`.
`--ca-file` selects a private CA; `--insecure` is an explicit last-resort
option. The script adds a write block, uses Elasticsearch's clone API, waits
for the destination, rewrites Spring Data `_class` values from the legacy Java
package to the Specus package, compares document counts, restores the source
write state, and keeps the source index for rollback.

Redis coordination contains only leased presence, revision and rate-limit
windows. It is intentionally not copied: stop every old instance, start every
new instance with `specus:v2:public-transfer`, and let old prefixed keys expire.
Do not perform a mixed rolling deployment because the protocol migration is
not backward compatible.

## Windows and local SQLite

Plan:

```powershell
.\deploy\migrations\specus-v1\migrate.ps1 `
  -ConfigPath .\server.env `
  -SqliteDatabase .\shuai-tunnel.db
```

Apply after stopping the server:

```powershell
.\deploy\migrations\specus-v1\migrate.ps1 `
  -ConfigPath .\server.env `
  -SqliteDatabase .\shuai-tunnel.db `
  -Apply
```

Every changed config and SQLite database receives a timestamped
`.pre-specus-*.bak` backup. Use `-RewriteDomain` only for the coordinated DNS
cutover. `-KeepConfigFilename` and `-KeepDatabaseFilename` retain filenames
when an external supervisor requires them. The SQLite migrator also recognizes
the transitional C# filename `shuai-specus.db`.

## Linux systemd installation

The script defaults to plan mode. It detects the implementation's legacy env
and SQLite files, migrates them, moves mutable runtime directories, installs
the supplied new artifact and systemd unit, and starts the new service only
with `--apply`. The old `/opt` directory is retained for rollback; the script
never tries to run an old binary with renamed configuration.

```bash
sudo bash ./deploy/migrations/specus-v1/migrate-linux.sh \
  --implementation java
```

Build the release, then apply it during the maintenance window:

```bash
sudo bash ./deploy/migrations/specus-v1/migrate-linux.sh \
  --implementation java \
  --artifact ./implementations/java/server/target/specus-server.jar \
  --apply
```

Use `--implementation go` or `--implementation csharp` for another server.
For Go, `--artifact` is the new executable. For .NET, it is the complete
`dotnet publish` output directory.
Additional files can be supplied with repeated `--config PATH` and
`--sqlite PATH` arguments.

## PostgreSQL

Take a backup first, then run the transactional migration:

```bash
pg_dump --format=custom --file=before-specus.dump "$DATABASE_URL"
psql "$DATABASE_URL" \
  --set=ON_ERROR_STOP=1 \
  --file=deploy/migrations/specus-v1/database/postgresql.sql
```

The script renames tables, constraints, indexes and sequences in the current
schema and updates the old default virtual-device value. Any old/new table
collision aborts and rolls back the transaction.

To rename the PostgreSQL database itself, connect to a different maintenance
database after the schema migration:

```bash
psql postgres \
  --set=source_database=shuai \
  --set=destination_database=specus \
  --file=deploy/migrations/specus-v1/database/rename_postgresql_database.sql
```

This terminates sessions connected to the source database immediately before
`ALTER DATABASE`; run it only inside the same maintenance window.

## MySQL

MySQL DDL auto-commits, so the backup is mandatory:

```bash
mysqldump --single-transaction --routines --events \
  --databases "$DATABASE_NAME" > before-specus.sql
mysql --database="$DATABASE_NAME" \
  < deploy/migrations/specus-v1/database/mysql.sql
```

The script preflights all table and index collisions before renaming tables and
indexes, then updates the old default virtual-device value. Re-running it after
a successful migration is safe.

MySQL has no safe `RENAME DATABASE` command. To move to the `specus` database
name while retaining the source for rollback, use the clone wrapper:

```bash
bash ./deploy/migrations/specus-v1/database/clone_mysql_database.sh \
  --source shuai

bash ./deploy/migrations/specus-v1/database/clone_mysql_database.sh \
  --source shuai \
  --destination specus \
  --apply
```

The wrapper uses standard MySQL credential sources, copies the complete schema
and data, applies `mysql.sql` to the destination, verifies legacy table names
are gone, and leaves the source database untouched.

## Verification

Run the migration unit tests:

```powershell
cd .\deploy\migrations\specus-v1
python -m unittest -v test_migrate_env.py test_migrate_elasticsearch.py test_migrate_s3_prefix.py database/test_migrate_sqlite.py database/test_database_scripts.py
```

For SQLite, verify there are no old schema objects:

```bash
sqlite3 specus.db \
  "select type,name from sqlite_master where lower(name) like '%tunnel%';"
```

After the external repository has also been renamed, update a clone from its
parent directory:

```powershell
Rename-Item .\shuai-tunnel specus
Set-Location .\specus
git remote set-url origin <new-repository-url>
```

Repository history, migration scripts and third-party Draw.io stencil names
can legitimately retain the word `tunnel`; active Specus source and deployment
configuration must not.
