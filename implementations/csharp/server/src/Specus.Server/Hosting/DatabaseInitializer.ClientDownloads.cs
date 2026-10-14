using Specus.Server.Data;

namespace Specus.Server.Hosting;

public sealed partial class DatabaseInitializer
{
    private static Task EnsurePostgresClientDownloadShapeAsync(SpecusDbContext db, CancellationToken cancellationToken)
    {
        // Earlier fallback DDL used lowercase id + SMALLINT enabled, unlike the EF
        // migration. Validate before any ALTER, then normalize both atomically in
        // one PostgreSQL statement. Renaming keeps the actual PK/indexes and values.
        // Resolve the very relation used by the unqualified SQL, not a same-named
        // table in another schema. Everything below is closed, fixed SQL.
        return ExecuteSchemaSqlAsync(db, """
            DO $specus_downloads$
            DECLARE
              has_lower BOOLEAN;
              has_quoted BOOLEAN;
              enabled_type OID;
              enabled_default TEXT;
            BEGIN
              SELECT COALESCE(bool_or(attname = 'id'), FALSE),
                     COALESCE(bool_or(attname = 'Id'), FALSE)
                INTO has_lower, has_quoted
                FROM pg_catalog.pg_attribute
                WHERE attrelid = pg_catalog.to_regclass('client_download_link')
                  AND attnum > 0 AND NOT attisdropped;
              IF has_lower AND has_quoted THEN
                RAISE EXCEPTION 'Ambiguous client download primary key columns; refusing automatic repair';
              END IF;
              IF NOT has_lower AND NOT has_quoted THEN
                RAISE EXCEPTION 'Missing client download primary key column; refusing automatic repair';
              END IF;
              SELECT a.atttypid, pg_catalog.pg_get_expr(d.adbin, d.adrelid)
                INTO enabled_type, enabled_default
                FROM pg_catalog.pg_attribute a
                LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                WHERE a.attrelid = pg_catalog.to_regclass('client_download_link')
                  AND a.attname = 'enabled' AND a.attnum > 0 AND NOT a.attisdropped;
              IF enabled_type = 'smallint'::regtype THEN
                IF EXISTS (SELECT 1 FROM client_download_link WHERE enabled IS NULL OR enabled NOT IN (0, 1)) THEN
                  RAISE EXCEPTION 'Invalid legacy client download enabled values; refusing lossy conversion';
                END IF;
                IF enabled_default IS NOT NULL AND enabled_default NOT IN ('0', '1') THEN
                  RAISE EXCEPTION 'Unsupported legacy client download enabled default; refusing lossy conversion';
                END IF;
              ELSIF enabled_type IS DISTINCT FROM 'boolean'::regtype THEN
                RAISE EXCEPTION 'Unsupported client download enabled type; refusing automatic repair';
              END IF;
              IF has_lower THEN
                ALTER TABLE client_download_link RENAME COLUMN id TO "Id";
              END IF;
              IF enabled_type = 'smallint'::regtype THEN
                ALTER TABLE client_download_link ALTER COLUMN enabled DROP DEFAULT;
                ALTER TABLE client_download_link ALTER COLUMN enabled TYPE BOOLEAN USING (enabled = 1);
                IF enabled_default = '1' THEN
                  ALTER TABLE client_download_link ALTER COLUMN enabled SET DEFAULT TRUE;
                ELSIF enabled_default = '0' THEN
                  ALTER TABLE client_download_link ALTER COLUMN enabled SET DEFAULT FALSE;
                END IF;
              END IF;
            END
            $specus_downloads$;
            """, cancellationToken);
    }
}
