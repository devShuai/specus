using Specus.Server.Data;

namespace Specus.Server.Hosting;

public sealed partial class DatabaseInitializer
{
    private static Task EnsurePostgresPeerBooleanShapeAsync(SpecusDbContext db, CancellationToken ct) =>
        ExecuteSchemaSqlAsync(db, """
            DO $specus_peer_flags$
            DECLARE
              flag RECORD;
              relation REGCLASS;
              flag_type OID;
              flag_default TEXT;
              flag_not_null BOOLEAN;
              invalid_value BOOLEAN;
            BEGIN
              -- Closed application-owned columns only. Healthy BOOLEAN NOT NULL columns need
              -- no DDL/strong table lock. Lock repair candidates in a stable order and validate
              -- ALL columns before any ALTER, so rejected conversion is not partial.
              FOR flag IN SELECT * FROM (VALUES
                ('peer_mesh_acl', 'allowed'),
                ('peer_mesh_device', 'enabled'),
                ('peer_mesh_service_sharing', 'enabled'),
                ('peer_mesh_service_sharing', 'mdns_import_enabled'),
                ('peer_mesh_shared_service', 'enabled')
              ) AS flags(table_name, column_name) ORDER BY table_name, column_name LOOP
                relation := pg_catalog.to_regclass(flag.table_name);
                IF relation IS NULL THEN RAISE EXCEPTION 'Missing Peer boolean relation; refusing automatic repair'; END IF;
                SELECT a.atttypid, a.attnotnull INTO flag_type, flag_not_null
                  FROM pg_catalog.pg_attribute a WHERE a.attrelid=relation
                    AND a.attname=flag.column_name AND a.attnum>0 AND NOT a.attisdropped;
                IF flag_type = 'smallint'::regtype OR (flag_type = 'boolean'::regtype AND NOT flag_not_null) THEN
                  EXECUTE format('LOCK TABLE %s IN ACCESS EXCLUSIVE MODE', relation);
                END IF;
              END LOOP;
              FOR flag IN SELECT * FROM (VALUES
                ('peer_mesh_acl', 'allowed'),
                ('peer_mesh_device', 'enabled'),
                ('peer_mesh_service_sharing', 'enabled'),
                ('peer_mesh_service_sharing', 'mdns_import_enabled'),
                ('peer_mesh_shared_service', 'enabled')
              ) AS flags(table_name, column_name) ORDER BY table_name, column_name LOOP
                relation := pg_catalog.to_regclass(flag.table_name);
                SELECT a.atttypid, pg_catalog.pg_get_expr(d.adbin, d.adrelid), a.attnotnull
                  INTO flag_type, flag_default, flag_not_null
                  FROM pg_catalog.pg_attribute a
                  LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                  WHERE a.attrelid = relation AND a.attname = flag.column_name AND a.attnum > 0 AND NOT a.attisdropped;
                IF flag_type = 'smallint'::regtype THEN
                  EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s WHERE %I IS NULL OR %I NOT IN (0, 1))', relation, flag.column_name, flag.column_name) INTO invalid_value;
                  IF invalid_value THEN RAISE EXCEPTION 'Invalid legacy Peer boolean values; refusing lossy conversion'; END IF;
                  IF flag_default IS NOT NULL AND flag_default NOT IN ('0', '1') THEN
                    RAISE EXCEPTION 'Unsupported legacy Peer boolean default; refusing lossy conversion';
                  END IF;
                ELSIF flag_type = 'boolean'::regtype THEN
                  IF NOT flag_not_null THEN
                    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s WHERE %I IS NULL)', relation, flag.column_name) INTO invalid_value;
                    IF invalid_value THEN RAISE EXCEPTION 'NULL Peer boolean values; refusing lossy conversion'; END IF;
                  END IF;
                ELSE
                  RAISE EXCEPTION 'Unsupported or missing Peer boolean type; refusing automatic repair';
                END IF;
              END LOOP;
              FOR flag IN SELECT * FROM (VALUES
                ('peer_mesh_acl', 'allowed'),
                ('peer_mesh_device', 'enabled'),
                ('peer_mesh_service_sharing', 'enabled'),
                ('peer_mesh_service_sharing', 'mdns_import_enabled'),
                ('peer_mesh_shared_service', 'enabled')
              ) AS flags(table_name, column_name) ORDER BY table_name, column_name LOOP
                relation := pg_catalog.to_regclass(flag.table_name);
                SELECT a.atttypid, pg_catalog.pg_get_expr(d.adbin, d.adrelid), a.attnotnull
                  INTO flag_type, flag_default, flag_not_null
                  FROM pg_catalog.pg_attribute a
                  LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                  WHERE a.attrelid = relation AND a.attname = flag.column_name AND a.attnum > 0 AND NOT a.attisdropped;
                IF flag_type = 'smallint'::regtype THEN
                  EXECUTE format('ALTER TABLE %s ALTER COLUMN %I DROP DEFAULT', relation, flag.column_name);
                  EXECUTE format('ALTER TABLE %s ALTER COLUMN %I TYPE BOOLEAN USING (%I = 1)', relation, flag.column_name, flag.column_name);
                  IF flag_default = '0' THEN
                    EXECUTE format('ALTER TABLE %s ALTER COLUMN %I SET DEFAULT FALSE', relation, flag.column_name);
                  ELSIF flag_default = '1' THEN
                    EXECUTE format('ALTER TABLE %s ALTER COLUMN %I SET DEFAULT TRUE', relation, flag.column_name);
                  END IF;
                END IF;
                IF NOT flag_not_null THEN
                  EXECUTE format('ALTER TABLE %s ALTER COLUMN %I SET NOT NULL', relation, flag.column_name);
                END IF;
              END LOOP;
            END
            $specus_peer_flags$;
            """, ct);
}
