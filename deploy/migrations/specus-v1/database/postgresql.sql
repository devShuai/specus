\set ON_ERROR_STOP on

BEGIN;

DO $specus_migration$
DECLARE
    item RECORD;
    object_item RECORD;
    old_relation REGCLASS;
    new_relation REGCLASS;
    new_name TEXT;
BEGIN
    FOR item IN
        SELECT *
          FROM (VALUES
            ('tunnel_client_account', 'specus_client_account'),
            ('tunnel_client_auth_nonce', 'specus_client_auth_nonce'),
            ('tunnel_client_credential', 'specus_client_credential'),
            ('tunnel_websocket_ticket', 'specus_websocket_ticket'),
            ('tunnel_client_identity', 'specus_client_identity'),
            ('tunnel_client_session', 'specus_client_session'),
            ('tunnel_management_user', 'specus_management_user'),
            ('tunnel_management_user_email', 'specus_management_user_email'),
            ('tunnel_management_registration_challenge',
             'specus_management_registration_challenge'),
            ('tunnel_connection_record', 'specus_connection_record'),
            ('tunnel_connection_stat', 'specus_connection_stat'),
            ('tunnel_mapping', 'specus_mapping'),
            ('tunnel_traffic_usage', 'specus_traffic_usage'),
            ('tunnel_resource_traffic_usage', 'specus_resource_traffic_usage'),
            ('tunnel_http_traffic_exchange', 'specus_http_traffic_exchange'),
            ('tunnel_tcp_traffic_frame', 'specus_tcp_traffic_frame'),
            ('tunnel_http_media_capture', 'specus_http_media_capture'),
            ('tunnel_http_media_reference', 'specus_http_media_reference'),
            ('tunnel_session', 'specus_session')
          ) AS table_map(old_name, new_name)
    LOOP
        old_relation := to_regclass(
            format('%I.%I', current_schema(), item.old_name)
        );
        new_relation := to_regclass(
            format('%I.%I', current_schema(), item.new_name)
        );
        IF old_relation IS NOT NULL AND new_relation IS NOT NULL THEN
            RAISE EXCEPTION
                'Cannot migrate %: destination % already exists',
                item.old_name,
                item.new_name;
        ELSIF old_relation IS NOT NULL THEN
            EXECUTE format(
                'ALTER TABLE %I.%I RENAME TO %I',
                current_schema(),
                item.old_name,
                item.new_name
            );
        END IF;
    END LOOP;

    FOR object_item IN
        SELECT constraint_row.conname,
               constraint_row.conrelid,
               constraint_row.conrelid::REGCLASS AS table_relation
          FROM pg_constraint constraint_row
          JOIN pg_class table_row
            ON table_row.oid = constraint_row.conrelid
          JOIN pg_namespace namespace_row
            ON namespace_row.oid = table_row.relnamespace
         WHERE namespace_row.nspname = current_schema()
           AND POSITION('tunnel' IN LOWER(constraint_row.conname)) > 0
    LOOP
        new_name := replace(
            replace(
                replace(object_item.conname, 'TUNNEL', 'SPECUS'),
                'Tunnel',
                'Specus'
            ),
            'tunnel',
            'specus'
        );
        IF EXISTS (
            SELECT 1
              FROM pg_constraint
             WHERE conrelid = object_item.conrelid
               AND conname = new_name
        ) THEN
            RAISE EXCEPTION
                'Cannot rename constraint %: destination % already exists',
                object_item.conname,
                new_name;
        END IF;
        EXECUTE format(
            'ALTER TABLE %s RENAME CONSTRAINT %I TO %I',
            object_item.table_relation,
            object_item.conname,
            new_name
        );
    END LOOP;

    FOR object_item IN
        SELECT relation_row.relkind, relation_row.relname
          FROM pg_class relation_row
          JOIN pg_namespace namespace_row
            ON namespace_row.oid = relation_row.relnamespace
         WHERE namespace_row.nspname = current_schema()
           AND relation_row.relkind IN ('i', 'S')
           AND POSITION('tunnel' IN LOWER(relation_row.relname)) > 0
         ORDER BY relation_row.relkind, relation_row.relname
    LOOP
        new_name := replace(
            replace(
                replace(object_item.relname, 'TUNNEL', 'SPECUS'),
                'Tunnel',
                'Specus'
            ),
            'tunnel',
            'specus'
        );
        new_relation := to_regclass(
            format('%I.%I', current_schema(), new_name)
        );
        IF new_relation IS NOT NULL THEN
            RAISE EXCEPTION
                'Cannot rename relation %: destination % already exists',
                object_item.relname,
                new_name;
        END IF;
        IF object_item.relkind = 'i' THEN
            EXECUTE format(
                'ALTER INDEX %I.%I RENAME TO %I',
                current_schema(),
                object_item.relname,
                new_name
            );
        ELSE
            EXECUTE format(
                'ALTER SEQUENCE %I.%I RENAME TO %I',
                current_schema(),
                object_item.relname,
                new_name
            );
        END IF;
    END LOOP;

    IF to_regclass(
        format('%I.%I', current_schema(), 'peer_mesh_device')
    ) IS NOT NULL THEN
        UPDATE peer_mesh_device
           SET virtual_device_name = 'specus0'
         WHERE virtual_device_name = 'shuai0';
    END IF;

    IF to_regclass(
        format('%I.%I', current_schema(), 'transfer_attachment')
    ) IS NOT NULL THEN
        UPDATE transfer_attachment
           SET object_key =
               'specus/attachments'
               || substring(
                   object_key
                   FROM char_length('shuai-tunnel/attachments') + 1
               )
         WHERE object_key = 'shuai-tunnel/attachments'
            OR object_key LIKE 'shuai-tunnel/attachments/%';
    END IF;

    IF to_regclass(
        format('%I.%I', current_schema(), 'specus_http_media_capture')
    ) IS NOT NULL THEN
        UPDATE specus_http_media_capture
           SET object_key =
               'specus/http-media'
               || substring(
                   object_key
                   FROM char_length('shuai-tunnel/http-media') + 1
               )
         WHERE object_key = 'shuai-tunnel/http-media'
            OR object_key LIKE 'shuai-tunnel/http-media/%';
    END IF;
END
$specus_migration$;

COMMIT;
