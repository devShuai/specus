-- MySQL DDL auto-commits. Take a physical or logical backup before running this file.
-- Run with: mysql --database=YOUR_DATABASE < mysql.sql

DROP TEMPORARY TABLE IF EXISTS specus_migration_table_map;
CREATE TEMPORARY TABLE specus_migration_table_map (
    old_name VARCHAR(64) NOT NULL PRIMARY KEY,
    new_name VARCHAR(64) NOT NULL UNIQUE
);

INSERT INTO specus_migration_table_map (old_name, new_name) VALUES
    ('tunnel_client_account', 'specus_client_account'),
    ('tunnel_client_auth_nonce', 'specus_client_auth_nonce'),
    ('tunnel_client_credential', 'specus_client_credential'),
    ('tunnel_websocket_ticket', 'specus_websocket_ticket'),
    ('tunnel_client_identity', 'specus_client_identity'),
    ('tunnel_client_session', 'specus_client_session'),
    ('tunnel_management_user', 'specus_management_user'),
    ('tunnel_management_user_email', 'specus_management_user_email'),
    (
        'tunnel_management_registration_challenge',
        'specus_management_registration_challenge'
    ),
    ('tunnel_connection_record', 'specus_connection_record'),
    ('tunnel_connection_stat', 'specus_connection_stat'),
    ('tunnel_mapping', 'specus_mapping'),
    ('tunnel_traffic_usage', 'specus_traffic_usage'),
    ('tunnel_resource_traffic_usage', 'specus_resource_traffic_usage'),
    ('tunnel_http_traffic_exchange', 'specus_http_traffic_exchange'),
    ('tunnel_tcp_traffic_frame', 'specus_tcp_traffic_frame'),
    ('tunnel_http_media_capture', 'specus_http_media_capture'),
    ('tunnel_http_media_reference', 'specus_http_media_reference'),
    ('tunnel_session', 'specus_session');

DELIMITER $$

DROP PROCEDURE IF EXISTS specus_preflight$$
CREATE PROCEDURE specus_preflight()
BEGIN
    DECLARE finished INTEGER DEFAULT 0;
    DECLARE old_table VARCHAR(64);
    DECLARE new_table VARCHAR(64);
    DECLARE old_count INTEGER DEFAULT 0;
    DECLARE new_count INTEGER DEFAULT 0;
    DECLARE object_key_collision_count BIGINT DEFAULT 0;
    DECLARE failure_message VARCHAR(255);
    DECLARE table_cursor CURSOR FOR
        SELECT old_name, new_name
          FROM specus_migration_table_map
         ORDER BY old_name;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET finished = 1;

    OPEN table_cursor;
    table_loop: LOOP
        FETCH table_cursor INTO old_table, new_table;
        IF finished = 1 THEN
            LEAVE table_loop;
        END IF;
        SELECT COUNT(*) INTO old_count
          FROM information_schema.tables
         WHERE table_schema = DATABASE()
           AND table_name = old_table
           AND table_type = 'BASE TABLE';
        SELECT COUNT(*) INTO new_count
          FROM information_schema.tables
         WHERE table_schema = DATABASE()
           AND table_name = new_table
           AND table_type = 'BASE TABLE';
        IF old_count > 0 AND new_count > 0 THEN
            SET failure_message = CONCAT(
                'Cannot migrate ',
                old_table,
                ': destination ',
                new_table,
                ' already exists'
            );
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = failure_message;
        END IF;
    END LOOP;
    CLOSE table_cursor;

    IF EXISTS (
        SELECT 1
          FROM (
            SELECT source_index.table_name,
                   source_index.index_name,
                   REPLACE(
                       REPLACE(
                           REPLACE(source_index.index_name, 'TUNNEL', 'SPECUS'),
                           'Tunnel',
                           'Specus'
                       ),
                       'tunnel',
                       'specus'
                   ) AS target_index_name
              FROM information_schema.statistics source_index
             WHERE source_index.table_schema = DATABASE()
               AND source_index.index_name <> 'PRIMARY'
               AND LOWER(source_index.index_name) LIKE '%tunnel%'
             GROUP BY source_index.table_name, source_index.index_name
          ) candidates
          JOIN information_schema.statistics target_index
            ON target_index.table_schema = DATABASE()
           AND target_index.table_name = candidates.table_name
           AND target_index.index_name = candidates.target_index_name
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Cannot migrate: a destination index already exists';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = DATABASE()
           AND table_name = 'transfer_attachment'
           AND column_name = 'object_key'
    ) THEN
        SET @specus_object_key_collision_count = 0;
        SET @specus_object_key_collision_sql = CONCAT(
            'SELECT COUNT(*) INTO @specus_object_key_collision_count ',
            'FROM transfer_attachment source_attachment ',
            'JOIN transfer_attachment target_attachment ',
            'ON target_attachment.object_key = CONCAT(',
            '''specus/attachments'', SUBSTRING(',
            'source_attachment.object_key, ',
            'CHAR_LENGTH(''shuai-tunnel/attachments'') + 1)) ',
            'AND target_attachment.id <> source_attachment.id ',
            'WHERE source_attachment.object_key = ',
            '''shuai-tunnel/attachments'' ',
            'OR source_attachment.object_key LIKE ',
            '''shuai-tunnel/attachments/%'''
        );
        PREPARE object_key_collision_statement
           FROM @specus_object_key_collision_sql;
        EXECUTE object_key_collision_statement;
        DEALLOCATE PREPARE object_key_collision_statement;
        SET object_key_collision_count =
            @specus_object_key_collision_count;
        IF object_key_collision_count > 0 THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT =
                    'Cannot migrate: attachment object-key destination exists';
        END IF;
    END IF;
END$$

DROP PROCEDURE IF EXISTS specus_rename_tables$$
CREATE PROCEDURE specus_rename_tables()
BEGIN
    DECLARE finished INTEGER DEFAULT 0;
    DECLARE old_table VARCHAR(64);
    DECLARE new_table VARCHAR(64);
    DECLARE old_count INTEGER DEFAULT 0;
    DECLARE table_cursor CURSOR FOR
        SELECT old_name, new_name
          FROM specus_migration_table_map
         ORDER BY old_name;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET finished = 1;

    OPEN table_cursor;
    table_loop: LOOP
        FETCH table_cursor INTO old_table, new_table;
        IF finished = 1 THEN
            LEAVE table_loop;
        END IF;
        SELECT COUNT(*) INTO old_count
          FROM information_schema.tables
         WHERE table_schema = DATABASE()
           AND table_name = old_table
           AND table_type = 'BASE TABLE';
        IF old_count > 0 THEN
            SET @rename_table_sql = CONCAT(
                'RENAME TABLE `',
                REPLACE(old_table, '`', '``'),
                '` TO `',
                REPLACE(new_table, '`', '``'),
                '`'
            );
            PREPARE rename_table_statement FROM @rename_table_sql;
            EXECUTE rename_table_statement;
            DEALLOCATE PREPARE rename_table_statement;
        END IF;
    END LOOP;
    CLOSE table_cursor;
END$$

DROP PROCEDURE IF EXISTS specus_rename_indexes$$
CREATE PROCEDURE specus_rename_indexes()
BEGIN
    DECLARE finished INTEGER DEFAULT 0;
    DECLARE current_table VARCHAR(64);
    DECLARE old_index VARCHAR(64);
    DECLARE new_index VARCHAR(64);
    DECLARE index_cursor CURSOR FOR
        SELECT table_name,
               index_name,
               REPLACE(
                   REPLACE(
                       REPLACE(index_name, 'TUNNEL', 'SPECUS'),
                       'Tunnel',
                       'Specus'
                   ),
                   'tunnel',
                   'specus'
               )
          FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND index_name <> 'PRIMARY'
           AND LOWER(index_name) LIKE '%tunnel%'
         GROUP BY table_name, index_name
         ORDER BY table_name, index_name;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET finished = 1;

    OPEN index_cursor;
    index_loop: LOOP
        FETCH index_cursor INTO current_table, old_index, new_index;
        IF finished = 1 THEN
            LEAVE index_loop;
        END IF;
        SET @rename_index_sql = CONCAT(
            'ALTER TABLE `',
            REPLACE(current_table, '`', '``'),
            '` RENAME INDEX `',
            REPLACE(old_index, '`', '``'),
            '` TO `',
            REPLACE(new_index, '`', '``'),
            '`'
        );
        PREPARE rename_index_statement FROM @rename_index_sql;
        EXECUTE rename_index_statement;
        DEALLOCATE PREPARE rename_index_statement;
    END LOOP;
    CLOSE index_cursor;
END$$

DROP PROCEDURE IF EXISTS specus_rewrite_data$$
CREATE PROCEDURE specus_rewrite_data()
BEGIN
    IF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = DATABASE()
           AND table_name = 'peer_mesh_device'
           AND column_name = 'virtual_device_name'
    ) THEN
        UPDATE peer_mesh_device
           SET virtual_device_name = 'specus0'
         WHERE virtual_device_name = 'shuai0';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = DATABASE()
           AND table_name = 'transfer_attachment'
           AND column_name = 'object_key'
    ) THEN
        UPDATE transfer_attachment
           SET object_key = CONCAT(
               'specus/attachments',
               SUBSTRING(
                   object_key,
                   CHAR_LENGTH('shuai-tunnel/attachments') + 1
               )
           )
         WHERE object_key = 'shuai-tunnel/attachments'
            OR object_key LIKE 'shuai-tunnel/attachments/%';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = DATABASE()
           AND table_name = 'specus_http_media_capture'
           AND column_name = 'object_key'
    ) THEN
        UPDATE specus_http_media_capture
           SET object_key = CONCAT(
               'specus/http-media',
               SUBSTRING(
                   object_key,
                   CHAR_LENGTH('shuai-tunnel/http-media') + 1
               )
           )
         WHERE object_key = 'shuai-tunnel/http-media'
            OR object_key LIKE 'shuai-tunnel/http-media/%';
    END IF;
END$$

DELIMITER ;

CALL specus_preflight();
CALL specus_rename_tables();
CALL specus_rename_indexes();
CALL specus_rewrite_data();

DROP PROCEDURE specus_preflight;
DROP PROCEDURE specus_rename_tables;
DROP PROCEDURE specus_rename_indexes;
DROP PROCEDURE specus_rewrite_data;
DROP TEMPORARY TABLE specus_migration_table_map;
