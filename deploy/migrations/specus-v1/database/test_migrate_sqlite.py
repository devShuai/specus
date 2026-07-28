from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from migrate_sqlite import migrate_database, renamed_database_path


class SqliteMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "legacy.db"
        self.table_map = Path(__file__).with_name("table-map.json")
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE tunnel_client_account (
                    id INTEGER PRIMARY KEY,
                    client_name TEXT NOT NULL UNIQUE
                );
                CREATE TABLE tunnel_mapping (
                    id INTEGER PRIMARY KEY,
                    client_id INTEGER NOT NULL,
                    FOREIGN KEY (client_id) REFERENCES tunnel_client_account(id)
                );
                CREATE INDEX idx_tunnel_mapping_client
                    ON tunnel_mapping(client_id);
                CREATE TABLE peer_mesh_device (
                    id INTEGER PRIMARY KEY,
                    virtual_device_name TEXT
                );
                CREATE TABLE transfer_attachment (
                    id INTEGER PRIMARY KEY,
                    object_key TEXT NOT NULL UNIQUE
                );
                CREATE TABLE tunnel_http_media_capture (
                    id INTEGER PRIMARY KEY,
                    object_key TEXT NOT NULL
                );
                CREATE TABLE unrelated_table (id INTEGER PRIMARY KEY);
                INSERT INTO tunnel_client_account(id, client_name)
                    VALUES (1, 'alpha');
                INSERT INTO tunnel_mapping(id, client_id) VALUES (7, 1);
                INSERT INTO peer_mesh_device(id, virtual_device_name)
                    VALUES (9, 'shuai0');
                INSERT INTO transfer_attachment(id, object_key)
                    VALUES (10, 'shuai-tunnel/attachments/public-transfer/a.png');
                INSERT INTO tunnel_http_media_capture(id, object_key)
                    VALUES (11, 'shuai-tunnel/http-media/tenant/video/part-1');
                """
            )
            connection.commit()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_migrates_tables_indexes_and_data_idempotently(self) -> None:
        actions, _ = migrate_database(
            self.database,
            self.table_map,
            apply=True,
            create_backup=False,
        )
        self.assertIn(
            "table tunnel_client_account -> specus_client_account",
            actions,
        )
        self.assertIn(
            "index idx_tunnel_mapping_client -> idx_specus_mapping_client",
            actions,
        )
        self.assertIn(
            "data peer_mesh_device.virtual_device_name: shuai0 -> specus0 (1 rows)",
            actions,
        )
        self.assertIn(
            "data transfer_attachment.object_key: prefix "
            "shuai-tunnel/attachments -> specus/attachments (1 rows)",
            actions,
        )
        self.assertIn(
            "data tunnel_http_media_capture.object_key: prefix "
            "shuai-tunnel/http-media -> specus/http-media (1 rows)",
            actions,
        )

        with closing(sqlite3.connect(self.database)) as connection:
            names = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')"
                )
            }
            self.assertIn("specus_client_account", names)
            self.assertIn("specus_mapping", names)
            self.assertIn("specus_http_media_capture", names)
            self.assertIn("idx_specus_mapping_client", names)
            self.assertIn("unrelated_table", names)
            self.assertNotIn("tunnel_client_account", names)
            self.assertEqual(
                [(7, "alpha")],
                connection.execute(
                    """
                    SELECT m.id, c.client_name
                      FROM specus_mapping m
                      JOIN specus_client_account c ON c.id = m.client_id
                    """
                ).fetchall(),
            )
            self.assertEqual(
                [("specus0",)],
                connection.execute(
                    "SELECT virtual_device_name FROM peer_mesh_device WHERE id = 9"
                ).fetchall(),
            )
            self.assertEqual(
                [("specus/attachments/public-transfer/a.png",)],
                connection.execute(
                    "SELECT object_key FROM transfer_attachment WHERE id = 10"
                ).fetchall(),
            )
            self.assertEqual(
                [("specus/http-media/tenant/video/part-1",)],
                connection.execute(
                    "SELECT object_key FROM specus_http_media_capture WHERE id = 11"
                ).fetchall(),
            )
            self.assertEqual([], connection.execute("PRAGMA foreign_key_check").fetchall())

        second_actions, _ = migrate_database(
            self.database,
            self.table_map,
            apply=True,
            create_backup=False,
        )
        self.assertEqual([], second_actions)

    def test_rejects_old_and_new_table_collision(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "CREATE TABLE specus_client_account (id INTEGER PRIMARY KEY)"
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            migrate_database(
                self.database,
                self.table_map,
                apply=True,
                create_backup=False,
            )

    def test_renames_legacy_and_transitional_database_filenames(self) -> None:
        self.assertEqual(
            "specus.db",
            renamed_database_path(Path("shuai-tunnel.db")).name,
        )
        self.assertEqual(
            "specus.db",
            renamed_database_path(Path("shuai-specus.db")).name,
        )


if __name__ == "__main__":
    unittest.main()
