from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class DatabaseScriptParityTests(unittest.TestCase):
    def test_relational_scripts_cover_the_canonical_table_map(self) -> None:
        table_map = json.loads(
            (ROOT / "table-map.json").read_text(encoding="utf-8")
        )["tables"]
        postgresql = (ROOT / "postgresql.sql").read_text(encoding="utf-8")
        mysql = (ROOT / "mysql.sql").read_text(encoding="utf-8")
        for item in table_map:
            pair = re.compile(
                rf"\(\s*'{re.escape(item['from'])}'\s*,\s*"
                rf"'{re.escape(item['to'])}'\s*\)"
            )
            self.assertRegex(postgresql, pair)
            self.assertRegex(mysql, pair)

    def test_all_database_migrations_rewrite_the_default_virtual_device(self) -> None:
        for name in ("migrate_sqlite.py", "postgresql.sql", "mysql.sql"):
            script = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("shuai0", script)
            self.assertIn("specus0", script)

    def test_all_database_migrations_rewrite_object_key_prefixes(self) -> None:
        for name in ("migrate_sqlite.py", "postgresql.sql", "mysql.sql"):
            script = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("shuai-tunnel/attachments", script)
            self.assertIn("specus/attachments", script)
            self.assertIn("shuai-tunnel/http-media", script)
            self.assertIn("specus/http-media", script)


if __name__ == "__main__":
    unittest.main()
