from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from migrate_env import migrate_file, migrate_text


class EnvironmentMigrationTests(unittest.TestCase):
    def test_rewrites_keys_paths_and_preserves_secrets(self) -> None:
        source = """
TUNNEL_DB_URL=jdbc:sqlite:/var/lib/tunnel-server/shuai-tunnel.db
SHUAI_PEER_SECRET=do-not-change-this
ConnectionStrings__Tunnel=Data Source=shuai-tunnel.db
SPECUS_AUTH_PASSWORD=still-secret
PUBLIC_URL=https://tunnel.devshuai.com
JAVA_OPTS=-Dshuai.peerMesh.wintunDll=/opt/wintun.dll
SYSTEMD_LINE=Environment=TUNNEL_LOG_FILE=/var/log/tunnel-server/server.log
REFERENCE=${TUNNEL_DB_URL}
PEER_MAGIC=shuai-peer-mesh
DEVICE=shuai0
SPECUS_OBJECT_STORAGE_PREFIX=shuai-tunnel/attachments
SPECUS_MEDIA_CAPTURE_PREFIX=shuai-tunnel/http-media
SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX=shuai-tunnel:v2:public-transfer
SPECUS_ELASTICSEARCH_HTTP_INDEX=shuai-tunnel-http-traffic
SPECUS_ELASTICSEARCH_TCP_INDEX=shuai-tunnel-tcp-traffic
STUN_SOFTWARE=shuai-tunnel-rfc5780-stun
CSHARP_DB=Data Source=shuai-specus.db
tunnel:
  netty:
    port: 7010
"""
        migrated, count = migrate_text(source, rewrite_domain=True)
        self.assertGreaterEqual(count, 20)
        self.assertIn("SPECUS_DB_URL=", migrated)
        self.assertIn("SPECUS_PEER_SECRET=do-not-change-this", migrated)
        self.assertIn("ConnectionStrings__Specus=Data Source=specus.db", migrated)
        self.assertIn("/var/lib/specus-server/specus.db", migrated)
        self.assertIn("https://specus.devshuai.com", migrated)
        self.assertIn("SPECUS_AUTH_PASSWORD=still-secret", migrated)
        self.assertIn("-Dspecus.peerMesh.wintunDll=", migrated)
        self.assertIn("Environment=SPECUS_LOG_FILE=", migrated)
        self.assertIn("REFERENCE=${SPECUS_DB_URL}", migrated)
        self.assertIn("PEER_MAGIC=specus-peer-mesh", migrated)
        self.assertIn("DEVICE=specus0", migrated)
        self.assertIn("SPECUS_OBJECT_STORAGE_PREFIX=specus/attachments", migrated)
        self.assertIn("SPECUS_MEDIA_CAPTURE_PREFIX=specus/http-media", migrated)
        self.assertIn(
            "SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX=specus:v2:public-transfer",
            migrated,
        )
        self.assertIn("SPECUS_ELASTICSEARCH_HTTP_INDEX=specus-http-traffic", migrated)
        self.assertIn("SPECUS_ELASTICSEARCH_TCP_INDEX=specus-tcp-traffic", migrated)
        self.assertIn("STUN_SOFTWARE=specus-rfc5780-stun", migrated)
        self.assertIn("CSHARP_DB=Data Source=specus.db", migrated)
        self.assertIn("\nspecus:\n", migrated)

    def test_rejects_duplicate_destination_key(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "both TUNNEL_DB_URL"):
            migrate_text(
                "TUNNEL_DB_URL=old\nSPECUS_DB_URL=new\n",
                rewrite_domain=False,
            )

    def test_plan_does_not_write_and_apply_creates_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tunnel-server.env"
            path.write_text("TUNNEL_NETTY_PORT=7010\n", encoding="utf-8")
            plan = migrate_file(
                path,
                apply=False,
                rewrite_domain=False,
                rename_file=True,
            )
            self.assertEqual("tunnel-server.env", path.name)
            self.assertEqual("TUNNEL_NETTY_PORT=7010\n", plan.path.read_text())
            self.assertEqual("specus-server.env", plan.destination.name)

            result = migrate_file(
                path,
                apply=True,
                rewrite_domain=False,
                rename_file=True,
            )
            self.assertEqual("specus-server.env", result.destination.name)
            self.assertTrue(result.destination.is_file())
            self.assertIsNotNone(result.backup)
            self.assertEqual(
                "SPECUS_NETTY_PORT=7010\n",
                result.destination.read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
