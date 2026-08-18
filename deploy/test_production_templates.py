from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIMES = ("java-server", "go-server", "csharp-server")


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def env_values(runtime: str) -> dict[str, str]:
    content = read(f"deploy/{runtime}/systemd/specus-server.env.example")
    values: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


class ProductionTemplateTests(unittest.TestCase):
    def test_all_server_templates_are_safe_by_default(self) -> None:
        expected = {
            "SPECUS_ENV": "prod",
            "SPECUS_DB_SEED_DEMO_CLIENT": "false",
            "SPECUS_AUTH_PASSWORD_LOGIN_ENABLED": "false",
            "SPECUS_AUTH_PASSWORD": "",
            "SPECUS_AUTH_JWT_SECRET": "",
        }
        for runtime in RUNTIMES:
            with self.subTest(runtime=runtime):
                values = env_values(runtime)
                for key, value in expected.items():
                    self.assertIn(key, values)
                    self.assertEqual(value, values[key], key)

    def test_installers_preserve_live_env_and_do_not_start_services(self) -> None:
        for runtime in RUNTIMES:
            with self.subTest(runtime=runtime):
                script = read(f"deploy/{runtime}/systemd/install.sh")
                live_env_guard = (
                    r'if \[\[ ! -f "(?:\$ENV_FILE|\$CONFIG_DIR/specus-server\.env)" \]\]'
                )
                self.assertRegex(script, live_env_guard)
                self.assertIn("强口令", script)
                self.assertIn("JWT", script)
                self.assertIsNone(
                    re.search(r"^\s*systemctl\s+(?:start|restart)\b", script, re.MULTILINE),
                    "first-time installer must not start or restart the service",
                )
                self.assertIsNone(
                    re.search(r"^\s*systemctl\s+enable\s+--now\b", script, re.MULTILINE),
                    "first-time installer must not enable and start in one command",
                )


if __name__ == "__main__":
    unittest.main()
