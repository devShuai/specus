#!/usr/bin/env python3
"""An explicit reuse request must never start the full Makefile suite."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


class SmokeReuseTests(unittest.TestCase):
    def test_peer_namespace_receives_the_selected_artifact_and_reuse_flag(self):
        with tempfile.TemporaryDirectory(prefix="specus smoke namespace ") as directory:
            root = Path(directory)
            scripts = root / "implementations/c/server/scripts"
            scripts.mkdir(parents=True)
            for name in ("peer_mesh_e2e.sh", "smoke_server.sh"):
                (scripts / name).write_text((SCRIPTS / name).read_text())
            artifact = root / "CMake server artifact"
            artifact.write_text("#!/bin/sh\nexit 0\n")
            artifact.chmod(0o700)
            commands = root / "commands"
            commands.mkdir()
            marker = root / "namespace-arguments"
            unshare = commands / "unshare"
            unshare.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$SPECUS_TEST_NAMESPACE_ARGS"\nexit 0\n')
            unshare.chmod(0o700)
            result = subprocess.run(["bash", str(scripts / "peer_mesh_e2e.sh")], cwd=root,
                env={**os.environ, "PATH": str(commands) + os.pathsep + os.defpath,
                     "SPECUS_SMOKE_REUSE_BUILD": "1", "SPECUS_SMOKE_SERVER_BINARY": str(artifact),
                     "SPECUS_TEST_NAMESPACE_ARGS": str(marker), "SPECUS_PEER_MESH_E2E_ISOLATED": "0"},
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            arguments = marker.read_text().splitlines()
            self.assertIn("SPECUS_SMOKE_REUSE_BUILD=1", arguments)
            self.assertIn("SPECUS_SMOKE_SERVER_BINARY=" + str(artifact), arguments)

    def test_missing_reused_binary_fails_before_make_or_network_setup(self):
        for name in ("nat_e2e_smoke.sh", "runtime_config_e2e.sh", "direct_route_e2e.sh",
                     "tls_client_e2e.sh", "peer_mesh_e2e.sh"):
            with self.subTest(script=name), tempfile.TemporaryDirectory(prefix="specus-smoke-reuse-test-") as directory:
                root = Path(directory)
                scripts = root / "implementations/c/server/scripts"
                scripts.mkdir(parents=True)
                # Match a native Linux checkout when this test is launched from a
                # Windows worktree whose shell files use CRLF on disk.
                (scripts / name).write_text((SCRIPTS / name).read_text())
                helper = SCRIPTS / "smoke_server.sh"
                if helper.exists():
                    (scripts / helper.name).write_text(helper.read_text())
                commands = root / "commands"
                commands.mkdir()
                marker = root / "make-was-called"
                make = commands / "make"
                make.write_text('#!/bin/sh\nprintf called > "$SPECUS_TEST_MAKE_MARKER"\nexit 86\n')
                make.chmod(0o700)
                result = subprocess.run(["bash", str(scripts / name)], cwd=root,
                    env={**os.environ, "PATH": str(commands) + os.pathsep + os.defpath,
                         "SPECUS_SMOKE_REUSE_BUILD": "1", "SPECUS_SMOKE_SERVER_BINARY": "", "SPECUS_CLIENT_COMMAND": "/bin/true",
                         "SPECUS_E2E_LOG_DIR": "",
                         "SPECUS_TEST_MAKE_MARKER": str(marker), "SPECUS_PEER_MESH_E2E_ISOLATED": "0"},
                    capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(marker.exists(), f"{name} silently started make instead of reusing a binary")
                self.assertIn("server binary", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
