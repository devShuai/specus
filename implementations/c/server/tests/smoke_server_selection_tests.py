#!/usr/bin/env python3
"""Pure process/fixture tests; no real builds, network changes or servers."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HELPER = Path(__file__).resolve().parents[1] / "scripts/smoke_server.sh"


class SmokeServerSelectionTests(unittest.TestCase):
    def run_selection(self, *, reuse="", explicit=None, present=False, executable=True,
                      make_exit=0, build_binary=True):
        with tempfile.TemporaryDirectory(prefix="specus smoke selection ") as directory:
            root = Path(directory)
            c_dir = root / "server sources"
            c_dir.mkdir()
            helper = root / "smoke_server.sh"
            helper.write_text(HELPER.read_text())
            default = c_dir / "build/specus-server-c"
            selected = root / "selected server" if explicit else default
            if present:
                selected.parent.mkdir(parents=True, exist_ok=True)
                selected.write_text("#!/bin/sh\nexit 0\n")
                selected.chmod(0o700 if executable else 0o600)
            commands = root / "commands"
            commands.mkdir()
            marker = root / "make-invocations"
            make = commands / "make"
            make.write_text('''#!/bin/sh
printf '%s\n' "$*" >> "$SPECUS_TEST_MAKE_MARKER"
if [ "$SPECUS_TEST_MAKE_EXIT" != 0 ]; then exit "$SPECUS_TEST_MAKE_EXIT"; fi
if [ "$SPECUS_TEST_BUILD_BINARY" = 1 ]; then
  mkdir -p "$SPECUS_TEST_C_DIR/build"
  printf '#!/bin/sh\nexit 0\n' > "$SPECUS_TEST_C_DIR/build/specus-server-c"
  chmod 700 "$SPECUS_TEST_C_DIR/build/specus-server-c"
fi
''')
            make.chmod(0o700)
            result = subprocess.run(["bash", "-euc", 'source "$1"; specus_smoke_prepare_server "$2"; printf "%s\\n" "$SPECUS_SMOKE_RESOLVED_SERVER"',
                "fixture", str(helper), str(c_dir)], capture_output=True, text=True, timeout=10,
                env={**os.environ, "PATH": str(commands) + os.pathsep + os.defpath,
                     "SPECUS_SMOKE_REUSE_BUILD": reuse, "SPECUS_SMOKE_SERVER_BINARY": str(selected) if explicit else "",
                     "SPECUS_TEST_C_DIR": str(c_dir), "SPECUS_TEST_MAKE_MARKER": str(marker),
                     "SPECUS_TEST_MAKE_EXIT": str(make_exit), "SPECUS_TEST_BUILD_BINARY": "1" if build_binary else "0"})
            calls = marker.read_text().splitlines() if marker.exists() else []
            return result, calls, str(selected)

    def test_default_runs_the_independent_make_suite_once(self):
        result, calls, selected = self.run_selection()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].endswith(" test"))
        self.assertEqual(result.stdout.strip(), selected)

    def test_reuse_present_binary_does_not_build(self):
        result, calls, selected = self.run_selection(reuse="1", present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])
        self.assertEqual(result.stdout.strip(), selected)

    def test_explicit_artifact_with_spaces_is_used_without_make(self):
        result, calls, selected = self.run_selection(explicit=True, present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])
        self.assertEqual(result.stdout.strip(), selected)

    def test_reuse_missing_binary_fails_without_make(self):
        result, calls, _ = self.run_selection(reuse="1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, [])
        self.assertIn("server binary", result.stderr)

    def test_explicit_missing_binary_never_falls_back(self):
        result, calls, _ = self.run_selection(explicit=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, [])

    def test_nonexecutable_artifact_is_rejected(self):
        result, calls, _ = self.run_selection(explicit=True, present=True, executable=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, [])

    def test_make_failure_is_preserved(self):
        result, calls, _ = self.run_selection(make_exit=17)
        self.assertEqual(result.returncode, 17)
        self.assertEqual(len(calls), 1)

    def test_successful_make_without_a_binary_is_not_success(self):
        result, calls, _ = self.run_selection(build_binary=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(calls), 1)
        self.assertIn("server binary", result.stderr)


if __name__ == "__main__":
    unittest.main()
