#!/usr/bin/env python3
"""Tests for the SCA severity gate.

The gate decides whether a build fails, so its behaviour on partial and malformed feed data
matters as much as on the happy path: a parser that silently returns "no advisories" for a report
it could not understand turns the whole gate into decoration.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).with_name("fail_on_severity.py")


def run(report) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "report.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(GATE), str(path), "--label", "test"],
            capture_output=True, text=True, check=False)


def report_with(*vulnerabilities) -> dict:
    return {
        "results": [{
            "source": {"path": "pom.xml"},
            "packages": [{
                "package": {"name": "example", "version": "1.0.0"},
                "vulnerabilities": list(vulnerabilities),
            }],
        }]
    }


def check(name: str, condition: bool, detail: str = "") -> bool:
    print(f"{'PASS' if condition else 'FAIL'}  {name}{'  ' + detail if detail else ''}")
    return condition


def main() -> int:
    passed = True

    result = run({"results": []})
    passed &= check("a clean scan passes", result.returncode == 0
                    and "no advisories" in result.stdout)

    # A numeric CVSS score is the most precise signal, and 9.8 must block.
    result = run(report_with({"id": "OSV-1", "severity": [{"type": "CVSS_V3", "score": "9.8"}]}))
    passed &= check("a critical score blocks", result.returncode == 1
                    and "CRITICAL" in result.stdout, result.stdout.strip()[:60])

    result = run(report_with({"id": "OSV-2", "severity": [{"type": "CVSS_V3", "score": "7.5"}]}))
    passed &= check("a high score blocks", result.returncode == 1 and "HIGH" in result.stdout)

    # Medium and low are reported but must not block, or the gate gets bypassed on principle.
    result = run(report_with({"id": "OSV-3", "severity": [{"type": "CVSS_V3", "score": "5.0"}]}))
    passed &= check("a medium score is reported without failing",
                    result.returncode == 0 and "OSV-3" in result.stdout)

    result = run(report_with({"id": "OSV-4", "severity": [{"type": "CVSS_V3", "score": "2.0"}]}))
    passed &= check("a low score does not block", result.returncode == 0)

    # GitHub advisories carry a label rather than a score.
    result = run(report_with({"id": "GHSA-1", "database_specific": {"severity": "HIGH"}}))
    passed &= check("a GHSA high label blocks", result.returncode == 1)

    result = run(report_with({"id": "GHSA-2", "database_specific": {"severity": "moderate"}}))
    passed &= check("a moderate label does not block", result.returncode == 0)

    # Some feeds put the label on the affected range instead.
    result = run(report_with({
        "id": "GHSA-3",
        "affected": [{"database_specific": {"severity": "CRITICAL"}}],
    }))
    passed &= check("a label on the affected range still blocks", result.returncode == 1)

    # Silence is not evidence of safety, but it is not evidence of danger either: report, don't block.
    result = run(report_with({"id": "OSV-5"}))
    passed &= check("an advisory with no severity is reported, not fatal",
                    result.returncode == 0 and "UNKNOWN" in result.stdout)

    # One critical among many must still fail the build.
    result = run(report_with(
        {"id": "OSV-6", "severity": [{"type": "CVSS_V3", "score": "3.1"}]},
        {"id": "OSV-7", "database_specific": {"severity": "CRITICAL"}},
        {"id": "OSV-8"},
    ))
    passed &= check("one critical among many blocks", result.returncode == 1
                    and "1 at high or critical" in result.stdout)

    # A report the gate cannot read must fail rather than pass silently.
    with tempfile.TemporaryDirectory() as directory:
        broken = Path(directory) / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        result = subprocess.run([sys.executable, str(GATE), str(broken)],
                                capture_output=True, text=True, check=False)
        passed &= check("an unreadable report fails", result.returncode == 1)

        missing = Path(directory) / "absent.json"
        result = subprocess.run([sys.executable, str(GATE), str(missing)],
                                capture_output=True, text=True, check=False)
        passed &= check("a missing report fails", result.returncode == 1)

    print("\nall gate tests passed" if passed else "\ngate tests FAILED")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
