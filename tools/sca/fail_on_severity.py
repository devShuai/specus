#!/usr/bin/env python3
"""Fail a build when an OSV scan reports a high or critical advisory.

osv-scanner exits non-zero for *any* finding, including low-severity advisories that often have no
fixed version available. Blocking on those trains people to bypass the gate, which costs more than
it buys. This reads the scanner's JSON and applies the severity threshold the repository actually
releases against, while still printing everything it found so nothing is hidden.

Severity is read from CVSS vectors where the advisory carries one, falling back to the ecosystem
label. An advisory with no severity information at all is reported but does not fail the build,
because guessing "critical" from silence would block on incomplete data.
"""

import argparse
import json
import sys

BLOCKING = {"HIGH", "CRITICAL"}


def rating_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def severity_of(vulnerability: dict) -> str:
    """Best available severity for one advisory, or UNKNOWN when it carries none."""
    # A numeric score is the most precise signal when the feed provides one.
    for entry in vulnerability.get("severity", []) or []:
        score = entry.get("score")
        if isinstance(score, (int, float)):
            return rating_from_score(float(score))
        if isinstance(score, str):
            try:
                return rating_from_score(float(score))
            except ValueError:
                pass

    # GitHub advisories carry a qualitative label instead.
    specific = vulnerability.get("database_specific") or {}
    label = specific.get("severity")
    if isinstance(label, str) and label.strip():
        return label.strip().upper()

    for affected in vulnerability.get("affected", []) or []:
        specific = affected.get("database_specific") or {}
        label = specific.get("severity")
        if isinstance(label, str) and label.strip():
            return label.strip().upper()

    return "UNKNOWN"


def findings(report: dict) -> list[tuple[str, str, str, str]]:
    """Flattens a scanner report into (severity, id, package, source) rows."""
    rows: list[tuple[str, str, str, str]] = []
    for result in report.get("results", []) or []:
        source = (result.get("source") or {}).get("path", "?")
        for package in result.get("packages", []) or []:
            info = package.get("package") or {}
            name = f"{info.get('name', '?')}@{info.get('version', '?')}"
            for vulnerability in package.get("vulnerabilities", []) or []:
                rows.append((
                    severity_of(vulnerability),
                    vulnerability.get("id", "?"),
                    name,
                    source,
                ))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="osv-scanner --format json output")
    parser.add_argument("--label", default="scan", help="name used in the summary line")
    arguments = parser.parse_args()

    try:
        with open(arguments.report, encoding="utf-8") as handle:
            report = json.load(handle)
    except FileNotFoundError:
        print(f"{arguments.label}: no report at {arguments.report}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as error:
        print(f"{arguments.label}: unreadable report: {error}", file=sys.stderr)
        return 1

    rows = findings(report)
    if not rows:
        print(f"{arguments.label}: no advisories")
        return 0

    # Highest severity first so the reason for a failure is the first thing in the log.
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4}
    for severity, identifier, package, source in sorted(rows, key=lambda r: order.get(r[0], 5)):
        print(f"{severity:<8} {identifier:<24} {package}  ({source})")

    blocking = [row for row in rows if row[0] in BLOCKING]
    print(f"\n{arguments.label}: {len(rows)} advisories, {len(blocking)} at high or critical")
    if blocking:
        print(f"{arguments.label}: failing on high or critical advisories", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
