"""Fail CI when native Go session tests were filtered, skipped or stayed on SQLite."""

import argparse
import json
from pathlib import Path


ORDER_ROOT = "TestOnlineEgressSessionOrderingVector"
SCOPE_ROOT = "TestOnlineSessionScopeDoesNotUseDatabaseCollation"
BOOTSTRAP_ROOT = "TestMySQLWorkbenchDDLIsTerminatedBeforeProductMetrics"
NATIVE_ORDER_MARKER = "native MySQL database for all 26 persisted ordering vectors"


def expected_pass_tests():
    vectors = Path(__file__).resolve().parents[1] / "protocol" / "test-vectors"
    order = json.loads((vectors / "peer-egress-session-order-v1.json").read_text(encoding="utf-8"))
    scope = json.loads((vectors / "peer-egress-session-scope-v1.json").read_text(encoding="utf-8"))
    order_names = {case["name"] for case in order["cases"]}
    scope_names = {case["name"] for case in scope["cases"]}
    if len(order_names) != 26 or len(order["cases"]) != 26 or len(scope_names) != 8 or len(scope["cases"]) != 8:
        raise ValueError("unexpected shared vector coverage")
    if order["consumerIpv6DataPlaneEnabled"] or scope["consumerIpv6DataPlaneEnabled"]:
        raise ValueError("metadata tests must not enable the consumer IPv6 data plane")
    expected = {ORDER_ROOT, SCOPE_ROOT, BOOTSTRAP_ROOT}
    expected.update(f"{ORDER_ROOT}/{name}" for name in order_names)
    for provider in ("sqlite-binary", "sqlite-nocase", "mysql-native"):
        expected.add(f"{SCOPE_ROOT}/{provider}")
        expected.update(f"{SCOPE_ROOT}/{provider}/{name}" for name in scope_names)
    return expected


def verify_events(events):
    if any(event.get("Action") in ("fail", "skip") for event in events):
        raise ValueError("native Go tests failed or skipped")
    passed = [event["Test"] for event in events if event.get("Action") == "pass" and event.get("Test")]
    expected = expected_pass_tests()
    if set(passed) != expected or len(passed) != len(expected):
        raise ValueError("missing, duplicate or unexpected native Go test cases")
    if not any(NATIVE_ORDER_MARKER in event.get("Output", "") for event in events):
        raise ValueError("26 ordering vectors did not select the native database connection")
    if not any(event.get("Action") == "pass" and not event.get("Test") for event in events):
        raise ValueError("Go package did not finish successfully")
    return {"ordering": 26, "nativeScope": 8, "sqliteScopeControls": 16, "bootstrap": 1, "failed": 0, "skipped": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=Path)
    args = parser.parse_args()
    for path in args.logs:
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        print(f"{path.name}: {json.dumps(verify_events(events), sort_keys=True)}")


if __name__ == "__main__":
    main()
