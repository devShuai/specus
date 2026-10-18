"""Exercise the actual acceptance method with a deterministic snapshot clock.

No network, namespace, subprocess or running client is used by these unit tests.
The real Linux matrix remains the separate process-level acceptance gate.
"""
import json
import types
import unittest
from unittest.mock import Mock, patch

import lab


class StopAfterStatus(Exception):
    pass


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def peer(path="direct", flows=0, client_id=42):
    return {"clientId": client_id, "online": True, "standing": "offered",
            "path": path, "flows": flows}


def snapshot(peers):
    return {"data": {"instances": [{"egress": {"consumer": {"peers": peers}}}]}}


class StatusReadinessTests(unittest.TestCase):
    def acceptance_status(self, snapshots):
        instance = lab.Lab.__new__(lab.Lab)
        instance.snapshots = {}
        instance.say = Mock()
        instance.describe = Mock(return_value="controlled successful data path")
        instance.whoami = Mock(side_effect=lambda url: {
            "src": lab.EGRESS_IP if url == lab.TARGET_URL else lab.CONSUMER_IP})
        table = (f"{lab.RULE_CIDR} dev {lab.CONSUMER_TUN} scope link\n"
                 f"{lab.SERVER_IP} via {lab.CONSUMER_GW} dev con0\n")
        instance.consumer_table = Mock(return_value=table)
        instance.lab_routes = Mock(return_value=table.splitlines())
        reads = []

        def read(role):
            self.assertEqual("consumer", role)
            item = snapshots[min(len(reads), len(snapshots) - 1)]
            reads.append(item)
            return item

        instance.client_status = Mock(side_effect=read)
        result = []

        def check(name, ok, evidence=""):
            if name == "status names the path to the egress and its flow count":
                result.append((bool(ok), evidence))
                raise StopAfterStatus()
            self.assertTrue(ok, (name, evidence))

        instance.check = check
        clock = Clock()
        # Keep the original wait implementation and verify its unchanged bounds.
        instance.wait_for = Mock(wraps=instance.wait_for)
        with patch.object(lab.time, "monotonic", clock.monotonic), patch.object(lab.time, "sleep", clock.sleep):
            with self.assertRaises(StopAfterStatus):
                instance.acceptance()
        self.assertEqual(1, len(result))
        self.assertEqual(1, instance.wait_for.call_count)
        self.assertEqual((30, 1.0), instance.wait_for.call_args.args[2:])
        return result[0], reads, clock, instance

    def test_listed_peer_before_published_path_does_not_end_the_wait(self):
        stale = peer("none")
        stale["standing"] = "not-offered"
        (ok, _), reads, clock, _ = self.acceptance_status([
            snapshot([stale]), snapshot([peer("direct", 0)])])
        self.assertTrue(ok)
        self.assertEqual(2, len(reads))
        self.assertEqual([1.0], clock.sleeps)

    def test_ready_relay_with_zero_flows_needs_no_extra_poll_or_sleep(self):
        (ok, _), reads, clock, _ = self.acceptance_status([snapshot([peer("relay", 0)])])
        self.assertTrue(ok)
        self.assertEqual(1, len(reads))
        self.assertEqual([], clock.sleeps)

    def test_missing_snapshot_and_empty_peers_wait_for_reported_path(self):
        (ok, _), reads, clock, _ = self.acceptance_status([
            None, snapshot([]), snapshot([peer("direct", 3)])])
        self.assertTrue(ok)
        self.assertEqual(3, len(reads))
        self.assertEqual([1.0, 1.0], clock.sleeps)

    def test_all_peers_must_satisfy_the_original_path_and_count_assertion(self):
        (ok, _), reads, _, _ = self.acceptance_status([
            snapshot([peer(), peer("none", client_id=43)]),
            snapshot([peer(), peer("relay", 2, client_id=43)])])
        self.assertTrue(ok)
        self.assertEqual(2, len(reads))

    def test_a_permanently_missing_path_fails_at_the_original_deadline(self):
        stale = peer("none")
        stale["standing"] = "not-offered"
        (ok, evidence), reads, clock, instance = self.acceptance_status([snapshot([stale])])
        self.assertFalse(ok)
        self.assertEqual(30.0, clock.now)
        self.assertEqual(31, len(reads))
        self.assertEqual("none", json.loads(evidence)[0]["path"])
        self.assertIn("not-offered", instance.snapshots["consumer status (egress --json)"])

    def test_a_permanently_noninteger_count_is_not_accepted(self):
        (ok, evidence), reads, clock, _ = self.acceptance_status([snapshot([peer("direct", "0")])])
        self.assertFalse(ok)
        self.assertEqual(30.0, clock.now)
        self.assertEqual(31, len(reads))
        self.assertEqual("0", json.loads(evidence)[0]["flows"])

    def test_an_unknown_path_name_is_not_accepted(self):
        (ok, evidence), _, clock, _ = self.acceptance_status([snapshot([peer("direct-pending", 1)])])
        self.assertFalse(ok)
        self.assertEqual(30.0, clock.now)
        self.assertEqual("direct-pending", json.loads(evidence)[0]["path"])


if __name__ == "__main__":
    unittest.main()
