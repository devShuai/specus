import types
import json
import socket
import subprocess
import sys
import threading
from pathlib import Path
import unittest
from unittest.mock import Mock

from lab import (BROAD_GRANT, BURST_SCRIPT, CODE_LIMIT, HOLD_SCRIPT, METADATA_IP, RULE_GRANT,
                 Lab, Proc, p95)


class RoleCommandTests(unittest.TestCase):
    def lab(self, **overrides):
        instance = Lab.__new__(Lab)
        instance.args = types.SimpleNamespace(client="/default-client", **overrides)
        return instance

    def test_default_go_client_is_used_for_both_roles(self):
        instance = self.lab()
        self.assertEqual("/default-client", instance.client_binary("consumer"))
        self.assertEqual("/default-client", instance.client_binary("egress"))
        self.assertEqual("Go", instance.client_label("egress"))

    def test_override_does_not_change_other_role_or_claim_go(self):
        instance = self.lab(egress_client="/dotnet-client")
        self.assertEqual("/default-client", instance.client_binary("consumer"))
        self.assertEqual("/dotnet-client", instance.client_binary("egress"))
        self.assertEqual("custom", instance.client_label("egress"))

    def test_start_uses_literal_executable_and_role_environment(self):
        instance = self.lab(consumer_client="/path with spaces/java-client", consumer_implementation="Java")
        instance.start = Mock()
        instance.client_env = Mock(return_value=["env", "HOME=/fixture/consumer"])
        instance.start_client("consumer", "/fixture/config.jsonc")
        role, command = instance.start.call_args.args
        self.assertEqual("consumer", role)
        self.assertIn("/path with spaces/java-client", command)
        self.assertNotIn("/default-client", command)
        self.assertEqual("Java", instance.client_label("consumer"))

    def test_policy_evidence_accepts_dotnet_boolean_case(self):
        proc = Proc.__new__(Proc)
        proc.label = "egress"
        proc.log_since = Mock(return_value="[peer-egress] policy applied enabled=True revision=2")
        proc.lab = types.SimpleNamespace(wait_for=lambda _, predicate, timeout: (predicate(), 0))
        self.assertIsNotNone(proc.wait_log(r"policy applied enabled=true", 1))


class OfflineDiagnosticsTests(unittest.TestCase):
    def test_failed_refusal_keeps_status_before_restarting_egress(self):
        for status in ({"data": {"instances": []}}, None):
            with self.subTest(status=status):
                instance = Lab.__new__(Lab)
                instance.work = Path("/fixture")
                instance.procs = {"egress": Mock()}
                instance.snapshots = {}
                instance.target_mark = Mock(return_value=0)
                instance.wait_for = Mock(side_effect=[(None, 90), ({"src": "egress"}, 1)])
                instance.check = Mock()
                instance.measure = Mock()
                instance.leak_check = Mock()
                instance.client_status = Mock(return_value=status)
                instance.through_egress = Mock()

                def restart(*_):
                    instance.client_status.assert_called_once_with("consumer")
                    if status:
                        self.assertEqual(status["data"], json.loads(instance.snapshots[
                            "consumer status after offline refusal timed out"]))
                    else:
                        self.assertEqual({}, instance.snapshots)
                    return Mock()

                instance.start_client = Mock(side_effect=restart)
                instance.fault_egress_stopped()
                instance.start_client.assert_called_once()


class PerformanceGateTests(unittest.TestCase):
    def lab(self):
        instance = Lab.__new__(Lab)
        instance.results = []
        instance.measurements = {}
        instance.say = Mock()
        return instance

    def test_p95_is_a_value_that_was_observed(self):
        self.assertEqual(19, p95(range(1, 21)))
        self.assertEqual(95, p95(range(100, 0, -1)))
        self.assertEqual(7, p95([7]))

    def test_median_gate_judges_the_median_rather_than_the_best_run(self):
        instance = self.lab()
        instance.gate_median("download", [9.0, 3.0, 3.5, 3.9, 12.0], True, 4.0)
        self.assertFalse(instance.results[-1]["ok"])
        instance.gate_median("download", [4.1, 3.0, 4.5, 3.9, 12.0], True, 4.0)
        self.assertTrue(instance.results[-1]["ok"])

    def test_median_gate_fails_when_any_run_did_not_arrive_intact(self):
        instance = self.lab()
        instance.gate_median("download", [9.0, 9.0, 9.0, 9.0, 9.0], False, 4.0)
        self.assertFalse(instance.results[-1]["ok"])
        self.assertEqual({}, instance.measurements)


class RefusalEvidenceTests(unittest.TestCase):
    def lab(self):
        instance = Lab.__new__(Lab)
        instance.results = []
        instance.notes = []
        instance.say = Mock()
        instance.egress_id = 7
        # One look at the predicate: these tests are about what counts, not about waiting.
        instance.wait_for = lambda _, predicate, timeout, interval=0.5: (predicate(), 0)
        return instance

    def test_every_policy_push_carries_domain_rules_and_limits(self):
        # The server keeps a field a request leaves out, so a grant made for one check would
        # otherwise outlive it into every check after.
        instance = self.lab()
        instance.admin = Mock()
        instance.policy([1], domains=({"match": "*.lab.test"},), per_consumer=4, idle_seconds=3)
        instance.policy([1])
        granted, plain = (call.args[2] for call in instance.admin.call.call_args_list)
        self.assertEqual([{"match": "*.lab.test"}], granted["domainRules"])
        self.assertEqual(4, granted["maxFlowsPerConsumer"])
        self.assertEqual(3, granted["idleTimeoutSeconds"])
        self.assertEqual([], plain["domainRules"])
        self.assertEqual([RULE_GRANT], plain["destinationRules"])
        self.assertEqual(128, plain["maxFlowsPerConsumer"])
        self.assertEqual(60, plain["idleTimeoutSeconds"])

    def test_set_policy_waits_for_the_push_with_its_rule_count(self):
        instance = self.lab()
        instance.policy = Mock()
        egress = Mock()
        egress.log_offset.return_value = 42
        instance.procs = {"egress": egress}
        self.assertTrue(instance.set_policy([1], destinations=(RULE_GRANT, BROAD_GRANT)))
        pattern, _, offset = egress.wait_log.call_args.args
        self.assertIn("rules=2", pattern)
        self.assertEqual(42, offset)
        egress.wait_log.return_value = None
        self.assertFalse(instance.set_policy([1]))
        self.assertIn("rules=1", egress.wait_log.call_args.args[0])
        self.assertEqual(1, len(instance.notes))

    def test_egress_refused_reads_the_egress_roles_own_section(self):
        instance = self.lab()
        instance.client_status = Mock(return_value={"data": {"instances": [{"egress": {
            "consumer": {"blocked": {"rejected-egress_limit_exceeded": 9}},
            "egress": {"flows": 0, "refused": {CODE_LIMIT: 2, "garbled": "x"}}}}]}})
        self.assertEqual({CODE_LIMIT: 2}, instance.egress_refused())
        instance.client_status = Mock(return_value=None)
        self.assertIsNone(instance.egress_refused())

    def test_a_refusal_counts_only_when_the_egress_count_grows(self):
        instance = self.lab()
        instance.egress_refused = Mock(return_value={CODE_LIMIT: 3, "EGRESS_DEST_DENIED": 9})
        self.assertIsNone(instance.refused_at_egress(CODE_LIMIT, {CODE_LIMIT: 3}))
        # Another code growing is not the refusal being looked for.
        self.assertIsNone(instance.refused_at_egress(CODE_LIMIT, {CODE_LIMIT: 3, "EGRESS_DEST_DENIED": 1}))
        self.assertIsNotNone(instance.refused_at_egress(CODE_LIMIT, {CODE_LIMIT: 2}))
        self.assertIsNotNone(instance.refused_at_egress(CODE_LIMIT, {}))
        # A threshold: three more are not five more, and the evidence says where the count got to.
        self.assertIsNone(instance.refused_at_egress(CODE_LIMIT, {}, at_least=5))
        self.assertEqual(f"egress refused[{CODE_LIMIT}] 0 -> 3", instance.refusal_evidence(CODE_LIMIT, {}, None))
        self.assertIsNotNone(instance.refused_at_egress(CODE_LIMIT, {}, at_least=3))
        self.assertEqual(f"egress refused[{CODE_LIMIT}] 2 -> 3",
                         instance.refusal_evidence(CODE_LIMIT, {CODE_LIMIT: 2}, {CODE_LIMIT: 3}))
        instance.last_refused = None
        self.assertEqual(f"egress refused[{CODE_LIMIT}] 2 -> 2",
                         instance.refusal_evidence(CODE_LIMIT, {CODE_LIMIT: 2}, None))

    def test_egress_counts_reads_refusals_and_admitted_flows(self):
        instance = self.lab()
        instance.client_status = Mock(return_value={"data": {"instances": [{"egress": {
            "egress": {"refused": {CODE_LIMIT: 7}, "totalFlows": 140}}}]}})
        self.assertEqual(({CODE_LIMIT: 7}, 140), instance.egress_counts())
        instance.client_status = Mock(return_value={"data": {"instances": [{"egress": {
            "egress": {"refused": {}, "totalFlows": "many"}}}]}})
        self.assertEqual(({}, None), instance.egress_counts())
        instance.client_status = Mock(return_value=None)
        self.assertEqual((None, None), instance.egress_counts())

    def test_nothing_reached_fails_for_any_source(self):
        instance = self.lab()
        instance.check = Mock()
        instance.target_entries = Mock(return_value=[{"src": "10.90.1.2", "dst": "203.0.113.10"}])
        instance.nothing_reached("restricted target", 0, METADATA_IP)
        self.assertTrue(instance.check.call_args.args[1])
        instance.target_entries = Mock(return_value=[{"src": "10.90.2.2", "dst": METADATA_IP}])
        instance.nothing_reached("restricted target", 0, METADATA_IP)
        self.assertFalse(instance.check.call_args.args[1])
        self.assertIn("10.90.2.2", instance.check.call_args.args[2])


class ProbeScriptTests(unittest.TestCase):
    """The scripts the lab runs in the consumer's namespace, against a listener on this machine."""

    def run_script(self, script, *args):
        got = subprocess.run([sys.executable, "-c", script, *map(str, args)], capture_output=True, text=True,
                             timeout=60)
        self.assertEqual(0, got.returncode, got.stderr)
        return json.loads(got.stdout.strip().splitlines()[-1])

    def listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(64)
        self.addCleanup(server.close)
        return server.getsockname()[1]

    def closed_port(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        return port

    def udp_echo(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        self.addCleanup(server.close)

        def serve():
            while True:
                try:
                    data, peer = server.recvfrom(512)
                    server.sendto(data, peer)
                except OSError:
                    return
        threading.Thread(target=serve, daemon=True).start()
        return server.getsockname()[1]

    def test_burst_sends_one_datagram_per_flow_and_counts_the_answers(self):
        result = self.run_script(BURST_SCRIPT, "127.0.0.1", self.udp_echo(), 8, 1)
        self.assertEqual(8, result["sent"])
        self.assertEqual(8, result["answered"])
        self.assertGreaterEqual(result["lastAnswer"], 0)

    def test_burst_with_nobody_answering_ends_after_the_quiet_period(self):
        closed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        result = self.run_script(BURST_SCRIPT, "127.0.0.1", port, 3, 0.5)
        self.assertEqual(0, result["answered"])
        self.assertEqual(0, result["lastAnswer"])

    def test_hold_keeps_what_connects_and_stops_at_the_first_refusal(self):
        self.assertEqual({"held": 3, "next": "never refused"},
                         self.run_script(HOLD_SCRIPT, "127.0.0.1", self.listener(), 3))
        self.assertEqual({"held": 0, "next": "refused"},
                         self.run_script(HOLD_SCRIPT, "127.0.0.1", self.closed_port(), 3))


if __name__ == "__main__":
    unittest.main()
