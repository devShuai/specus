import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from lab import EGRESS_IP, GATE_FIRST_BYTE_SAMPLES, Lab
from new_flow_trace import MAX_EVENTS, NewFlowTrace, collect, packet_metadata, read_summary


def ipv4(protocol, body, source="100.96.0.1", target="203.0.113.10", fragment=0):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1, fragment, 64, protocol, 0,
                       socket.inet_aton(source), socket.inet_aton(target)) + body


def tcp(body=b"", sport=40000, dport=80):
    return struct.pack("!HHIIBBHHH", sport, dport, 1234, 5678, 5 << 4, 18, 65535, 0, 0) + body


def udp(body):
    return struct.pack("!HHHH", 50000, 50001, len(body) + 8, 0) + body


class PacketMetadataTests(unittest.TestCase):
    address = ("specusc0", 0x0800, 4, 0, b"")

    def test_direct_host_namespace_use_never_opens_a_capture_socket(self):
        with patch("new_flow_trace.os.readlink", return_value="same-netns"), \
             patch("new_flow_trace.socket.socket") as channel:
            with self.assertRaisesRegex(RuntimeError, "private network namespace"):
                collect("con", "/must-not-create")
            channel.assert_not_called()

    def test_tcp_headers_keep_tuple_sequence_flags_and_window_but_not_payload(self):
        secret = b"Authorization: Bearer fixture-secret\r\nrequest-body"
        row = packet_metadata(ipv4(6, tcp(secret)), self.address, 99)
        self.assertEqual({"kind", "timeNs", "interface", "direction", "source", "target", "sourcePort",
                          "targetPort", "length", "protocol", "sequence", "acknowledgement", "flags", "window"},
                         set(row))
        self.assertEqual(("tcp", 1234, 5678, 18, 65535),
                         (row["protocol"], row["sequence"], row["acknowledgement"], row["flags"], row["window"]))
        self.assertNotIn("fixture-secret", json.dumps(row))
        self.assertNotIn("Authorization", json.dumps(row))

    def test_truncated_capture_does_not_need_or_save_application_data(self):
        row = packet_metadata(ipv4(6, tcp(b"private" * 100))[:40], self.address, 1)
        self.assertEqual(740, row["length"])
        self.assertNotIn("private", json.dumps(row))

    def test_spm2_keeps_only_the_clear_session_and_sequence_header(self):
        row = packet_metadata(ipv4(17, udp(b"SPM2" + struct.pack("!QQ", 7, 9) + b"ciphertext-secret"),
                                   "10.90.1.2", "10.90.2.2"), self.address, 1)
        self.assertEqual(("udp", 7, 9), (row["protocol"], row["session"], row["sequence"]))
        self.assertNotIn("ciphertext", json.dumps(row))

    def test_probe_token_is_not_decoded_or_saved(self):
        row = packet_metadata(ipv4(17, udp(b'{"token":"peer-secret"}'),
                                   "10.90.2.2", "10.90.1.2"), self.address, 1)
        self.assertNotIn("session", row)
        self.assertNotIn("peer-secret", json.dumps(row))

    def test_other_endpoints_and_non_lab_ports_are_not_recorded(self):
        for packet in (ipv4(6, tcp(), target="198.51.100.10"), ipv4(6, tcp(dport=443)),
                       ipv4(17, udp(b"data"), "10.90.1.2", "203.0.113.2"),
                       ipv4(6, tcp(sport=444, dport=80), source="203.0.113.10", target="100.96.0.1")):
            self.assertIsNone(packet_metadata(packet, self.address, 1))

    def test_short_invalid_headers_and_fragments_are_refused(self):
        valid = ipv4(6, tcp())
        bad_offset = bytearray(valid)
        bad_offset[32] = 15 << 4
        bad_udp = bytearray(ipv4(17, udp(b"data"), "10.90.1.2", "10.90.2.2"))
        struct.pack_into("!H", bad_udp, 24, 65535)
        for packet in (b"", valid[:19], valid[:39], b"\x65" + valid[1:], b"\x44" + valid[1:],
                       ipv4(6, tcp(), fragment=1), ipv4(6, tcp(), fragment=0x2000), bad_offset, bad_udp):
            with self.subTest(packet=bytes(packet).hex()):
                self.assertIsNone(packet_metadata(packet, self.address, 1))


class SummaryTests(unittest.TestCase):
    def write(self, directory, *, packets=0, declared=None, namespace="con", summary=True, **extra):
        path = Path(directory) / f"{namespace}.jsonl"
        rows = [{"kind": "header", "version": 1, "namespace": namespace}]
        rows.extend({"kind": "packet"} for _ in range(packets))
        if summary:
            rows.append({"kind": "summary", "events": packets if declared is None else declared,
                         "socketDrops": 0, "timedOut": False, "truncated": False, **extra})
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        return path

    def test_zero_events_is_an_observed_empty_window_not_a_missing_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(0, read_summary(self.write(directory), "con")["events"])

    def test_incomplete_or_mismatched_streams_are_not_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            for options in ({"summary": False}, {"packets": 1, "declared": 0}, {"namespace": "egr"}):
                with self.assertRaises(ValueError):
                    read_summary(self.write(directory, **options), "con")

    def test_event_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, packets=MAX_EVENTS + 1)
            with self.assertRaisesRegex(ValueError, "unbounded"):
                read_summary(path)

    def test_namespace_file_missing_or_drops_unknown_are_not_replaced_by_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = NewFlowTrace(directory, 20)
            trace.samples = 20
            self.assertFalse(trace.close()["complete"])
            trace = NewFlowTrace(directory, 20)
            trace.samples = 20
            process = Mock()
            process.poll.return_value = 0
            process.returncode = 0
            self.write(trace.directory, socketDrops=None)
            trace.workers = [("con", process, Mock())]
            status = trace.close()
            self.assertFalse(status["complete"])
            self.assertIsNone(status["namespaces"]["con"]["socketDrops"])

    def test_killed_or_truncated_collector_cannot_be_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = NewFlowTrace(directory, 20)
            trace.samples = 20
            process = Mock()
            process.poll.return_value = -9
            process.returncode = -9
            self.write(trace.directory, truncated=True)
            trace.workers = [("con", process, Mock())]
            result = trace.close()
            self.assertFalse(result["complete"])
            self.assertTrue(result["errors"])

    def test_complete_requires_all_three_collectors_and_the_actual_sample_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = NewFlowTrace(directory, 20)
            for sample in range(20):
                trace.sample(sample, sample + 1, {"code": 0, "src": EGRESS_IP,
                                               "connect": 0.001, "firstByte": 0.002}, None, None)
            for namespace in ("con", "egr", "tgt"):
                self.write(trace.directory, namespace=namespace).rename(trace.directory / f"{namespace}.jsonl")
                process = Mock()
                process.poll.return_value = 0
                process.returncode = 0
                trace.workers.append((namespace, process, Mock()))
            self.assertTrue(trace.close()["complete"])

    def test_claimed_count_without_a_journal_cannot_be_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = NewFlowTrace(directory, 20)
            trace.samples = 20
            for namespace in ("con", "egr", "tgt"):
                self.write(trace.directory, namespace=namespace).rename(trace.directory / f"{namespace}.jsonl")
                process = Mock()
                process.poll.return_value = 0
                process.returncode = 0
                trace.workers.append((namespace, process, Mock()))
            self.assertFalse(trace.close()["complete"])

    def test_stalled_worker_is_killed_and_reported_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = NewFlowTrace(directory, 20)
            process = Mock()
            process.poll.return_value = None
            process.wait.side_effect = [subprocess.TimeoutExpired("collector", 5), 0]
            process.returncode = -9
            self.write(trace.directory)
            trace.workers = [("con", process, Mock())]
            self.assertFalse(trace.close()["complete"])
            process.terminate.assert_called_once()
            process.kill.assert_called_once()
            process.stdout.close.assert_called_once()


class GateFidelityTests(unittest.TestCase):
    def lab(self, directory, trace=False):
        instance = Lab.__new__(Lab)
        instance.args = types.SimpleNamespace(trace_new_flows=trace)
        instance.work = Path(directory)
        instance.report_dir = Path(directory) / "report"
        instance.report_dir.mkdir()
        instance.results, instance.notes, instance.measurements = [], [], {}
        instance.say = Mock()
        instance.tcp_counters = Mock(return_value={"con.TcpExtTCPSynRetrans": 0})
        values = [1.054, 1.0054] + [0.001] * (GATE_FIRST_BYTE_SAMPLES - 2)
        instance.whoami = Mock(side_effect=[
            {"code": 0, "src": EGRESS_IP, "connect": value, "firstByte": value} for value in values])
        return instance

    def assert_original_failure_retained(self, instance):
        self.assertEqual(GATE_FIRST_BYTE_SAMPLES, instance.whoami.call_count)
        gate = next(row for row in instance.results if row["name"].startswith("performance gate: first byte"))
        self.assertFalse(gate["ok"])
        self.assertEqual("p95 1005.4 ms over 20 flows", gate["evidence"])

    def test_original_failed_samples_are_not_retried_filtered_or_relaxed(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = self.lab(directory)
            instance.first_byte_gate()
            self.assert_original_failure_retained(instance)

    def test_every_sample_including_slow_ones_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = self.lab(directory)
            trace = NewFlowTrace(directory, GATE_FIRST_BYTE_SAMPLES)
            instance.first_byte_gate(trace)
            rows = [json.loads(line) for line in (trace.directory / "samples.jsonl").read_text().splitlines()]
            self.assertEqual(GATE_FIRST_BYTE_SAMPLES, len(rows))
            self.assertEqual([1.054, 1.0054], [row["firstByte"] for row in rows[:2]])
            self.assertEqual(GATE_FIRST_BYTE_SAMPLES + 2, instance.tcp_counters.call_count,
                             "tracing must not add counter polls between the original samples")
            self.assert_original_failure_retained(instance)

    def test_collector_startup_failure_does_not_skip_or_pass_performance_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = self.lab(directory, trace=True)
            with patch("lab.NewFlowTrace.start", side_effect=RuntimeError("injected startup failure")):
                with instance.new_flow_evidence() as trace:
                    instance.first_byte_gate(trace)
            self.assert_original_failure_retained(instance)
            self.assertFalse(instance.results[-1]["ok"])
            self.assertTrue(list(instance.report_dir.glob("new-flow-trace-*/samples.jsonl")))

    @unittest.skipUnless(os.name == "posix", "POSIX artifact directory permissions")
    def test_archived_evidence_uses_report_permissions_without_changing_private_source(self):
        # mkdtemp is 0700. copytree copies that mode too; the sudo lab's archive
        # then cannot be scanned by the ordinary CI runner that uploads reports.
        for report_mode in (0o755, 0o750):
            with self.subTest(report_mode=oct(report_mode)), tempfile.TemporaryDirectory() as directory:
                instance = self.lab(directory, trace=True)
                instance.report_dir.chmod(report_mode)
                with patch("lab.NewFlowTrace.start", side_effect=RuntimeError("no namespace in fixture")):
                    with instance.new_flow_evidence() as trace:
                        instance.first_byte_gate(trace)
                archived = instance.report_dir / trace.directory.name
                self.assertEqual(report_mode, stat.S_IMODE(archived.stat().st_mode))
                self.assertEqual(0o700, stat.S_IMODE(trace.directory.stat().st_mode))
                self.assertTrue((archived / "samples.jsonl").is_file())

    def test_diagnostic_write_failure_does_not_discard_the_slow_sample(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = self.lab(directory)
            trace = NewFlowTrace(directory, GATE_FIRST_BYTE_SAMPLES)
            trace.sample = Mock(side_effect=OSError("injected write failure"))
            instance.first_byte_gate(trace)
            self.assert_original_failure_retained(instance)
            self.assertTrue(trace.errors)

    def test_failed_curl_is_kept_in_evidence_and_fails_the_original_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = self.lab(directory)
            failed = {"code": 7, "src": None, "connect": 0, "firstByte": 0}
            success = {"code": 0, "src": EGRESS_IP, "connect": 0.001, "firstByte": 0.002}
            instance.whoami = Mock(side_effect=[failed] + [success] * (GATE_FIRST_BYTE_SAMPLES - 1))
            trace = NewFlowTrace(directory, GATE_FIRST_BYTE_SAMPLES)
            instance.first_byte_gate(trace)
            self.assertEqual(GATE_FIRST_BYTE_SAMPLES, instance.whoami.call_count)
            self.assertFalse(instance.results[0]["ok"])
            self.assertEqual("only 19/20 new flows went through the egress", instance.results[0]["evidence"])
            rows = [json.loads(line) for line in (trace.directory / "samples.jsonl").read_text().splitlines()]
            self.assertEqual(GATE_FIRST_BYTE_SAMPLES, len(rows))
            self.assertEqual(7, rows[0]["code"])


if __name__ == "__main__":
    unittest.main()
