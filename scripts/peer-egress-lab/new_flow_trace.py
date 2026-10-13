"""Bounded, metadata-only new-flow evidence for this lab's synthetic namespaces.

No packet payload is serialized. Timestamps are userspace CLOCK_MONOTONIC arrival
times, shared by the lab namespaces, not kernel wire timestamps. Captured SPM2
session/sequence headers cannot identify their encrypted inner packet on their own.
"""
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

NAMESPACES = ("con", "egr", "tgt")
MAX_EVENTS = 20_000
MAX_SECONDS = 240
TARGET = "203.0.113.10"
PEER_LINK = {"10.90.1.2", "10.90.2.2"}


def packet_metadata(packet, address, now_ns):
    """Parse only the IPv4/TCP/UDP and optional clear SPM2 headers."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header = (packet[0] & 15) * 4
    total = struct.unpack_from("!H", packet, 2)[0]
    # Fragments cannot be interpreted as independent TCP/UDP headers.
    if header < 20 or len(packet) < header + 8 or total < header + 8:
        return None
    if struct.unpack_from("!H", packet, 6)[0] & 0x3fff:
        return None
    source, target = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
    sport, dport = struct.unpack_from("!HH", packet, header)
    row = {"kind": "packet", "timeNs": now_ns, "interface": address[0], "direction": address[2],
           "source": source, "target": target, "sourcePort": sport, "targetPort": dport, "length": total}
    if packet[9] == 6 and ((source == TARGET and sport == 80) or (target == TARGET and dport == 80)):
        if len(packet) < header + 20 or total < header + 20:
            return None
        tcp_header = (packet[header + 12] >> 4) * 4
        if tcp_header < 20 or tcp_header > total - header or tcp_header > len(packet) - header:
            return None
        row.update(protocol="tcp", sequence=struct.unpack_from("!I", packet, header + 4)[0],
                   acknowledgement=struct.unpack_from("!I", packet, header + 8)[0],
                   flags=packet[header + 13], window=struct.unpack_from("!H", packet, header + 14)[0])
    elif packet[9] == 17 and {source, target} == PEER_LINK:
        udp_length = struct.unpack_from("!H", packet, header + 4)[0]
        if udp_length < 8 or udp_length > total - header:
            return None
        row.update(protocol="udp")
        # Clear header only: do not decode probes, tokens, ciphertext or application data.
        body = packet[header + 8:min(len(packet), header + udp_length)]
        if len(body) >= 20 and body[:4] == b"SPM2":
            row.update(session=struct.unpack_from("!Q", body, 4)[0],
                       sequence=struct.unpack_from("!Q", body, 12)[0])
    else:
        return None
    return row


def collect(namespace, output):
    if namespace not in NAMESPACES:
        raise ValueError("unknown lab namespace")
    # Direct accidental use in the host namespace is refused. Fake-root user
    # namespaces may not read PID1; AF_PACKET still requires owning this network
    # namespace, and the lab's role-specific physical link must also be present.
    try:
        if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
            raise RuntimeError("collector requires a private network namespace")
    except PermissionError:
        if Path("/proc/self/uid_map").read_text().split() == ["0", "0", "4294967295"]:
            raise RuntimeError("cannot verify private network namespace") from None
    if f"{namespace}0" not in {name for _, name in socket.if_nameindex()}:
        raise RuntimeError("lab namespace link is missing")
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    channel = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
    channel.settimeout(0.2)
    count, timed_out, truncated = 0, False, False
    deadline = time.monotonic() + MAX_SECONDS
    try:
        with Path(output).open("w", encoding="utf-8") as stream:
            stream.write(json.dumps({"kind": "header", "version": 1, "namespace": namespace,
                                     "timestamp": "userspace-monotonic", "maxEvents": MAX_EVENTS,
                                     "maxSeconds": MAX_SECONDS}) + "\n")
            stream.flush()
            print("READY", flush=True)
            while running:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                try:
                    packet, address = channel.recvfrom(384)
                except socket.timeout:
                    continue
                row = packet_metadata(packet, address, time.monotonic_ns())
                if row is None:
                    continue
                if count == MAX_EVENTS:
                    truncated = True
                    break
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
                count += 1
            dropped = None
            try:
                # Linux SOL_PACKET/PACKET_STATISTICS: explicit unavailable, never fake zero.
                _, dropped = struct.unpack("=II", channel.getsockopt(263, 6, 8))
            except OSError:
                pass
            stream.write(json.dumps({"kind": "summary", "events": count, "socketDrops": dropped,
                                     "timedOut": timed_out, "truncated": truncated}) + "\n")
    finally:
        channel.close()


def read_summary(path, namespace=None):
    """Require a terminated evidence stream; incomplete/error files must not look healthy."""
    with Path(path).open(encoding="utf-8") as stream:
        header = json.loads(next(stream))
        last, count = None, 0
        for line in stream:
            last = json.loads(line)
            if last.get("kind") == "packet":
                count += 1
                if count > MAX_EVENTS:
                    raise ValueError("unbounded evidence stream")
        if header.get("kind") != "header" or header.get("version") != 1 or header.get("namespace") not in NAMESPACES:
            raise ValueError("invalid evidence header")
        if namespace is not None and header["namespace"] != namespace:
            raise ValueError("evidence belongs to another namespace")
        if not last or last.get("kind") != "summary" or last.get("events") != count:
            raise ValueError("missing or inconsistent evidence summary")
        return last


class NewFlowTrace:
    def __init__(self, work, expected_samples):
        self.directory = Path(tempfile.mkdtemp(prefix="new-flow-trace-", dir=work))
        self.expected_samples = expected_samples
        self.samples = 0
        self.workers = []
        self.errors = []
        self.summaries = {}

    def start(self):
        for namespace in NAMESPACES:
            output = self.directory / f"{namespace}.jsonl"
            errors = (self.directory / f"{namespace}.errors.txt").open("w", encoding="utf-8")
            try:
                process = subprocess.Popen(["ip", "netns", "exec", namespace, sys.executable,
                                            str(Path(__file__).resolve()), "--collect", namespace, str(output)],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errors)
            except Exception:
                errors.close()
                raise
            self.workers.append((namespace, process, errors))
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(timeout=5) or process.stdout.readline().strip() != b"READY":
                    raise RuntimeError(f"{namespace} metadata collector did not become ready")

    def sample(self, started_ns, ended_ns, result, before_counters, after_counters):
        self.samples += 1
        row = {"sample": self.samples, "startNs": started_ns, "endNs": ended_ns, "code": result["code"],
               "source": result.get("src"), "connect": result.get("connect"), "firstByte": result.get("firstByte"),
               "countersBefore": before_counters, "countersAfter": after_counters}
        with (self.directory / "samples.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, allow_nan=False) + "\n")

    def close(self):
        for _, process, _ in self.workers:
            if process.poll() is None:
                process.terminate()
        for namespace, process, errors in self.workers:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.errors.append(f"{namespace} collector did not terminate")
                process.kill()
                process.wait(timeout=5)
            finally:
                process.stdout.close()
                errors.close()
            if process.returncode != 0:
                self.errors.append(f"{namespace} collector exited {process.returncode}")
            try:
                summary = read_summary(self.directory / f"{namespace}.jsonl", namespace)
                self.summaries[namespace] = summary
                if summary["socketDrops"] != 0 or summary["timedOut"] or summary["truncated"]:
                    self.errors.append(f"{namespace} evidence incomplete: {summary}")
            except (OSError, ValueError, StopIteration, KeyError) as error:
                self.errors.append(f"{namespace} evidence unreadable: {type(error).__name__}")
        try:
            with (self.directory / "samples.jsonl").open(encoding="utf-8") as stream:
                saved = 0
                for line in stream:
                    saved += 1
                    if saved > self.expected_samples or json.loads(line).get("sample") != saved:
                        raise ValueError("inconsistent sample journal")
                if saved != self.samples or saved != self.expected_samples:
                    raise ValueError("incomplete sample journal")
        except (OSError, ValueError, AttributeError) as error:
            self.errors.append(f"sample journal incomplete: {type(error).__name__}")
        complete = (not self.errors and len(self.summaries) == len(NAMESPACES)
                    and self.samples == self.expected_samples)
        summary = {"version": 1, "complete": complete, "samples": self.samples,
                   "expectedSamples": self.expected_samples, "namespaces": self.summaries, "errors": self.errors}
        (self.directory / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--collect":
        collect(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("usage: new_flow_trace.py --collect {con|egr|tgt} OUTPUT")
