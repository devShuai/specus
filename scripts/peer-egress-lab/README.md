# Peer egress Linux lab

Issue #56's acceptance list, run against real processes on one Linux machine: the Go server, a
consumer with a TUN device and routes of its own, an egress, and a target that records who
reached it, each in a network namespace behind one router namespace.

```
             br-wan 203.0.113.1 / 198.51.100.1
   srv 203.0.113.2 ──┤                       ├── tgt 203.0.113.10 (under the rule)
                     │        router         │       198.51.100.10 (under no rule)
   con 10.90.1.2 ────┤ 10.90.1.1   10.90.2.1 ├── egr 10.90.2.2
```

The consumer's rule sends `203.0.113.0/24` through the egress, and that prefix holds the server on
purpose: the control connection only survives if the bypass `/32` is really installed, and a bypass
on a physical interface is what a `kill -9` leaves behind for the next start to take back. The
target's second address is the same server reached under no rule, which is what lets the leak checks
tell the consumer's own address from the egress's.

## What it checks

- TCP and UDP under the rule arrive from the egress's address; under no rule from the consumer's.
- The consumer's table holds the exact prefix, the bypass `/32` and the mesh host routes, and no
  default or half-default route.
- 8 MiB down and 8 MiB up arrive intact through the egress; throughput and connect times are
  recorded as input for the performance baseline (#50). A 512 KiB download over a link that drops
  2% each way must also arrive intact. Downloads are verified by SHA-256, not just byte count.
- Large-response regression (#74): 512 KiB, 1 MiB and 8 MiB responses must pass both length and
  SHA-256 checks. Failures fail the lab rather than merely recording the old receiver-buffer
  ceiling. `--ceiling-sizes` overrides these probes; the largest passing size is coverage, not a
  claimed maximum response size.
- Concurrent downstream integrity: by default 16 parallel 1 MiB downloads must all match SHA-256
  and none may leave from the consumer's local address. Use `--concurrent-flows 64` for a larger
  run, `--concurrent-bytes` to change the per-flow size, or `--concurrent-flows 0` to skip it.
- Fault injection, each with a leak check on the target's log: ACL revoked (flow-reject at the
  consumer), tenant switch off (an established flow is cut, a new one refused), egress process
  stopped and restarted, rule changed to `block` across a consumer restart, consumer `kill -9`
  with a user route of its own in the table.
- The consumer's routing table after a normal exit, after `kill -9`, after the restart, and at the
  end.

A leak check can fail intermittently, and when it does it is not the lab being flaky. A control
connection that drops takes the client through its full restart, which withdraws every route it
owns and reinstalls them a couple of seconds later; requests under a rule go out locally in that
window. It reproduces on some runs and not others, which is why the probe that catches it also
captures the consumer's routing table at that instant. Tracked in issue #73.

## Running it

CI runs it in `.github/workflows/peer-egress-lab.yml`. By hand, with both binaries built:

```bash
sudo -n unshare -n -m python3 scripts/peer-egress-lab/lab.py \
  --server /path/to/specus-server --client /path/to/specus-client --report-dir /tmp/lab
```

Without sudo, a user namespace's fake root is enough on a kernel that lets it create TUN devices
(WSL 2 does): `unshare -rnm python3 scripts/peer-egress-lab/lab.py ...`. The lab refuses to run in
a namespace whose main table is not empty, so started on a machine's own network it stops instead
of rearranging its routes. `--skip-faults` and `--skip-lossy` shorten a run while iterating.
It also requires a private mount namespace and always mounts a private tmpfs over `/run`; a mount
namespace alone would hide the namespace mounts but still leave their empty handle files on the host.

### Mixed-language clients

`--client` supplies the default Go executable for both roles. Override either role with
`--consumer-client` or `--egress-client`; both overrides also work without `--client`.
Each value is a literal executable path, not a shell command. Java needs an executable wrapper
which forwards arguments and uses `exec`, so shutdown/kill signals reach the JVM:

```sh
#!/bin/sh
exec /absolute/path/to/java -jar /absolute/path/to/specus-client-exec.jar "$@"
```

For example, to exercise a Java consumer against a .NET egress:

```bash
sudo -n unshare -n -m python3 scripts/peer-egress-lab/lab.py \
  --server /path/to/go-specus-server \
  --consumer-client /path/to/java-wrapper --consumer-implementation Java \
  --egress-client /path/to/dotnet-specus-client --egress-implementation .NET \
  --report-dir /tmp/mixed-lab --switch-off-repetitions 3
```

Implementation labels only describe the report; they do not change the command. An override
without a label is reported as `custom`. Every client must implement the shared CLI/config
contract and support real Linux TUN. Bring-up is gated by a successful request observed from the
egress address, not an implementation-specific INFO log. Path type is reported as `unreported`
when neither client logs it; that is not evidence of a direct path. Log evidence is case-insensitive
to handle Java/.NET formatting, while packet integrity, source addresses and route checks are unchanged.

Use `--switch-off-repetitions 5` to repeat the established-flow revocation regression (#75).
Each round checks the application's failure, the egress's completed drain (`count > 0`, `active=0`),
new-flow rejection, no local leak, and recovery after re-enabling. The consumer's refusal evidence
uses the reason-only log, not a target address. Go, Java and .NET unit tests additionally deliver
`flow-reject` without a preceding RST, then deliver a duplicate and a late RST; they also ensure a
different egress cannot revoke the flow. These deterministic cases cover notification ordering
that a normal live run cannot guarantee it exercised.

On 2026-09-26, a WSL 2 real-TUN Go run with five rounds passed 60 checks; established downloads
were reset in 0.0–0.1 seconds. That targeted run used `--skip-lossy --ceiling-sizes 65536`: it does
not establish a new large-response performance ceiling or validate the Windows/macOS or mixed-
language system matrix. The large-response work (#74) was tested separately below.
After isolating `/run`, a second run repeated revocation three times and passed all 48 checks;
no lab processes or namespace handles remained in the host after exit.

## Send-window regression baseline (#74)

On 2026-09-26, the development send-window implementation passed all 52 checks on WSL 2
(kernel 6.6.87.2, Go consumer/egress/server, real TUN, direct peer path, 1280 MTU), using the
default sizes and `--switch-off-repetitions 3`. Both the large-response probes and the lossy
download were mandatory SHA-256 checks in this run.

| Measurement | Observed result |
| --- | --- |
| 8 MiB downstream | 8.70 MiB/s; 0.92 s; SHA-256 matched |
| 8 MiB upstream | 7.06 MiB/s; target verified contents |
| 512 KiB / 1 MiB / 8 MiB response probes | All complete and SHA-256 matched |
| 512 KiB downstream, 2% loss each way | 0.13 MiB/s; 3.8 s; SHA-256 matched |
| Established-flow revocation, three rounds | All reset immediately (0.0 s at report precision) |

These are single-machine observations, not throughput guarantees. An earlier run of the same
implementation downloaded 8 MiB at 1.66 MiB/s; scheduling and loss recovery affect results.
Go, Java and .NET share vectors for window-limited sends, deferred FIN, zero-window persistence,
partial ACK/window shrink and data arriving before the handshake completes. Each flow bounds
pending plus unacknowledged bytes to 65536, pauses socket reads when full, and permits at most
four MSS in flight subject to the peer's window. This is not adaptive congestion control.

The subsequent queue-admission change adds nonblocking admission for egress TCP payload/FIN:
a full 512-entry outbound queue leaves data in its bounded TCP buffer and does not advance sequence
space or spend a retransmission attempt. Dequeue notifications rotate waiting flows; the 100 ms
tick is a fallback. Go tests force a one-slot queue full and verify two waiting flows get turns.
All three implementations test prolonged rejection, ordered data/FIN recovery and retry-budget
preservation. The separate 2048-entry receive worker queue still drops on overload, and UDP,
initial SYN-ACK and untracked control frames remain best effort. Windows/macOS real TUN and
mixed-language integration remain separate acceptance work.

The final queue-admission build was rerun on the same WSL host with 64 concurrent 1 MiB
downloads and three revocation rounds: **54 checks passed, zero failed**. Every concurrent
response matched SHA-256 (64 MiB total, 2.97 s, 21.58 MiB/s aggregate); no local-source leak
was observed. The 8 MiB single download was 7.63 MiB/s, upload 6.89 MiB/s; the 512 KiB
download with 2% loss each way matched SHA-256 at 0.155 MiB/s. Route and process cleanup
also passed. These figures do not prove production-queue saturation occurred: forced
queue-full behavior is covered deterministically by the admission and one-slot runtime tests.

## Mixed-language acceptance progress (2026-09-26)

Development builds on the same WSL 2 host used the Go server and the default full checks,
16 concurrent 1 MiB responses, 8 MiB upload/download, 2% bidirectional loss and three revocation
rounds. The arrow below means consumer → egress, not server implementation parity.

| Client roles | Latest full run | Remaining failure |
| --- | --- | --- |
| Go → .NET | 54 passed, 0 failed | None in this run |
| Java → Go | 54 passed, 0 failed | None in this run |
| Go → Java | 53 passed, 1 failed | Lossy 512 KiB response stalled at 464308 B and timed out at 60 s |
| .NET → Go | 53 passed, 1 failed | No recovery within 90 s after egress restart; server restart subsequently restored traffic |

These runs drove fixes for Java/.NET consumer availability synchronization (including removed
peers), null `publicStunServers` from the Go server, .NET Linux TUN synchronous-handle/unbuffered
I/O and idle read shutdown, and lost-token refresh after a server restart in all three clients.
The recoverable data-login/control-login ordering rejection must not terminate the client and
withdraw its routes. An earlier Java-consumer run did terminate on this rejection and leaked;
the subsequent 54-check run above retained routes and observed no local-source leaks.

The two failing rows remain open acceptance work under #50/#74. A prior Go → Java run passed
its loss check, so the later failure must not be hidden by quoting only that earlier pass.
Windows/macOS, Java↔.NET full fault coverage, repeated reliability runs and adaptive congestion
control are not established by these results. A separate .NET NAT OPEN/DATA race exposed by
the existing reconnect integration test is tracked in #77; that test is not included in the
164 passing targeted egress/configuration/login-classification tests. Java's matching targeted
suite passed 158 tests, the Go client package tests passed, and the lab harness passed four tests.

After the final consumer-lock ordering adjustment, a Java → .NET smoke run passed all 11 checks
(TCP/UDP, route shape, 8 MiB each direction and 16 concurrent SHA-256-verified downloads).
That run explicitly skipped faults and loss; it does not replace a full Java↔.NET matrix.

The server binary needs `implementations/go/server/web/static/` to exist for its embed directive;
the workflow drops a placeholder there, and so can you.
