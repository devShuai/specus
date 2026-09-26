# Peer egress Linux lab

Issue #56's acceptance list, run against real processes on one Linux machine: the Go server, a Go
consumer with a TUN device and routes of its own, a Go egress, and a target that records who
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

The server binary needs `implementations/go/server/web/static/` to exist for its embed directive;
the workflow drops a placeholder there, and so can you.
