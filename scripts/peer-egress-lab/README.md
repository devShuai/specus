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
- 64 KiB down and 8 MiB up arrive intact through the egress; throughput and connect times are
  recorded as the first input for the performance baseline (#50), together with a download over a
  link that drops 2% each way.
- How large a response the egress can actually deliver. It cannot deliver an arbitrary one: past
  what the receiver's buffer holds, a download stalls and is reset rather than slowing down
  (issue #74). The ceiling moves with that buffer, so the lab measures it and records it in the
  report instead of asserting a number, and the intact-arrival check above sits well clear of it.
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

The server binary needs `implementations/go/server/web/static/` to exist for its embed directive;
the workflow drops a placeholder there, and so can you.
