# Load test helpers

This directory contains standalone helpers for capacity checks. They are not part of the Maven build.

## idle-tcp-hold

Open and hold many TCP connections against one public tunnel port.

```powershell
go run .\tools\loadtest\idle_tcp_hold.go -addr 127.0.0.1:19000 -connections 10000 -ramp 200
```

Flags:

- `-addr`: target TCP address.
- `-connections`: total connections to keep open.
- `-ramp`: new connections per second.
- `-read`: keep a read loop running for every connection.

Use this for the first P0 acceptance check: 10k mostly idle connections held long enough to watch fd count, heap, direct memory, and the admin overview metrics.
