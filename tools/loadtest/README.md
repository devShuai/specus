# Load test helpers

This directory contains standalone helpers for capacity checks. They are not part of the Maven build.

## idle-tcp-hold

Open and hold many TCP connections against one public specus port.

```powershell
go run .\tools\loadtest\idle_tcp_hold.go -addr 127.0.0.1:19000 -connections 10000 -ramp 200
```

Flags:

- `-addr`: target TCP address.
- `-connections`: total connections to keep open.
- `-ramp`: new connections per second.
- `-read`: keep a read loop running for every connection.

Use this for the first P0 acceptance check: 10k mostly idle connections held long enough to watch fd count, heap, direct memory, and the admin overview metrics.

## tcp-stream-load

Run an end-to-end echo workload through a public TCP specus. The default levels are the protocol audit's
`1/10/100/1000` concurrent streams. Each level produces operation count, errors, bidirectional throughput,
and bounded-histogram p50/p95/p99 latency in JSON.

```powershell
go run .\tools\loadtest\tcp_stream_load.go `
  -addr specus.example.com:19000 `
  -duration 60s `
  -output .\tcp-capacity.json
```

The target must be a byte-for-byte TCP echo service behind the specus. Use `-slow-read 250ms` to exercise
flow-control behavior with slow consumers. An operation counts as successful only when the echoed payload
matches exactly.

On Linux, apply repeatable RTT/loss profiles to the test interface before a run:

```bash
sudo ./tools/loadtest/netem-profile.sh apply eth0 100 3
go run ./tools/loadtest/tcp_stream_load.go -addr specus.example.com:19000 -duration 60s
sudo ./tools/loadtest/netem-profile.sh clear eth0
```

Record clean, `20/100/300 ms`, `1%/3%` loss, and slow-reader runs. Always clear the qdisc after testing.

## Peer codec microbenchmarks

The SPM2 codec baselines use the same `64/512/1200` byte payload sizes in each desktop runtime:

```powershell
mvn -pl implementations/java/client -Ppeer-mesh-benchmark -DskipTests package
java -jar implementations/java/client/target/specus-client-1.0.0-SNAPSHOT-benchmarks.jar PeerDataFrameCodecBenchmark

Set-Location implementations/go/client
go test ./internal/client -run '^$' -bench BenchmarkPeerDataFrameCodec -benchmem

dotnet run -c Release --project implementations/csharp/client/benchmarks/Specus.Client.Benchmarks
```
