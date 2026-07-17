# Deployment Assets

Deployment files are organized by runtime target.

- `java-server/systemd`: production-style Linux systemd install/update scripts for the Java reference server.
- `stun-server/systemd`: Java/Go/.NET standalone RFC 5780 STUN server templates with four UDP endpoints, rate limiting, firewall guidance and Prometheus alerts.
- `stun-server/remote`: config-driven Java STUN deployment for the `ali2` A1 node and `ali` A2 node, including authenticated private-network forwarding, per-node environment rendering and rollback.
- `go-server/systemd`: Linux systemd install/update scripts for the Go server.
- `csharp-server/systemd`: Linux systemd install/update scripts for the framework-dependent .NET server publish output.
- `openresty`: OpenResty configuration and helper script for serving the admin web as cached,
  pre-compressed static files while proxying API/WebSocket traffic to tunnel-server.
- `remote`: macOS/Linux Bash and Windows PowerShell entry points that build the current workspace,
  upload it over SSH, reuse the Java/OpenResty update scripts, and verify the remote deployment;
  the optional `IncludeStun` stage first updates and verifies both standalone STUN nodes.

The C server keeps its lightweight systemd example under
`implementations/c/server/deploy/systemd`. Future targets such as Docker should be added as sibling directories.
