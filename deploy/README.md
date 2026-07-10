# Deployment Assets

Deployment files are organized by runtime target.

- `java-server/systemd`: production-style Linux systemd install/update scripts for the Java reference server.
- `go-server/systemd`: Linux systemd install/update scripts for the Go server.
- `csharp-server/systemd`: Linux systemd install/update scripts for the framework-dependent .NET server publish output.
- `openresty`: OpenResty configuration and helper script for serving the admin web as cached,
  pre-compressed static files while proxying API/WebSocket traffic to tunnel-server.

The C server keeps its lightweight systemd example under
`implementations/c/server/deploy/systemd`. Future targets such as Docker should be added as sibling directories.
