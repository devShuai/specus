# Deployment Assets

Deployment files are organized by runtime target.

- `java-server/systemd`: production-style Linux systemd install/update scripts for the Java reference server.
- `openresty`: OpenResty configuration and helper script for serving the admin web as cached,
  pre-compressed static files while proxying API/WebSocket traffic to tunnel-server.

Future targets should be added as sibling directories, for example
`go-server/systemd`, `csharp-server/systemd`, or `docker`.
