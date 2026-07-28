---
name: deploy-java-server-ali2
description: Current specus project only. Use when the user asks to package/build the Java specus-server and push/deploy it to ali2, including requests like "打包server，推到ali2", "更新服务端到ali2", or "部署 Java server 到 ali2". Also deploy the OpenResty-served admin frontend for specus.devshuai.com. This skill is not for other repositories or other deployment targets.
---

# Deploy Java Server To ali2

This skill is scoped to the current specus repository. Do not use it for other repositories unless the user explicitly says to adapt it.

## Workflow

1. Start in the repository root and inspect the worktree with `git status --short`. Do not commit, stage, reset, or revert unless the user explicitly asks.
2. Package the Java reference server with frontend assets included:

```powershell
mvn -pl :specus-server -am -DskipTests clean package
```

Use this command from the repository root. The Maven build for `specus-server` invokes the admin-web Java deploy step, so the jar should include the current management UI. Do not add `-Dspecus.server.web.skip=true` for ali2 deployment unless the user explicitly wants a backend-only jar.

3. If `clean` fails because Windows reports `Access is denied` or `Failed to clean ... target`, assume a local Java/Maven/IDE process is holding files under `target`. First report the lock symptom. If the user still wants deployment immediately, use the non-clean fallback only after noting the tradeoff:

```powershell
mvn -pl :specus-server -am -DskipTests package
```

If both commands fail, stop and report the Maven error. Do not recursively delete locked target directories without explicit user approval.

4. Build the OpenResty static admin frontend:

```powershell
npm run build:openresty
```

Run it from `apps/admin-web`. This produces `apps/admin-web/dist` plus precompressed `.gz` / `.br` assets for OpenResty. If this fails, stop and do not deploy a stale frontend.

5. Select the deployable jar from:

```text
implementations/java/server/target/specus-server-1.0-SNAPSHOT.jar
```

If the version changes, choose the newest `implementations/java/server/target/specus-server-*.jar` that is not `*.jar.original`.

6. Push the jar, current systemd deployment scripts, OpenResty deployment files, and built admin frontend to `ali2`. Network/SSH/SCP commands require escalated approval in this environment.

Typical commands:

```powershell
scp implementations/java/server/target/specus-server-1.0-SNAPSHOT.jar ali2:/tmp/specus-server.jar
scp -r deploy/java-server/systemd ali2:/tmp/specus-java-systemd
scp -r deploy/openresty ali2:/tmp/specus-openresty
scp -r apps/admin-web/dist ali2:/tmp/specus-admin-web-dist
ssh ali2 "sudo bash /tmp/specus-java-systemd/update.sh /tmp/specus-server.jar"
ssh ali2 "sudo ADMIN_WEB_DIST=/tmp/specus-admin-web-dist bash /tmp/specus-openresty/install-admin-web.sh && sudo openresty -s reload"
```

The update script syncs `specus-server.service` and `specus-server.env.example`, backs up the current jar, stops `specus-server`, replaces the jar, starts the service, performs its health check, and rolls back on failure.

The OpenResty script installs `apps/admin-web/dist` into `/opt/specus/admin-web`, fixes static file permissions for the OpenResty worker, installs `deploy/openresty/specus.conf` as `/usr/local/openresty/nginx/conf/conf.d/specus.devshuai.com.conf` by default when that directory exists, runs `openresty -t`, and then the deployment command reloads OpenResty. Override `OPENRESTY_CONF_NAME` only when deploying to a different config file. The current config is for `specus.devshuai.com` and proxies dynamic requests to `127.0.0.1:8088`.

7. Verify the remote service and OpenResty frontend:

```powershell
ssh ali2 "systemctl is-active specus-server && journalctl -u specus-server -n 80 --no-pager"
ssh ali2 "openresty -t && curl -k -I https://specus.devshuai.com/ && curl -k -I -H 'Accept-Encoding: gzip' https://specus.devshuai.com/assets/$(ls /opt/specus/admin-web/assets | grep '^index-.*\.js$' | head -n 1)"
```

Summarize whether the service is active, whether OpenResty config test passed, and whether `/` and a hashed asset return the expected cache/compression headers. Include only important recent log lines. Do not paste long logs unless the user asks.

## Configuration Rules

- Existing remote config lives at `/etc/specus-server/specus-server.env`; do not overwrite it.
- `deploy/java-server/systemd/update.sh` refreshes `/etc/specus-server/specus-server.env.example` only.
- OpenResty config lives under `deploy/openresty` locally and normally installs to `/usr/local/openresty/nginx/conf/conf.d/specus.devshuai.com.conf` on ali2. Do not overwrite certificates under `/usr/local/openresty/nginx/certs`.
- OpenResty static root is `/opt/specus/admin-web`; it is safe for `install-admin-web.sh` to replace this static directory with the freshly built `dist`.
- If deployment fails because a new required env var is missing, compare the example with the live env and tell the user exactly which field is missing before editing. Only edit remote config when the user asks.

## Safety Notes

- Treat ali2 as production-like. Avoid destructive remote commands except the project-provided `update.sh` flow.
- For OpenResty, use the project-provided `deploy/openresty/install-admin-web.sh` flow. Do not manually edit remote nginx/OpenResty config unless the user asks.
- Do not use `git reset`, `git checkout --`, or broad deletes to make the build pass.
- If the local build fails, do not deploy an older jar silently. Ask or clearly state that deployment did not happen.
