---
name: deploy-java-server-ali2
description: Current shuai-tunnel project only. Use when the user asks to package/build the Java tunnel-server and push/deploy it to ali2, including requests like "打包server，推到ali2", "更新服务端到ali2", or "部署 Java server 到 ali2". This skill is not for other repositories or other deployment targets.
---

# Deploy Java Server To ali2

This skill is scoped to the current project: `C:\Users\shshi\dev\backend\shuai-tunnel`. Do not use it for other repositories unless the user explicitly says to adapt it.

## Workflow

1. Start in the repository root and inspect the worktree with `git status --short`. Do not commit, stage, reset, or revert unless the user explicitly asks.
2. Package the Java reference server with frontend assets included:

```powershell
mvn -pl :tunnel-server -am -DskipTests clean package
```

Use this command from the repository root. The Maven build for `tunnel-server` invokes the admin-web Java deploy step, so the jar should include the current management UI. Do not add `-Dtunnel.server.web.skip=true` for ali2 deployment unless the user explicitly wants a backend-only jar.

3. If `clean` fails because Windows reports `Access is denied` or `Failed to clean ... target`, assume a local Java/Maven/IDE process is holding files under `target`. First report the lock symptom. If the user still wants deployment immediately, use the non-clean fallback only after noting the tradeoff:

```powershell
mvn -pl :tunnel-server -am -DskipTests package
```

If both commands fail, stop and report the Maven error. Do not recursively delete locked target directories without explicit user approval.

4. Select the deployable jar from:

```text
implementations/java/server/target/tunnel-server-1.0-SNAPSHOT.jar
```

If the version changes, choose the newest `implementations/java/server/target/tunnel-server-*.jar` that is not `*.jar.original`.

5. Push the jar and current systemd deployment scripts to `ali2`. Network/SSH/SCP commands require escalated approval in this environment.

Typical commands:

```powershell
scp implementations/java/server/target/tunnel-server-1.0-SNAPSHOT.jar ali2:/tmp/tunnel-server.jar
scp -r deploy/java-server/systemd ali2:/tmp/shuai-tunnel-java-systemd
ssh ali2 "sudo bash /tmp/shuai-tunnel-java-systemd/update.sh /tmp/tunnel-server.jar"
```

The update script syncs `tunnel-server.service` and `tunnel-server.env.example`, backs up the current jar, stops `tunnel-server`, replaces the jar, starts the service, performs its health check, and rolls back on failure.

6. Verify the remote service:

```powershell
ssh ali2 "systemctl is-active tunnel-server && journalctl -u tunnel-server -n 80 --no-pager"
```

Summarize whether the service is active and include only the important recent log lines. Do not paste long logs unless the user asks.

## Configuration Rules

- Existing remote config lives at `/etc/tunnel-server/tunnel-server.env`; do not overwrite it.
- `deploy/java-server/systemd/update.sh` refreshes `/etc/tunnel-server/tunnel-server.env.example` only.
- If deployment fails because a new required env var is missing, compare the example with the live env and tell the user exactly which field is missing before editing. Only edit remote config when the user asks.

## Safety Notes

- Treat ali2 as production-like. Avoid destructive remote commands except the project-provided `update.sh` flow.
- Do not use `git reset`, `git checkout --`, or broad deletes to make the build pass.
- If the local build fails, do not deploy an older jar silently. Ask or clearly state that deployment did not happen.
