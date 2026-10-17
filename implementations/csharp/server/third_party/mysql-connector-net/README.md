# Local Connector/NET TLS cancellation patch

This is an unsigned, local-source build of Oracle MySQL Connector/NET **26.7.0**,
not an Oracle binary or a published NuGet package. It is used only by the .NET 10
server. Its informational version is `26.7.0+specus.tls-cancel.1`; the local
project's compatibility package ID/version override the existing transitive
`MySql.Data/26.7.0` dependency. `IsPackable=false`; do not publish this identity.
No Oracle signing key, delay signing or signature impersonation is used.

The original driver registers a cancellation callback that throws while its TLS
handshake does not receive the cancellation token. A host can consequently fail
to stop, and public connection closure cannot reach the still-unassigned driver.
Only two upstream runtime files are changed:

- `common/Ssl.cs`: use the cancellation-aware TLS authentication overload in the
  async path and its synchronous wrapper; dispose a failed handshake. Preserve
  the original server-validation callback, hostname, client certificates,
  selected TLS protocols and revocation-check setting. Do not weaken SSL modes.
- `Driver.cs`: scope and dispose the linked timeout/cancellation source; after
  cleanup, preserve the original caller token only for actual caller cancellation.
  Other failures are not suppressed or relabeled as caller cancellation.

`upstream/` retains the complete library sources from the official source archive;
`LICENSE` retains its GPLv2, Universal FOSS Exception and third-party notices.
The original Windows x64 Kerberos native dependencies are retained in `MITLibs/`.
The upstream project and assembly metadata remain available for comparison; the
custom project builds only .NET 10, retains signed-provider friend declarations,
and clearly marks the local binary using `PatchVersionInfo.cs`.
Local build/publish artifacts also carry the corresponding sources, build recipe,
provenance and license under `third-party/mysql-connector-net/`.
The server executable project selects the Windows x64 native runtime files using
its actual publish RID; RID-agnostic library builds must not select them by host OS.

Source: https://cdn.mysql.com/Downloads/Connector-Net/mysql-connector-net-26.7.0-src.zip

Archive SHA-256: `215f2f87d974c44ae5b8c0d47c6b1c81f0322f211490ded50b6c67746f2fd757`.
`INFO_SRC` identifies `release/26.7.0`, commit
`fb441af4400e1afa8599e73c16239644e654f543`. The public GitHub 9.x tree is not used
as a substitute for this release's source.

Run `python3 verify_source.py` before building. `provenance.json` pins the original
source/native inputs and the exact two patched inputs, with Git newline conversion
accounted for. `tls-cancel.patch` can be applied to the original library source
directory with `git apply`; no network fetch is needed during normal builds.

Restore `audit/UpstreamAudit.csproj` independently to retain upstream package
advisory coverage alongside normal dependency auditing. Updating or retiring this
patch requires the native MySQL regressions: real TLS held indefinitely by a
transparent proxy while actual EF/Host.Stop finishes within the unchanged 10-second
gate **before** releasing TLS, original caller-token identity, trusted/untrusted
CA checks, hostname rejection and explicit local-binary identity. Run the full
server/protocol suite and all three mandatory real-database projects as well.
Keep historical failures; do not disable TLS, shorten the held interval, increase
the gate, or replace these cases with mocks. An upstream update must pass the same
regressions before the local override is removed.
