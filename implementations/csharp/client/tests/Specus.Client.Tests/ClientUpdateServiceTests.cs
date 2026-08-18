using System.IO.Compression;
using System.Formats.Tar;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Specus.Client.Configuration;
using Specus.Client.Updates;

namespace Specus.Client.Tests;

public sealed class ClientUpdateServiceTests
{
    [Fact]
    public async Task VersionCheckUsesCamelCaseContractAndAcceptsAndroidGenericTarget()
    {
        HttpRequestMessage? captured = null;
        using var client = new HttpClient(new CallbackHandler(request =>
        {
            captured = request;
            return JsonResponse("""
                {
                  "updateAvailable": true,
                  "mandatory": true,
                  "latestVersion": "2.1.0",
                  "packageId": 42,
                  "downloadUrl": "/api/public/client-packages/42/download",
                  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "fileSize": 1024,
                  "changelogUrl": "https://specus.example/changelog"
                }
                """, request);
        }));
        using var service = new ClientUpdateService(client);

        var result = await service.CheckAsync(new Uri("https://specus.example/base"),
            new ClientUpdateTarget("android", "android", "any"), "2.0.0");

        Assert.True(result.UpdateAvailable);
        Assert.True(result.Mandatory);
        Assert.Equal("2.1.0", result.LatestVersion);
        Assert.Equal(42, result.PackageId);
        Assert.Equal(new Uri("https://specus.example/api/public/client-packages/42/download"),
            result.DownloadUri);
        Assert.NotNull(captured);
        Assert.Contains("implementation=android", captured!.RequestUri!.Query, StringComparison.Ordinal);
        Assert.Contains("platform=android", captured.RequestUri.Query, StringComparison.Ordinal);
        Assert.Contains("arch=any", captured.RequestUri.Query, StringComparison.Ordinal);
        Assert.Contains("current=2.0.0", captured.RequestUri.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VersionCheckRejectsHttpAndNonHostedUpdateMetadata()
    {
        using var client = new HttpClient(new CallbackHandler(request => JsonResponse("""
            {
              "updateAvailable": true,
              "mandatory": false,
              "latestVersion": "2.0.0",
              "packageId": null,
              "downloadUrl": "https://downloads.example/client.zip",
              "sha256": null,
              "fileSize": 0,
              "changelogUrl": null
            }
            """, request)));
        using var service = new ClientUpdateService(client);

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.CheckAsync(
            new Uri("http://specus.example"), ClientUpdateTarget.CSharpCommandLine, "1.0.0"));
        await Assert.ThrowsAsync<InvalidDataException>(() => service.CheckAsync(
            new Uri("https://specus.example"), ClientUpdateTarget.CSharpCommandLine, "1.0.0"));
    }

    [Fact]
    public async Task CrossOriginHttpsRedirectsAreRejectedForMetadataAndPackageBytes()
    {
        const string validJson = """
            {
              "updateAvailable": true,
              "mandatory": false,
              "latestVersion": "2.0.0",
              "packageId": 42,
              "downloadUrl": "/api/public/client-packages/42/download",
              "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "fileSize": 10,
              "changelogUrl": null
            }
            """;
        using (var metadataClient = new HttpClient(new CallbackHandler(_ =>
                   JsonResponse(validJson,
                       new HttpRequestMessage(HttpMethod.Get, "https://evil.example/version-check")))))
        using (var metadataService = new ClientUpdateService(metadataClient))
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => metadataService.CheckAsync(
                new Uri("https://specus.example"), ClientUpdateTarget.CSharpCommandLine, "1.0.0"));
        }

        var root = TempDirectory();
        var app = Path.Combine(root, "client");
        Directory.CreateDirectory(app);
        var entry = Path.Combine(app, "specus-client.dll");
        await File.WriteAllTextAsync(entry, "old");
        var package = Zip(("specus-client.dll", "new"));
        using var packageClient = new HttpClient(new CallbackHandler(_ =>
            PackageResponse(package,
                new HttpRequestMessage(HttpMethod.Get, "https://evil.example/package.zip"))));
        using var packageService = new ClientUpdateService(packageClient);
        try
        {
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                packageService.DownloadAndPrepareAsync(UpdateFor(package),
                    new ClientUpdateInstallationRequest(app, entry, entry, [], 1)));
        }
        finally
        {
            DeleteDirectory(root);
        }
    }

    [Fact]
    public async Task ExternalReleaseFollowsBoundedHttpsRedirectAndVerifiesBytes()
    {
        var root = TempDirectory();
        var app = Path.Combine(root, "client");
        Directory.CreateDirectory(app);
        var entry = Path.Combine(app, "specus-client.dll");
        await File.WriteAllTextAsync(entry, "old");
        var package = Zip(("specus-client.dll", "external-new"));
        var digest = Convert.ToHexString(SHA256.HashData(package)).ToLowerInvariant();
        var calls = new List<Uri>();
        using var client = new HttpClient(new CallbackHandler(request =>
        {
            calls.Add(request.RequestUri!);
            if (request.RequestUri!.Host == "specus.example")
            {
                return JsonResponse($$"""
                    {
                      "updateAvailable": true,
                      "mandatory": false,
                      "latestVersion": "2.0.0",
                      "packageId": null,
                      "downloadUrl": "https://github.example/releases/client.zip",
                      "sha256": "{{digest}}",
                      "fileSize": {{package.Length}},
                      "changelogUrl": "https://github.example/releases/changelog"
                    }
                    """, request);
            }
            if (request.RequestUri.Host == "github.example")
            {
                var redirect = new HttpResponseMessage(HttpStatusCode.Redirect)
                {
                    RequestMessage = request,
                };
                redirect.Headers.Location = new Uri(
                    "https://objects.example/client.zip?signature=temporary");
                return redirect;
            }
            return PackageResponse(package, request);
        }));
        using var service = new ClientUpdateService(client);
        ClientUpdateInstallationPlan? plan = null;
        try
        {
            var update = await service.CheckAsync(new Uri("https://specus.example"),
                ClientUpdateTarget.CSharpCommandLine, "1.0.0");
            Assert.Null(update.PackageId);
            plan = await service.DownloadAndPrepareAsync(update,
                new ClientUpdateInstallationRequest(app, entry, entry, [], int.MaxValue));

            Assert.Equal("external-new", await File.ReadAllTextAsync(
                Path.Combine(plan.PreparedDirectory, "specus-client.dll")));
            Assert.Contains(calls, uri => uri.Host == "objects.example"
                && uri.Query == "?signature=temporary");
        }
        finally
        {
            if (plan is not null) ClientUpdateService.CleanupPreparedUpdate(plan);
            DeleteDirectory(root);
        }
    }

    [Fact]
    public async Task ExternalReleaseRejectsUnsafeInitialUrlDowngradeAndExcessiveRedirects()
    {
        foreach (var invalidUrl in new[]
                 {
                     "http://downloads.example/client.zip",
                     "https://user@downloads.example/client.zip",
                     "https://downloads.example/client.zip?token=metadata",
                     "https://downloads.example/client.zip#fragment",
                 })
        {
            var json = $$"""
                {
                  "updateAvailable": true,
                  "mandatory": false,
                  "latestVersion": "2.0.0",
                  "packageId": null,
                  "downloadUrl": "{{invalidUrl}}",
                  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "fileSize": 10,
                  "changelogUrl": null
                }
                """;
            using var metadataClient = new HttpClient(new CallbackHandler(
                request => JsonResponse(json, request)));
            using var metadataService = new ClientUpdateService(metadataClient);
            await Assert.ThrowsAsync<InvalidDataException>(() => metadataService.CheckAsync(
                new Uri("https://specus.example"), ClientUpdateTarget.CSharpCommandLine, "1.0.0"));
        }

        var package = Zip(("specus-client.dll", "new"));
        var root = TempDirectory();
        var app = Path.Combine(root, "client");
        Directory.CreateDirectory(app);
        var entry = Path.Combine(app, "specus-client.dll");
        await File.WriteAllTextAsync(entry, "old");
        try
        {
            using (var downgradeClient = new HttpClient(new CallbackHandler(request =>
                   RedirectResponse(request, "http://objects.example/client.zip"))))
            using (var downgradeService = new ClientUpdateService(downgradeClient))
            {
                await Assert.ThrowsAsync<InvalidDataException>(() => downgradeService.DownloadAndPrepareAsync(
                    ExternalUpdateFor(package, "https://downloads.example/client.zip"),
                    new ClientUpdateInstallationRequest(app, entry, entry, [], 1)));
            }

            var redirectNumber = 0;
            using var loopClient = new HttpClient(new CallbackHandler(request => RedirectResponse(request,
                $"https://objects.example/client.zip?hop={++redirectNumber}")));
            using var loopService = new ClientUpdateService(loopClient);
            await Assert.ThrowsAsync<InvalidDataException>(() => loopService.DownloadAndPrepareAsync(
                ExternalUpdateFor(package, "https://downloads.example/client.zip"),
                new ClientUpdateInstallationRequest(app, entry, entry, [], 1)));
            Assert.Equal(6, redirectNumber);
        }
        finally
        {
            DeleteDirectory(root);
        }
    }

    [Fact]
    public async Task MetadataAndPackageBodyDeadlinesCoverStalledResponseStreams()
    {
        using (var metadataClient = new HttpClient(new CallbackHandler(request =>
               StalledResponse(request, contentLength: 1))))
        using (var metadataService = new ClientUpdateService(metadataClient,
                   metadataTimeout: TimeSpan.FromMilliseconds(50)))
        {
            await Assert.ThrowsAsync<TimeoutException>(() => metadataService.CheckAsync(
                new Uri("https://specus.example"), ClientUpdateTarget.CSharpCommandLine, "1.0.0"));
        }

        var root = TempDirectory();
        var app = Path.Combine(root, "client");
        Directory.CreateDirectory(app);
        var entry = Path.Combine(app, "specus-client.dll");
        await File.WriteAllTextAsync(entry, "old");
        var package = Zip(("specus-client.dll", "new"));
        try
        {
            using (var packageClient = new HttpClient(new CallbackHandler(request =>
                   StalledResponse(request, package.Length))))
            using (var packageService = new ClientUpdateService(packageClient,
                       packageTimeout: TimeSpan.FromMilliseconds(50)))
            {
                await Assert.ThrowsAsync<TimeoutException>(() => packageService.DownloadAndPrepareAsync(
                    ExternalUpdateFor(package, "https://downloads.example/client.zip"),
                    new ClientUpdateInstallationRequest(app, entry, entry, [], 1)));
            }

            using var cancellationClient = new HttpClient(new CallbackHandler(request =>
                StalledResponse(request, package.Length)));
            using var cancellationService = new ClientUpdateService(cancellationClient,
                packageTimeout: TimeSpan.FromSeconds(5));
            using var callerCancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                cancellationService.DownloadAndPrepareAsync(
                    ExternalUpdateFor(package, "https://downloads.example/client.zip"),
                    new ClientUpdateInstallationRequest(app, entry, entry, [], 1),
                    cancellationToken: callerCancellation.Token));
        }
        finally
        {
            DeleteDirectory(root);
        }
    }

    [Fact]
    public async Task HostedPackageMetadataRequiresTheExactRawRouteForItsPackageId()
    {
        var invalidUrls = new[]
        {
            "/api/public/client-packages/41/download",
            "/api/public/client-packages/%34%32/download",
            "/api/public/client-packages/42/./download",
            "/api/public/client-packages/42/download?raw=1",
            "/api/public/client-packages/42/download#fragment",
            "https://user@specus.example/api/public/client-packages/42/download",
        };
        foreach (var downloadUrl in invalidUrls)
        {
            var json = $$"""
                {
                  "updateAvailable": true,
                  "mandatory": false,
                  "latestVersion": "2.0.0",
                  "packageId": 42,
                  "downloadUrl": "{{downloadUrl}}",
                  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "fileSize": 10,
                  "changelogUrl": null
                }
                """;
            using var client = new HttpClient(new CallbackHandler(request => JsonResponse(json, request)));
            using var service = new ClientUpdateService(client);
            await Assert.ThrowsAsync<InvalidDataException>(() => service.CheckAsync(
                new Uri("https://specus.example"), ClientUpdateTarget.CSharpCommandLine, "1.0.0"));
        }
    }

    [Fact]
    public async Task ManuallyConstructedUpdateCannotBypassHostedPackageRouteBinding()
    {
        var invalid = new ClientUpdateCheck(true, false, "2.0.0", 42,
            new Uri("https://specus.example/api/public/client-packages/41/download?alias=42"),
            new string('a', 64), 10, null, new Uri("https://specus.example"));
        using var client = new HttpClient(new CallbackHandler(_ =>
            throw new InvalidOperationException("HTTP must not be reached")));
        using var service = new ClientUpdateService(client);

        await Assert.ThrowsAsync<InvalidDataException>(() => service.DownloadAndPrepareAsync(invalid,
            new ClientUpdateInstallationRequest("unused", "unused", "unused", [], 1)));
    }

    [Fact]
    public void ReplacementHelpersBoundParentWaitWithoutTouchingTheCurrentInstallOnTimeout()
    {
        var request = new ClientUpdateInstallationRequest("unused", "unused", "/restart/specus", [], 42);
        var windows = ClientUpdateService.BuildWindowsScript("C:\\current", "C:\\prepared",
            "C:\\backup", "C:\\helper.ps1", request);
        const string windowsTimeout =
            "if ($waitSeconds -ge 120) { Remove-UpdateFiles $true; exit 1 }";
        Assert.Contains(windowsTimeout, windows, StringComparison.Ordinal);
        Assert.DoesNotContain("C:\\current", windowsTimeout, StringComparison.Ordinal);
        Assert.DoesNotContain("C:\\backup", windowsTimeout, StringComparison.Ordinal);

        var posix = ClientUpdateService.BuildPosixScript("/current", "/prepared", "/backup",
            "/helper.sh", request);
        Assert.Contains("if [ \"$wait_seconds\" -ge 120 ]; then cleanup_update prepared; exit 1; fi",
            posix, StringComparison.Ordinal);
        var cleanupStart = posix.IndexOf("cleanup_update()", StringComparison.Ordinal);
        var cleanupEnd = posix.IndexOf("start_client()", cleanupStart, StringComparison.Ordinal);
        var posixCleanup = posix[cleanupStart..cleanupEnd];
        Assert.Contains("/prepared", posixCleanup, StringComparison.Ordinal);
        Assert.Contains("/helper.sh", posixCleanup, StringComparison.Ordinal);
        Assert.DoesNotContain("/current", posixCleanup, StringComparison.Ordinal);
        Assert.DoesNotContain("/backup", posixCleanup, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WindowsHelperRecoversJournaledBackupAndRestartsOldClientAfterInterruption()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = Path.Combine(TempDirectory(), "客户端 % & update");
        var app = Path.Combine(root, "client");
        var prepared = Path.Combine(root, "prepared");
        var backup = app + ".bak";
        Directory.CreateDirectory(app);
        Directory.CreateDirectory(prepared);
        var startedMarker = Path.Combine(root, "old-started.txt");
        var restartScript = Path.Combine(app, "restart.ps1");
        await File.WriteAllTextAsync(restartScript, $$"""
            [IO.File]::WriteAllText({{PowerShellLiteral(startedMarker)}},
              $env:SPECUS_SKIP_UPDATE_ONCE)
            Start-Sleep -Seconds 2
            """, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        await File.WriteAllTextAsync(Path.Combine(prepared, "new.txt"), "new");
        var helper = Path.Combine(root, "updater.ps1");
        var journal = Path.Combine(root, "update.journal");
        const string token = "0123456789abcdef0123456789abcdef";
        await File.WriteAllTextAsync(journal, token, Encoding.ASCII);
        var powershell = Path.Combine(Environment.SystemDirectory,
            "WindowsPowerShell", "v1.0", "powershell.exe");
        var request = new ClientUpdateInstallationRequest(app, restartScript, powershell,
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", restartScript,
                "中文 % & argument", "C:\\trailing\\"], int.MaxValue);
        var script = ClientUpdateService.BuildWindowsScript(app, prepared, backup, helper, request,
            journal, token, enableTestFaultInjection: true);
        await File.WriteAllTextAsync(helper, script,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

        try
        {
            var interrupted = StartPowerShell(helper);
            interrupted.StartInfo.Environment["SPECUS_UPDATE_TEST_ABORT_AFTER_BACKUP"] = "1";
            Assert.True(interrupted.Start());
            await interrupted.WaitForExitAsync();
            Assert.Equal(86, interrupted.ExitCode);
            Assert.False(Directory.Exists(app));
            Assert.True(Directory.Exists(backup));
            Assert.True(File.Exists(journal));
            Assert.True(File.Exists(helper));

            using var recovery = StartPowerShell(helper);
            Assert.True(recovery.Start());
            await recovery.WaitForExitAsync();
            Assert.Equal(1, recovery.ExitCode);
            Assert.True(Directory.Exists(app));
            Assert.False(Directory.Exists(backup));
            await WaitForFileAsync(startedMarker);
            Assert.Equal("1", await File.ReadAllTextAsync(startedMarker));
            Assert.False(File.Exists(journal));
        }
        finally
        {
            await Task.Delay(2200);
            DeleteDirectory(Path.GetDirectoryName(root)!);
        }
    }

    [Fact]
    public async Task WindowsHelperRestartsRestoredOldClientWhenNewVersionExitsDuringHealthCheck()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var temp = TempDirectory();
        var root = Path.Combine(temp, "rollback 客户端 % &");
        var app = Path.Combine(root, "client");
        var prepared = Path.Combine(root, "prepared");
        var backup = app + ".bak";
        Directory.CreateDirectory(app);
        Directory.CreateDirectory(prepared);
        var oldStarted = Path.Combine(root, "old-started.txt");
        var newStarted = Path.Combine(root, "new-started.txt");
        var restartScript = Path.Combine(app, "restart.ps1");
        await File.WriteAllTextAsync(restartScript, $$"""
            [IO.File]::WriteAllText({{PowerShellLiteral(oldStarted)}},
              $env:SPECUS_SKIP_UPDATE_ONCE)
            Start-Sleep -Seconds 2
            """, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        await File.WriteAllTextAsync(Path.Combine(prepared, "restart.ps1"), $$"""
            [IO.File]::WriteAllText({{PowerShellLiteral(newStarted)}}, 'attempted')
            exit 23
            """, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        var helper = Path.Combine(root, "updater.ps1");
        var journal = Path.Combine(root, "update.journal");
        const string token = "fedcba9876543210fedcba9876543210";
        await File.WriteAllTextAsync(journal, token, Encoding.ASCII);
        var powershell = Path.Combine(Environment.SystemDirectory,
            "WindowsPowerShell", "v1.0", "powershell.exe");
        var request = new ClientUpdateInstallationRequest(app, restartScript, powershell,
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", restartScript,
                "中文 % & argument", "C:\\trailing\\"], int.MaxValue);
        await File.WriteAllTextAsync(helper,
            ClientUpdateService.BuildWindowsScript(app, prepared, backup, helper, request,
                journal, token),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

        try
        {
            using var update = StartPowerShell(helper);
            Assert.True(update.Start());
            await update.WaitForExitAsync();
            Assert.Equal(1, update.ExitCode);
            await WaitForFileAsync(newStarted);
            await WaitForFileAsync(oldStarted);
            Assert.Equal("1", await File.ReadAllTextAsync(oldStarted));
            Assert.True(Directory.Exists(app));
            Assert.False(Directory.Exists(backup));
            Assert.False(File.Exists(journal));
        }
        finally
        {
            await Task.Delay(2200);
            DeleteDirectory(temp);
        }
    }

    [Fact]
    public async Task VerifiedZipPreparesSiblingSwapPreservesConfigAndWritesRollbackHelper()
    {
        var root = TempDirectory();
        var app = Path.Combine(root, "client");
        Directory.CreateDirectory(app);
        var entry = Path.Combine(app, "specus-client.dll");
        await File.WriteAllTextAsync(entry, "old-client");
        await File.WriteAllTextAsync(Path.Combine(app, "client.jsonc"), "local-secret-config");
        var package = Zip(("specus-client.dll", "new-client"), ("client.jsonc", "packaged-config"));
        var update = UpdateFor(package);
        using var client = new HttpClient(new CallbackHandler(request => PackageResponse(package, request)));
        using var service = new ClientUpdateService(client);
        ClientUpdateInstallationPlan? plan = null;
        try
        {
            var unownedBackup = app + ".bak";
            Directory.CreateDirectory(unownedBackup);
            await File.WriteAllTextAsync(Path.Combine(unownedBackup, "keep.txt"), "user-data");
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                service.DownloadAndPrepareAsync(update,
                    new ClientUpdateInstallationRequest(app, entry, entry, [], 12345)));
            Assert.Equal("user-data", await File.ReadAllTextAsync(
                Path.Combine(unownedBackup, "keep.txt")));
            Directory.Delete(unownedBackup, recursive: true);

            plan = await service.DownloadAndPrepareAsync(update,
                new ClientUpdateInstallationRequest(app, entry, entry, ["--config", "client.jsonc"], 12345));

            Assert.Equal("new-client", await File.ReadAllTextAsync(
                Path.Combine(plan.PreparedDirectory, "specus-client.dll")));
            Assert.Equal("local-secret-config", await File.ReadAllTextAsync(
                Path.Combine(plan.PreparedDirectory, "client.jsonc")));
            Assert.EndsWith(".bak", plan.BackupDirectory, StringComparison.Ordinal);
            Assert.Contains(plan.BackupDirectory, plan.ScriptContents, StringComparison.Ordinal);
            Assert.Contains(".specus-update-backup", plan.ScriptContents, StringComparison.Ordinal);
            Assert.Contains("12345", plan.ScriptContents, StringComparison.Ordinal);
            Assert.DoesNotContain("SPECUS_UPDATE_TEST_ABORT_AFTER_BACKUP", plan.ScriptContents,
                StringComparison.Ordinal);
            Assert.True(File.Exists(plan.HelperPath));
            Assert.True(File.Exists(plan.JournalPath));
            Assert.Equal(plan.OperationToken, (await File.ReadAllTextAsync(plan.JournalPath)).Trim());
            Assert.DoesNotContain(Directory.EnumerateFiles(root), path =>
                path.EndsWith(".download", StringComparison.Ordinal));
        }
        finally
        {
            if (plan is not null)
            {
                ClientUpdateService.CleanupPreparedUpdate(plan);
            }
            DeleteDirectory(root);
        }
    }

    [Fact]
    public async Task ShaMismatchAndTraversalArchiveLeaveCurrentInstallUntouched()
    {
        var root = TempDirectory();
        var app = Path.Combine(root, "client");
        Directory.CreateDirectory(app);
        var entry = Path.Combine(app, "specus-client.dll");
        await File.WriteAllTextAsync(entry, "old-client");
        try
        {
            var safePackage = Zip(("specus-client.dll", "new-client"));
            var badHashUpdate = UpdateFor(safePackage) with
            {
                Sha256 = new string('0', 64),
            };
            using (var hashClient = new HttpClient(new CallbackHandler(
                       request => PackageResponse(safePackage, request))))
            using (var hashService = new ClientUpdateService(hashClient))
            {
                await Assert.ThrowsAsync<CryptographicException>(() =>
                    hashService.DownloadAndPrepareAsync(badHashUpdate,
                        new ClientUpdateInstallationRequest(app, entry, entry, [], 1)));
            }

            var traversalPackage = Zip(("../escaped.txt", "escape"),
                ("specus-client.dll", "new-client"));
            using (var traversalClient = new HttpClient(new CallbackHandler(
                       request => PackageResponse(traversalPackage, request))))
            using (var traversalService = new ClientUpdateService(traversalClient))
            {
                await Assert.ThrowsAsync<InvalidDataException>(() =>
                    traversalService.DownloadAndPrepareAsync(UpdateFor(traversalPackage),
                        new ClientUpdateInstallationRequest(app, entry, entry, [], 1)));
            }

            Assert.Equal("old-client", await File.ReadAllTextAsync(entry));
            Assert.False(File.Exists(Path.Combine(root, "escaped.txt")));
            Assert.DoesNotContain(Directory.EnumerateFileSystemEntries(root), path =>
                Path.GetFileName(path).StartsWith(".client.next-", StringComparison.Ordinal)
                || Path.GetFileName(path).StartsWith(".specus-", StringComparison.Ordinal));
        }
        finally
        {
            DeleteDirectory(root);
        }
    }

    [Fact]
    public async Task TarGzipReleasePackageIsExtractedBeforeSwap()
    {
        var root = TempDirectory();
        var app = Path.Combine(root, "client");
        Directory.CreateDirectory(app);
        var entry = Path.Combine(app, "specus-client.dll");
        await File.WriteAllTextAsync(entry, "old-client");
        var package = TarGzip(("./specus-client.dll", "new-tar-client"));
        using var client = new HttpClient(new CallbackHandler(request => PackageResponse(package, request)));
        using var service = new ClientUpdateService(client);
        ClientUpdateInstallationPlan? plan = null;
        try
        {
            plan = await service.DownloadAndPrepareAsync(UpdateFor(package),
                new ClientUpdateInstallationRequest(app, entry, entry, [], 42));

            Assert.Equal("new-tar-client", await File.ReadAllTextAsync(
                Path.Combine(plan.PreparedDirectory, "specus-client.dll")));
        }
        finally
        {
            if (plan is not null) ClientUpdateService.CleanupPreparedUpdate(plan);
            DeleteDirectory(root);
        }
    }

    [Fact]
    public void BuildVersionDropsOnlyBuildMetadata()
    {
        Assert.Equal("1.2.3", ClientVersion.Normalize("1.2.3+abcdef"));
        Assert.Equal("1.2.3-rc.1", ClientVersion.Normalize("1.2.3-rc.1+abcdef"));
        Assert.Equal("999999999999999999999.2.3", ClientVersion.Normalize(
            "v999999999999999999999.2.3"));
        Assert.Null(ClientVersion.Normalize("1.2.3.0"));
        Assert.Null(ClientVersion.Normalize("1.2.3-01"));
        Assert.Null(ClientVersion.Normalize("1.2.3+"));
        Assert.Null(ClientVersion.Normalize("1.2.3+!!!"));
        Assert.DoesNotContain('+', ClientVersion.Current);
    }

    [Fact]
    public async Task VersionCheckNormalizesStrictSemverAndNeutralizesRemoteDisplayControls()
    {
        HttpRequestMessage? captured = null;
        using var client = new HttpClient(new CallbackHandler(request =>
        {
            captured = request;
            return JsonResponse("""
                {
                  "updateAvailable": true,
                  "mandatory": false,
                  "latestVersion": "v2.1.0-rc.1+build.7",
                  "packageId": 42,
                  "downloadUrl": "/api/public/client-packages/42/download",
                  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "fileSize": 1024,
                  "changelogUrl": "https://specus.example/log\u001b[31m\r\nforged\u2028line"
                }
                """, request);
        }));
        using var service = new ClientUpdateService(client);

        var result = await service.CheckAsync(new Uri("https://specus.example"),
            ClientUpdateTarget.CSharpCommandLine, "v2.0.0");

        Assert.Equal("2.1.0-rc.1+build.7", result.LatestVersion);
        Assert.Equal("https://specus.example/log forged line", result.ChangelogUrl);
        Assert.NotNull(result.ChangelogUrl);
        Assert.Contains("current=2.0.0", captured!.RequestUri!.Query, StringComparison.Ordinal);
        Assert.DoesNotContain('\u001b', result.ChangelogUrl!);
        Assert.DoesNotContain('\r', result.ChangelogUrl!);
        Assert.DoesNotContain('\n', result.ChangelogUrl!);
    }

    [Theory]
    [InlineData("1.2.3.0", "2.0.0")]
    [InlineData("1.2.3-01", "2.0.0")]
    [InlineData("1.2.3", "2.0.0+")]
    [InlineData("1.2.3", "2.0.0+!!!")]
    public async Task VersionCheckRejectsInvalidCurrentOrRemoteSemanticVersion(
        string currentVersion, string latestVersion)
    {
        var json = $$"""
            {
              "updateAvailable": true,
              "mandatory": false,
              "latestVersion": "{{latestVersion}}",
              "packageId": 42,
              "downloadUrl": "/api/public/client-packages/42/download",
              "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "fileSize": 1024,
              "changelogUrl": null
            }
            """;
        using var client = new HttpClient(new CallbackHandler(request => JsonResponse(json, request)));
        using var service = new ClientUpdateService(client);

        await Assert.ThrowsAnyAsync<Exception>(() => service.CheckAsync(
            new Uri("https://specus.example"), ClientUpdateTarget.CSharpCommandLine,
            currentVersion));
    }

    private static ClientUpdateCheck UpdateFor(byte[] package)
    {
        var origin = new Uri("https://specus.example");
        return new ClientUpdateCheck(true, false, "2.0.0", 42,
            new Uri(origin, "/api/public/client-packages/42/download"),
            Convert.ToHexString(SHA256.HashData(package)).ToLowerInvariant(), package.Length, null, origin);
    }

    private static ClientUpdateCheck ExternalUpdateFor(byte[] package, string downloadUrl)
    {
        var origin = new Uri("https://specus.example");
        return new ClientUpdateCheck(true, false, "2.0.0", null, new Uri(downloadUrl),
            Convert.ToHexString(SHA256.HashData(package)).ToLowerInvariant(), package.Length, null, origin);
    }

    private static HttpResponseMessage JsonResponse(string json, HttpRequestMessage request) => new(HttpStatusCode.OK)
    {
        RequestMessage = request,
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    private static HttpResponseMessage PackageResponse(byte[] package, HttpRequestMessage request)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = request,
            Content = new ByteArrayContent(package),
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        response.Content.Headers.ContentLength = package.Length;
        response.Content.Headers.ContentDisposition = new ContentDispositionHeaderValue("attachment")
        {
            FileNameStar = "specus-client.zip",
        };
        return response;
    }

    private static HttpResponseMessage RedirectResponse(HttpRequestMessage request, string location)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Redirect)
        {
            RequestMessage = request,
        };
        response.Headers.Location = new Uri(location);
        return response;
    }

    private static HttpResponseMessage StalledResponse(HttpRequestMessage request, long contentLength)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = request,
            Content = new StreamContent(new StallingStream()),
        };
        response.Content.Headers.ContentLength = contentLength;
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return response;
    }

    private static byte[] Zip(params (string Path, string Content)[] files)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var file in files)
            {
                var entry = archive.CreateEntry(file.Path, CompressionLevel.Fastest);
                using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
                writer.Write(file.Content);
            }
        }
        return output.ToArray();
    }

    private static byte[] TarGzip(params (string Path, string Content)[] files)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true))
        using (var archive = new TarWriter(gzip, leaveOpen: false))
        {
            foreach (var file in files)
            {
                archive.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, file.Path)
                {
                    DataStream = new MemoryStream(Encoding.UTF8.GetBytes(file.Content)),
                    Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                });
            }
        }
        return output.ToArray();
    }

    private static string TempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"specus-update-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private static Process StartPowerShell(string scriptPath)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory,
                    "WindowsPowerShell", "v1.0", "powershell.exe"),
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        process.StartInfo.ArgumentList.Add("-NoLogo");
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-NonInteractive");
        process.StartInfo.ArgumentList.Add("-ExecutionPolicy");
        process.StartInfo.ArgumentList.Add("Bypass");
        process.StartInfo.ArgumentList.Add("-File");
        process.StartInfo.ArgumentList.Add(scriptPath);
        return process;
    }

    private static async Task WaitForFileAsync(string path)
    {
        for (var attempt = 0; attempt < 30 && !File.Exists(path); attempt++)
        {
            await Task.Delay(100);
        }
        Assert.True(File.Exists(path), $"Expected helper restart marker at {path}");
    }

    private static string PowerShellLiteral(string value) =>
        "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";

    private static void DeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); } catch { }
    }

    private sealed class CallbackHandler(Func<HttpRequestMessage, HttpResponseMessage> callback)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) => Task.FromResult(callback(request));
    }

    private sealed class StallingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count,
            CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
    }
}
