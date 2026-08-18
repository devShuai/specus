using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Specus.Client.Configuration;

namespace Specus.Client.Updates;

public sealed record ClientUpdateTarget(string Implementation, string Platform, string Arch)
{
    public static ClientUpdateTarget CSharpCommandLine { get; } = new("csharp", "any", "any");

    public static ClientUpdateTarget CSharpDesktop => new(
        "csharp",
        "windows",
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
            System.Runtime.InteropServices.Architecture.Arm64 ? "arm64" : "x64");
}

public sealed record ClientUpdateCheck(
    bool UpdateAvailable,
    bool Mandatory,
    string? LatestVersion,
    long? PackageId,
    Uri? DownloadUri,
    string? Sha256,
    long FileSize,
    string? ChangelogUrl,
    Uri ServerOrigin);

public sealed record ClientUpdateInstallationRequest(
    string ApplicationDirectory,
    string EntryFilePath,
    string RestartExecutable,
    IReadOnlyList<string> RestartArguments,
    int ProcessId);

public sealed record ClientUpdateInstallationPlan(
    string PreparedDirectory,
    string BackupDirectory,
    string HelperPath,
    string JournalPath,
    string OperationToken,
    string ScriptContents,
    bool IsWindows);

public sealed record ClientUpdateProgress(long BytesReceived, long TotalBytes);

/// <summary>
/// Checks the public package catalogue and prepares a verified, same-volume directory swap.
/// The helper is intentionally outside the application directory so Windows can run it after
/// the current executable has exited and released its file locks.
/// </summary>
public sealed class ClientUpdateService : IClientUpdateService, IDisposable
{
    public const long MaxPackageBytes = 2L * 1024 * 1024 * 1024;
    internal const long MaxExpandedBytes = 4L * 1024 * 1024 * 1024;
    internal const int MaxArchiveEntries = 20_000;
    private const int MaxVersionResponseBytes = 64 * 1024;
    private const string BackupOwnershipMarker = ".specus-update-backup";
    private const string BackupOwnershipValue = "specus-update-backup-v1";
    private const string TransactionMarker = ".specus-update-transaction";
    private static readonly TimeSpan DefaultMetadataTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DefaultPackageTimeout = TimeSpan.FromMinutes(30);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly TimeSpan _metadataTimeout;
    private readonly TimeSpan _packageTimeout;

    public ClientUpdateService(HttpClient? httpClient = null, TimeSpan? metadataTimeout = null,
        TimeSpan? packageTimeout = null)
    {
        _httpClient = httpClient ?? BuildDefaultClient();
        _ownsHttpClient = httpClient is null;
        _metadataTimeout = RequirePositiveTimeout(metadataTimeout ?? DefaultMetadataTimeout,
            nameof(metadataTimeout));
        _packageTimeout = RequirePositiveTimeout(packageTimeout ?? DefaultPackageTimeout,
            nameof(packageTimeout));
    }

    public static HttpClient BuildDefaultClient() => new(new SocketsHttpHandler
    {
        // Redirects are handled explicitly so catalogue metadata remains same-origin while an
        // external release may follow a bounded HTTPS-only chain before digest verification.
        AllowAutoRedirect = false,
        AutomaticDecompression = System.Net.DecompressionMethods.None,
        ConnectTimeout = TimeSpan.FromSeconds(15),
    })
    {
        Timeout = Timeout.InfiniteTimeSpan,
    };

    public async Task<ClientUpdateCheck> CheckAsync(Uri serverBaseUri, ClientUpdateTarget target,
        string currentVersion, CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_metadataTimeout);
        try
        {
            return await CheckCoreAsync(serverBaseUri, target, currentVersion, timeout.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("Version-check metadata timed out", exception);
        }
    }

    private async Task<ClientUpdateCheck> CheckCoreAsync(Uri serverBaseUri, ClientUpdateTarget target,
        string currentVersion, CancellationToken cancellationToken)
    {
        var origin = RequireSecureServerOrigin(serverBaseUri);
        ValidateTarget(target);
        if (!ClientSemanticVersion.TryNormalize(currentVersion, out var canonicalCurrent))
        {
            throw new ArgumentException("currentVersion must be a semantic version", nameof(currentVersion));
        }

        var query = $"implementation={Uri.EscapeDataString(target.Implementation)}" +
            $"&platform={Uri.EscapeDataString(target.Platform)}" +
            $"&arch={Uri.EscapeDataString(target.Arch)}" +
            $"&current={Uri.EscapeDataString(canonicalCurrent)}";
        var endpoint = new Uri(origin, $"/api/public/client-version-check?{query}");
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        EnsureSecureFinalUri(response, origin);
        EnsureSuccessWithoutRemoteReason(response);
        if (response.Content.Headers.ContentLength is > MaxVersionResponseBytes)
        {
            throw new InvalidDataException("Version-check response is too large");
        }

        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        var json = await ReadLimitedAsync(responseStream, MaxVersionResponseBytes, cancellationToken)
            .ConfigureAwait(false);
        var payload = JsonSerializer.Deserialize<ClientVersionCheckPayload>(json, JsonOptions)
            ?? throw new InvalidDataException("Version-check response is empty");
        string? canonicalLatest = null;
        if (payload.LatestVersion is not null
            && !ClientSemanticVersion.TryNormalize(payload.LatestVersion, out canonicalLatest))
        {
            throw new InvalidDataException("Update metadata has an invalid latestVersion");
        }
        var safeChangelog = ClientUpdateDisplay.Sanitize(payload.ChangelogUrl);
        if (safeChangelog is not null
            && (!Uri.TryCreate(safeChangelog, UriKind.Absolute, out var changelogUri)
                || changelogUri.Scheme != Uri.UriSchemeHttps
                || string.IsNullOrWhiteSpace(changelogUri.Host)
                || !string.IsNullOrEmpty(changelogUri.UserInfo)))
        {
            throw new InvalidDataException("Update changelogUrl must be an absolute HTTPS URL");
        }
        if (!payload.UpdateAvailable)
        {
            return new ClientUpdateCheck(false, payload.Mandatory, canonicalLatest,
                payload.PackageId, null, payload.Sha256, payload.FileSize, safeChangelog, origin);
        }

        if (canonicalLatest is null)
        {
            throw new InvalidDataException("Update metadata has no valid latestVersion");
        }
        if (payload.PackageId is <= 0)
        {
            throw new InvalidDataException("Update metadata has an invalid packageId");
        }
        if (string.IsNullOrWhiteSpace(payload.DownloadUrl))
        {
            throw new InvalidDataException("Update metadata has no downloadUrl");
        }
        if (!IsSha256(payload.Sha256))
        {
            throw new InvalidDataException("Update metadata has no valid SHA-256 digest");
        }
        if (payload.FileSize <= 0 || payload.FileSize > MaxPackageBytes)
        {
            throw new InvalidDataException("Update package size is outside the permitted range");
        }

        Uri downloadUri;
        if (payload.PackageId is { } packageId)
        {
            if (!Uri.TryCreate(origin, payload.DownloadUrl, out var hostedUri)
                || hostedUri is null || !hostedUri.IsAbsoluteUri || !SameOrigin(origin, hostedUri)
                || !IsExactHostedPackageUri(hostedUri, packageId))
            {
                throw new InvalidDataException(
                    "Hosted update download must exactly match its HTTPS package route");
            }
            downloadUri = hostedUri;
        }
        else if (!Uri.TryCreate(payload.DownloadUrl, UriKind.Absolute, out var externalUri)
                 || externalUri is null || !IsInitialExternalDownloadUri(externalUri))
        {
            throw new InvalidDataException(
                "External update download must be an absolute HTTPS URL without credentials, query or fragment");
        }
        else
        {
            downloadUri = externalUri;
        }

        return new ClientUpdateCheck(true, payload.Mandatory, canonicalLatest,
            payload.PackageId, downloadUri, payload.Sha256!.ToLowerInvariant(), payload.FileSize,
            safeChangelog, origin);
    }

    public async Task<ClientUpdateInstallationPlan> DownloadAndPrepareAsync(ClientUpdateCheck update,
        ClientUpdateInstallationRequest installation, IProgress<ClientUpdateProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateInstallableUpdate(update);
        var paths = ResolveInstallationPaths(installation);
        EnsureReservedMarkerPathsAbsent(paths.ApplicationDirectory);
        var backupDirectory = paths.ApplicationDirectory + ".bak";
        EnsureBackupPathOwnedOrAbsent(backupDirectory);
        var archivePath = Path.Combine(paths.ParentDirectory, $".specus-package-{Guid.NewGuid():N}.download");
        var preparedDirectory = Path.Combine(paths.ParentDirectory,
            $".{Path.GetFileName(paths.ApplicationDirectory)}.next-{Guid.NewGuid():N}");
        var operationToken = Guid.NewGuid().ToString("N");
        var helperExtension = OperatingSystem.IsWindows() ? ".ps1" : ".sh";
        var helperPath = Path.Combine(paths.ParentDirectory,
            $".specus-updater-{operationToken}{helperExtension}");
        var journalPath = Path.Combine(paths.ParentDirectory,
            $".specus-update-{operationToken}.journal");

        try
        {
            var fileName = await DownloadVerifiedAsync(update, archivePath, progress, cancellationToken)
                .ConfigureAwait(false);
            Directory.CreateDirectory(preparedDirectory);
            await ExtractArchiveAsync(archivePath, fileName, preparedDirectory, cancellationToken)
                .ConfigureAwait(false);

            var preparedEntry = SafeCombine(preparedDirectory, paths.EntryRelativePath);
            if (!File.Exists(preparedEntry))
            {
                throw new InvalidDataException(
                    $"Update package does not contain {paths.EntryRelativePath}");
            }
            if (paths.RestartRelativePath is { } restartRelative
                && !File.Exists(SafeCombine(preparedDirectory, restartRelative)))
            {
                throw new InvalidDataException(
                    $"Update package does not contain {restartRelative}");
            }
            PreserveLocalFile(paths.ApplicationDirectory, preparedDirectory, "client.jsonc");

            var isWindows = OperatingSystem.IsWindows();
            var script = isWindows
                ? BuildWindowsScript(paths.ApplicationDirectory, preparedDirectory, backupDirectory,
                    helperPath, installation, journalPath, operationToken)
                : BuildPosixScript(paths.ApplicationDirectory, preparedDirectory, backupDirectory,
                    helperPath, installation, journalPath, operationToken);
            await using (var helper = new FileStream(helperPath, FileMode.CreateNew, FileAccess.Write,
                             FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                // Windows PowerShell 5.1 requires a BOM to decode non-ASCII paths reliably.
                var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: isWindows);
                if (isWindows)
                {
                    await helper.WriteAsync(encoding.GetPreamble(), cancellationToken)
                        .ConfigureAwait(false);
                }
                var scriptBytes = encoding.GetBytes(script);
                await helper.WriteAsync(scriptBytes, cancellationToken).ConfigureAwait(false);
                await helper.FlushAsync(cancellationToken).ConfigureAwait(false);
                helper.Flush(flushToDisk: true);
            }
            await WriteJournalAsync(journalPath, operationToken, cancellationToken).ConfigureAwait(false);
            return new ClientUpdateInstallationPlan(preparedDirectory, backupDirectory, helperPath,
                journalPath, operationToken, script, isWindows);
        }
        catch
        {
            DeleteDirectoryBestEffort(preparedDirectory);
            DeleteFileBestEffort(helperPath);
            DeleteFileBestEffort(journalPath);
            throw;
        }
        finally
        {
            DeleteFileBestEffort(archivePath);
        }
    }

    public static void LaunchPreparedUpdate(ClientUpdateInstallationPlan plan)
    {
        if (!File.Exists(plan.HelperPath) || !Directory.Exists(plan.PreparedDirectory)
            || !File.Exists(plan.JournalPath)
            || !FixedTimeEquals(File.ReadAllText(plan.JournalPath).Trim(), plan.OperationToken))
        {
            throw new InvalidOperationException("Prepared update is incomplete");
        }
        var start = plan.IsWindows
            ? new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory,
                    "WindowsPowerShell", "v1.0", "powershell.exe"),
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(plan.HelperPath)!,
            }
            : new ProcessStartInfo
            {
                FileName = "/bin/sh",
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(plan.HelperPath)!,
            };
        if (plan.IsWindows)
        {
            start.ArgumentList.Add("-NoLogo");
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-NonInteractive");
            start.ArgumentList.Add("-ExecutionPolicy");
            start.ArgumentList.Add("Bypass");
            start.ArgumentList.Add("-File");
            start.ArgumentList.Add(plan.HelperPath);
        }
        else
        {
            start.ArgumentList.Add(plan.HelperPath);
        }
        _ = Process.Start(start) ?? throw new InvalidOperationException("Could not start update helper");
    }

    public static void CleanupPreparedUpdate(ClientUpdateInstallationPlan plan)
    {
        DeleteDirectoryBestEffort(plan.PreparedDirectory);
        DeleteFileBestEffort(plan.HelperPath);
        DeleteFileBestEffort(plan.JournalPath);
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }

    private async Task<string?> DownloadVerifiedAsync(ClientUpdateCheck update, string destinationPath,
        IProgress<ClientUpdateProgress>? progress, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_packageTimeout);
        try
        {
            return await DownloadVerifiedCoreAsync(update, destinationPath, progress, timeout.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("Update package download timed out", exception);
        }
    }

    private async Task<string?> DownloadVerifiedCoreAsync(ClientUpdateCheck update,
        string destinationPath, IProgress<ClientUpdateProgress>? progress,
        CancellationToken cancellationToken)
    {
        using var response = await SendPackageRequestAsync(update, cancellationToken).ConfigureAwait(false);
        EnsureSuccessWithoutRemoteReason(response);
        if (response.Content.Headers.ContentLength is { } contentLength && contentLength != update.FileSize)
        {
            throw new InvalidDataException("Update package Content-Length does not match the catalogue");
        }

        var fileName = response.Content.Headers.ContentDisposition?.FileNameStar
            ?? response.Content.Headers.ContentDisposition?.FileName;
        fileName = ClientUpdateDisplay.Sanitize(fileName?.Trim().Trim('"'));
        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var destination = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write,
            FileShare.None, 128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        long total = 0;
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            total = checked(total + read);
            if (total > update.FileSize || total > MaxPackageBytes)
            {
                throw new InvalidDataException("Update package exceeds its declared size");
            }
            hash.AppendData(buffer.AsSpan(0, read));
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            progress?.Report(new ClientUpdateProgress(total, update.FileSize));
        }
        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (total != update.FileSize)
        {
            throw new InvalidDataException("Update package size does not match the catalogue");
        }
        var actualSha256 = Convert.ToHexString(hash.GetHashAndReset());
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(actualSha256),
                Encoding.ASCII.GetBytes(update.Sha256!.ToUpperInvariant())))
        {
            throw new CryptographicException("Update package SHA-256 verification failed");
        }
        return fileName;
    }

    private async Task<HttpResponseMessage> SendPackageRequestAsync(ClientUpdateCheck update,
        CancellationToken cancellationToken)
    {
        var requestUri = update.DownloadUri!;
        var redirects = 0;
        while (true)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
            var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (!IsRedirect(response.StatusCode))
            {
                if (update.PackageId is not null)
                {
                    EnsureSecureFinalUri(response, update.ServerOrigin);
                    if (response.RequestMessage?.RequestUri is not { } finalHostedUri
                        || !IsExactHostedPackageUri(finalHostedUri, update.PackageId.Value))
                    {
                        response.Dispose();
                        throw new InvalidDataException(
                            "Hosted package request left its exact download route");
                    }
                }
                else if (response.RequestMessage?.RequestUri is not { } finalUri
                         || !IsExternalRedirectUri(finalUri))
                {
                    response.Dispose();
                    throw new InvalidDataException("External update request left HTTPS");
                }
                return response;
            }

            try
            {
                if (update.PackageId is not null)
                {
                    throw new InvalidDataException("Hosted package downloads must not redirect");
                }
                if (redirects >= 5 || response.Headers.Location is not { } location
                    || !Uri.TryCreate(requestUri, location, out var nextUri)
                    || !IsExternalRedirectUri(nextUri))
                {
                    throw new InvalidDataException(
                        "External update redirect chain is invalid or exceeds five hops");
                }
                redirects++;
                requestUri = nextUri;
            }
            finally
            {
                response.Dispose();
            }
        }
    }

    private static async Task ExtractArchiveAsync(string archivePath, string? fileName,
        string destinationDirectory, CancellationToken cancellationToken)
    {
        var magic = new byte[4];
        await using (var probe = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                         magic.Length, FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            var count = await probe.ReadAsync(magic, cancellationToken).ConfigureAwait(false);
            if (count >= 4 && magic[0] == 0x50 && magic[1] == 0x4b)
            {
                await ExtractZipAsync(archivePath, destinationDirectory, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }
            if (count >= 2 && magic[0] == 0x1f && magic[1] == 0x8b)
            {
                await ExtractTarGzipAsync(archivePath, destinationDirectory, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }
        }
        throw new InvalidDataException($"Unsupported update archive format: {fileName ?? "unknown"}");
    }

    private static async Task ExtractZipAsync(string archivePath, string destinationDirectory,
        CancellationToken cancellationToken)
    {
        await using var input = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var archive = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: false);
        if (archive.Entries.Count > MaxArchiveEntries)
        {
            throw new InvalidDataException("Update archive contains too many entries");
        }
        long expanded = 0;
        var files = 0;
        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (IsZipSymlink(entry))
            {
                throw new InvalidDataException("Update archive contains a symbolic link");
            }
            var relativePath = NormalizeArchivePath(entry.FullName);
            if (relativePath is null)
            {
                continue;
            }
            var target = SafeCombine(destinationDirectory, relativePath);
            if (string.IsNullOrEmpty(entry.Name))
            {
                Directory.CreateDirectory(target);
                continue;
            }
            files++;
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            await using var source = entry.Open();
            await using var destination = new FileStream(target, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            expanded = await CopyExpandedAsync(source, destination, expanded, cancellationToken)
                .ConfigureAwait(false);
        }
        if (files == 0)
        {
            throw new InvalidDataException("Update archive contains no files");
        }
    }

    private static async Task ExtractTarGzipAsync(string archivePath, string destinationDirectory,
        CancellationToken cancellationToken)
    {
        await using var input = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var gzip = new GZipStream(input, CompressionMode.Decompress, leaveOpen: false);
        using var reader = new TarReader(gzip, leaveOpen: false);
        long expanded = 0;
        var entries = 0;
        var files = 0;
        while (await reader.GetNextEntryAsync(copyData: false, cancellationToken).ConfigureAwait(false)
               is { } entry)
        {
            entries++;
            if (entries > MaxArchiveEntries)
            {
                throw new InvalidDataException("Update archive contains too many entries");
            }
            var relativePath = NormalizeArchivePath(entry.Name);
            if (relativePath is null)
            {
                continue;
            }
            var target = SafeCombine(destinationDirectory, relativePath);
            if (entry.EntryType == TarEntryType.Directory)
            {
                Directory.CreateDirectory(target);
                continue;
            }
            if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile))
            {
                throw new InvalidDataException(
                    $"Update archive entry type {entry.EntryType} is not permitted");
            }
            files++;
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            await using (var destination = new FileStream(target, FileMode.CreateNew, FileAccess.Write,
                             FileShare.None, 128 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                if (entry.DataStream is not null)
                {
                    expanded = await CopyExpandedAsync(entry.DataStream, destination, expanded,
                        cancellationToken).ConfigureAwait(false);
                }
            }
            if (!OperatingSystem.IsWindows())
            {
                var safeMode = entry.Mode & (UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                    UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
                File.SetUnixFileMode(target, safeMode);
            }
        }
        if (files == 0)
        {
            throw new InvalidDataException("Update archive contains no files");
        }
    }

    private static async Task<long> CopyExpandedAsync(Stream source, Stream destination, long alreadyWritten,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[128 * 1024];
        var total = alreadyWritten;
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return total;
            }
            total = checked(total + read);
            if (total > MaxExpandedBytes)
            {
                throw new InvalidDataException("Expanded update archive is too large");
            }
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<byte[]> ReadLimitedAsync(Stream stream, int maximum,
        CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return output.ToArray();
            }
            if (output.Length + read > maximum)
            {
                throw new InvalidDataException("Version-check response is too large");
            }
            output.Write(buffer, 0, read);
        }
    }

    private static ResolvedInstallationPaths ResolveInstallationPaths(
        ClientUpdateInstallationRequest installation)
    {
        if (installation.ProcessId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(installation), "ProcessId must be positive");
        }
        if (string.IsNullOrWhiteSpace(installation.RestartExecutable)
            || !Path.IsPathFullyQualified(installation.RestartExecutable)
            || !File.Exists(installation.RestartExecutable))
        {
            throw new ArgumentException("RestartExecutable must be an existing absolute file",
                nameof(installation));
        }
        if (installation.RestartExecutable.IndexOfAny(['\r', '\n', '\0']) >= 0
            || installation.RestartArguments.Any(argument => argument is null
                || argument.IndexOfAny(['\r', '\n', '\0']) >= 0
                || OperatingSystem.IsWindows() && argument.Contains('"')))
        {
            throw new ArgumentException("Restart command contains unsafe control characters",
                nameof(installation));
        }
        var applicationDirectory = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(installation.ApplicationDirectory));
        if (!Directory.Exists(applicationDirectory)
            || string.Equals(applicationDirectory, Path.GetPathRoot(applicationDirectory),
                PathComparison))
        {
            throw new ArgumentException("ApplicationDirectory must be an existing non-root directory",
                nameof(installation));
        }
        var parent = Directory.GetParent(applicationDirectory)?.FullName
            ?? throw new ArgumentException("ApplicationDirectory has no parent", nameof(installation));
        var entry = Path.GetFullPath(installation.EntryFilePath);
        if (!File.Exists(entry) || !IsContainedBy(applicationDirectory, entry))
        {
            throw new ArgumentException("EntryFilePath must be a file inside ApplicationDirectory",
                nameof(installation));
        }
        var relative = Path.GetRelativePath(applicationDirectory, entry);
        var restart = Path.GetFullPath(installation.RestartExecutable);
        var restartRelative = IsContainedBy(applicationDirectory, restart)
            ? Path.GetRelativePath(applicationDirectory, restart)
            : null;
        return new ResolvedInstallationPaths(applicationDirectory, parent, relative, restartRelative);
    }

    private static void ValidateInstallableUpdate(ClientUpdateCheck update)
    {
        if (!update.UpdateAvailable || update.PackageId is <= 0 || update.DownloadUri is null
            || !IsSha256(update.Sha256) || update.FileSize <= 0 || update.FileSize > MaxPackageBytes)
        {
            throw new ArgumentException("Update does not contain installable hosted-package metadata",
                nameof(update));
        }
        if (!ClientSemanticVersion.TryNormalize(update.LatestVersion, out _))
        {
            throw new InvalidDataException("Update latestVersion is not valid semantic version metadata");
        }
        var validLocation = update.PackageId is { } packageId
            ? SameOrigin(update.ServerOrigin, update.DownloadUri)
                && IsExactHostedPackageUri(update.DownloadUri, packageId)
            : IsInitialExternalDownloadUri(update.DownloadUri);
        if (!validLocation)
        {
            throw new InvalidDataException(
                "Update download does not match a secure hosted or external release route");
        }
    }

    private static Uri RequireSecureServerOrigin(Uri serverBaseUri)
    {
        ArgumentNullException.ThrowIfNull(serverBaseUri);
        if (!serverBaseUri.IsAbsoluteUri || serverBaseUri.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(serverBaseUri.UserInfo))
        {
            throw new InvalidOperationException("Automatic update checks require an HTTPS serverBaseUrl");
        }
        return new Uri(serverBaseUri.GetLeftPart(UriPartial.Authority));
    }

    private static TimeSpan RequirePositiveTimeout(TimeSpan value, string parameterName)
    {
        if (value <= TimeSpan.Zero || value == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(parameterName, "timeout must be positive and finite");
        }
        return value;
    }

    private static void EnsureSecureFinalUri(HttpResponseMessage response, Uri expectedOrigin)
    {
        if (response.RequestMessage?.RequestUri is not { IsAbsoluteUri: true } uri
            || uri.Scheme != Uri.UriSchemeHttps
            || !SameOrigin(expectedOrigin, uri))
        {
            throw new InvalidDataException("Update request left its configured HTTPS origin");
        }
    }

    private static void EnsureSuccessWithoutRemoteReason(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Update request failed with HTTP {(int)response.StatusCode}", null,
                response.StatusCode);
        }
    }

    private static void ValidateTarget(ClientUpdateTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (target.Implementation is not ("java" or "go" or "csharp" or "android")
            || target.Platform is not ("windows" or "linux" or "macos" or "android" or "any")
            || target.Arch is not ("x64" or "arm64" or "any"))
        {
            throw new ArgumentException("Unknown update target", nameof(target));
        }
        if (target.Implementation == "android"
            && (target.Platform != "android" || target.Arch != "any"))
        {
            throw new ArgumentException("Android updates require android/any", nameof(target));
        }
    }

    private static bool SameOrigin(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase)
        && left.Port == right.Port;

    private static bool IsInitialExternalDownloadUri(Uri uri) =>
        IsExternalRedirectUri(uri)
        && string.IsNullOrEmpty(uri.Query)
        && string.IsNullOrEmpty(uri.Fragment);

    private static bool IsExternalRedirectUri(Uri uri) => uri.IsAbsoluteUri
        && uri.Scheme == Uri.UriSchemeHttps
        && !string.IsNullOrWhiteSpace(uri.Host)
        && string.IsNullOrEmpty(uri.UserInfo);

    private static bool IsRedirect(HttpStatusCode statusCode) => statusCode is
        HttpStatusCode.MovedPermanently or HttpStatusCode.Redirect or HttpStatusCode.RedirectMethod
        or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;

    private static bool IsExactHostedPackageUri(Uri candidate, long packageId)
    {
        if (!candidate.IsAbsoluteUri || packageId <= 0 || !string.IsNullOrEmpty(candidate.UserInfo)
            || !string.IsNullOrEmpty(candidate.Query) || !string.IsNullOrEmpty(candidate.Fragment))
        {
            return false;
        }
        var expectedPath = $"/api/public/client-packages/{packageId.ToString(System.Globalization.CultureInfo.InvariantCulture)}/download";
        if (!string.Equals(candidate.AbsolutePath, expectedPath, StringComparison.Ordinal))
        {
            return false;
        }

        // Uri.AbsolutePath canonicalizes dot segments and escaped digits. Check OriginalString as
        // well so /%34%32/, /42/./ and similar alternate spellings cannot alias package 42.
        var original = candidate.OriginalString;
        var authorityEnd = original.IndexOf("://", StringComparison.Ordinal);
        if (authorityEnd < 0)
        {
            return false;
        }
        var pathStart = original.IndexOf('/', authorityEnd + 3);
        if (pathStart < 0)
        {
            return false;
        }
        var pathEnd = original.IndexOfAny(['?', '#'], pathStart);
        var rawPath = pathEnd < 0 ? original[pathStart..] : original[pathStart..pathEnd];
        return string.Equals(rawPath, expectedPath, StringComparison.Ordinal);
    }

    private static bool IsSha256(string? value) => value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsZipSymlink(ZipArchiveEntry entry) =>
        ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000;

    private static string? NormalizeArchivePath(string name)
    {
        var normalized = name.Replace('\\', '/');
        while (normalized.StartsWith("./", StringComparison.Ordinal))
        {
            normalized = normalized[2..];
        }
        if (normalized.Length == 0 || normalized == ".")
        {
            return null;
        }
        if (normalized.StartsWith("/", StringComparison.Ordinal)
            || (normalized.Length >= 2 && normalized[1] == ':'))
        {
            throw new InvalidDataException("Update archive contains an absolute path");
        }
        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(segment => segment is "." or ".."
                || segment.Contains(':')
                || segment.IndexOf('\0') >= 0
                || string.Equals(segment, BackupOwnershipMarker, StringComparison.OrdinalIgnoreCase)
                || string.Equals(segment, TransactionMarker, StringComparison.OrdinalIgnoreCase)
                || (OperatingSystem.IsWindows() && IsUnsafeWindowsPathSegment(segment))))
        {
            throw new InvalidDataException("Update archive contains an unsafe path");
        }
        return Path.Combine(segments);
    }

    private static bool IsUnsafeWindowsPathSegment(string segment)
    {
        if (!string.Equals(segment, segment.TrimEnd(' ', '.'), StringComparison.Ordinal))
        {
            return true;
        }
        var stem = segment.Split('.', 2)[0];
        return stem.Equals("CON", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("AUX", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase)
            || (stem.Length == 4
                && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase)
                    || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase))
                && stem[3] is >= '1' and <= '9');
    }

    private static string SafeCombine(string root, string relativePath)
    {
        var canonicalRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var path = Path.GetFullPath(Path.Combine(canonicalRoot, relativePath));
        if (!IsContainedBy(canonicalRoot, path))
        {
            throw new InvalidDataException("Update archive path escapes its destination");
        }
        return path;
    }

    private static bool IsContainedBy(string root, string path)
    {
        var prefix = Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar;
        return path.StartsWith(prefix, PathComparison);
    }

    private static StringComparison PathComparison => OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;

    private static void PreserveLocalFile(string currentDirectory, string preparedDirectory,
        string relativePath)
    {
        var current = SafeCombine(currentDirectory, relativePath);
        if (!File.Exists(current))
        {
            return;
        }
        var prepared = SafeCombine(preparedDirectory, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(prepared)!);
        File.Copy(current, prepared, overwrite: true);
    }

    private static void EnsureBackupPathOwnedOrAbsent(string backupDirectory)
    {
        if (!Directory.Exists(backupDirectory) && !File.Exists(backupDirectory))
        {
            return;
        }
        if (!Directory.Exists(backupDirectory)
            || File.GetAttributes(backupDirectory).HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidOperationException(
                $"Refusing to replace unowned backup path: {backupDirectory}");
        }
        var marker = Path.Combine(backupDirectory, BackupOwnershipMarker);
        string value;
        try
        {
            value = File.ReadAllText(marker).Trim();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"Refusing to replace unowned backup path: {backupDirectory}", exception);
        }
        if (!string.Equals(value, BackupOwnershipValue, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Refusing to replace unowned backup path: {backupDirectory}");
        }
    }

    private static void EnsureReservedMarkerPathsAbsent(string applicationDirectory)
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(applicationDirectory))
        {
            var name = Path.GetFileName(path);
            if (string.Equals(name, BackupOwnershipMarker, PathComparison)
                || string.Equals(name, TransactionMarker, PathComparison))
            {
                throw new InvalidOperationException(
                    "Current installation contains a reserved updater transaction marker");
            }
        }
    }

    private static async Task WriteJournalAsync(string path, string token,
        CancellationToken cancellationToken)
    {
        await using var journal = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
            FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough);
        await journal.WriteAsync(Encoding.ASCII.GetBytes(token), cancellationToken)
            .ConfigureAwait(false);
        await journal.FlushAsync(cancellationToken).ConfigureAwait(false);
        journal.Flush(flushToDisk: true);
    }

    private static bool FixedTimeEquals(string left, string right)
    {
        var leftBytes = Encoding.ASCII.GetBytes(left);
        var rightBytes = Encoding.ASCII.GetBytes(right);
        return leftBytes.Length == rightBytes.Length
            && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    internal static string BuildWindowsScript(string applicationDirectory, string preparedDirectory,
        string backupDirectory, string helperPath, ClientUpdateInstallationRequest installation,
        string? journalPath = null, string? operationToken = null,
        bool enableTestFaultInjection = false)
    {
        journalPath ??= helperPath + ".journal";
        operationToken ??= "test-operation-token";
        var restartArguments = string.Join(' ', installation.RestartArguments
            .Select(QuoteWindowsCommandLineArgument));
        var faultInjection = enableTestFaultInjection
            ? "if ($env:SPECUS_UPDATE_TEST_ABORT_AFTER_BACKUP -eq '1') { exit 86 }"
            : string.Empty;
        return $$"""
            $ErrorActionPreference = 'Stop'
            $application = {{QuotePowerShellLiteral(applicationDirectory)}}
            $prepared = {{QuotePowerShellLiteral(preparedDirectory)}}
            $backup = {{QuotePowerShellLiteral(backupDirectory)}}
            $helper = {{QuotePowerShellLiteral(helperPath)}}
            $journal = {{QuotePowerShellLiteral(journalPath)}}
            $token = {{QuotePowerShellLiteral(operationToken)}}
            $restartExecutable = {{QuotePowerShellLiteral(installation.RestartExecutable)}}
            $restartArguments = {{QuotePowerShellLiteral(restartArguments)}}
            $ownerName = '{{BackupOwnershipMarker}}'
            $ownerValue = '{{BackupOwnershipValue}}'
            $transactionName = '{{TransactionMarker}}'

            function Test-Token([string] $path, [string] $expected) {
              try { return (Get-Content -LiteralPath $path -Raw -ErrorAction Stop).Trim() -ceq $expected }
              catch { return $false }
            }
            function Write-Token([string] $path, [string] $value) {
              $bytes = [Text.Encoding]::ASCII.GetBytes($value)
              $stream = [IO.FileStream]::new($path, [IO.FileMode]::Create,
                [IO.FileAccess]::Write, [IO.FileShare]::None, 4096,
                [IO.FileOptions]::WriteThrough)
              try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
              finally { $stream.Dispose() }
            }
            function Remove-UpdateFiles([bool] $removePrepared) {
              if ($removePrepared -and (Test-Path -LiteralPath $prepared)) {
                Remove-Item -LiteralPath $prepared -Recurse -Force -ErrorAction SilentlyContinue
              }
              Remove-Item -LiteralPath $journal -Force -ErrorAction SilentlyContinue
              Remove-Item -LiteralPath $helper -Force -ErrorAction SilentlyContinue
            }
            function Start-Client([bool] $skipUpdate) {
              try {
                $info = [Diagnostics.ProcessStartInfo]::new()
                $info.FileName = $restartExecutable
                $info.Arguments = $restartArguments
                $info.WorkingDirectory = $application
                $info.UseShellExecute = $false
                $info.CreateNoWindow = $true
                if ($skipUpdate) { $info.EnvironmentVariables['SPECUS_SKIP_UPDATE_ONCE'] = '1' }
                $process = [Diagnostics.Process]::Start($info)
                if ($null -eq $process) { return $false }
                Start-Sleep -Milliseconds 1000
                return -not $process.HasExited
              }
              catch { return $false }
            }
            function Restore-OldClient {
              $appTransaction = Join-Path $application $transactionName
              $backupTransaction = Join-Path $backup $transactionName
              if ((Test-Path -LiteralPath $application) -and (Test-Token $appTransaction $token)) {
                Remove-Item -LiteralPath $application -Recurse -Force
              }
              if (-not (Test-Path -LiteralPath $application) -and (Test-Token $backupTransaction $token)) {
                Move-Item -LiteralPath $backup -Destination $application
                Remove-Item -LiteralPath (Join-Path $application $ownerName) -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath (Join-Path $application $transactionName) -Force -ErrorAction SilentlyContinue
                $started = Start-Client $true
                Remove-UpdateFiles $true
                return $started
              }
              return $false
            }

            if (Test-Token $journal ($token + ':committed')) {
              if (Start-Client $false) {
                if (Test-Token (Join-Path $application $transactionName) $token) {
                  Remove-Item -LiteralPath (Join-Path $application $transactionName) -Force -ErrorAction SilentlyContinue
                }
                if (Test-Token (Join-Path $backup $transactionName) $token) {
                  Remove-Item -LiteralPath (Join-Path $backup $transactionName) -Force -ErrorAction SilentlyContinue
                }
                Remove-UpdateFiles $true
                exit 0
              }
              $null = Restore-OldClient
              exit 1
            }
            if (-not (Test-Token $journal $token)) { exit 1 }
            $waitSeconds = 0
            while ($null -ne (Get-Process -Id {{installation.ProcessId}} -ErrorAction SilentlyContinue)) {
              if ($waitSeconds -ge 120) { Remove-UpdateFiles $true; exit 1 }
              Start-Sleep -Seconds 1
              $waitSeconds++
            }

            $backupOwner = Join-Path $backup $ownerName
            $backupTransaction = Join-Path $backup $transactionName
            $appTransaction = Join-Path $application $transactionName
            if (-not (Test-Path -LiteralPath $backup) -and
                (Test-Token (Join-Path $application $ownerName) $ownerValue) -and
                (Test-Token $appTransaction $token)) {
              Remove-Item -LiteralPath (Join-Path $application $ownerName) -Force -ErrorAction SilentlyContinue
              Remove-Item -LiteralPath $appTransaction -Force -ErrorAction SilentlyContinue
              $null = Start-Client $true
              Remove-UpdateFiles $true
              exit 1
            }
            if (Test-Token $backupTransaction $token) {
              if (-not (Test-Path -LiteralPath $application)) {
                $null = Restore-OldClient
                exit 1
              }
              if (Test-Token $appTransaction $token) {
                if (Start-Client $false) {
                  Remove-Item -LiteralPath $appTransaction -Force -ErrorAction SilentlyContinue
                  Remove-Item -LiteralPath $backupTransaction -Force -ErrorAction SilentlyContinue
                  Remove-UpdateFiles $true
                  exit 0
                }
                $null = Restore-OldClient
                exit 1
              }
              exit 1
            }

            if (Test-Path -LiteralPath $backup) {
              if (-not (Test-Token $backupOwner $ownerValue) -or
                  (Test-Path -LiteralPath $backupTransaction)) { Remove-UpdateFiles $true; exit 1 }
              Remove-Item -LiteralPath $backup -Recurse -Force
            }
            try {
              Write-Token (Join-Path $application $ownerName) $ownerValue
              Write-Token (Join-Path $application $transactionName) $token
              Write-Token (Join-Path $prepared $transactionName) $token
              Move-Item -LiteralPath $application -Destination $backup
              {{faultInjection}}
              Move-Item -LiteralPath $prepared -Destination $application
              if (-not (Start-Client $false)) { $null = Restore-OldClient; exit 1 }
              Write-Token $journal ($token + ':committed')
              Remove-Item -LiteralPath (Join-Path $application $transactionName) -Force -ErrorAction SilentlyContinue
              Remove-Item -LiteralPath (Join-Path $backup $transactionName) -Force -ErrorAction SilentlyContinue
              Remove-UpdateFiles $false
              exit 0
            }
            catch {
              if (Test-Path -LiteralPath $application) {
                Remove-Item -LiteralPath (Join-Path $application $ownerName) -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath (Join-Path $application $transactionName) -Force -ErrorAction SilentlyContinue
              }
              $null = Restore-OldClient
              Remove-UpdateFiles $true
              exit 1
            }
            """;
    }

    internal static string BuildPosixScript(string applicationDirectory, string preparedDirectory,
        string backupDirectory, string helperPath, ClientUpdateInstallationRequest installation,
        string? journalPath = null, string? operationToken = null,
        bool enableTestFaultInjection = false)
    {
        journalPath ??= helperPath + ".journal";
        operationToken ??= "test-operation-token";
        var ownerInBackup = Path.Combine(backupDirectory, BackupOwnershipMarker);
        var transactionInBackup = Path.Combine(backupDirectory, TransactionMarker);
        var transactionInApp = Path.Combine(applicationDirectory, TransactionMarker);
        var ownerInApp = Path.Combine(applicationDirectory, BackupOwnershipMarker);
        var transactionInPrepared = Path.Combine(preparedDirectory, TransactionMarker);
        var restart = string.Join(' ', new[] { installation.RestartExecutable }
            .Concat(installation.RestartArguments).Select(QuotePosixArgument));
        var faultInjection = enableTestFaultInjection
            ? "if [ \"${SPECUS_UPDATE_TEST_ABORT_AFTER_BACKUP:-}\" = \"1\" ]; then exit 86; fi"
            : string.Empty;
        return $$"""
            #!/bin/sh
            test_token() { [ -f "$1" ] && [ "$(cat -- "$1")" = "$2" ]; }
            cleanup_update() {
              [ "$1" = "prepared" ] && rm -rf -- {{QuotePosixArgument(preparedDirectory)}}
              rm -f -- {{QuotePosixArgument(journalPath)}} {{QuotePosixArgument(helperPath)}}
            }
            start_client() {
              cd -- {{QuotePosixArgument(applicationDirectory)}} || return 1
              if [ "$1" = "skip" ]; then
                SPECUS_SKIP_UPDATE_ONCE=1 nohup {{restart}} >/dev/null 2>&1 &
              else
                nohup {{restart}} >/dev/null 2>&1 &
              fi
              restart_pid=$!
              sleep 1
              kill -0 "$restart_pid" 2>/dev/null
            }
            restore_old() {
              if [ -e {{QuotePosixArgument(applicationDirectory)}} ] && test_token {{QuotePosixArgument(transactionInApp)}} {{QuotePosixArgument(operationToken)}}; then
                rm -rf -- {{QuotePosixArgument(applicationDirectory)}}
              fi
              if [ ! -e {{QuotePosixArgument(applicationDirectory)}} ] && test_token {{QuotePosixArgument(transactionInBackup)}} {{QuotePosixArgument(operationToken)}}; then
                mv -- {{QuotePosixArgument(backupDirectory)}} {{QuotePosixArgument(applicationDirectory)}} || return 1
                rm -f -- {{QuotePosixArgument(ownerInApp)}} {{QuotePosixArgument(transactionInApp)}}
                start_client skip
                result=$?
                cleanup_update prepared
                return "$result"
              fi
              return 1
            }

            if test_token {{QuotePosixArgument(journalPath)}} {{QuotePosixArgument(operationToken + ":committed")}}; then
              if start_client normal; then
                test_token {{QuotePosixArgument(transactionInApp)}} {{QuotePosixArgument(operationToken)}} && rm -f -- {{QuotePosixArgument(transactionInApp)}}
                test_token {{QuotePosixArgument(transactionInBackup)}} {{QuotePosixArgument(operationToken)}} && rm -f -- {{QuotePosixArgument(transactionInBackup)}}
                cleanup_update prepared
                exit 0
              fi
              restore_old
              exit 1
            fi
            if ! test_token {{QuotePosixArgument(journalPath)}} {{QuotePosixArgument(operationToken)}}; then exit 1; fi
            wait_seconds=0
            while kill -0 {{installation.ProcessId}} 2>/dev/null; do
              if [ "$wait_seconds" -ge 120 ]; then cleanup_update prepared; exit 1; fi
              sleep 1
              wait_seconds=$((wait_seconds + 1))
            done

            if [ ! -e {{QuotePosixArgument(backupDirectory)}} ] && test_token {{QuotePosixArgument(ownerInApp)}} {{QuotePosixArgument(BackupOwnershipValue)}} && test_token {{QuotePosixArgument(transactionInApp)}} {{QuotePosixArgument(operationToken)}}; then
              rm -f -- {{QuotePosixArgument(ownerInApp)}} {{QuotePosixArgument(transactionInApp)}}
              start_client skip || true
              cleanup_update prepared
              exit 1
            fi
            if test_token {{QuotePosixArgument(transactionInBackup)}} {{QuotePosixArgument(operationToken)}}; then
              if [ ! -e {{QuotePosixArgument(applicationDirectory)}} ]; then restore_old; exit 1; fi
              if test_token {{QuotePosixArgument(transactionInApp)}} {{QuotePosixArgument(operationToken)}}; then
                if start_client normal; then
                  rm -f -- {{QuotePosixArgument(transactionInApp)}} {{QuotePosixArgument(transactionInBackup)}}
                  cleanup_update prepared
                  exit 0
                fi
                restore_old
                exit 1
              fi
              exit 1
            fi

            if [ -e {{QuotePosixArgument(backupDirectory)}} ]; then
              if ! test_token {{QuotePosixArgument(ownerInBackup)}} {{QuotePosixArgument(BackupOwnershipValue)}} || [ -e {{QuotePosixArgument(transactionInBackup)}} ]; then
                cleanup_update prepared
                exit 1
              fi
              rm -rf -- {{QuotePosixArgument(backupDirectory)}}
            fi
            printf '%s' {{QuotePosixArgument(BackupOwnershipValue)}} > {{QuotePosixArgument(ownerInApp)}} || { cleanup_update prepared; exit 1; }
            printf '%s' {{QuotePosixArgument(operationToken)}} > {{QuotePosixArgument(transactionInApp)}} || { cleanup_update prepared; exit 1; }
            printf '%s' {{QuotePosixArgument(operationToken)}} > {{QuotePosixArgument(transactionInPrepared)}} || { cleanup_update prepared; exit 1; }
            sync
            if ! mv -- {{QuotePosixArgument(applicationDirectory)}} {{QuotePosixArgument(backupDirectory)}}; then
              rm -f -- {{QuotePosixArgument(ownerInApp)}} {{QuotePosixArgument(transactionInApp)}}
              cleanup_update prepared
              exit 1
            fi
            {{faultInjection}}
            if ! mv -- {{QuotePosixArgument(preparedDirectory)}} {{QuotePosixArgument(applicationDirectory)}}; then
              restore_old
              exit 1
            fi
            if start_client normal; then
              printf '%s' {{QuotePosixArgument(operationToken + ":committed")}} > {{QuotePosixArgument(journalPath)}}
              sync
              rm -f -- {{QuotePosixArgument(transactionInApp)}} {{QuotePosixArgument(transactionInBackup)}}
              cleanup_update keep
              exit 0
            fi
            restore_old
            exit 1
            """;
    }

    private static string QuotePosixArgument(string value) =>
        "'" + value.Replace("'", "'\"'\"'", StringComparison.Ordinal) + "'";

    private static string QuotePowerShellLiteral(string value) =>
        "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";

    private static string QuoteWindowsCommandLineArgument(string value)
    {
        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }
            if (character == '"')
            {
                builder.Append('\\', backslashes * 2 + 1);
                builder.Append('"');
                backslashes = 0;
                continue;
            }
            builder.Append('\\', backslashes);
            backslashes = 0;
            builder.Append(character);
        }
        builder.Append('\\', backslashes * 2);
        builder.Append('"');
        return builder.ToString();
    }

    private static void DeleteFileBestEffort(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static void DeleteDirectoryBestEffort(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); } catch { }
    }

    private sealed record ResolvedInstallationPaths(string ApplicationDirectory,
        string ParentDirectory, string EntryRelativePath, string? RestartRelativePath);

    private sealed class ClientVersionCheckPayload
    {
        [JsonPropertyName("updateAvailable")]
        public bool UpdateAvailable { get; init; }

        [JsonPropertyName("mandatory")]
        public bool Mandatory { get; init; }

        [JsonPropertyName("latestVersion")]
        public string? LatestVersion { get; init; }

        [JsonPropertyName("packageId")]
        public long? PackageId { get; init; }

        [JsonPropertyName("downloadUrl")]
        public string? DownloadUrl { get; init; }

        [JsonPropertyName("sha256")]
        public string? Sha256 { get; init; }

        [JsonPropertyName("fileSize")]
        public long FileSize { get; init; }

        [JsonPropertyName("changelogUrl")]
        public string? ChangelogUrl { get; init; }
    }
}
