using System.Data;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.Server.Management;

/// <summary>Version catalogue, local package persistence and public update lookup.</summary>
public sealed class ClientPackageService
{
    internal const string DownloadPrefix = "/api/public/client-packages/";

    private readonly SpecusDbContext _db;
    private readonly ClientPackageStore _store;
    private readonly ILogger<ClientPackageService> _logger;

    public ClientPackageService(SpecusDbContext db, ClientPackageStore store,
        ILogger<ClientPackageService> logger)
    {
        _db = db;
        _store = store;
        _logger = logger;
    }

    public async Task<ClientDownloadLinkView> UploadAsync(ManagementContext context, Stream content,
        long declaredLength, ClientPackageUploadMutation request, CancellationToken cancellationToken)
    {
        ManagementUserService.RequireAdmin(context);
        var metadata = ClientPackageMetadata.NormalizeUpload(request);
        var id = ClientIdGenerator.NewId();
        var stored = await _store.SaveAsync(id, content, declaredLength, cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        var link = new ClientDownloadLink
        {
            Id = id,
            Implementation = metadata.Implementation,
            Platform = metadata.Platform,
            Arch = metadata.Arch,
            DisplayName = metadata.DisplayName,
            DownloadUrl = HostedDownloadUrl(id),
            Description = metadata.Description,
            Version = metadata.Version,
            Sha256 = stored.Sha256,
            FileSize = stored.FileSize,
            IsLatest = request.IsLatest ?? false,
            ChangelogUrl = metadata.ChangelogUrl,
            MinSupportedVersion = metadata.MinSupportedVersion,
            DisplayOrder = request.DisplayOrder ?? 0,
            Enabled = request.Enabled ?? true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        EnsureLatestCanBePublished(link);

        try
        {
            await using var transaction = await _db.Database
                .BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await LockCatalogueGroupAsync(link, cancellationToken).ConfigureAwait(false);
            await EnsureVersionAvailableAsync(link, null, cancellationToken).ConfigureAwait(false);
            if (link.IsLatest)
            {
                await ClearLatestAsync(link, null, cancellationToken).ConfigureAwait(false);
            }
            SynchronizeLatestSlot(link);
            _db.ClientDownloadLinks.Add(link);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return ToView(link);
        }
        catch (Exception exception)
        {
            _store.Delete(id);
            if (exception is DbUpdateException)
            {
                throw new ArgumentException("a package with this implementation, platform, arch and version already exists",
                    exception);
            }
            throw;
        }
    }

    public async Task<ClientDownloadLinkView> CreateExternalLinkAsync(ManagementContext context,
        ClientDownloadLinkMutation request, CancellationToken cancellationToken)
    {
        ManagementUserService.RequireAdmin(context);
        var metadata = ClientPackageMetadata.NormalizeLink(request, requireVersion: false);
        var now = DateTimeOffset.UtcNow;
        var link = new ClientDownloadLink
        {
            Id = ClientIdGenerator.NewId(),
            Implementation = metadata.Implementation,
            Platform = metadata.Platform,
            Arch = metadata.Arch,
            DisplayName = metadata.DisplayName,
            DownloadUrl = ClientPackageMetadata.RequireExternalUrl(request.DownloadUrl),
            Description = metadata.Description,
            Version = metadata.Version,
            Sha256 = ClientPackageMetadata.NormalizeExternalSha256(request.Sha256, request.FileSize),
            FileSize = ClientPackageMetadata.NormalizeExternalFileSize(request.Sha256, request.FileSize),
            IsLatest = request.IsLatest ?? false,
            ChangelogUrl = metadata.ChangelogUrl,
            MinSupportedVersion = metadata.MinSupportedVersion,
            DisplayOrder = request.DisplayOrder ?? 0,
            Enabled = request.Enabled ?? true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        EnsureLatestCanBePublished(link);
        await SaveCatalogueMutationAsync(link, null, cancellationToken).ConfigureAwait(false);
        return ToView(link);
    }

    public async Task<ClientDownloadLinkView> UpdateAsync(ManagementContext context, long id,
        ClientDownloadLinkMutation request, CancellationToken cancellationToken)
    {
        ManagementUserService.RequireAdmin(context);
        var link = await _db.ClientDownloadLinks.FirstOrDefaultAsync(row => row.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"client download link not found: {id}");
        var hostedStorage = HasHostedStorage(link);
        var metadata = ClientPackageMetadata.NormalizeLink(request, requireVersion: hostedStorage);
        link.Implementation = metadata.Implementation;
        link.Platform = metadata.Platform;
        link.Arch = metadata.Arch;
        link.DisplayName = metadata.DisplayName;
        link.Description = metadata.Description;
        link.Version = metadata.Version;
        link.ChangelogUrl = metadata.ChangelogUrl;
        link.MinSupportedVersion = metadata.MinSupportedVersion;
        if (!hostedStorage)
        {
            link.DownloadUrl = ClientPackageMetadata.RequireExternalUrl(request.DownloadUrl);
            link.Sha256 = ClientPackageMetadata.NormalizeExternalSha256(request.Sha256, request.FileSize);
            link.FileSize = ClientPackageMetadata.NormalizeExternalFileSize(request.Sha256, request.FileSize);
        }
        else if (!string.IsNullOrWhiteSpace(request.DownloadUrl)
                 && !string.Equals(request.DownloadUrl.Trim(), HostedDownloadUrl(id), StringComparison.Ordinal))
        {
            throw new ArgumentException("downloadUrl of a hosted package is managed by the server");
        }
        if (request.DisplayOrder is not null)
        {
            link.DisplayOrder = request.DisplayOrder.Value;
        }
        if (request.Enabled is not null)
        {
            link.Enabled = request.Enabled.Value;
        }
        if (request.IsLatest is not null)
        {
            link.IsLatest = request.IsLatest.Value;
        }
        EnsureLatestCanBePublished(link);
        link.UpdatedAt = DateTimeOffset.UtcNow;
        await SaveCatalogueMutationAsync(link, id, cancellationToken).ConfigureAwait(false);
        return ToView(link);
    }

    public async Task<ClientDownloadLinkView> SetLatestAsync(ManagementContext context, long id,
        CancellationToken cancellationToken)
    {
        ManagementUserService.RequireAdmin(context);
        var link = await _db.ClientDownloadLinks.FirstOrDefaultAsync(row => row.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"client download link not found: {id}");
        if (!link.Enabled || !SemanticVersion.TryParse(link.Version, out _)
            || !IsInstallableRelease(link))
        {
            throw new ArgumentException(
                "only an enabled installable entry with a semantic version can be latest");
        }
        link.IsLatest = true;
        link.UpdatedAt = DateTimeOffset.UtcNow;
        await SaveCatalogueMutationAsync(link, id, cancellationToken).ConfigureAwait(false);
        return ToView(link);
    }

    public async Task DeleteAsync(ManagementContext context, long id, CancellationToken cancellationToken)
    {
        ManagementUserService.RequireAdmin(context);
        var link = await _db.ClientDownloadLinks.FirstOrDefaultAsync(row => row.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"client download link not found: {id}");
        var staged = HasHostedStorage(link) ? _store.StageDelete(id) : null;
        try
        {
            await using var transaction = await _db.Database
                .BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await LockCatalogueGroupAsync(link, cancellationToken).ConfigureAwait(false);
            _db.ClientDownloadLinks.Remove(link);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            _store.RollbackDelete(staged, id);
            throw;
        }
        try
        {
            _store.CommitDelete(staged);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The catalogue transaction is already committed. A quarantined orphan is safer than
            // reporting a false transaction failure or restoring bytes for a deleted package.
            _logger.LogWarning(exception,
                "client package {PackageId} was deleted from the catalogue but quarantine cleanup failed",
                id);
        }
    }

    public async Task<ClientVersionCheckView> CheckVersionAsync(string? implementation, string? platform,
        string? arch, string? current, CancellationToken cancellationToken)
    {
        var normalizedImplementation = ClientPackageMetadata.RequireImplementation(implementation);
        var normalizedPlatform = ClientPackageMetadata.RequirePlatform(platform);
        var normalizedArch = ClientPackageMetadata.RequireArch(arch);
        if (!SemanticVersion.TryParse(current, out var currentVersion))
        {
            throw new ArgumentException("current must be a semantic version");
        }

        var candidates = await _db.ClientDownloadLinks.AsNoTracking()
            .Where(row => row.Enabled
                && row.Implementation == normalizedImplementation
                && (row.Platform == normalizedPlatform || row.Platform == "any")
                && (row.Arch == normalizedArch || row.Arch == "any")
                && row.Version != null
                && row.Sha256 != null
                && row.FileSize > 0)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

        var parsed = candidates
            .Where(IsInstallableRelease)
            .Select(row => new Candidate(row, SemanticVersion.ParseOrNull(row.Version),
                Specificity(row, normalizedPlatform, normalizedArch)))
            .Where(candidate => candidate.Version is not null && candidate.Row.IsLatest)
            .ToList();
        var latest = parsed
            .OrderByDescending(candidate => candidate.Specificity)
            .ThenByDescending(candidate => candidate.Version)
            .FirstOrDefault();
        if (latest is null)
        {
            return new ClientVersionCheckView(false, false, null, null, null, null, 0, null);
        }

        var updateAvailable = latest.Version!.Value.CompareTo(currentVersion) > 0;
        var minimum = SemanticVersion.ParseOrNull(latest.Row.MinSupportedVersion);
        var mandatory = updateAvailable && minimum is not null && currentVersion.CompareTo(minimum.Value) < 0;
        return new ClientVersionCheckView(
            updateAvailable,
            mandatory,
            latest.Row.Version,
            HasHostedStorage(latest.Row) ? latest.Row.Id : null,
            latest.Row.DownloadUrl,
            latest.Row.Sha256,
            latest.Row.FileSize,
            latest.Row.ChangelogUrl);
    }

    public async Task<ClientPackageDownload> OpenDownloadAsync(long id, CancellationToken cancellationToken)
    {
        var link = await _db.ClientDownloadLinks.AsNoTracking()
            .FirstOrDefaultAsync(row => row.Id == id && row.Enabled, cancellationToken)
            .ConfigureAwait(false);
        if (link is null || !IsHosted(link) || link.FileSize <= 0 || string.IsNullOrWhiteSpace(link.Sha256))
        {
            throw new ResourceNotFoundException("package not found");
        }
        var stream = _store.OpenRead(id, link.FileSize);
        return new ClientPackageDownload(stream, SafeDownloadName(link), link.FileSize,
            link.Sha256, link.UpdatedAt);
    }

    internal static bool IsHosted(ClientDownloadLink link) =>
        link.FileSize > 0
        && IsAuthoritativeSha256(link.Sha256)
        && HasHostedStorage(link);

    internal static bool HasHostedStorage(ClientDownloadLink link) =>
        string.Equals(link.DownloadUrl, HostedDownloadUrl(link.Id), StringComparison.Ordinal);

    internal static bool IsInstallableRelease(ClientDownloadLink link) =>
        link.FileSize > 0
        && IsAuthoritativeSha256(link.Sha256)
        && (HasHostedStorage(link) || ClientPackageMetadata.IsExternalUrl(link.DownloadUrl));

    internal static bool IsAuthoritativeSha256(string? value) => value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    internal static string HostedDownloadUrl(long id) =>
        $"{DownloadPrefix}{id.ToString(CultureInfo.InvariantCulture)}/download";

    internal static ClientDownloadLinkView ToView(ClientDownloadLink link) => new(
        link.Id,
        link.Implementation,
        link.Platform,
        link.Arch,
        link.DisplayName,
        link.DownloadUrl,
        link.Description,
        link.Version,
        link.Sha256,
        link.FileSize,
        link.IsLatest,
        link.ChangelogUrl,
        link.MinSupportedVersion,
        IsHosted(link),
        IsHosted(link) ? link.Id : null,
        link.DisplayOrder,
        link.Enabled,
        link.CreatedAt.ToString("O"),
        link.UpdatedAt.ToString("O"));

    private async Task SaveCatalogueMutationAsync(ClientDownloadLink link, long? currentId,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var transaction = await _db.Database
                .BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await LockCatalogueGroupAsync(link, cancellationToken).ConfigureAwait(false);
            await EnsureVersionAvailableAsync(link, currentId, cancellationToken).ConfigureAwait(false);
            if (link.IsLatest)
            {
                await ClearLatestAsync(link, currentId, cancellationToken).ConfigureAwait(false);
            }
            SynchronizeLatestSlot(link);
            if (currentId is null)
            {
                _db.ClientDownloadLinks.Add(link);
            }
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException exception)
        {
            throw new ArgumentException("a package with this implementation, platform, arch and version already exists",
                exception);
        }
    }

    private async Task LockCatalogueGroupAsync(ClientDownloadLink link, CancellationToken cancellationToken)
    {
        // The SERIALIZABLE read makes normal transitions deterministic. The nullable unique
        // latest_slot is the final cross-provider invariant when two empty-range writes race.
        _ = await _db.ClientDownloadLinks.AsNoTracking()
            .Where(row => row.Implementation == link.Implementation
                && row.Platform == link.Platform && row.Arch == link.Arch)
            .Select(row => row.Id)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    private Task<bool> VersionExistsAsync(ClientDownloadLink link, long? currentId,
        CancellationToken cancellationToken) => _db.ClientDownloadLinks.AsNoTracking().AnyAsync(row =>
            row.Id != currentId
            && row.Implementation == link.Implementation
            && row.Platform == link.Platform
            && row.Arch == link.Arch
            && row.Version == link.Version, cancellationToken);

    private async Task EnsureVersionAvailableAsync(ClientDownloadLink link, long? currentId,
        CancellationToken cancellationToken)
    {
        if (link.Version is not null && await VersionExistsAsync(link, currentId, cancellationToken).ConfigureAwait(false))
        {
            throw new ArgumentException("a package with this implementation, platform, arch and version already exists");
        }
    }

    private Task<int> ClearLatestAsync(ClientDownloadLink link, long? currentId,
        CancellationToken cancellationToken) => _db.ClientDownloadLinks
        .Where(row => row.Id != currentId
            && row.Implementation == link.Implementation
            && row.Platform == link.Platform
            && row.Arch == link.Arch
            && row.IsLatest)
        .ExecuteUpdateAsync(update => update
            .SetProperty(row => row.IsLatest, false)
            .SetProperty(row => row.LatestSlot, (string?)null)
            .SetProperty(row => row.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);

    private static void EnsureLatestCanBePublished(ClientDownloadLink link)
    {
        if (!link.IsLatest)
        {
            return;
        }
        if (!link.Enabled)
        {
            throw new ArgumentException("a disabled package cannot be latest");
        }
        if (!SemanticVersion.TryParse(link.Version, out _))
        {
            throw new ArgumentException("a latest package must have a semantic version");
        }
        if (!IsInstallableRelease(link))
        {
            throw new ArgumentException(
                "a latest package must have an HTTPS downloadUrl, SHA-256 and positive fileSize");
        }
    }

    private static void SynchronizeLatestSlot(ClientDownloadLink link) =>
        link.LatestSlot = link.IsLatest
            ? $"{link.Implementation}/{link.Platform}/{link.Arch}"
            : null;

    private static int Specificity(ClientDownloadLink row, string platform, string arch) =>
        (row.Platform == platform ? 2 : 0) + (row.Arch == arch ? 1 : 0);

    private static string SafeDownloadName(ClientDownloadLink link)
    {
        var fileName = Path.GetFileName(link.DisplayName.Trim());
        if (string.IsNullOrWhiteSpace(fileName) || fileName.IndexOfAny(['\r', '\n', '\0']) >= 0)
        {
            fileName = "specus-client-package";
        }
        if (link.Implementation == "android" && link.Platform == "android" && link.Arch == "any"
            && !fileName.EndsWith(".apk", StringComparison.OrdinalIgnoreCase))
        {
            fileName += ".apk";
        }
        return fileName;
    }

    private sealed record Candidate(ClientDownloadLink Row, SemanticVersion? Version, int Specificity);
}

public sealed record ClientPackageDownload(Stream Stream, string FileName, long FileSize, string Sha256,
    DateTimeOffset LastModified);

public sealed class ClientPackageStore
{
    private readonly string _packagesRoot;
    private readonly long _maxPackageBytes;

    public ClientPackageStore(IOptions<ClientPackageOptions> options, IWebHostEnvironment environment)
    {
        var configured = string.IsNullOrWhiteSpace(options.Value.DataDirectory)
            ? "data"
            : options.Value.DataDirectory.Trim();
        var dataRoot = Path.GetFullPath(Path.IsPathRooted(configured)
            ? configured
            : Path.Combine(environment.ContentRootPath, configured));
        _packagesRoot = Path.GetFullPath(Path.Combine(dataRoot, "packages"));
        _maxPackageBytes = Math.Clamp(options.Value.MaxPackageBytes, 1, 16L * 1024 * 1024 * 1024);
        Directory.CreateDirectory(_packagesRoot);
        EnsurePackagesRootIsOwnedDirectory();
        if (!OperatingSystem.IsWindows())
        {
            // Package bytes are server-managed. Owner-only traversal/write permission prevents
            // other local users from swapping a numeric package path between validation and open.
            File.SetUnixFileMode(_packagesRoot,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        EnsurePackagesRootIsOwnedDirectory();
    }

    public async Task<StoredClientPackage> SaveAsync(long id, Stream source, long declaredLength,
        CancellationToken cancellationToken)
    {
        if (declaredLength is <= 0 || declaredLength > _maxPackageBytes)
        {
            throw new ArgumentException($"package size must be between 1 and {_maxPackageBytes} bytes");
        }
        var finalPath = PathFor(id);
        var temporaryPath = Path.Combine(_packagesRoot, $".upload-{Guid.NewGuid():N}.tmp");
        long total = 0;
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using (var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write,
                             FileShare.None, 128 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough))
            {
                var buffer = new byte[128 * 1024];
                while (true)
                {
                    var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }
                    total = checked(total + read);
                    if (total > _maxPackageBytes || total > declaredLength)
                    {
                        throw new ArgumentException("package body exceeds the declared or configured size");
                    }
                    hash.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                }
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            if (total != declaredLength)
            {
                throw new ArgumentException("package body length does not match multipart metadata");
            }
            File.Move(temporaryPath, finalPath, overwrite: false);
            return new StoredClientPackage(Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant(), total);
        }
        catch
        {
            TryDelete(temporaryPath);
            throw;
        }
    }

    public Stream OpenRead(long id, long expectedLength)
    {
        var path = PathFor(id);
        var info = new FileInfo(path);
        if (!IsRegularUnlinkedFile(info) || info.Length != expectedLength)
        {
            throw new ResourceNotFoundException("package not found");
        }
        FileStream? stream = null;
        try
        {
            stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete,
                128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            info.Refresh();
            if (!IsRegularUnlinkedFile(info) || info.Length != expectedLength
                || stream.Length != expectedLength)
            {
                throw new ResourceNotFoundException("package not found");
            }
            return stream;
        }
        catch
        {
            stream?.Dispose();
            throw;
        }
    }

    public string? StageDelete(long id)
    {
        var path = PathFor(id);
        if (!File.Exists(path))
        {
            return null;
        }
        var staged = Path.Combine(_packagesRoot, $".delete-{id}-{Guid.NewGuid():N}.tmp");
        File.Move(path, staged, overwrite: false);
        return staged;
    }

    public void RollbackDelete(string? stagedPath, long id)
    {
        if (stagedPath is not null && File.Exists(stagedPath) && !File.Exists(PathFor(id)))
        {
            File.Move(stagedPath, PathFor(id), overwrite: false);
        }
    }

    public void CommitDelete(string? stagedPath) => TryDelete(stagedPath);
    public void Delete(long id) => TryDelete(PathFor(id));

    internal string PathFor(long id)
    {
        if (id <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(id));
        }
        EnsurePackagesRootIsOwnedDirectory();
        var path = Path.GetFullPath(Path.Combine(_packagesRoot, id.ToString(CultureInfo.InvariantCulture)));
        var prefix = _packagesRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                     + Path.DirectorySeparatorChar;
        if (!path.StartsWith(prefix, OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal))
        {
            throw new InvalidOperationException("package path escaped the configured data root");
        }
        return path;
    }

    private void EnsurePackagesRootIsOwnedDirectory()
    {
        var root = new DirectoryInfo(_packagesRoot);
        root.Refresh();
        if (!root.Exists || root.LinkTarget is not null
            || root.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidOperationException("client package root must be a real directory, not a link");
        }
    }

    private static bool IsRegularUnlinkedFile(FileInfo info)
    {
        info.Refresh();
        return info.Exists
            && info.LinkTarget is null
            && !info.Attributes.HasFlag(FileAttributes.ReparsePoint)
            && !info.Attributes.HasFlag(FileAttributes.Directory)
            && !info.Attributes.HasFlag(FileAttributes.Device);
    }

    private static void TryDelete(string? path)
    {
        if (path is null)
        {
            return;
        }
        try
        {
            File.Delete(path);
        }
        catch (FileNotFoundException)
        {
        }
    }
}

public sealed record StoredClientPackage(string Sha256, long FileSize);

public sealed class ClientPackagePublicRateLimiter
{
    private readonly object _gate = new();
    private readonly Dictionary<string, RateWindow> _windows = new(StringComparer.Ordinal);
    private readonly int _limit;
    private readonly int _maxTracked;
    private readonly TimeSpan _window;
    private readonly TimeProvider _timeProvider;

    public ClientPackagePublicRateLimiter(IOptions<ClientPackageOptions> options, TimeProvider timeProvider)
    {
        _limit = Math.Clamp(options.Value.PublicRequestsPerIp, 1, 100_000);
        _maxTracked = Math.Clamp(options.Value.MaxTrackedSources, 64, 100_000);
        _window = TimeSpan.FromSeconds(Math.Clamp(options.Value.PublicRateLimitWindowSeconds, 1, 86_400));
        _timeProvider = timeProvider;
    }

    public bool TryAcquire(string? source, out int retryAfterSeconds)
    {
        var key = string.IsNullOrWhiteSpace(source) ? "unknown" : source.Trim();
        var now = _timeProvider.GetUtcNow();
        lock (_gate)
        {
            if (_windows.TryGetValue(key, out var existing) && now - existing.Start < _window)
            {
                if (existing.Count >= _limit)
                {
                    retryAfterSeconds = Math.Max(1, (int)Math.Ceiling((_window - (now - existing.Start)).TotalSeconds));
                    return false;
                }
                _windows[key] = existing with { Count = existing.Count + 1 };
                retryAfterSeconds = 0;
                return true;
            }

            if (_windows.Count >= _maxTracked)
            {
                foreach (var expired in _windows.Where(pair => now - pair.Value.Start >= _window)
                             .Select(pair => pair.Key).Take(Math.Max(1, _maxTracked / 8)).ToArray())
                {
                    _windows.Remove(expired);
                }
                if (_windows.Count >= _maxTracked && !_windows.ContainsKey(key))
                {
                    retryAfterSeconds = Math.Max(1, (int)Math.Ceiling(_window.TotalSeconds));
                    return false;
                }
            }
            _windows[key] = new RateWindow(now, 1);
            retryAfterSeconds = 0;
            return true;
        }
    }

    private sealed record RateWindow(DateTimeOffset Start, int Count);
}

internal sealed record NormalizedClientPackageMetadata(string Implementation, string Platform, string Arch,
    string DisplayName, string? Version, string? Description, string? ChangelogUrl,
    string? MinSupportedVersion);

internal static class ClientPackageMetadata
{
    private static readonly HashSet<string> Implementations =
        new(StringComparer.Ordinal) { "java", "go", "csharp", "android" };
    private static readonly HashSet<string> Platforms =
        new(StringComparer.Ordinal) { "windows", "linux", "macos", "android", "any" };
    private static readonly HashSet<string> Architectures =
        new(StringComparer.Ordinal) { "x64", "arm64", "any" };

    public static NormalizedClientPackageMetadata NormalizeUpload(ClientPackageUploadMutation request)
    {
        var normalized = Normalize(request.Implementation, request.Platform, request.Arch,
            request.DisplayName, request.Version, request.Description, request.ChangelogUrl,
            request.MinSupportedVersion, requireVersion: true);
        if (normalized.Implementation == "android"
            && (normalized.Platform != "android" || normalized.Arch != "any"))
        {
            throw new ArgumentException("android packages must use platform=android and arch=any");
        }
        return normalized;
    }

    public static NormalizedClientPackageMetadata NormalizeLink(ClientDownloadLinkMutation request,
        bool requireVersion) => Normalize(request.Implementation, request.Platform, request.Arch,
        request.DisplayName, request.Version, request.Description, request.ChangelogUrl,
        request.MinSupportedVersion, requireVersion);

    public static string RequireImplementation(string? value) =>
        RequireEnum(value, Implementations, "implementation must be one of [java go csharp android]");

    public static string RequirePlatform(string? value) =>
        RequireEnum(value, Platforms, "platform must be one of [windows linux macos android any]");

    public static string RequireArch(string? value) =>
        RequireEnum(value, Architectures, "arch must be one of [x64 arm64 any]");

    public static string RequireExternalUrl(string? value)
    {
        var normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length is 0 or > 1024
            || !IsExternalUrl(normalized))
        {
            throw new ArgumentException(
                "downloadUrl must be an absolute HTTPS URL without credentials, query or fragment");
        }
        return normalized;
    }

    public static bool IsExternalUrl(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttps
        && !string.IsNullOrWhiteSpace(uri.Host)
        && string.IsNullOrEmpty(uri.UserInfo)
        && string.IsNullOrEmpty(uri.Query)
        && string.IsNullOrEmpty(uri.Fragment);

    public static string? NormalizeExternalSha256(string? sha256, long? fileSize)
    {
        if (string.IsNullOrWhiteSpace(sha256) && fileSize is null or 0)
        {
            return null;
        }
        var normalized = sha256?.Trim();
        if (!ClientPackageService.IsAuthoritativeSha256(normalized)
            || fileSize is null or <= 0)
        {
            throw new ArgumentException(
                "external release sha256 and positive fileSize must be supplied together");
        }
        return normalized;
    }

    public static long NormalizeExternalFileSize(string? sha256, long? fileSize) =>
        NormalizeExternalSha256(sha256, fileSize) is null ? 0 : fileSize!.Value;

    private static NormalizedClientPackageMetadata Normalize(string? implementation, string? platform,
        string? arch, string? displayName, string? version, string? description, string? changelogUrl,
        string? minSupportedVersion, bool requireVersion)
    {
        var normalizedVersion = NormalizeVersion(version, "version", requireVersion);
        var normalizedMinimum = NormalizeVersion(minSupportedVersion, "minSupportedVersion", false);
        if (normalizedMinimum is not null)
        {
            if (normalizedVersion is null)
            {
                throw new ArgumentException("minSupportedVersion requires version");
            }
            var parsedVersion = SemanticVersion.ParseOrNull(normalizedVersion)!.Value;
            var parsedMinimum = SemanticVersion.ParseOrNull(normalizedMinimum)!.Value;
            if (parsedMinimum.CompareTo(parsedVersion) > 0)
            {
                throw new ArgumentException("minSupportedVersion cannot be greater than version");
            }
        }
        return new NormalizedClientPackageMetadata(
            RequireImplementation(implementation),
            RequirePlatform(platform),
            RequireArch(arch),
            RequireText(displayName, "displayName", 120),
            normalizedVersion,
            NormalizeOptionalText(description, 512),
            NormalizeOptionalUrl(changelogUrl),
            normalizedMinimum);
    }

    private static string RequireEnum(string? value, IReadOnlySet<string> allowed, string error)
    {
        var normalized = value?.Trim().ToLowerInvariant() ?? string.Empty;
        if (!allowed.Contains(normalized))
        {
            throw new ArgumentException(error);
        }
        return normalized;
    }

    private static string RequireText(string? value, string field, int maxLength)
    {
        var normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length == 0 || normalized.Length > maxLength
            || normalized.IndexOfAny(['\r', '\n', '\0']) >= 0)
        {
            throw new ArgumentException($"{field} must contain 1 to {maxLength} safe characters");
        }
        return normalized;
    }

    private static string? NormalizeVersion(string? value, string field, bool required)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrEmpty(normalized))
        {
            if (required)
            {
                throw new ArgumentException($"{field} is required");
            }
            return null;
        }
        var canonical = normalized.StartsWith('v') ? normalized[1..] : normalized;
        if (canonical.Length > 32 || !SemanticVersion.TryParse(normalized, out _))
        {
            throw new ArgumentException($"{field} must be a semantic version no longer than 32 characters");
        }
        return canonical;
    }

    private static string? NormalizeOptionalText(string? value, int maxLength)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrEmpty(normalized))
        {
            return null;
        }
        if (normalized.Length > maxLength || normalized.IndexOfAny(['\r', '\0']) >= 0)
        {
            throw new ArgumentException($"text must not exceed {maxLength} safe characters");
        }
        return normalized;
    }

    private static string? NormalizeOptionalUrl(string? value)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrEmpty(normalized))
        {
            return null;
        }
        if (normalized.Length > 1024 || !Uri.TryCreate(normalized, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(uri.Host)
            || !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException("changelogUrl must be an absolute HTTPS URL");
        }
        return normalized;
    }
}

internal readonly record struct SemanticVersion(BigInteger Major, BigInteger Minor, BigInteger Patch,
    IReadOnlyList<string> PreRelease) : IComparable<SemanticVersion>
{
    public static bool TryParse(string? value, out SemanticVersion version)
    {
        version = default;
        var text = value?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }
        if (text.StartsWith('v'))
        {
            text = text[1..];
        }
        if (text.Length is 0 or > 32)
        {
            return false;
        }

        var buildAt = text.IndexOf('+');
        string[] build = [];
        if (buildAt >= 0)
        {
            build = text[(buildAt + 1)..].Split('.');
            text = text[..buildAt];
        }
        var dashAt = text.IndexOf('-');
        var core = dashAt < 0 ? text : text[..dashAt];
        string[] pre = dashAt < 0 ? [] : text[(dashAt + 1)..].Split('.');
        var parts = core.Split('.');
        if (parts.Length != 3 || !TryNumber(parts[0], out var major)
                              || !TryNumber(parts[1], out var minor)
                              || !TryNumber(parts[2], out var patch)
                              || pre.Any(identifier => !ValidIdentifier(identifier)
                                  || IsNumeric(identifier) && identifier.Length > 1 && identifier[0] == '0')
                              || build.Any(identifier => !ValidIdentifier(identifier)))
        {
            return false;
        }
        version = new SemanticVersion(major, minor, patch, pre);
        return true;
    }

    public static SemanticVersion? ParseOrNull(string? value) =>
        TryParse(value, out var parsed) ? parsed : null;

    public int CompareTo(SemanticVersion other)
    {
        var core = Major.CompareTo(other.Major);
        if (core == 0) core = Minor.CompareTo(other.Minor);
        if (core == 0) core = Patch.CompareTo(other.Patch);
        if (core != 0) return core;
        if (PreRelease.Count == 0) return other.PreRelease.Count == 0 ? 0 : 1;
        if (other.PreRelease.Count == 0) return -1;
        for (var i = 0; i < Math.Min(PreRelease.Count, other.PreRelease.Count); i++)
        {
            var leftNumeric = IsNumeric(PreRelease[i]);
            var rightNumeric = IsNumeric(other.PreRelease[i]);
            int comparison;
            if (leftNumeric && rightNumeric)
            {
                comparison = BigInteger.Parse(PreRelease[i], CultureInfo.InvariantCulture)
                    .CompareTo(BigInteger.Parse(other.PreRelease[i], CultureInfo.InvariantCulture));
            }
            else if (leftNumeric) comparison = -1;
            else if (rightNumeric) comparison = 1;
            else comparison = string.CompareOrdinal(PreRelease[i], other.PreRelease[i]);
            if (comparison != 0) return comparison;
        }
        return PreRelease.Count.CompareTo(other.PreRelease.Count);
    }

    private static bool TryNumber(string text, out BigInteger value)
    {
        value = BigInteger.Zero;
        return IsNumeric(text) && (text.Length == 1 || text[0] != '0')
            && BigInteger.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    private static bool IsNumeric(string identifier) => identifier.Length > 0
        && identifier.All(character => character is >= '0' and <= '9');

    private static bool ValidIdentifier(string identifier) => identifier.Length > 0
        && identifier.All(character => char.IsAsciiLetterOrDigit(character) || character == '-');
}
