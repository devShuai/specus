using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;

namespace Specus.IntegrationTests;

public sealed class ClientPackageApiTests : IAsyncLifetime
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _dataRoot = Path.Combine(Path.GetTempPath(), $"specus-packages-{Guid.NewGuid():N}");
    private TestServerFixture? _server;

    public async Task InitializeAsync()
    {
        _server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:ClientPackages:DataDirectory"] = _dataRoot,
            ["Specus:ClientPackages:MaxPackageBytes"] = "1048576",
            ["Specus:ClientPackages:PublicRequestsPerIp"] = "1000",
        });
    }

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
        try
        {
            if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true);
        }
        catch
        {
            // Best effort on Windows: a failed assertion can leave a response stream briefly open.
        }
    }

    [Fact]
    public async Task HostedPackageLifecycleStreamsVerifiedBytesAndSwitchesLatestAtomically()
    {
        using var admin = await AuthenticatedClientAsync(_server!);
        var firstBytes = Encoding.UTF8.GetBytes("specus-csharp-1.2.0");
        var secondBytes = Encoding.UTF8.GetBytes("specus-csharp-1.3.0");

        var first = await UploadAsync(admin, firstBytes, "1.2.0", isLatest: true);
        var second = await UploadAsync(admin, secondBytes, "1.3.0", isLatest: true,
            minSupportedVersion: "1.1.0");

        Assert.True(first.Hosted);
        Assert.Equal(first.Id, first.PackageId);
        Assert.Equal(Sha256(firstBytes), first.Sha256);
        Assert.Equal(firstBytes.Length, first.FileSize);
        Assert.Equal($"/api/public/client-packages/{first.Id}/download", first.DownloadUrl);
        Assert.True(second.IsLatest);

        var adminRows = await admin.GetFromJsonAsync<List<DownloadBody>>(
            "/api/admin/client-downloads", JsonOptions);
        Assert.NotNull(adminRows);
        Assert.False(Assert.Single(adminRows!, row => row.Id == first.Id).IsLatest);
        Assert.True(Assert.Single(adminRows!, row => row.Id == second.Id).IsLatest);

        using var anonymous = _server!.CreateClient();
        var publicRows = await anonymous.GetFromJsonAsync<List<DownloadBody>>(
            "/api/public/client-downloads", JsonOptions);
        var publicCSharpRows = publicRows!.Where(row => row.Implementation == "csharp"
            && row.Platform == "windows" && row.Arch == "x64").ToList();
        Assert.Equal(second.Id, Assert.Single(publicCSharpRows).Id);

        using var checkResponse = await anonymous.GetAsync(
            "/api/public/client-version-check?implementation=csharp&platform=windows&arch=x64&current=1.0.0");
        checkResponse.EnsureSuccessStatusCode();
        Assert.True(checkResponse.Headers.CacheControl?.NoStore);
        var check = await checkResponse.Content.ReadFromJsonAsync<VersionCheckBody>(JsonOptions);
        Assert.NotNull(check);
        Assert.True(check!.UpdateAvailable);
        Assert.True(check.Mandatory);
        Assert.Equal("1.3.0", check.LatestVersion);
        Assert.Equal(second.Id, check.PackageId);
        Assert.Equal(second.Sha256, check.Sha256);

        using var download = await anonymous.GetAsync(check.DownloadUrl);
        download.EnsureSuccessStatusCode();
        Assert.Equal("nosniff", download.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.True(download.Headers.CacheControl?.NoStore);
        Assert.Equal(secondBytes, await download.Content.ReadAsByteArrayAsync());

        using var rangeRequest = new HttpRequestMessage(HttpMethod.Get, check.DownloadUrl);
        rangeRequest.Headers.Range = new RangeHeaderValue(0, 5);
        using var range = await anonymous.SendAsync(rangeRequest);
        Assert.Equal(HttpStatusCode.PartialContent, range.StatusCode);
        Assert.Equal(secondBytes[..6], await range.Content.ReadAsByteArrayAsync());

        using var delete = await admin.DeleteAsync($"/api/admin/client-downloads/{second.Id}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
        Assert.False(File.Exists(Path.Combine(_dataRoot, "packages", second.Id.ToString())));

        var afterDelete = await anonymous.GetFromJsonAsync<VersionCheckBody>(
            "/api/public/client-version-check?implementation=csharp&platform=windows&arch=x64&current=1.0.0",
            JsonOptions);
        Assert.NotNull(afterDelete);
        Assert.False(afterDelete!.UpdateAvailable);
        Assert.Null(afterDelete.LatestVersion);
        Assert.Null(afterDelete.PackageId);
        Assert.False(afterDelete.Mandatory);
        var publicAfterDelete = await anonymous.GetFromJsonAsync<List<DownloadBody>>(
            "/api/public/client-downloads", JsonOptions);
        Assert.DoesNotContain(publicAfterDelete!, row => row.Implementation == "csharp"
            && row.Platform == "windows" && row.Arch == "x64");
    }

    [Fact]
    public async Task ExternalLatestWithAuthoritativeIntegrityBecomesUpdateCandidate()
    {
        using var admin = await AuthenticatedClientAsync(_server!);
        _ = await UploadAsync(admin, Encoding.UTF8.GetBytes("trusted-hosted"), "1.0.0", true,
            implementation: "csharp", platform: "any", arch: "any");
        using var created = await admin.PostAsJsonAsync("/api/admin/client-downloads", new
        {
            implementation = "csharp",
            platform = "any",
            arch = "any",
            displayName = "external-client.zip",
            downloadUrl = "https://downloads.example/external-client.zip",
            version = "99.0.0",
            sha256 = new string('a', 64),
            fileSize = 987654,
            isLatest = true,
            enabled = true,
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var external = await created.Content.ReadFromJsonAsync<DownloadBody>(JsonOptions);
        Assert.NotNull(external);
        Assert.False(external!.Hosted);

        using var anonymous = _server!.CreateClient();
        var publicRows = await anonymous.GetFromJsonAsync<List<DownloadBody>>(
            "/api/public/client-downloads", JsonOptions);
        Assert.Equal(external.Id, Assert.Single(publicRows!, row => row.Implementation == "csharp"
            && row.Platform == "any" && row.Arch == "any").Id);

        var check = await anonymous.GetFromJsonAsync<VersionCheckBody>(
            "/api/public/client-version-check?implementation=csharp&platform=any&arch=any&current=0.9.0",
            JsonOptions);
        Assert.NotNull(check);
        Assert.True(check!.UpdateAvailable);
        Assert.Equal("99.0.0", check.LatestVersion);
        Assert.Null(check.PackageId);
        Assert.Equal(new string('a', 64), check.Sha256);
        Assert.Equal(987654, check.FileSize);
        Assert.Equal("https://downloads.example/external-client.zip", check.DownloadUrl);
    }

    [Fact]
    public async Task UploadDefaultsToDraftAndRejectsIncompleteOrInvertedPublicationMetadata()
    {
        using var admin = await AuthenticatedClientAsync(_server!);
        using var draftForm = PackageForm(Encoding.UTF8.GetBytes("draft"), "3.0.0",
            "go", "linux", "arm64", isLatest: null);
        using var draftResponse = await admin.PostAsync("/api/admin/client-packages", draftForm);
        Assert.Equal(HttpStatusCode.Created, draftResponse.StatusCode);
        var draft = await draftResponse.Content.ReadFromJsonAsync<DownloadBody>(JsonOptions);
        Assert.NotNull(draft);
        Assert.False(draft!.IsLatest);

        using var anonymous = _server!.CreateClient();
        var check = await anonymous.GetFromJsonAsync<VersionCheckBody>(
            "/api/public/client-version-check?implementation=go&platform=linux&arch=arm64&current=1.0.0",
            JsonOptions);
        Assert.NotNull(check);
        Assert.False(check!.UpdateAvailable);
        var publicRows = await anonymous.GetFromJsonAsync<List<DownloadBody>>(
            "/api/public/client-downloads", JsonOptions);
        Assert.DoesNotContain(publicRows!, row => row.Id == draft.Id);

        using var latestWithoutVersion = await admin.PostAsJsonAsync("/api/admin/client-downloads", new
        {
            implementation = "java",
            platform = "any",
            arch = "any",
            displayName = "unversioned-latest",
            downloadUrl = "https://downloads.example/unversioned",
            enabled = true,
            isLatest = true,
        });
        Assert.Equal(HttpStatusCode.BadRequest, latestWithoutVersion.StatusCode);

        using var minimumWithoutVersion = await admin.PostAsJsonAsync("/api/admin/client-downloads", new
        {
            implementation = "java",
            platform = "any",
            arch = "any",
            displayName = "unversioned-minimum",
            downloadUrl = "https://downloads.example/unversioned-minimum",
            enabled = true,
            minSupportedVersion = "1.0.0",
        });
        Assert.Equal(HttpStatusCode.BadRequest, minimumWithoutVersion.StatusCode);

        using var publishedExternalResponse = await admin.PostAsJsonAsync("/api/admin/client-downloads", new
        {
            implementation = "java",
            platform = "windows",
            arch = "x64",
            displayName = "published-external",
            downloadUrl = "https://downloads.example/published-external",
            version = "1.0.0",
            sha256 = new string('b', 64),
            fileSize = 1234,
            enabled = true,
            isLatest = true,
        });
        Assert.Equal(HttpStatusCode.Created, publishedExternalResponse.StatusCode);
        var publishedExternal = await publishedExternalResponse.Content
            .ReadFromJsonAsync<DownloadBody>(JsonOptions);
        Assert.NotNull(publishedExternal);
        using var removePublishedVersion = await admin.PutAsJsonAsync(
            $"/api/admin/client-downloads/{publishedExternal!.Id}", new
            {
                implementation = publishedExternal.Implementation,
                platform = publishedExternal.Platform,
                arch = publishedExternal.Arch,
                displayName = publishedExternal.DisplayName,
                downloadUrl = publishedExternal.DownloadUrl,
                sha256 = publishedExternal.Sha256,
                fileSize = publishedExternal.FileSize,
                enabled = true,
                isLatest = true,
            });
        Assert.Equal(HttpStatusCode.BadRequest, removePublishedVersion.StatusCode);

        using var invertedForm = PackageForm(Encoding.UTF8.GetBytes("inverted"), "1.0.0",
            "csharp", "linux", "x64", isLatest: false, minSupportedVersion: "2.0.0");
        using var inverted = await admin.PostAsync("/api/admin/client-packages", invertedForm);
        Assert.Equal(HttpStatusCode.BadRequest, inverted.StatusCode);

        foreach (var invalidUrl in new[]
                 {
                     "http://downloads.example/client.zip",
                     "https://user@downloads.example/client.zip",
                     "https://downloads.example/client.zip?token=metadata",
                     "https://downloads.example/client.zip#fragment",
                 })
        {
            using var invalidExternal = await admin.PostAsJsonAsync("/api/admin/client-downloads", new
            {
                implementation = "java",
                platform = "linux",
                arch = "x64",
                displayName = "invalid-external",
                downloadUrl = invalidUrl,
                version = "2.0.0",
                sha256 = new string('c', 64),
                fileSize = 10,
                enabled = true,
                isLatest = true,
            });
            Assert.Equal(HttpStatusCode.BadRequest, invalidExternal.StatusCode);
        }

        using var incompleteIntegrity = await admin.PostAsJsonAsync("/api/admin/client-downloads", new
        {
            implementation = "java",
            platform = "linux",
            arch = "x64",
            displayName = "incomplete-integrity",
            downloadUrl = "https://downloads.example/incomplete.zip",
            version = "2.0.0",
            sha256 = new string('d', 64),
            enabled = true,
            isLatest = true,
        });
        Assert.Equal(HttpStatusCode.BadRequest, incompleteIntegrity.StatusCode);
    }

    [Fact]
    public async Task NonCanonicalDigestCannotAuthorizeAHostedUpdateOrDownload()
    {
        using var admin = await AuthenticatedClientAsync(_server!);
        var package = await UploadAsync(admin, Encoding.UTF8.GetBytes("canonical-digest"), "6.0.0", true,
            implementation: "go", platform: "linux", arch: "arm64");
        await using (var scope = _server!.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var row = await db.ClientDownloadLinks.FindAsync(package.Id);
            Assert.NotNull(row);
            row!.Sha256 = new string('A', 64);
            await db.SaveChangesAsync();
        }

        using var anonymous = _server.CreateClient();
        var check = await anonymous.GetFromJsonAsync<VersionCheckBody>(
            "/api/public/client-version-check?implementation=go&platform=linux&arch=arm64&current=1.0.0",
            JsonOptions);
        Assert.NotNull(check);
        Assert.False(check!.UpdateAvailable);
        using var download = await anonymous.GetAsync(package.DownloadUrl);
        Assert.Equal(HttpStatusCode.NotFound, download.StatusCode);

        var publicRows = await anonymous.GetFromJsonAsync<List<DownloadBody>>(
            "/api/public/client-downloads", JsonOptions);
        var visible = Assert.Single(publicRows!, row => row.Id == package.Id);
        Assert.False(visible.Hosted);
        Assert.Null(visible.PackageId);
    }

    [Fact]
    public async Task VersionedTargetSuppressesLegacyLinkUntilAnExplicitLatestIsPublished()
    {
        using var admin = await AuthenticatedClientAsync(_server!);
        using var legacyResponse = await admin.PostAsJsonAsync("/api/admin/client-downloads", new
        {
            implementation = "java",
            platform = "macos",
            arch = "arm64",
            displayName = "legacy-java-client",
            downloadUrl = "https://downloads.example/legacy-java-client",
            enabled = true,
        });
        legacyResponse.EnsureSuccessStatusCode();
        var legacy = await legacyResponse.Content.ReadFromJsonAsync<DownloadBody>(JsonOptions);
        Assert.NotNull(legacy);

        using var anonymous = _server!.CreateClient();
        var before = await anonymous.GetFromJsonAsync<List<DownloadBody>>(
            "/api/public/client-downloads", JsonOptions);
        Assert.Equal(legacy!.Id, Assert.Single(before!, row => row.Implementation == "java"
            && row.Platform == "macos" && row.Arch == "arm64").Id);

        var published = await UploadAsync(admin, Encoding.UTF8.GetBytes("published-java"), "5.0.0", false,
            implementation: "java", platform: "macos", arch: "arm64");
        var unpublished = await anonymous.GetFromJsonAsync<List<DownloadBody>>(
            "/api/public/client-downloads", JsonOptions);
        Assert.DoesNotContain(unpublished!, row => row.Implementation == "java"
            && row.Platform == "macos" && row.Arch == "arm64");

        using var markLatest = await admin.PostAsync(
            $"/api/admin/client-downloads/{published.Id}/latest", content: null);
        markLatest.EnsureSuccessStatusCode();
        var after = await anonymous.GetFromJsonAsync<List<DownloadBody>>(
            "/api/public/client-downloads", JsonOptions);
        Assert.Equal(published.Id, Assert.Single(after!, row => row.Implementation == "java"
            && row.Platform == "macos" && row.Arch == "arm64").Id);
        Assert.DoesNotContain(after!, row => row.Id == legacy.Id);

        using var disable = await admin.PutAsJsonAsync($"/api/admin/client-downloads/{published.Id}", new
        {
            implementation = published.Implementation,
            platform = published.Platform,
            arch = published.Arch,
            displayName = published.DisplayName,
            version = published.Version,
            enabled = false,
            isLatest = false,
        });
        disable.EnsureSuccessStatusCode();
        var afterDisable = await anonymous.GetFromJsonAsync<List<DownloadBody>>(
            "/api/public/client-downloads", JsonOptions);
        Assert.DoesNotContain(afterDisable!, row => row.Implementation == "java"
            && row.Platform == "macos" && row.Arch == "arm64");
    }

    [Fact]
    public async Task PackageDownloadRejectsSymbolicLinkTargetsWhenPlatformSupportsLinks()
    {
        using var admin = await AuthenticatedClientAsync(_server!);
        var bytes = Encoding.UTF8.GetBytes("outside-package-with-the-same-length");
        var package = await UploadAsync(admin, bytes, "8.0.0", true,
            implementation: "go", platform: "macos", arch: "arm64");
        var storedPath = Path.Combine(_dataRoot, "packages", package.Id.ToString());
        var outsidePath = Path.Combine(Path.GetTempPath(), $"specus-outside-{Guid.NewGuid():N}");
        await File.WriteAllBytesAsync(outsidePath, bytes);
        File.Delete(storedPath);
        try
        {
            try
            {
                File.CreateSymbolicLink(storedPath, outsidePath);
            }
            catch (Exception exception) when (exception is UnauthorizedAccessException
                or IOException or NotSupportedException)
            {
                return;
            }

            using var anonymous = _server!.CreateClient();
            using var response = await anonymous.GetAsync(package.DownloadUrl);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
        finally
        {
            try { File.Delete(storedPath); } catch { }
            try { File.Delete(outsidePath); } catch { }
        }
    }

    [Fact]
    public async Task ConcurrentLatestUploadsAcrossRequestDbContextsNeverCreateTwoLatestRows()
    {
        using var firstAdmin = await AuthenticatedClientAsync(_server!);
        using var secondAdmin = await AuthenticatedClientAsync(_server!);
        using var firstForm = PackageForm(Encoding.UTF8.GetBytes("parallel-a"), "7.0.0",
            "go", "linux", "x64", true);
        using var secondForm = PackageForm(Encoding.UTF8.GetBytes("parallel-b"), "7.1.0",
            "go", "linux", "x64", true);

        var responses = await Task.WhenAll(
            firstAdmin.PostAsync("/api/admin/client-packages", firstForm),
            secondAdmin.PostAsync("/api/admin/client-packages", secondForm));
        try
        {
            Assert.Contains(responses, response => response.StatusCode == HttpStatusCode.Created);
            Assert.DoesNotContain(responses, response =>
                (int)response.StatusCode >= (int)HttpStatusCode.InternalServerError);
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }

        var rows = await firstAdmin.GetFromJsonAsync<List<DownloadBody>>(
            "/api/admin/client-downloads", JsonOptions);
        var targetRows = rows!.Where(row => row.Implementation == "go"
            && row.Platform == "linux" && row.Arch == "x64").ToList();
        Assert.Single(targetRows, row => row.IsLatest);
    }

    [Fact]
    public async Task UploadRejectsDuplicatesOversizeAndNonAdminCallersWithoutLeavingFiles()
    {
        using var admin = await AuthenticatedClientAsync(_server!);
        var bytes = Encoding.UTF8.GetBytes("first");
        _ = await UploadAsync(admin, bytes, "2.0.0", isLatest: false);

        using var duplicate = PackageForm(bytes, "2.0.0", "csharp", "windows", "x64", false);
        using var duplicateResponse = await admin.PostAsync("/api/admin/client-packages", duplicate);
        Assert.Equal(HttpStatusCode.BadRequest, duplicateResponse.StatusCode);

        using var forgedDigest = PackageForm(bytes, "2.1.0", "csharp", "windows", "x64", false);
        forgedDigest.Add(new StringContent(new string('0', 64)), "sha256");
        using var forgedDigestResponse = await admin.PostAsync("/api/admin/client-packages", forgedDigest);
        Assert.Equal(HttpStatusCode.BadRequest, forgedDigestResponse.StatusCode);

        using var anonymous = _server!.CreateClient();
        using var unauthorizedForm = PackageForm(bytes, "3.0.0", "csharp", "windows", "x64", true);
        using var unauthorized = await anonymous.PostAsync("/api/admin/client-packages", unauthorizedForm);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);

        var oversizedBytes = new byte[1_048_577];
        using var oversizedForm = PackageForm(oversizedBytes, "4.0.0", "csharp", "windows", "x64", true);
        using var oversized = await admin.PostAsync("/api/admin/client-packages", oversizedForm);
        Assert.True(oversized.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.RequestEntityTooLarge,
            await oversized.Content.ReadAsStringAsync());

        var files = Directory.Exists(Path.Combine(_dataRoot, "packages"))
            ? Directory.EnumerateFiles(Path.Combine(_dataRoot, "packages"))
                .Where(path => !Path.GetFileName(path).StartsWith(".", StringComparison.Ordinal)).ToArray()
            : [];
        Assert.Single(files);
    }

    [Fact]
    public async Task AndroidGenericApkIsAcceptedAndInvalidAndroidTargetIsRejected()
    {
        using var admin = await AuthenticatedClientAsync(_server!);
        var apk = await UploadAsync(admin, [0x50, 0x4b, 0x03, 0x04], "v1.4.0", true,
            implementation: "android", platform: "android", arch: "any");
        Assert.Equal("android", apk.Implementation);
        Assert.Equal("android", apk.Platform);
        Assert.Equal("any", apk.Arch);
        Assert.Equal("1.4.0", apk.Version);

        using var invalidForm = PackageForm([1, 2, 3], "1.4.1", "android", "windows", "x64", true);
        using var invalid = await admin.PostAsync("/api/admin/client-packages", invalidForm);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        using var anonymous = _server!.CreateClient();
        var check = await anonymous.GetFromJsonAsync<VersionCheckBody>(
            "/api/public/client-version-check?implementation=android&platform=android&arch=any&current=1.3.0",
            JsonOptions);
        Assert.NotNull(check);
        Assert.True(check!.UpdateAvailable);
        Assert.Equal("1.4.0", check.LatestVersion);

        using var head = new HttpRequestMessage(HttpMethod.Head, apk.DownloadUrl);
        using var headResponse = await anonymous.SendAsync(head);
        headResponse.EnsureSuccessStatusCode();
        Assert.EndsWith(".apk", headResponse.Content.Headers.ContentDisposition?.FileNameStar
            ?? headResponse.Content.Headers.ContentDisposition?.FileName, StringComparison.OrdinalIgnoreCase);
        Assert.True(headResponse.Headers.CacheControl?.NoStore);
        Assert.Equal("nosniff", headResponse.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal(apk.FileSize, headResponse.Content.Headers.ContentLength);
        Assert.Equal($"\"sha256-{apk.Sha256}\"", headResponse.Headers.ETag?.Tag);
    }

    [Fact]
    public async Task PublicRateLimitCannotBeRotatedWithForwardedHeadersFromUntrustedPeer()
    {
        var dataRoot = Path.Combine(Path.GetTempPath(), $"specus-package-limit-{Guid.NewGuid():N}");
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:TrustedProxies"] = string.Empty,
            ["Specus:ClientPackages:DataDirectory"] = dataRoot,
            ["Specus:ClientPackages:PublicRequestsPerIp"] = "2",
            ["Specus:ClientPackages:PublicRateLimitWindowSeconds"] = "300",
        });
        using var client = server.CreateClient();
        using var first = RequestWithForwardedAddress("203.0.113.1");
        using var second = RequestWithForwardedAddress("203.0.113.2");
        using var third = RequestWithForwardedAddress("203.0.113.3");
        using var firstResponse = await client.SendAsync(first);
        using var secondResponse = await client.SendAsync(second);
        using var thirdResponse = await client.SendAsync(third);

        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, thirdResponse.StatusCode);
        Assert.True(thirdResponse.Headers.Contains("Retry-After"));
        Assert.Equal("application/json", thirdResponse.Content.Headers.ContentType?.MediaType);
        using var error = JsonDocument.Parse(await thirdResponse.Content.ReadAsStringAsync());
        Assert.Equal("rate_limited", error.RootElement.GetProperty("error").GetString());
        try { if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, true); } catch { }
    }

    private static HttpRequestMessage RequestWithForwardedAddress(string address)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/public/client-downloads");
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", address);
        return request;
    }

    private static async Task<DownloadBody> UploadAsync(HttpClient admin, byte[] bytes, string version,
        bool isLatest, string? minSupportedVersion = null, string implementation = "csharp",
        string platform = "windows", string arch = "x64")
    {
        using var form = PackageForm(bytes, version, implementation, platform, arch, isLatest,
            minSupportedVersion);
        using var response = await admin.PostAsync("/api/admin/client-packages", form);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<DownloadBody>(JsonOptions);
        return Assert.IsType<DownloadBody>(body);
    }

    private static MultipartFormDataContent PackageForm(byte[] bytes, string version,
        string implementation, string platform, string arch, bool? isLatest,
        string? minSupportedVersion = null)
    {
        var form = new MultipartFormDataContent();
        var file = new ByteArrayContent(bytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(file, "file", $"specus-{version}.zip");
        form.Add(new StringContent(implementation), "implementation");
        form.Add(new StringContent(platform), "platform");
        form.Add(new StringContent(arch), "arch");
        var displayName = implementation == "android"
            ? $"specus-{implementation}-{version}"
            : $"specus-{implementation}-{version}.zip";
        form.Add(new StringContent(displayName), "displayName");
        form.Add(new StringContent(version), "version");
        if (isLatest is not null)
        {
            form.Add(new StringContent(isLatest.Value.ToString()), "isLatest");
        }
        form.Add(new StringContent("true"), "enabled");
        if (minSupportedVersion is not null)
        {
            form.Add(new StringContent(minSupportedVersion), "minSupportedVersion");
        }
        return form;
    }

    private static async Task<HttpClient> AuthenticatedClientAsync(TestServerFixture server)
    {
        var client = server.CreateClient();
        using var response = await client.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = "admin",
        });
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenBody>(JsonOptions);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", Assert.IsType<TokenBody>(token).AccessToken);
        return client;
    }

    private static string Sha256(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed record TokenBody(string AccessToken);

    private sealed record DownloadBody(long Id, string Implementation, string Platform, string Arch,
        string DisplayName, string DownloadUrl, string? Description, string? Version, string? Sha256,
        long FileSize, bool IsLatest, string? ChangelogUrl, string? MinSupportedVersion, bool Hosted,
        long? PackageId, int DisplayOrder, bool Enabled, string CreatedAt, string UpdatedAt);

    private sealed record VersionCheckBody(bool UpdateAvailable, bool Mandatory, string? LatestVersion,
        long? PackageId, string? DownloadUrl, string? Sha256, long FileSize, string? ChangelogUrl);
}
