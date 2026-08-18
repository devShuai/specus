using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
        var check = await anonymous.GetFromJsonAsync<VersionCheckBody>(
            "/api/public/client-version-check?implementation=csharp&platform=windows&arch=x64&current=1.0.0",
            JsonOptions);
        Assert.NotNull(check);
        Assert.True(check!.UpdateAvailable);
        Assert.True(check.Mandatory);
        Assert.Equal("1.3.0", check.LatestVersion);
        Assert.Equal(second.Id, check.PackageId);
        Assert.Equal(second.Sha256, check.Sha256);

        using var download = await anonymous.GetAsync(check.DownloadUrl);
        download.EnsureSuccessStatusCode();
        Assert.Equal("nosniff", download.Headers.GetValues("X-Content-Type-Options").Single());
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
        Assert.Equal("1.2.0", afterDelete!.LatestVersion);
        Assert.False(afterDelete.Mandatory);
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
        var apk = await UploadAsync(admin, [0x50, 0x4b, 0x03, 0x04], "1.4.0", true,
            implementation: "android", platform: "android", arch: "any");
        Assert.Equal("android", apk.Implementation);
        Assert.Equal("android", apk.Platform);
        Assert.Equal("any", apk.Arch);

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
        string implementation, string platform, string arch, bool isLatest,
        string? minSupportedVersion = null)
    {
        var form = new MultipartFormDataContent();
        var file = new ByteArrayContent(bytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(file, "file", $"specus-{version}.zip");
        form.Add(new StringContent(implementation), "implementation");
        form.Add(new StringContent(platform), "platform");
        form.Add(new StringContent(arch), "arch");
        form.Add(new StringContent($"specus-{implementation}-{version}.zip"), "displayName");
        form.Add(new StringContent(version), "version");
        form.Add(new StringContent(isLatest.ToString()), "isLatest");
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
