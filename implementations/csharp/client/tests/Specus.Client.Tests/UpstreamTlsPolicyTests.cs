using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Specus.Client;

namespace Specus.Client.Tests;

public sealed class UpstreamTlsPolicyTests : IDisposable
{
    public void Dispose() => UpstreamTlsPolicy.Configure(null);

    /// <summary>
    /// The default has to verify. Anything able to answer on the target address would otherwise be
    /// accepted, and the tunnel would carry the result to a remote user who cannot tell.
    /// </summary>
    [Fact]
    public void DefaultPolicyVerifies()
    {
        var policy = new UpstreamTlsPolicy(false, null, []);

        Assert.True(policy.Verifies);
        Assert.False(policy.Pins);
        // No callback means the platform performs its normal chain and hostname checks.
        Assert.Null(policy.CreateOptions("example.test").RemoteCertificateValidationCallback);
    }

    /// <summary>If configuration never arrives, the forwarding paths must still verify.</summary>
    [Fact]
    public void CurrentDefaultsToVerifying()
    {
        Assert.True(UpstreamTlsPolicy.Current.Verifies);

        UpstreamTlsPolicy.Configure(new UpstreamTlsPolicy(true, null, []));
        Assert.False(UpstreamTlsPolicy.Current.Verifies);

        UpstreamTlsPolicy.Configure(null);
        Assert.True(UpstreamTlsPolicy.Current.Verifies);
    }

    /// <summary>The opt-out still exists, because some deployments genuinely cannot do better.</summary>
    [Fact]
    public void ExplicitOptOutAcceptsAnything()
    {
        var options = new UpstreamTlsPolicy(true, null, []).CreateOptions("example.test");

        Assert.NotNull(options.RemoteCertificateValidationCallback);
        Assert.True(options.RemoteCertificateValidationCallback!(
            this, null, null, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void PinnedPolicyAcceptsOnlyTheMatchingCertificate()
    {
        using var certificate = SelfSigned("pinned.test");
        var fingerprint = UpstreamTlsPolicy.Fingerprint(certificate);
        var policy = new UpstreamTlsPolicy(false, null, [fingerprint]);

        Assert.True(policy.Pins);
        var callback = policy.CreateOptions("pinned.test").RemoteCertificateValidationCallback;
        Assert.NotNull(callback);
        Assert.True(callback!(this, certificate, null, SslPolicyErrors.RemoteCertificateChainErrors));

        using var other = SelfSigned("other.test");
        Assert.False(callback(this, other, null, SslPolicyErrors.None));
        Assert.False(callback(this, null, null, SslPolicyErrors.RemoteCertificateNotAvailable));
    }

    /// <summary>A fingerprint copied out of a tool has colons and uppercase; it is the same pin.</summary>
    [Fact]
    public void FingerprintsAreAcceptedInTheFormToolsPrint()
    {
        var plain = string.Concat(Enumerable.Repeat("0123456789abcdef", 4));
        var colonised = string.Join(':',
            Enumerable.Range(0, plain.Length / 2).Select(i => plain.Substring(i * 2, 2).ToUpperInvariant()));

        var normalized = UpstreamTlsPolicy.NormalizePins([colonised]);

        Assert.Single(normalized);
        Assert.Contains(plain, normalized);
    }

    [Fact]
    public void BlankEntriesAreIgnored()
    {
        Assert.Empty(UpstreamTlsPolicy.NormalizePins(["", "   "]));
        Assert.Empty(UpstreamTlsPolicy.NormalizePins([]));
    }

    /// <summary>
    /// Misconfiguration has to fail rather than quietly fall back to trusting everything, which is
    /// the failure mode this change exists to remove.
    /// </summary>
    [Fact]
    public void MisconfigurationFailsRatherThanFallingBack()
    {
        Assert.Throws<InvalidOperationException>(
            () => new UpstreamTlsPolicy(false, null, ["abcd"]));
        Assert.Throws<InvalidOperationException>(
            () => new UpstreamTlsPolicy(false, null, [new string('z', 64)]));
        Assert.Throws<InvalidOperationException>(
            () => new UpstreamTlsPolicy(false, "no-such-file.pem", []));
    }

    /// <summary>A name mismatch is never something an extra trusted root can excuse.</summary>
    [Fact]
    public void ExtraRootsDoNotExcuseANameMismatch()
    {
        using var certificate = SelfSigned("somewhere-else.test");
        var pemPath = Path.Combine(Path.GetTempPath(), $"ca-{Guid.NewGuid():N}.pem");
        File.WriteAllText(pemPath, certificate.ExportCertificatePem());
        try
        {
            var policy = new UpstreamTlsPolicy(false, pemPath, []);
            var callback = policy.CreateOptions("expected.test").RemoteCertificateValidationCallback;
            Assert.NotNull(callback);
            Assert.False(callback!(this, certificate, null, SslPolicyErrors.RemoteCertificateNameMismatch));
        }
        finally
        {
            File.Delete(pemPath);
        }
    }

    private static X509Certificate2 SelfSigned(string commonName)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={commonName}", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddHours(1));
    }

    /// <summary>
    /// The HTTP forwarding path leaves TargetHost empty and lets SocketsHttpHandler fill it in per
    /// request. If that ever stopped happening, hostname verification would silently weaken, so
    /// this drives a real request against a self-signed server and requires it to be refused.
    /// </summary>
    [Fact]
    public async Task ForwardingHandlerRefusesASelfSignedServer()
    {
        using var certificate = SelfSignedForLocalhost();
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serving = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync();
                await using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(certificate);
            }
            catch
            {
                // The client is expected to reject the handshake; that is the point of the test.
            }
        });

        var options = UpstreamTlsPolicy.Current.CreateOptions(string.Empty);
        using var handler = new SocketsHttpHandler { SslOptions = options };
        using var httpClient = new HttpClient(handler);

        await Assert.ThrowsAnyAsync<HttpRequestException>(
            () => httpClient.GetAsync(new Uri($"https://localhost:{port}/")));

        listener.Stop();
        await serving;
    }

    private static X509Certificate2 SelfSignedForLocalhost()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        request.CertificateExtensions.Add(names.Build());
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddHours(1));
        // The server needs the private key attached, which round-tripping through PFX guarantees.
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);
    }
}
