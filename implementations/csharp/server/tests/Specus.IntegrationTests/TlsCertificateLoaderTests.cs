using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Specus.Server.Configuration;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

/// <summary>
/// The server certificate has to be usable as a TLS server credential on the platform it was
/// loaded for, which is not something inspecting the object can tell you.
///
/// <para>Every mode loaded the key with <c>EphemeralKeySet</c>, and Windows Schannel refuses an
/// ephemeral key as a server credential, so the server could not terminate TLS on Windows at all.
/// Nothing caught it because no test drove a handshake through the production loader: the object
/// looked correct, had a private key, and only failed when Schannel was asked to use it.</para>
/// </summary>
public sealed class TlsCertificateLoaderTests
{
    /// <summary>
    /// The regression test for the defect: an actual handshake against a certificate the
    /// production loader produced.
    /// </summary>
    [Fact]
    public async Task SelfSignedCertificateCompletesARealServerHandshake()
    {
        using var certificate = TlsCertificateLoader.LoadServerCertificate(
            new TlsOptions { Mode = "self-signed" });
        Assert.NotNull(certificate);

        await AssertCompletesHandshakeAsync(certificate!);
    }

    /// <summary>A PFX on disk is the other production path into the same flags.</summary>
    [Fact]
    public async Task CertificateLoadedFromAPfxFileCompletesARealServerHandshake()
    {
        var path = Path.Combine(Path.GetTempPath(), $"specus-tls-{Guid.NewGuid():N}.pfx");
        File.WriteAllBytes(path, GenerateExportablePkcs12());
        try
        {
            using var certificate = TlsCertificateLoader.LoadServerCertificate(new TlsOptions
            {
                Mode = "file",
                Keystore = path,
                KeystorePassword = string.Empty,
            });
            Assert.NotNull(certificate);

            await AssertCompletesHandshakeAsync(certificate!);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// Kestrel and the control channel each load a certificate. Generating a fresh key pair per
    /// call meant the two ports presented different identities, so a client that trusted or pinned
    /// one would reject the other.
    /// </summary>
    [Fact]
    public void SelfSignedIdentityIsStableAcrossCallers()
    {
        var options = new TlsOptions { Mode = "self-signed" };

        using var forKestrel = TlsCertificateLoader.LoadServerCertificate(options);
        using var forControlChannel = TlsCertificateLoader.LoadServerCertificate(options);

        Assert.NotNull(forKestrel);
        Assert.NotNull(forControlChannel);
        Assert.Equal(forKestrel!.Thumbprint, forControlChannel!.Thumbprint);
    }

    /// <summary>
    /// Each caller must still own its instance: sharing one object would mean whichever consumer
    /// disposed first broke the other.
    /// </summary>
    [Fact]
    public void EachCallerGetsItsOwnInstance()
    {
        var options = new TlsOptions { Mode = "self-signed" };

        using var first = TlsCertificateLoader.LoadServerCertificate(options);
        var second = TlsCertificateLoader.LoadServerCertificate(options);
        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.NotSame(first, second);

        second!.Dispose();
        // The surviving instance must still be usable after the other was disposed.
        Assert.False(string.IsNullOrEmpty(first!.Thumbprint));
    }

    [Fact]
    public void DisabledModeLoadsNothing()
    {
        Assert.Null(TlsCertificateLoader.LoadServerCertificate(new TlsOptions { Mode = "disabled" }));
    }

    [Fact]
    public void SelfSignedCertificateCarriesItsPrivateKeyAndLoopbackNames()
    {
        using var certificate = TlsCertificateLoader.LoadServerCertificate(
            new TlsOptions { Mode = "self-signed" });

        Assert.NotNull(certificate);
        Assert.True(certificate!.HasPrivateKey);

        var names = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single();
        Assert.Contains("localhost", names.EnumerateDnsNames());
    }

    /// <summary>
    /// Drives a real TLS handshake with the certificate as the server credential. Verification is
    /// skipped on the client side deliberately: the point is whether the platform can use this key
    /// to serve at all, not whether a self-signed chain validates.
    /// </summary>
    private static async Task AssertCompletesHandshakeAsync(X509Certificate2 certificate)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Exception? serverError = null;
        var server = Task.Run(async () =>
        {
            try
            {
                using var accepted = await listener.AcceptTcpClientAsync();
                await using var ssl = new SslStream(accepted.GetStream(), leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions { ServerCertificate = certificate });
            }
            catch (Exception error)
            {
                serverError = error;
            }
        });

        Exception? clientError = null;
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            await using var clientSsl = new SslStream(
                client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            await clientSsl.AuthenticateAsClientAsync("localhost");
        }
        catch (Exception error)
        {
            clientError = error;
        }

        await server;
        listener.Stop();

        // The server error is the informative one; the client only ever sees an EOF when the
        // server could not use its own key, which is what made the original defect so opaque.
        Assert.True(serverError is null,
            $"the server could not use its certificate: {serverError?.Message}");
        Assert.True(clientError is null, $"the handshake failed: {clientError?.Message}");
    }

    private static byte[] GenerateExportablePkcs12()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=specus-test", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return certificate.Export(X509ContentType.Pfx);
    }
}
