using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;

namespace Specus.Server.Security;

public sealed class ControlChannelTlsProvider : IDisposable
{
    private readonly TlsOptions _options;
    private readonly ILogger<ControlChannelTlsProvider> _logger;
    private X509Certificate2? _certificate;

    public ControlChannelTlsProvider(IOptions<TlsOptions> options, ILogger<ControlChannelTlsProvider> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public X509Certificate2? GetServerCertificate()
    {
        if (_options.ResolveMode() == TlsMode.Disabled)
        {
            return null;
        }

        _certificate ??= TlsCertificateLoader.LoadServerCertificate(_options);
        _logger.LogInformation("[tls] control channel is encrypted (mode={Mode})", _options.Mode);
        return _certificate;
    }

    /// <summary>
    /// Releases the certificate at shutdown.
    ///
    /// <para>On Windows the imported private key lives in a key container under the user profile,
    /// and disposing the certificate is what removes it — measured, not assumed: five imports add
    /// five containers and disposing them all returns the count to its starting value. Holding a
    /// singleton that owns an IDisposable without disposing it would leave one behind per run.</para>
    /// </summary>
    public void Dispose()
    {
        _certificate?.Dispose();
        _certificate = null;
    }
}

public static class TlsCertificateLoader
{
    /// <summary>
    /// How the private key is stored after import, which is not a free choice on Windows.
    ///
    /// <para>Schannel cannot use an ephemeral key as a server credential: the handshake fails with
    /// "the platform does not support ephemeral keys" and the peer sees only an unexpected EOF. All
    /// three TLS modes went through these flags, so the server could not terminate TLS on Windows
    /// at all — in self-signed mode, from a PEM pair, or from a PFX file.</para>
    ///
    /// <para>EphemeralKeySet is kept everywhere else, because it is the better answer where it
    /// works: the key never reaches disk. On Windows the key is imported into the current user's
    /// container instead, which is why LoadServerCertificate hands out one certificate per process
    /// rather than minting one per caller.</para>
    /// </summary>
    private static X509KeyStorageFlags ServerKeyStorageFlags => OperatingSystem.IsWindows()
        ? X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet
        : X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;

    private static readonly object CertificateGate = new();
    private static string? _cachedSignature;
    private static byte[]? _cachedSelfSignedPkcs12;

    /// <summary>
    /// Loads the server certificate for the configured mode.
    ///
    /// <para>Called once for the Kestrel endpoint and once for the control channel. In self-signed
    /// mode that used to generate a fresh key pair each time, so the two ports presented different
    /// certificates and a client that trusted or pinned one would reject the other. The generated
    /// material is now created once per process and re-imported, which keeps the identity stable
    /// while still giving each caller its own instance to own.</para>
    /// </summary>
    public static X509Certificate2? LoadServerCertificate(TlsOptions options) => options.ResolveMode() switch
    {
        TlsMode.Disabled => null,
        TlsMode.SelfSigned => LoadStableSelfSignedCertificate(options),
        TlsMode.File => LoadFromFile(options),
        _ => null,
    };

    /// <summary>
    /// Returns the process-wide self-signed certificate, generating it on first use.
    /// </summary>
    private static X509Certificate2 LoadStableSelfSignedCertificate(TlsOptions options)
    {
        // The signature guards against a test or host that reconfigures TLS in-process: a changed
        // configuration must not silently keep serving the previous identity.
        var signature = $"self-signed|{options.ResolveMode()}";
        byte[] pkcs12;
        lock (CertificateGate)
        {
            if (_cachedSelfSignedPkcs12 is null || _cachedSignature != signature)
            {
                _cachedSelfSignedPkcs12 = CreateSelfSignedPkcs12();
                _cachedSignature = signature;
            }
            pkcs12 = _cachedSelfSignedPkcs12;
        }
        return X509CertificateLoader.LoadPkcs12(pkcs12, string.Empty,
            ServerKeyStorageFlags, Pkcs12LoaderLimits.Defaults);
    }

    /// <summary>Discards the generated identity so the next load creates a new one. Tests only.</summary>
    internal static void ResetSelfSignedCertificateForTests()
    {
        lock (CertificateGate)
        {
            _cachedSelfSignedPkcs12 = null;
            _cachedSignature = null;
        }
    }

    private static X509Certificate2 LoadFromFile(TlsOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Keystore))
        {
            throw new InvalidOperationException("TLS keystore path is required when Specus:Tls:Mode=file.");
        }

        var path = options.Keystore;
        if (!File.Exists(path))
        {
            throw new InvalidOperationException($"TLS keystore not found: {Path.GetFullPath(path)}");
        }

        var extension = Path.GetExtension(path).ToLowerInvariant();
        var certificate = extension switch
        {
            ".pem" => LoadPem(path, options.KeyPassword ?? options.KeystorePassword),
            _ => X509CertificateLoader.LoadPkcs12FromFile(path, options.KeystorePassword,
                ServerKeyStorageFlags, Pkcs12LoaderLimits.Defaults),
        };

        if (!certificate.HasPrivateKey)
        {
            certificate.Dispose();
            throw new InvalidOperationException("TLS server certificate must include a private key.");
        }

        return certificate;
    }

    private static X509Certificate2 LoadPem(string path, string? password)
    {
        using var certificate = string.IsNullOrEmpty(password)
            ? X509Certificate2.CreateFromPemFile(path, path)
            : X509Certificate2.CreateFromEncryptedPemFile(path, password, path);

        var pfx = certificate.Export(X509ContentType.Pfx);
        return X509CertificateLoader.LoadPkcs12(pfx, string.Empty,
            ServerKeyStorageFlags, Pkcs12LoaderLimits.Defaults);
    }

    private static byte[] CreateSelfSignedPkcs12()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=specus",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection
            {
                new Oid("1.3.6.1.5.5.7.3.1", "Server Authentication"),
            },
            critical: false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        san.AddIpAddress(IPAddress.IPv6Loopback);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        return certificate.Export(X509ContentType.Pfx);
    }
}
