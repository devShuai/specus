using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;

namespace Specus.Server.Security;

public sealed class ControlChannelTlsProvider
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
}

public static class TlsCertificateLoader
{
    private const X509KeyStorageFlags ServerKeyStorageFlags =
        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;

    public static X509Certificate2? LoadServerCertificate(TlsOptions options) => options.ResolveMode() switch
    {
        TlsMode.Disabled => null,
        TlsMode.SelfSigned => CreateSelfSignedCertificate(),
        TlsMode.File => LoadFromFile(options),
        _ => null,
    };

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

    private static X509Certificate2 CreateSelfSignedCertificate()
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
        var pfx = certificate.Export(X509ContentType.Pfx);
        return X509CertificateLoader.LoadPkcs12(pfx, string.Empty,
            ServerKeyStorageFlags, Pkcs12LoaderLimits.Defaults);
    }
}
