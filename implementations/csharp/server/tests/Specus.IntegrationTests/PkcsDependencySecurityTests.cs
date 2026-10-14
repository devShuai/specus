using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Specus.IntegrationTests;

public sealed class PkcsDependencySecurityTests
{
    [Fact]
    public void RuntimePkcsIsAtLeastTheCve202684008PatchedRelease()
    {
        // AssemblyVersion stays 10.0.0.0 across servicing releases. Inspect the actual loaded
        // runtime asset's informational version, not merely the project reference or SDK version.
        var informational = typeof(SignedCms).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        Assert.NotNull(informational);
        var release = informational.Split('+')[0];
        Assert.True(Version.TryParse(release, out var version), $"Expected a stable Pkcs release, got {release}");
        Assert.True(version >= new Version(10, 0, 13), $"CVE-2026-84008 requires Pkcs >= 10.0.13; loaded {release}");
    }

    [Fact]
    public void DetachedCmsSignatureRoundTripsAndRejectsTampering()
    {
        // Exercise the mail dependency's real CMS signing/verification path without machine
        // certificate stores, a trusted root installation, network access, or an exploit payload.
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=specus-pkcs-regression", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        var content = Encoding.UTF8.GetBytes("Specus detached CMS 签名 smoke test");
        var signed = new SignedCms(new ContentInfo(content), detached: true);
        signed.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
        {
            IncludeOption = X509IncludeOption.EndCertOnly
        }, silent: true);
        var encoded = signed.Encode();
        var verified = new SignedCms(new ContentInfo(content), detached: true);
        verified.Decode(encoded);
        verified.CheckSignature(verifySignatureOnly: true);
        Assert.Single(verified.SignerInfos);

        var tampered = (byte[])content.Clone();
        tampered[0] ^= 1;
        var invalid = new SignedCms(new ContentInfo(tampered), detached: true);
        invalid.Decode(encoded);
        Assert.Throws<CryptographicException>(() => invalid.CheckSignature(verifySignatureOnly: true));
    }
}
