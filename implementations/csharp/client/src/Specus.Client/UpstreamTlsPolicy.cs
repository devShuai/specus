using System.Globalization;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Specus.Client;

/// <summary>
/// Trust policy for connections to the service this client forwards to.
///
/// <para>Those connections used to be made with verification disabled outright, on the reasoning
/// that an operator-managed LAN target commonly presents a self-signed certificate. That reasoning
/// trades a real guarantee for a convenience: anything able to answer on the target address, or to
/// sit between the client and it, was accepted silently, and the tunnel then carried the result to
/// a remote user with no way to notice.</para>
///
/// <para>Verification is the default. A self-signed target is still supported, but only by saying
/// so: name the CA that issued it, pin its leaf certificate, or state plainly that it is not
/// verified.</para>
/// </summary>
public sealed class UpstreamTlsPolicy
{
    private static UpstreamTlsPolicy _current = new(false, null, []);

    private readonly bool _insecureSkipVerify;
    private readonly X509Certificate2Collection? _extraRoots;
    private readonly HashSet<string> _pinned;

    public UpstreamTlsPolicy(bool insecureSkipVerify, string? caCertificatePath,
        IReadOnlyList<string> pinnedCertificateSha256)
    {
        _insecureSkipVerify = insecureSkipVerify;
        _pinned = NormalizePins(pinnedCertificateSha256);

        if (!string.IsNullOrWhiteSpace(caCertificatePath))
        {
            var path = caCertificatePath.Trim();
            if (!File.Exists(path))
            {
                throw new InvalidOperationException($"upstream CA certificate does not exist: {path}");
            }
            var collection = new X509Certificate2Collection();
            try
            {
                collection.ImportFromPemFile(path);
            }
            catch (CryptographicException error)
            {
                throw new InvalidOperationException(
                    $"upstream CA certificate {path} contains no usable certificate", error);
            }
            if (collection.Count == 0)
            {
                throw new InvalidOperationException(
                    $"upstream CA certificate {path} contains no usable certificate");
            }
            _extraRoots = collection;
        }
    }

    /// <summary>
    /// Publishes the operator's policy. The forwarding paths build their TLS options without a
    /// reference to the settings, so they read it from here. The default verifies, so a failure to
    /// configure leans towards checking certificates rather than towards trusting everything.
    /// </summary>
    public static void Configure(UpstreamTlsPolicy? policy) => _current = policy ?? new(false, null, []);

    public static UpstreamTlsPolicy Current => _current;

    public bool Verifies => !_insecureSkipVerify;

    public bool Pins => _pinned.Count > 0;

    /// <summary>Builds the options used to authenticate one upstream connection.</summary>
    public SslClientAuthenticationOptions CreateOptions(string targetHost) =>
        CreateOptions(targetHost, routeInsecureSkipVerify: false);

    /// <summary>
    /// Builds the options for one upstream route. A route may explicitly relax verification;
    /// it cannot make a globally insecure client verify only that route.
    /// </summary>
    public SslClientAuthenticationOptions CreateOptions(
        string targetHost, bool routeInsecureSkipVerify)
    {
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = targetHost,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        };

        if (_insecureSkipVerify || routeInsecureSkipVerify)
        {
            options.RemoteCertificateValidationCallback = static (_, _, _, _) => true;
            return options;
        }

        if (_pinned.Count > 0)
        {
            // Pinning replaces chain verification: a pinned target usually has no chain to verify.
            // The pin is the check, and it is stricter than a chain.
            options.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                certificate is not null && _pinned.Contains(Fingerprint(certificate));
            return options;
        }

        if (_extraRoots is not null)
        {
            // Custom roots are added to the default chain rather than replacing it, so a target
            // with a publicly trusted certificate keeps working.
            options.RemoteCertificateValidationCallback = ValidateAgainstExtraRoots;
        }

        // With no callback, the platform performs its normal chain and hostname checks.
        return options;
    }

    private bool ValidateAgainstExtraRoots(object sender, X509Certificate? certificate,
        X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None)
        {
            return true;
        }
        // A name mismatch is never something an extra root can excuse.
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch)
            || errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable)
            || certificate is null || _extraRoots is null)
        {
            return false;
        }

        using var rebuilt = new X509Chain();
        rebuilt.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        rebuilt.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        rebuilt.ChainPolicy.CustomTrustStore.AddRange(_extraRoots);
        if (chain is not null)
        {
            foreach (var element in chain.ChainElements)
            {
                rebuilt.ChainPolicy.ExtraStore.Add(element.Certificate);
            }
        }
        return rebuilt.Build(X509CertificateLoader.LoadCertificate(certificate.GetRawCertData()));
    }

    internal static string Fingerprint(X509Certificate certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData())).ToLowerInvariant();

    internal static HashSet<string> NormalizePins(IReadOnlyList<string> configured)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        if (configured.Count == 0)
        {
            return result;
        }
        foreach (var value in configured)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }
            // Tools print fingerprints as colon-separated uppercase pairs; accept that form too.
            var normalized = value.Trim()
                .Replace(":", string.Empty, StringComparison.Ordinal)
                .Replace(" ", string.Empty, StringComparison.Ordinal)
                .Replace("-", string.Empty, StringComparison.Ordinal)
                .ToLowerInvariant();
            if (normalized.Length != 64
                || !normalized.All(c => char.IsAsciiHexDigitLower(c)))
            {
                throw new InvalidOperationException(
                    string.Create(CultureInfo.InvariantCulture,
                        $"pinned certificate fingerprint is not a SHA-256 hex digest: {value}"));
            }
            result.Add(normalized);
        }
        return result;
    }
}
