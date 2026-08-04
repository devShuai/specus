using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Specus.Client.Configuration;

/// <summary>Validated, immutable TLS material derived from <see cref="SpecusClientConfig"/>.</summary>
internal sealed class ControlTlsSettings : IDisposable
{
    private ControlTlsSettings(
        bool? explicitEnabled,
        bool hasTlsOptions,
        string? serverName,
        bool insecureSkipVerify,
        X509Certificate2Collection? customTrustRoots)
    {
        ExplicitEnabled = explicitEnabled;
        HasTlsOptions = hasTlsOptions;
        ServerName = serverName;
        InsecureSkipVerify = insecureSkipVerify;
        CustomTrustRoots = customTrustRoots;
    }

    private bool? ExplicitEnabled { get; }

    private bool HasTlsOptions { get; }

    internal string? ServerName { get; }

    internal bool InsecureSkipVerify { get; }

    internal X509Certificate2Collection? CustomTrustRoots { get; }

    internal static ControlTlsSettings Create(SpecusClientConfig config, string source = "client configuration")
    {
        ArgumentNullException.ThrowIfNull(config);
        config.ControlTls ??= new ControlTlsConfig();
        config.ControlTls.Normalize();

        var tls = config.ControlTls;
        var hasTlsOptions = tls.HasTlsOptions;
        if (tls.Enabled == false && hasTlsOptions)
        {
            throw Invalid(source,
                "controlTls TLS options cannot be configured when controlTls.enabled is false");
        }

        ValidateServerName(tls.ServerName, source);
        if (tls.CaCertificatePath is not null && tls.InsecureSkipVerify)
        {
            throw Invalid(source,
                "controlTls.caCertificatePath cannot be combined with controlTls.insecureSkipVerify");
        }

        X509Certificate2Collection? roots = null;
        if (tls.CaCertificatePath is not null)
        {
            roots = LoadTrustRoots(tls.CaCertificatePath, source);
        }

        return new ControlTlsSettings(
            tls.Enabled, hasTlsOptions, tls.ServerName, tls.InsecureSkipVerify, roots);
    }

    internal bool ResolveEnabled(bool runtimeNettyTls)
        => ExplicitEnabled ?? (runtimeNettyTls || HasTlsOptions);

    internal static void Validate(SpecusClientConfig config, string source)
    {
        using var settings = Create(config, source);
    }

    private static X509Certificate2Collection LoadTrustRoots(string path, string source)
    {
        var roots = new X509Certificate2Collection();
        try
        {
            roots.ImportFromPemFile(path);
            if (roots.Count == 0)
            {
                throw new CryptographicException("the PEM file contains no certificates");
            }
            return roots;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        {
            foreach (var certificate in roots)
            {
                certificate.Dispose();
            }
            throw Invalid(source,
                $"cannot load controlTls.caCertificatePath '{path}' as PEM trust roots", ex);
        }
    }

    private static void ValidateServerName(string? serverName, string source)
    {
        if (serverName is null)
        {
            return;
        }
        if (serverName.Contains("://", StringComparison.Ordinal)
            || serverName.Contains('/')
            || serverName.Contains('\\'))
        {
            throw Invalid(source,
                "controlTls.serverName must be a hostname or IP address without scheme or path");
        }
        if (serverName.StartsWith("[", StringComparison.Ordinal)
            || serverName.EndsWith("]", StringComparison.Ordinal))
        {
            throw Invalid(source, "controlTls.serverName must not use brackets around an IP address");
        }
        if (serverName.Contains(':') && !IPAddress.TryParse(serverName, out _))
        {
            throw Invalid(source, "controlTls.serverName must not include a port");
        }
    }

    private static InvalidDataException Invalid(string source, string message, Exception? inner = null)
        => new($"{source}: {message}", inner);

    public void Dispose()
    {
        if (CustomTrustRoots is null)
        {
            return;
        }
        foreach (var certificate in CustomTrustRoots)
        {
            certificate.Dispose();
        }
    }
}
