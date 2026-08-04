using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Specus.Client.Configuration;

namespace Specus.Client.Control;

/// <summary>Creates bounded TCP and optional TLS connections for both protocol roles.</summary>
internal sealed class ControlConnectionFactory : IDisposable
{
    internal static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(5);

    private readonly ControlTlsSettings _tls;
    private readonly TimeSpan _connectTimeout;

    internal ControlConnectionFactory(SpecusClientConfig config, TimeSpan? connectTimeout = null)
    {
        _tls = ControlTlsSettings.Create(config);
        _connectTimeout = connectTimeout ?? DefaultConnectTimeout;
        if (_connectTimeout <= TimeSpan.Zero)
        {
            _tls.Dispose();
            throw new ArgumentOutOfRangeException(nameof(connectTimeout), "connect timeout must be positive");
        }
    }

    internal async Task<ControlConnection> ConnectAsync(
        string host,
        int port,
        string role,
        bool runtimeNettyTls,
        CancellationToken cancellationToken)
    {
        var tcp = new TcpClient { NoDelay = true };
        tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        Stream? stream = null;
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(_connectTimeout);
        try
        {
            await tcp.ConnectAsync(host, port, connectCts.Token).ConfigureAwait(false);
            stream = tcp.GetStream();
            if (_tls.ResolveEnabled(runtimeNettyTls))
            {
                var ssl = new SslStream(
                    stream,
                    leaveInnerStreamOpen: false,
                    _tls.InsecureSkipVerify ? static (_, _, _, _) => true : null);
                stream = ssl;
                await ssl.AuthenticateAsClientAsync(
                    CreateAuthenticationOptions(host), connectCts.Token).ConfigureAwait(false);
            }
            return new ControlConnection(tcp, stream);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            if (stream is not null)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }
            tcp.Dispose();
            throw new TimeoutException(
                $"connect {role} to {host}:{port} timed out after {_connectTimeout.TotalMilliseconds:0} ms", ex);
        }
        catch
        {
            if (stream is not null)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }
            tcp.Dispose();
            throw;
        }
    }

    private SslClientAuthenticationOptions CreateAuthenticationOptions(string host)
    {
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = _tls.ServerName ?? host,
            // Let the operating system apply its current secure protocol policy.
            EnabledSslProtocols = SslProtocols.None,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        };
        if (_tls.CustomTrustRoots is not null)
        {
            var policy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                VerificationFlags = X509VerificationFlags.NoFlag,
            };
            policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            policy.CustomTrustStore.AddRange(_tls.CustomTrustRoots);
            options.CertificateChainPolicy = policy;
        }
        return options;
    }

    public void Dispose() => _tls.Dispose();
}

internal sealed class ControlConnection : IAsyncDisposable
{
    private TcpClient? _tcp;

    internal ControlConnection(TcpClient tcp, Stream stream)
    {
        _tcp = tcp;
        Stream = stream;
    }

    internal Stream Stream { get; }

    public async ValueTask DisposeAsync()
    {
        var tcp = Interlocked.Exchange(ref _tcp, null);
        if (tcp is null)
        {
            return;
        }
        await Stream.DisposeAsync().ConfigureAwait(false);
        tcp.Dispose();
    }
}
