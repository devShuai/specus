using System.ComponentModel;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Protocol;

namespace Specus.Client.Tests;

public sealed class ControlConnectionFactoryTests
{
    [Fact]
    public async Task CustomTrustRootAndServerNameCompleteARealTlsHandshake()
    {
        using var certificates = TestCertificates.Create("control.specus.test");
        using var listener = StartListener();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = ServeTlsOnceAsync(listener, certificates.Server, timeout.Token);
        var config = ValidConfig("https://login.specus.test");
        config.ControlTls = new ControlTlsConfig
        {
            CaCertificatePath = certificates.CaPath,
            ServerName = "control.specus.test",
        };
        using var factory = new ControlConnectionFactory(config);

        try
        {
            await using var connection = await factory.ConnectAsync(
                "127.0.0.1", LocalPort(listener), ConnectionRole.Control,
                runtimeNettyTls: false, cancellationToken: timeout.Token);

            Assert.IsType<SslStream>(connection.Stream);
            await server;
        }
        catch (Exception ex) when (IsUnavailableWindowsTls(ex))
        {
            timeout.Cancel();
            await IgnoreExpectedTlsAbortAsync(server);
            return;
        }
    }

    [Fact]
    public async Task HostnameMismatchRejectsAnOtherwiseTrustedCertificate()
    {
        using var certificates = TestCertificates.Create("control.specus.test");
        using var listener = StartListener();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = ServeTlsOnceAsync(listener, certificates.Server, timeout.Token);
        var config = ValidConfig("https://login.specus.test");
        config.ControlTls = new ControlTlsConfig
        {
            CaCertificatePath = certificates.CaPath,
            ServerName = "other.specus.test",
        };
        using var factory = new ControlConnectionFactory(config);

        var error = await Record.ExceptionAsync(() => factory.ConnectAsync(
            "127.0.0.1", LocalPort(listener), ConnectionRole.Control,
            runtimeNettyTls: false, cancellationToken: timeout.Token));

        if (error is not null && IsUnavailableWindowsTls(error))
        {
            timeout.Cancel();
            await IgnoreExpectedTlsAbortAsync(server);
            return;
        }
        Assert.IsType<AuthenticationException>(error);
        await IgnoreExpectedTlsAbortAsync(server);
    }

    [Fact]
    public async Task DefaultTlsRejectsACertificateOutsideTheSystemTrustStore()
    {
        using var certificates = TestCertificates.Create("control.specus.test");
        using var listener = StartListener();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = ServeTlsOnceAsync(listener, certificates.Server, timeout.Token);
        var config = ValidConfig("https://login.specus.test");
        using var factory = new ControlConnectionFactory(config);

        var error = await Record.ExceptionAsync(() => factory.ConnectAsync(
            "127.0.0.1", LocalPort(listener), ConnectionRole.Control,
            runtimeNettyTls: true, cancellationToken: timeout.Token));

        if (error is not null && IsUnavailableWindowsTls(error))
        {
            timeout.Cancel();
            await IgnoreExpectedTlsAbortAsync(server);
            return;
        }
        Assert.IsType<AuthenticationException>(error);
        await IgnoreExpectedTlsAbortAsync(server);
    }

    [Fact]
    public async Task TlsHandshakeUsesTheSameConnectionTimeoutAsTcpDial()
    {
        using var listener = StartListener();
        using var serverCancellation = new CancellationTokenSource();
        var server = AcceptWithoutHandshakeAsync(listener, serverCancellation.Token);
        var config = ValidConfig("https://login.specus.test");
        config.ControlTls = new ControlTlsConfig
        {
            Enabled = true,
            InsecureSkipVerify = true,
        };
        using var factory = new ControlConnectionFactory(config, TimeSpan.FromMilliseconds(150));

        var error = await Record.ExceptionAsync(() => factory.ConnectAsync(
            "127.0.0.1", LocalPort(listener), ConnectionRole.Data,
            runtimeNettyTls: false, cancellationToken: CancellationToken.None));

        if (error is not null && IsUnavailableWindowsTls(error))
        {
            serverCancellation.Cancel();
            await server;
            return;
        }
        var timeoutError = Assert.IsType<TimeoutException>(error);
        Assert.Contains("data", timeoutError.Message, StringComparison.Ordinal);
        serverCancellation.Cancel();
        await server;
    }

    [Theory]
    [InlineData(false, null)]
    [InlineData(true, false)]
    public async Task MissingRuntimeSignalOrExplicitDisableUsesPlainTcp(
        bool runtimeNettyTls,
        bool? explicitEnabled)
    {
        using var listener = StartListener();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var accepted = listener.AcceptTcpClientAsync(timeout.Token).AsTask();
        var config = ValidConfig("https://login.specus.test");
        config.ControlTls.Enabled = explicitEnabled;
        using var factory = new ControlConnectionFactory(config);

        await using var connection = await factory.ConnectAsync(
            "127.0.0.1", LocalPort(listener), ConnectionRole.Control,
            runtimeNettyTls: runtimeNettyTls, cancellationToken: timeout.Token);
        using var server = await accepted;

        Assert.IsType<NetworkStream>(connection.Stream);
    }

    private static SpecusClientConfig ValidConfig(string serverBaseUrl) => new()
    {
        ServerBaseUrl = serverBaseUrl,
        ApiKey = "demo-client",
        Secret = "test1234",
    };

    private static TcpListener StartListener()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return listener;
    }

    private static int LocalPort(TcpListener listener)
        => ((IPEndPoint)listener.LocalEndpoint).Port;

    private static async Task ServeTlsOnceAsync(
        TcpListener listener,
        X509Certificate2 certificate,
        CancellationToken cancellationToken)
    {
        using var tcp = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = certificate,
            EnabledSslProtocols = SslProtocols.None,
            ClientCertificateRequired = false,
        }, cancellationToken);
    }

    private static async Task AcceptWithoutHandshakeAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        try
        {
            using var tcp = await listener.AcceptTcpClientAsync(cancellationToken);
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private static async Task IgnoreExpectedTlsAbortAsync(Task server)
    {
        try
        {
            await server;
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or OperationCanceledException)
        {
        }
    }

    private static bool IsUnavailableWindowsTls(Exception exception)
        => OperatingSystem.IsWindows()
           && exception is AuthenticationException
           {
               InnerException: Win32Exception
               {
                   NativeErrorCode: unchecked((int)0x8009030E),
               },
           };

    private sealed class TestCertificates : IDisposable
    {
        private TestCertificates(string caPath, X509Certificate2 ca, X509Certificate2 server)
        {
            CaPath = caPath;
            Ca = ca;
            Server = server;
        }

        internal string CaPath { get; }

        private X509Certificate2 Ca { get; }

        internal X509Certificate2 Server { get; }

        internal static TestCertificates Create(string dnsName)
        {
            using var caKey = RSA.Create(2048);
            var caRequest = new CertificateRequest(
                "CN=Specus test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));
            var ca = caRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));

            using var serverKey = RSA.Create(2048);
            var serverRequest = new CertificateRequest(
                $"CN={dnsName}", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(dnsName);
            san.AddIpAddress(IPAddress.Loopback);
            serverRequest.CertificateExtensions.Add(san.Build());
            var serial = RandomNumberGenerator.GetBytes(16);
            using var publicServer = serverRequest.Create(
                ca, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(12), serial);
            var server = publicServer.CopyWithPrivateKey(serverKey);

            var caPath = Path.Combine(Path.GetTempPath(), $"specus-ca-{Guid.NewGuid():N}.pem");
            File.WriteAllText(caPath, ca.ExportCertificatePem());
            return new TestCertificates(caPath, ca, server);
        }

        public void Dispose()
        {
            File.Delete(CaPath);
            Server.Dispose();
            Ca.Dispose();
        }
    }
}
