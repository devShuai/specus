using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;

namespace Specus.Client.PeerMesh;

internal enum NatPortMappingProtocol
{
    Upnp,
    NatPmp,
    Pcp,
}

internal sealed record NatPortMapping(
    NatPortMappingProtocol Protocol,
    string ExternalAddress,
    int ExternalPort,
    int InternalPort,
    int LeaseSeconds,
    DateTimeOffset CreatedAt)
{
    public bool ShouldRenew(DateTimeOffset now)
    {
        var lease = LeaseSeconds <= 0 ? 7200 : LeaseSeconds;
        return now >= CreatedAt.AddSeconds(Math.Max(60, lease - 60));
    }
}

internal interface INatPortMapper
{
    NatPortMappingProtocol Protocol { get; }

    Task<NatPortMapping?> AddMappingAsync(
        int internalPort,
        int preferredExternal,
        int leaseSeconds,
        string description,
        CancellationToken cancellationToken);

    Task DeleteMappingAsync(NatPortMapping mapping, CancellationToken cancellationToken);
}

internal sealed class NatPortMappingService
{
    private static readonly TimeSpan OverallTimeout = TimeSpan.FromSeconds(4);
    private readonly ILogger _logger;
    private readonly IReadOnlyList<INatPortMapper> _mappers;

    public NatPortMappingService(ILogger logger)
    {
        _logger = logger;
        _mappers =
        [
            new UpnpPortMapper(logger),
            new NatPmpPortMapper(logger),
            new PcpPortMapper(logger),
        ];
    }

    public async Task<NatPortMapping?> TryAcquireMappingAsync(
        int internalPort,
        int preferredExternal,
        int leaseSeconds,
        string description,
        CancellationToken cancellationToken)
    {
        if (internalPort <= 0 || internalPort > 65535)
        {
            return null;
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(OverallTimeout);
        var tasks = _mappers
            .Select(mapper => TryMapperAsync(mapper, internalPort, preferredExternal, leaseSeconds, description, timeout.Token))
            .ToList();
        while (tasks.Count > 0)
        {
            var completed = await Task.WhenAny(tasks).ConfigureAwait(false);
            tasks.Remove(completed);
            var mapping = await completed.ConfigureAwait(false);
            if (mapping is not null)
            {
                await timeout.CancelAsync().ConfigureAwait(false);
                return mapping;
            }
        }
        return null;
    }

    public async Task<NatPortMapping?> RenewMappingAsync(NatPortMapping mapping, int leaseSeconds, string description, CancellationToken cancellationToken)
    {
        var mapper = _mappers.FirstOrDefault(item => item.Protocol == mapping.Protocol);
        if (mapper is null)
        {
            return null;
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(OverallTimeout);
        try
        {
            return await mapper.AddMappingAsync(mapping.InternalPort, mapping.ExternalPort, leaseSeconds, description, timeout.Token)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            _logger.LogDebug(ex, "NAT port mapping renew failed: protocol={Protocol}", mapping.Protocol);
            return null;
        }
    }

    public async Task ReleaseMappingAsync(NatPortMapping mapping, CancellationToken cancellationToken)
    {
        var mapper = _mappers.FirstOrDefault(item => item.Protocol == mapping.Protocol);
        if (mapper is null)
        {
            return;
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            await mapper.DeleteMappingAsync(mapping, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            _logger.LogDebug(ex, "NAT port mapping release failed: protocol={Protocol}", mapping.Protocol);
        }
    }

    private async Task<NatPortMapping?> TryMapperAsync(
        INatPortMapper mapper,
        int internalPort,
        int preferredExternal,
        int leaseSeconds,
        string description,
        CancellationToken cancellationToken)
    {
        try
        {
            return await mapper.AddMappingAsync(internalPort, preferredExternal, leaseSeconds, description, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            _logger.LogDebug(ex, "NAT port mapping protocol failed: {Protocol}", mapper.Protocol);
            return null;
        }
    }
}

internal sealed class NatPmpPortMapper(ILogger logger) : INatPortMapper
{
    public NatPortMappingProtocol Protocol => NatPortMappingProtocol.NatPmp;

    public async Task<NatPortMapping?> AddMappingAsync(
        int internalPort,
        int preferredExternal,
        int leaseSeconds,
        string description,
        CancellationToken cancellationToken)
    {
        Exception? last = null;
        foreach (var gateway in DefaultGatewayDiscovery.Candidates())
        {
            try
            {
                var externalAddress = await RequestExternalAddressAsync(gateway, cancellationToken).ConfigureAwait(false);
                var request = new byte[12];
                request[1] = 1;
                BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4), (ushort)internalPort);
                BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(6), (ushort)preferredExternal);
                BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(8), (uint)leaseSeconds);
                var response = await PortMappingUdp.RequestAsync(gateway, 5351, request, 16, TimeSpan.FromMilliseconds(1500), cancellationToken)
                    .ConfigureAwait(false);
                if (response[0] != 0 || response[1] != 129)
                {
                    throw new InvalidOperationException("NAT-PMP map response shape unexpected");
                }
                var code = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2));
                if (code != 0)
                {
                    throw new InvalidOperationException($"NAT-PMP map rejected: code={code}");
                }
                var externalPort = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(10));
                var grantedLifetime = BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(12));
                return new NatPortMapping(
                    Protocol,
                    externalAddress,
                    externalPort,
                    internalPort,
                    Math.Max(60, (int)grantedLifetime),
                    DateTimeOffset.UtcNow);
            }
            catch (Exception ex) when (ex is IOException or SocketException or TaskCanceledException or InvalidOperationException)
            {
                last = ex;
                logger.LogDebug(ex, "NAT-PMP attempt failed: gateway={Gateway}", gateway);
            }
        }
        if (last is not null)
        {
            throw last;
        }
        return null;
    }

    public async Task DeleteMappingAsync(NatPortMapping mapping, CancellationToken cancellationToken)
    {
        foreach (var gateway in DefaultGatewayDiscovery.Candidates())
        {
            var request = new byte[12];
            request[1] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4), (ushort)mapping.InternalPort);
            try
            {
                await PortMappingUdp.RequestAsync(gateway, 5351, request, 16, TimeSpan.FromMilliseconds(700), cancellationToken)
                    .ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (ex is IOException or SocketException or TaskCanceledException or InvalidOperationException)
            {
                logger.LogDebug(ex, "NAT-PMP delete failed: gateway={Gateway}", gateway);
            }
        }
    }

    private static async Task<string> RequestExternalAddressAsync(IPAddress gateway, CancellationToken cancellationToken)
    {
        var response = await PortMappingUdp.RequestAsync(gateway, 5351, [0, 0], 12, TimeSpan.FromMilliseconds(1500), cancellationToken)
            .ConfigureAwait(false);
        if (response[0] != 0 || (response[1] & 0x7f) != 0)
        {
            throw new InvalidOperationException("NAT-PMP external address response shape unexpected");
        }
        var code = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2));
        if (code != 0)
        {
            throw new InvalidOperationException($"NAT-PMP external address rejected: code={code}");
        }
        return new IPAddress(response.AsSpan(8, 4)).ToString();
    }
}

internal sealed class PcpPortMapper(ILogger logger) : INatPortMapper
{
    private readonly byte[] _nonce = RandomNumberGenerator.GetBytes(12);

    public NatPortMappingProtocol Protocol => NatPortMappingProtocol.Pcp;

    public async Task<NatPortMapping?> AddMappingAsync(
        int internalPort,
        int preferredExternal,
        int leaseSeconds,
        string description,
        CancellationToken cancellationToken)
    {
        Exception? last = null;
        foreach (var gateway in DefaultGatewayDiscovery.Candidates())
        {
            try
            {
                var clientIp = DefaultGatewayDiscovery.LocalAddressMappedIpv6(gateway);
                var request = new byte[60];
                request[0] = 2;
                request[1] = 1;
                BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4), (uint)leaseSeconds);
                clientIp.CopyTo(request.AsSpan(8));
                _nonce.CopyTo(request.AsSpan(24));
                request[36] = 17;
                BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(40), (ushort)internalPort);
                BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(42), (ushort)preferredExternal);
                var response = await PortMappingUdp.RequestAsync(gateway, 5351, request, 60, TimeSpan.FromMilliseconds(1500), cancellationToken)
                    .ConfigureAwait(false);
                if (response[0] != 2 || response[1] != 0x81)
                {
                    throw new InvalidOperationException("PCP MAP response shape unexpected");
                }
                if (response[3] != 0)
                {
                    throw new InvalidOperationException($"PCP MAP rejected: code={response[3]}");
                }
                if (!response.AsSpan(24, 12).SequenceEqual(_nonce))
                {
                    throw new InvalidOperationException("PCP MAP response nonce mismatch");
                }
                var externalAddress = ExtractMappedIpv4(response.AsSpan(44, 16));
                if (string.IsNullOrWhiteSpace(externalAddress))
                {
                    throw new InvalidOperationException("PCP MAP response missing external address");
                }
                return new NatPortMapping(
                    Protocol,
                    externalAddress,
                    BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(42)),
                    internalPort,
                    Math.Max(60, (int)BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(4))),
                    DateTimeOffset.UtcNow);
            }
            catch (Exception ex) when (ex is IOException or SocketException or TaskCanceledException or InvalidOperationException)
            {
                last = ex;
                logger.LogDebug(ex, "PCP attempt failed: gateway={Gateway}", gateway);
            }
        }
        if (last is not null)
        {
            throw last;
        }
        return null;
    }

    public async Task DeleteMappingAsync(NatPortMapping mapping, CancellationToken cancellationToken)
        => await AddMappingAsync(mapping.InternalPort, 0, 0, "", cancellationToken).ConfigureAwait(false);

    private static string ExtractMappedIpv4(ReadOnlySpan<byte> value)
    {
        if (value.Length != 16)
        {
            return "";
        }
        var mapped = true;
        for (var i = 0; i < 10; i++)
        {
            mapped &= value[i] == 0;
        }
        if (mapped && value[10] == 0xff && value[11] == 0xff)
        {
            return new IPAddress(value[12..16]).ToString();
        }
        return new IPAddress(value).ToString();
    }
}

internal sealed partial class UpnpPortMapper(ILogger logger) : INatPortMapper
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromMilliseconds(2500) };
    private readonly object _sync = new();
    private UpnpGateway? _gateway;

    public NatPortMappingProtocol Protocol => NatPortMappingProtocol.Upnp;

    public async Task<NatPortMapping?> AddMappingAsync(
        int internalPort,
        int preferredExternal,
        int leaseSeconds,
        string description,
        CancellationToken cancellationToken)
    {
        var gateway = await EnsureGatewayAsync(cancellationToken).ConfigureAwait(false);
        var externalPort = preferredExternal > 0 ? preferredExternal : internalPort;
        var safeDescription = string.IsNullOrWhiteSpace(description) ? "specus" : description;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            try
            {
                await SoapAsync(
                    gateway,
                    "AddPortMapping",
                    $"<NewRemoteHost></NewRemoteHost><NewExternalPort>{externalPort}</NewExternalPort><NewProtocol>UDP</NewProtocol>" +
                    $"<NewInternalPort>{internalPort}</NewInternalPort><NewInternalClient>{Escape(gateway.LocalIp)}</NewInternalClient><NewEnabled>1</NewEnabled>" +
                    $"<NewPortMappingDescription>{Escape(safeDescription)}</NewPortMappingDescription><NewLeaseDuration>{Math.Max(60, leaseSeconds)}</NewLeaseDuration>",
                    cancellationToken).ConfigureAwait(false);
                return new NatPortMapping(
                    Protocol,
                    gateway.ExternalIp,
                    externalPort,
                    internalPort,
                    7200,
                    DateTimeOffset.UtcNow);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
            {
                logger.LogDebug(ex, "UPnP AddPortMapping failed: externalPort={ExternalPort}", externalPort);
                externalPort = RandomNumberGenerator.GetInt32(49152, 65152);
            }
        }
        return null;
    }

    public async Task DeleteMappingAsync(NatPortMapping mapping, CancellationToken cancellationToken)
    {
        UpnpGateway? gateway;
        lock (_sync)
        {
            gateway = _gateway;
        }
        if (gateway is null)
        {
            return;
        }
        await SoapAsync(
            gateway,
            "DeletePortMapping",
            $"<NewRemoteHost></NewRemoteHost><NewExternalPort>{mapping.ExternalPort}</NewExternalPort><NewProtocol>UDP</NewProtocol>",
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<UpnpGateway> EnsureGatewayAsync(CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            if (_gateway is not null)
            {
                return _gateway;
            }
        }
        var locations = await DiscoverLocationsAsync(cancellationToken).ConfigureAwait(false);
        Exception? last = null;
        foreach (var location in locations)
        {
            try
            {
                var gateway = await LoadGatewayAsync(location, cancellationToken).ConfigureAwait(false);
                lock (_sync)
                {
                    _gateway = gateway;
                }
                return gateway;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
            {
                last = ex;
            }
        }
        throw last ?? new InvalidOperationException("UPnP SSDP discovery found no usable IGD");
    }

    private async Task<UpnpGateway> LoadGatewayAsync(string location, CancellationToken cancellationToken)
    {
        var body = await _http.GetStringAsync(location, cancellationToken).ConfigureAwait(false);
        var uri = new Uri(location);
        var (serviceType, controlUrl) = ParseService(body, uri);
        var localIp = DefaultGatewayDiscovery.LocalAddressFor(uri.Host, uri.Port > 0 ? uri.Port : 80);
        var gateway = new UpnpGateway(serviceType, controlUrl, localIp, "");
        var externalIp = await SoapAsync(gateway, "GetExternalIPAddress", "", cancellationToken).ConfigureAwait(false);
        var parsed = XDocument.Parse(externalIp);
        var external = parsed.Descendants().FirstOrDefault(item => item.Name.LocalName == "NewExternalIPAddress")?.Value.Trim();
        if (string.IsNullOrWhiteSpace(external) || string.IsNullOrWhiteSpace(localIp))
        {
            throw new InvalidOperationException("UPnP gateway did not provide external or local address");
        }
        return gateway with { ExternalIp = external };
    }

    private async Task<string> SoapAsync(UpnpGateway gateway, string action, string inner, CancellationToken cancellationToken)
    {
        var envelope = "<?xml version=\"1.0\"?>" +
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
            $"<s:Body><u:{action} xmlns:u=\"{gateway.ServiceType}\">{inner}</u:{action}></s:Body></s:Envelope>";
        using var request = new HttpRequestMessage(HttpMethod.Post, gateway.ControlUrl)
        {
            Content = new StringContent(envelope, Encoding.UTF8, "text/xml"),
        };
        request.Headers.TryAddWithoutValidation("SOAPAction", $"\"{gateway.ServiceType}#{action}\"");
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"UPnP {action} status {(int)response.StatusCode}");
        }
        return body;
    }

    private static async Task<List<string>> DiscoverLocationsAsync(CancellationToken cancellationToken)
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        var target = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);
        foreach (var st in new[]
                 {
                     "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                     "urn:schemas-upnp-org:service:WANIPConnection:1",
                     "urn:schemas-upnp-org:service:WANPPPConnection:1",
                 })
        {
            var request = Encoding.ASCII.GetBytes(
                "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: 239.255.255.250:1900\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: 2\r\n" +
                $"ST: {st}\r\n\r\n");
            await udp.SendAsync(request, request.Length, target).ConfigureAwait(false);
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMilliseconds(2200));
        var locations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (!timeout.IsCancellationRequested)
        {
            try
            {
                var result = await udp.ReceiveAsync(timeout.Token).ConfigureAwait(false);
                var text = Encoding.ASCII.GetString(result.Buffer);
                var match = LocationHeaderRegex().Match(text);
                if (match.Success)
                {
                    locations.Add(match.Groups[1].Value.Trim());
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
        if (locations.Count == 0)
        {
            throw new InvalidOperationException("UPnP SSDP discovery found no locations");
        }
        return locations.ToList();
    }

    private static (string ServiceType, string ControlUrl) ParseService(string xml, Uri location)
    {
        var document = XDocument.Parse(xml);
        foreach (var service in document.Descendants().Where(item => item.Name.LocalName == "service"))
        {
            var type = service.Elements().FirstOrDefault(item => item.Name.LocalName == "serviceType")?.Value.Trim() ?? "";
            if (!type.Contains("WANIPConnection", StringComparison.OrdinalIgnoreCase)
                && !type.Contains("WANPPPConnection", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var control = service.Elements().FirstOrDefault(item => item.Name.LocalName == "controlURL")?.Value.Trim();
            if (string.IsNullOrWhiteSpace(control))
            {
                continue;
            }
            return (type, new Uri(location, control).ToString());
        }
        throw new InvalidOperationException("UPnP WANIPConnection/WANPPPConnection service not found");
    }

    private static string Escape(string value) => SecurityElement.Escape(value) ?? "";

    [GeneratedRegex("(?im)^location\\s*:\\s*(.+?)\\s*$")]
    private static partial Regex LocationHeaderRegex();

    private sealed record UpnpGateway(string ServiceType, string ControlUrl, string LocalIp, string ExternalIp);
}

internal static class DefaultGatewayDiscovery
{
    public static IReadOnlyList<IPAddress> Candidates()
    {
        var output = new List<IPAddress>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddFromLocal(IPAddress? address)
        {
            if (address?.AddressFamily != AddressFamily.InterNetwork)
            {
                return;
            }
            var bytes = address.GetAddressBytes();
            if (bytes[0] == 127 || bytes[0] == 169 && bytes[1] == 254)
            {
                return;
            }
            foreach (var last in new byte[] { 1, 254 })
            {
                var candidate = new IPAddress([bytes[0], bytes[1], bytes[2], last]);
                if (seen.Add(candidate.ToString()))
                {
                    output.Add(candidate);
                }
            }
        }
        foreach (var target in new[] { "1.1.1.1", "223.5.5.5" })
        {
            AddFromLocal(LocalAddressFor(target, 53, logFailure: false));
        }
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.OperationalStatus != OperationalStatus.Up || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }
            foreach (var address in networkInterface.GetIPProperties().UnicastAddresses.Select(item => item.Address))
            {
                AddFromLocal(address);
            }
        }
        return output;
    }

    public static byte[] LocalAddressMappedIpv6(IPAddress gateway)
    {
        var local = LocalAddressFor(gateway.ToString(), 5351, logFailure: false)
            ?? throw new InvalidOperationException("cannot determine local address for PCP");
        var bytes = local.GetAddressBytes();
        var mapped = new byte[16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        bytes.AsSpan().CopyTo(mapped.AsSpan(12));
        return mapped;
    }

    public static string LocalAddressFor(string host, int port)
        => LocalAddressFor(host, port, logFailure: false)?.ToString() ?? "";

    private static IPAddress? LocalAddressFor(string host, int port, bool logFailure)
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(host, port);
            return socket.LocalEndPoint is IPEndPoint endpoint ? endpoint.Address : null;
        }
        catch when (!logFailure)
        {
            return null;
        }
    }
}

internal static class PortMappingUdp
{
    public static async Task<byte[]> RequestAsync(
        IPAddress host,
        int port,
        byte[] request,
        int minResponse,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(host, port);
        await udp.SendAsync(request, request.Length).ConfigureAwait(false);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var result = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
        if (result.Buffer.Length < minResponse)
        {
            throw new InvalidOperationException($"UDP response truncated: {result.Buffer.Length} bytes");
        }
        return result.Buffer;
    }
}
