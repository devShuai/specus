using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Specus.Client.PeerMesh;

/// <summary>
/// One upstream resolver: an address and a port, 53 unless said otherwise.
/// </summary>
/// <remarks>
/// Step five records the system's own resolvers as these. Until then the caller passes them in, and
/// a port other than 53 is what lets a test stand a resolver up on a local socket.
/// </remarks>
internal readonly record struct PeerEgressDnsUpstream(IPAddress Address, int Port)
{
    internal const int DefaultPort = 53;

    public IPEndPoint EndPoint => new(Address, Port);

    /// <summary>
    /// Reads <c>192.0.2.53</c>, <c>192.0.2.53:5353</c>, <c>2001:db8::53</c> or
    /// <c>[2001:db8::53]:5353</c>.
    /// </summary>
    public static bool TryParse(string? text, out PeerEgressDnsUpstream upstream)
    {
        upstream = default;
        if (!IPEndPoint.TryParse(text?.Trim() ?? string.Empty, out var endpoint))
        {
            return false;
        }
        upstream = new PeerEgressDnsUpstream(endpoint.Address, endpoint.Port == 0 ? DefaultPort : endpoint.Port);
        return true;
    }

    /// <summary>The address alone on port 53, as the status shows it; with the port otherwise.</summary>
    public override string ToString() => Port == DefaultPort ? Address.ToString() : EndPoint.ToString();
}

/// <summary>Carries a query the responder does not answer itself to the upstreams.</summary>
internal interface IPeerEgressDnsForwarder
{
    /// <summary>
    /// The first upstream answer to a query, byte for byte, or null when every upstream failed.
    /// Over TCP when the query came over TCP.
    /// </summary>
    Task<byte[]?> ForwardAsync(byte[] query, bool tcp, IReadOnlyList<PeerEgressDnsUpstream> upstreams);
}

/// <summary>
/// Forwarding over real sockets (protocol/spec/peer-egress-dns.md, section three): the upstreams in
/// order, each given two seconds, the query and the answer passed through untouched.
/// </summary>
/// <remarks>
/// Nothing is resolved here and nothing is cached. Resolving on its own would be one more way out of
/// the machine that no rule governs, and a cache would answer with what an upstream said once rather
/// than what it says now. The sockets follow the system's routes, so an upstream covered by an
/// egress rule is reached through that egress, which is what the rule asks for.
/// </remarks>
/// <param name="perUpstreamMs">
/// How long one upstream is given. Two seconds in use; a test that waits for a silent upstream on
/// purpose gives it less.
/// </param>
internal sealed class PeerEgressDnsForwarder(long perUpstreamMs = PeerEgressDnsForwarder.UpstreamTimeoutMs) : IPeerEgressDnsForwarder
{
    /// <summary>How long one upstream has to answer, connection included over TCP.</summary>
    internal const long UpstreamTimeoutMs = 2000;

    private const int MaxMessageBytes = 65535;

    public async Task<byte[]?> ForwardAsync(byte[] query, bool tcp, IReadOnlyList<PeerEgressDnsUpstream> upstreams)
    {
        foreach (var upstream in upstreams)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(perUpstreamMs));
            try
            {
                var answer = tcp
                    ? await OverTcpAsync(query, upstream, deadline.Token).ConfigureAwait(false)
                    : await OverUdpAsync(query, upstream, deadline.Token).ConfigureAwait(false);
                if (answer is not null)
                {
                    return answer;
                }
            }
            catch (Exception failure) when (failure is SocketException or OperationCanceledException or IOException
                                                or ObjectDisposedException)
            {
                // Timed out, refused or unreachable: the next upstream is asked.
            }
        }
        return null;
    }

    /// <summary>
    /// One exchange over UDP. The socket is connected, so only the upstream's own address can
    /// answer it, and an answer is taken only with the query's ID: anything else on the socket is
    /// waited past, not relayed.
    /// </summary>
    private static async Task<byte[]?> OverUdpAsync(byte[] query, PeerEgressDnsUpstream upstream, CancellationToken token)
    {
        using var socket = new Socket(upstream.Address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await socket.ConnectAsync(upstream.EndPoint, token).ConfigureAwait(false);
        await socket.SendAsync(query, SocketFlags.None, token).ConfigureAwait(false);
        var buffer = new byte[MaxMessageBytes];
        var id = PeerEgressDnsWire.Id(query);
        while (true)
        {
            var received = await socket.ReceiveAsync(buffer, SocketFlags.None, token).ConfigureAwait(false);
            if (received >= 2 && PeerEgressDnsWire.Id(buffer.AsSpan(0, received)) == id)
            {
                return buffer[..received];
            }
        }
    }

    /// <summary>One exchange over TCP, with the two-byte length framing RFC 1035 gives it.</summary>
    private static async Task<byte[]?> OverTcpAsync(byte[] query, PeerEgressDnsUpstream upstream, CancellationToken token)
    {
        using var socket = new Socket(upstream.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(upstream.EndPoint, token).ConfigureAwait(false);
        var framed = new byte[2 + query.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
        query.CopyTo(framed.AsSpan(2));
        await socket.SendAsync(framed, SocketFlags.None, token).ConfigureAwait(false);
        var prefix = new byte[2];
        if (!await ReadExactlyAsync(socket, prefix, token).ConfigureAwait(false))
        {
            return null;
        }
        var answer = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
        if (!await ReadExactlyAsync(socket, answer, token).ConfigureAwait(false))
        {
            return null;
        }
        return answer.Length >= 2 && PeerEgressDnsWire.Id(answer) == PeerEgressDnsWire.Id(query) ? answer : null;
    }

    private static async Task<bool> ReadExactlyAsync(Socket socket, byte[] buffer, CancellationToken token)
    {
        var filled = 0;
        while (filled < buffer.Length)
        {
            var read = await socket.ReceiveAsync(buffer.AsMemory(filled), SocketFlags.None, token).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }
            filled += read;
        }
        return true;
    }
}
