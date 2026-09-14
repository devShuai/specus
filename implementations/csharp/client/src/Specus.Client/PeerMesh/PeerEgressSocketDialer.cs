using System.Net;
using System.Net.Sockets;

namespace Specus.Client.PeerMesh;

/// <summary>
/// The real outbound socket.
/// </summary>
/// <remarks>
/// This is the one place the egress touches the network directly, and the only part of the plane
/// that is not driven by the shared vectors: what it produces is a connection, not a value.
///
/// <para>The egress sends a consumer's traffic to the real internet. If the outbound socket picked
/// up this node's own tunnel route, that traffic would go back into the mesh instead of out, and on
/// a node that is both an egress and a consumer of another egress it would loop. On Windows and
/// macOS the socket is bound, before it connects, to the interface the operating system would have
/// used had those routes not been there; see <see cref="PeerEgressSocketBinding"/>. That binding is
/// not best-effort: a socket that cannot be bound is not opened.</para>
///
/// <para>On Linux the socket is marked so a policy routing rule can steer it to the physical
/// interface regardless of what the tunnel did to the main table. That one is set best-effort: a
/// node without the matching rule, or without permission to set a mark, still works whenever the
/// tunnel did not claim the default route, so failing the connect there would break the common case
/// in order to protect the uncommon one.</para>
/// </remarks>
internal sealed class PeerEgressSocketDialer(PeerEgressSocketBinder binder) : IPeerEgressDialer
{
    /// <summary>
    /// The mark a policy routing rule matches on. The same value the Go client uses, so one
    /// deployment's rule serves either implementation.
    /// </summary>
    private const int EgressSocketMark = 0x5350;

    private const int SolSocket = 1;
    private const int SoMark = 36;

    public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs)
    {
        if (!IPAddress.TryParse(host, out var address))
        {
            // Addresses arrive as literals from the flow key, so this means the host was not one.
            throw new InvalidOperationException($"cannot resolve {host}");
        }
        var target = new IPEndPoint(address, port);
        return protocol.Equals("udp", StringComparison.OrdinalIgnoreCase)
            ? new Datagram(target, EgressSocketMark, binder)
            : new Stream(target, timeoutMs, EgressSocketMark, binder);
    }

    private static void Mark(Socket socket, int mark)
    {
        if (!OperatingSystem.IsLinux())
        {
            // Windows and macOS bind the socket to an interface instead; see the binder.
            return;
        }
        try
        {
            socket.SetRawSocketOption(SolSocket, SoMark, BitConverter.GetBytes(mark));
        }
        catch (SocketException)
        {
            // Best effort; see the class comment.
        }
        catch (PlatformNotSupportedException)
        {
            // Same.
        }
    }

    /// <summary>One TCP connection.</summary>
    private sealed class Stream : IPeerEgressSocket
    {
        private readonly Socket _socket;

        public Stream(IPEndPoint target, long timeoutMs, int mark, PeerEgressSocketBinder binder)
        {
            _socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
            };
            try
            {
                Mark(_socket, mark);
                binder.Bind(_socket, target);
                _socket.Connect(target);
                _socket.ReceiveTimeout = 0;
                _socket.SendTimeout = (int)Math.Min(timeoutMs, int.MaxValue);
            }
            catch
            {
                _socket.Dispose();
                throw;
            }
        }

        public int Read(byte[] buffer)
        {
            var read = _socket.Receive(buffer);
            // A zero-length receive on a stream socket is the peer's end of stream, which the plane
            // turns into a FIN. Reporting it as zero bytes would spin the reader loop instead.
            return read == 0 ? -1 : read;
        }

        public void Write(byte[] data)
        {
            var sent = 0;
            while (sent < data.Length)
            {
                sent += _socket.Send(data, sent, data.Length - sent, SocketFlags.None);
            }
        }

        public void CloseWrite()
        {
            try
            {
                _socket.Shutdown(SocketShutdown.Send);
            }
            catch (SocketException)
            {
                // The consumer's half-close outliving the socket is ordinary.
            }
            catch (ObjectDisposedException)
            {
                // Same.
            }
        }

        public void Dispose() => _socket.Dispose();
    }

    /// <summary>
    /// One UDP session, connected to the target so a reply from anywhere else is not delivered.
    /// </summary>
    /// <remarks>
    /// Connecting rather than binding is what makes the reply path safe: an unconnected socket
    /// would accept a datagram from any source, and the plane would relay it to the consumer as
    /// though it came from the address they asked for.
    /// </remarks>
    private sealed class Datagram : IPeerEgressSocket
    {
        private readonly Socket _socket;

        public Datagram(IPEndPoint target, int mark, PeerEgressSocketBinder binder)
        {
            _socket = new Socket(target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                Mark(_socket, mark);
                binder.Bind(_socket, target);
                _socket.Connect(target);
                _socket.ReceiveTimeout = 0;
            }
            catch
            {
                _socket.Dispose();
                throw;
            }
        }

        public int Read(byte[] buffer) => _socket.Receive(buffer);

        public void Write(byte[] data) => _socket.Send(data);

        public void Dispose() => _socket.Dispose();
    }
}
