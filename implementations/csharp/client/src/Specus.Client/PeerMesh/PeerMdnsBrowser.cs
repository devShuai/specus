using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Specus.Client.PeerMesh;

internal static class PeerMdnsBrowser
{
    private static readonly string[] Queries =
        ["_http._tcp.local", "_https._tcp.local", "_ssh._tcp.local", "_udp.local"];

    public static IReadOnlyList<PeerMdnsCandidate> Browse(TimeSpan timeout)
    {
        try
        {
            using var socket = new UdpClient();
            socket.Client.ReceiveTimeout = Math.Max(50, (int)timeout.TotalMilliseconds);
            var mdns = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
            foreach (var name in Queries)
            {
                var query = EncodePtrQuery(name);
                socket.Send(query, query.Length, mdns);
            }
            var packets = new List<byte[]>();
            var deadline = DateTime.UtcNow.Add(timeout);
            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    IPEndPoint? remote = null;
                    var data = socket.Receive(ref remote!);
                    packets.Add(data);
                }
                catch
                {
                    break;
                }
            }
            return Parse(packets);
        }
        catch
        {
            return [];
        }
    }

    internal static IReadOnlyList<PeerMdnsCandidate> Parse(IReadOnlyList<byte[]> packets)
    {
        var ptr = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var srv = new Dictionary<string, (string Target, int Port)>(StringComparer.OrdinalIgnoreCase);
        var addr = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var packet in packets)
        {
            ParsePacket(packet, ptr, srv, addr);
        }
        var found = new Dictionary<string, PeerMdnsCandidate>(StringComparer.Ordinal);
        foreach (var (query, instance) in ptr)
        {
            if (!srv.TryGetValue(instance, out var record))
            {
                continue;
            }
            var host = addr.GetValueOrDefault(record.Target, record.Target);
            if (!IsLocalHost(host))
            {
                continue;
            }
            var application = ApplicationFor(query);
            var transport = application == "udp" ? "udp" : "tcp";
            var name = instance.Split('.', 2)[0];
            var key = $"{application}:{host}:{record.Port}";
            found[key] = new PeerMdnsCandidate
            {
                Name = name,
                Transport = transport,
                Application = application,
                TargetHost = host,
                TargetPort = record.Port,
            };
        }
        return found.Values.ToArray();
    }

    private static bool IsLocalHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || host is "127.0.0.1" or "::1")
        {
            return true;
        }
        if (!IPAddress.TryParse(host, out var ip) || ip is null)
        {
            return false;
        }
        if (IPAddress.IsLoopback(ip))
        {
            return true;
        }
        var bytes = ip.GetAddressBytes();
        return bytes.Length == 4 && (bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 169 && bytes[1] == 254));
    }

    private static string ApplicationFor(string ptr)
    {
        var value = ptr.ToLowerInvariant();
        if (value.Contains("_https._tcp"))
        {
            return "https";
        }
        if (value.Contains("_http._tcp"))
        {
            return "http";
        }
        if (value.Contains("_ssh._tcp"))
        {
            return "ssh";
        }
        return "udp";
    }

    private static byte[] EncodePtrQuery(string name)
    {
        var buffer = new List<byte> { 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.Split('.'))
        {
            var bytes = Encoding.UTF8.GetBytes(label);
            buffer.Add((byte)bytes.Length);
            buffer.AddRange(bytes);
        }
        buffer.Add(0);
        buffer.Add(0);
        buffer.Add(12);
        buffer.Add(0);
        buffer.Add(1);
        return [.. buffer];
    }

    private static void ParsePacket(byte[] packet, Dictionary<string, string> ptr,
        Dictionary<string, (string Target, int Port)> srv, Dictionary<string, string> addr)
    {
        if (packet.Length < 12)
        {
            return;
        }
        var offset = 12;
        var questions = (packet[4] << 8) | packet[5];
        var answers = (packet[6] << 8) | packet[7];
        var authority = (packet[8] << 8) | packet[9];
        var additional = (packet[10] << 8) | packet[11];
        for (var i = 0; i < questions && offset < packet.Length; i++)
        {
            SkipName(packet, ref offset);
            offset += 4;
        }
        var records = answers + authority + additional;
        for (var i = 0; i < records && offset + 10 <= packet.Length; i++)
        {
            var name = ReadName(packet, ref offset);
            if (offset + 10 > packet.Length)
            {
                return;
            }
            var type = (packet[offset] << 8) | packet[offset + 1];
            var rdlength = (packet[offset + 8] << 8) | packet[offset + 9];
            offset += 10;
            if (offset + rdlength > packet.Length)
            {
                return;
            }
            if (type == 12)
            {
                var dataAt = offset;
                ptr[name] = ReadName(packet, ref offset);
                offset = dataAt;
            }
            else if (type == 33 && rdlength >= 6)
            {
                var port = (packet[offset + 4] << 8) | packet[offset + 5];
                var dataAt = offset;
                offset += 6;
                srv[name] = (ReadName(packet, ref offset), port);
                offset = dataAt;
            }
            else if (type == 1 && rdlength == 4)
            {
                addr[name] = $"{packet[offset]}.{packet[offset + 1]}.{packet[offset + 2]}.{packet[offset + 3]}";
            }
            offset += rdlength;
        }
    }

    private static string ReadName(byte[] packet, ref int offset)
    {
        var labels = new List<string>();
        var hops = 0;
        var end = -1;
        while (hops++ < 16 && offset < packet.Length)
        {
            var len = packet[offset];
            if (len == 0)
            {
                offset++;
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                if (offset + 1 >= packet.Length)
                {
                    break;
                }
                if (end < 0)
                {
                    end = offset + 2;
                }
                offset = ((len & 0x3F) << 8) | packet[offset + 1];
                continue;
            }
            offset++;
            if (offset + len > packet.Length)
            {
                break;
            }
            labels.Add(Encoding.UTF8.GetString(packet, offset, len));
            offset += len;
        }
        if (end >= 0)
        {
            offset = end;
        }
        return string.Join('.', labels);
    }

    private static void SkipName(byte[] packet, ref int offset)
    {
        while (offset < packet.Length)
        {
            var len = packet[offset];
            if (len == 0)
            {
                offset++;
                return;
            }
            if ((len & 0xC0) == 0xC0)
            {
                offset += 2;
                return;
            }
            offset += 1 + len;
        }
    }
}

internal sealed class PeerMdnsCandidate
{
    public string Name { get; set; } = "";
    public string Transport { get; set; } = "tcp";
    public string Application { get; set; } = "tcp";
    public string TargetHost { get; set; } = "";
    public int TargetPort { get; set; }
}
