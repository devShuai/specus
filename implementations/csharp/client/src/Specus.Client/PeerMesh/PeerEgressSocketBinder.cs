using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Specus.Client.PeerMesh;

/// <summary>
/// Nothing but the tunnel leads to the destination. The dial is refused rather than left unbound,
/// because an unbound socket is exactly the one that would follow the tunnel route.
/// </summary>
internal sealed class PeerEgressNoPhysicalRouteException(string destination)
    : IOException($"bind egress socket for {destination}: no route outside the tunnel");

/// <summary>
/// Binds each egress socket to the interface <see cref="PeerEgressSocketBinding.Select"/> chooses:
/// <c>IP_UNICAST_IF</c> on Windows, <c>IP_BOUND_IF</c> on macOS.
/// </summary>
/// <remarks>
/// On Linux the socket is marked instead, for a policy routing rule to steer; see
/// <see cref="PeerEgressSocketDialer"/>.
/// </remarks>
internal class PeerEgressSocketBinder
{
    private readonly Func<string?> _tunnel;
    private readonly Func<string, string> _tunnelKey;
    private readonly Action<Socket, string>? _apply;

    internal PeerEgressSocketBinder(Func<string?> tunnel, Func<IReadOnlyList<PeerEgressBindRoute>>? routes,
        Func<string, string> tunnelKey, Action<Socket, string>? apply)
    {
        _tunnel = tunnel;
        Routes = routes;
        _tunnelKey = tunnelKey;
        _apply = apply;
    }

    /// <summary>Reads the candidate routes. Settable so the real-socket tests can hand the stack a route it has to refuse.</summary>
    internal Func<IReadOnlyList<PeerEgressBindRoute>>? Routes { get; set; }

    /// <summary>A binder that binds nothing.</summary>
    public static PeerEgressSocketBinder None() => new(() => "", null, _ => "", null);

    public static PeerEgressSocketBinder ForPlatform(Func<string?> tunnel)
    {
        if (OperatingSystem.IsWindows())
        {
            return new PeerEgressSocketBinder(tunnel, Windows.Routes, Windows.InterfaceKey, Windows.Apply);
        }
        if (OperatingSystem.IsMacOS())
        {
            var table = new MacosTable();
            return new PeerEgressSocketBinder(tunnel, table.Routes, name => name, Macos.Apply);
        }
        return None();
    }

    /// <summary>Turns a tunnel name into what the table's interface column holds, or "" when there is none.</summary>
    public string TunnelKey(string? name) => string.IsNullOrEmpty(name) ? "" : _tunnelKey(name);

    /// <summary>Binds <paramref name="socket"/>, before it connects, to the interface for <paramref name="target"/>.</summary>
    public void Bind(Socket socket, IPEndPoint target)
    {
        if (_apply is null)
        {
            return;
        }
        _apply(socket, Choose(target.Address.ToString()));
    }

    public string Choose(string destination)
    {
        var routes = (Routes ?? throw new InvalidOperationException("no routing table reader"))();
        return PeerEgressSocketBinding.Select(routes, TunnelKey(_tunnel()), destination)
            ?? throw new PeerEgressNoPhysicalRouteException(destination);
    }

    /// <summary>
    /// Windows: the table read natively on every connect, because a Get-NetRoute query costs 419 ms
    /// and these two calls cost microseconds and need no cache.
    /// </summary>
    internal static class Windows
    {
        private const ushort AfInet = 2;

        public static IReadOnlyList<PeerEgressBindRoute> Routes()
        {
            var forward = PeerEgressSocketBinding.ParseWindowsForwardTable(
                    Table(forward: true, PeerEgressSocketBinding.WindowsForwardRowSize))
                ?? throw new IOException("GetIpForwardTable2 returned a table shorter than its count");
            var interfaces = PeerEgressSocketBinding.ParseWindowsInterfaceTable(
                    Table(forward: false, PeerEgressSocketBinding.WindowsInterfaceRowSize))
                ?? throw new IOException("GetIpInterfaceTable returned a table shorter than its count");
            return PeerEgressSocketBinding.WindowsRoutes(forward, interfaces);
        }

        /// <summary>Copies one IPv4 MIB table out of the memory the API allocated, then frees it.</summary>
        public static byte[] Table(bool forward, int rowSize)
        {
            var status = forward ? GetIpForwardTable2(AfInet, out var table) : GetIpInterfaceTable(AfInet, out table);
            if (status != 0)
            {
                throw new IOException($"{(forward ? "GetIpForwardTable2" : "GetIpInterfaceTable")} failed with {status}");
            }
            try
            {
                var count = (uint)Marshal.ReadInt32(table);
                var copy = new byte[checked((int)(PeerEgressSocketBinding.WindowsTableHeader + count * (long)rowSize))];
                Marshal.Copy(table, copy, 0, copy.Length);
                return copy;
            }
            finally
            {
                FreeMibTable(table);
            }
        }

        /// <summary>An adapter's name, as the Wintun adapter was created with it, resolved to its index.</summary>
        public static string InterfaceKey(string name)
        {
            if (ConvertInterfaceAliasToLuid(name, out var luid) != 0
                || ConvertInterfaceLuidToIndex(in luid, out var index) != 0)
            {
                return "";
            }
            return index.ToString(CultureInfo.InvariantCulture);
        }

        public static void Apply(Socket socket, string iface)
        {
            if (!long.TryParse(iface, NumberStyles.None, CultureInfo.InvariantCulture, out var index))
            {
                throw new IOException($"bind egress socket: interface {iface} is not an index");
            }
            socket.SetRawSocketOption(PeerEgressSocketBinding.IpProtoIp, PeerEgressSocketBinding.WindowsIpUnicastIf,
                PeerEgressSocketBinding.WindowsUnicastInterfaceOption(index));
        }

        [DllImport("iphlpapi.dll")]
        private static extern uint GetIpForwardTable2(ushort family, out IntPtr table);

        [DllImport("iphlpapi.dll")]
        private static extern uint GetIpInterfaceTable(ushort family, out IntPtr table);

        [DllImport("iphlpapi.dll")]
        private static extern void FreeMibTable(IntPtr memory);

        [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint ConvertInterfaceAliasToLuid(string alias, out ulong luid);

        [DllImport("iphlpapi.dll")]
        private static extern uint ConvertInterfaceLuidToIndex(in ulong luid, out uint index);
    }

    internal static class Macos
    {
        public static void Apply(Socket socket, string iface)
        {
            var index = if_nametoindex(iface);
            if (index == 0)
            {
                throw new IOException($"bind egress socket: no interface named {iface}");
            }
            socket.SetRawSocketOption(PeerEgressSocketBinding.IpProtoIp, PeerEgressSocketBinding.MacosIpBoundIf,
                PeerEgressSocketBinding.MacosBoundInterfaceOption(index));
        }

        [DllImport("libc", SetLastError = true)]
        private static extern uint if_nametoindex(string name);
    }

    /// <summary>
    /// macOS: the same <c>netstat -rn -f inet</c> the route commander reads, held for two seconds.
    /// </summary>
    /// <remarks>
    /// The choice is made on every connect and a read costs 25 ms, so a page opening twenty
    /// connections would otherwise spend half a second asking. The tunnel's routes are left out of the
    /// choice anyway, so the only change a held table can miss is a physical one, and a connect that
    /// misses it fails rather than leaking.
    /// </remarks>
    internal sealed class MacosTable
    {
        private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(10);
        private readonly Lock _gate = new();
        private IReadOnlyList<PeerEgressBindRoute>? _held;
        private long _readAt;

        public IReadOnlyList<PeerEgressBindRoute> Routes()
        {
            lock (_gate)
            {
                if (_held is not null && Stopwatch.GetElapsedTime(_readAt) < Lifetime)
                {
                    return _held;
                }
                var command = PeerEgressMacosRouteCommands.ShowTableArgs();
                var start = new ProcessStartInfo(command[0])
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                };
                foreach (var argument in command[1..])
                {
                    start.ArgumentList.Add(argument);
                }
                using var process = Process.Start(start)
                    ?? throw new IOException($"{command[0]} did not start");
                var stdout = process.StandardOutput.ReadToEnd();
                if (!process.WaitForExit(CommandTimeout))
                {
                    process.Kill(entireProcessTree: true);
                    throw new IOException($"{command[0]} did not finish");
                }
                if (process.ExitCode != 0)
                {
                    _held = null;
                    throw new IOException($"{command[0]} exited {process.ExitCode}");
                }
                _held = PeerEgressSocketBinding.MacosRoutes(stdout);
                _readAt = Stopwatch.GetTimestamp();
                return _held;
            }
        }
    }
}
