using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;
using Specus.Client.Configuration;
using static Specus.Client.PeerMesh.PeerVirtualDeviceHelpers;

namespace Specus.Client.PeerMesh;

internal interface IPeerVirtualDevice : IAsyncDisposable
{
    string Name { get; }
    string Status { get; }
    string Error { get; }
    Task StartAsync(Func<byte[], ValueTask> outboundHandler, CancellationToken cancellationToken);

    Task SyncPeerRoutesAsync(IReadOnlyCollection<string> peerVirtualIps, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    ValueTask WritePacketAsync(byte[] packet, CancellationToken cancellationToken);
}

internal static class PeerVirtualDevices
{
    public static IPeerVirtualDevice Create(
        SpecusClientConfig config,
        PeerMeshConfig peerMesh,
        ILogger logger)
    {
        var mode = string.IsNullOrWhiteSpace(config.PeerMeshDevice)
            ? SpecusClientConfig.DefaultPeerMeshDevice
            : config.PeerMeshDevice.Trim().ToLowerInvariant();
        return mode switch
        {
            "noop" => new NoopPeerVirtualDevice(config.PeerMeshTunName),
            "linux-tun" => OperatingSystem.IsLinux()
                ? new LinuxTunPeerVirtualDevice(config, peerMesh, logger)
                : new NoopPeerVirtualDevice(config.PeerMeshTunName, "ERROR", "linux-tun can only run on Linux"),
            "windows-wintun" or "wintun" => OperatingSystem.IsWindows()
                ? new WindowsWintunPeerVirtualDevice(config, peerMesh, logger)
                : new NoopPeerVirtualDevice(config.PeerMeshTunName, "ERROR", "wintun can only run on Windows"),
            "auto" => OperatingSystem.IsLinux()
                ? new LinuxTunPeerVirtualDevice(config, peerMesh, logger)
                : OperatingSystem.IsWindows()
                    ? new WindowsWintunPeerVirtualDevice(config, peerMesh, logger)
                    : OperatingSystem.IsMacOS()
                        ? new DarwinUtunPeerVirtualDevice(config, peerMesh, logger)
                        : new NoopPeerVirtualDevice(config.PeerMeshTunName, "ERROR", "Peer Mesh virtual device is not supported on this OS"),
            "utun" or "mac-utun" or "macos-utun" or "darwin-utun" => OperatingSystem.IsMacOS()
                ? new DarwinUtunPeerVirtualDevice(config, peerMesh, logger)
                : new NoopPeerVirtualDevice(config.PeerMeshTunName, "ERROR", "utun can only run on macOS"),
            _ => new NoopPeerVirtualDevice(config.PeerMeshTunName, "NOOP", $"unsupported peerMeshDevice: {config.PeerMeshDevice}"),
        };
    }
}

internal sealed class NoopPeerVirtualDevice : IPeerVirtualDevice
{
    public NoopPeerVirtualDevice(string name, string status = "NOOP", string error = "")
    {
        Name = string.IsNullOrWhiteSpace(name) ? SpecusClientConfig.DefaultPeerMeshTunName : name;
        Status = status;
        Error = error;
    }

    public string Name { get; }
    public string Status { get; }
    public string Error { get; }
    public Task StartAsync(Func<byte[], ValueTask> outboundHandler, CancellationToken cancellationToken) => Task.CompletedTask;
    public ValueTask WritePacketAsync(byte[] packet, CancellationToken cancellationToken) => ValueTask.CompletedTask;
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

internal sealed class LinuxTunPeerVirtualDevice : IPeerVirtualDevice
{
    private const int OpenReadWrite = 0x0002;
    private const int InterfaceNameSize = 16;
    private const short IffTun = 0x0001;
    private const short IffNoPi = 0x1000;
    private const ulong TunSetIff = 0x400454ca;

    private readonly SpecusClientConfig _config;
    private readonly PeerMeshConfig _peerMesh;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _routeSync = new(1, 1);
    private readonly HashSet<string> _syncedPeerRoutes = new(StringComparer.Ordinal);
    private FileStream? _stream;
    private Task? _readTask;

    public LinuxTunPeerVirtualDevice(SpecusClientConfig config, PeerMeshConfig peerMesh, ILogger logger)
    {
        _config = config;
        _peerMesh = peerMesh;
        _logger = logger;
        Name = string.IsNullOrWhiteSpace(config.PeerMeshTunName) ? SpecusClientConfig.DefaultPeerMeshTunName : config.PeerMeshTunName;
        Status = "INIT";
        Error = "";
    }

    public string Name { get; private set; }
    public string Status { get; private set; }
    public string Error { get; private set; }

    public async Task StartAsync(Func<byte[], ValueTask> outboundHandler, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_peerMesh.VirtualIp) || string.IsNullOrWhiteSpace(_peerMesh.Cidr))
        {
            throw new InvalidOperationException("peer mesh Linux TUN missing virtualIp/cidr");
        }
        var fd = Open("/dev/net/tun", OpenReadWrite);
        var ifreq = new byte[40];
        Encoding.ASCII.GetBytes(Name.AsSpan(), ifreq.AsSpan(0, InterfaceNameSize));
        BitConverter.TryWriteBytes(ifreq.AsSpan(InterfaceNameSize, 2), (short)(IffTun | IffNoPi));
        if (!BitConverter.IsLittleEndian)
        {
            Array.Reverse(ifreq, InterfaceNameSize, 2);
        }
        if (Ioctl(fd, TunSetIff, ifreq) < 0)
        {
            _ = Close(fd);
            throw new InvalidOperationException($"Linux TUN TUNSETIFF failed: errno={Marshal.GetLastPInvokeError()}");
        }
        Name = ReadInterfaceName(ifreq);
        var handle = new SafeFileHandle(new IntPtr(fd), ownsHandle: true);
        _stream = new FileStream(handle, FileAccess.ReadWrite, 65535, isAsync: true);
        await ConfigureAsync(cancellationToken).ConfigureAwait(false);
        Status = "UP";
        Error = "";
        _readTask = Task.Run(() => ReadLoopAsync(outboundHandler, cancellationToken), CancellationToken.None);
    }

    public async Task SyncPeerRoutesAsync(IReadOnlyCollection<string> peerVirtualIps, CancellationToken cancellationToken)
    {
        await _routeSync.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var desired = NormalizePeerRoutes(peerVirtualIps, _peerMesh.VirtualIp);
            foreach (var routeIp in _syncedPeerRoutes.Where(item => !desired.Contains(item)).ToList())
            {
                await RunCommandQuietAsync(_logger, cancellationToken, "ip", "route", "del", $"{routeIp}/32", "dev", Name)
                    .ConfigureAwait(false);
                _syncedPeerRoutes.Remove(routeIp);
            }
            foreach (var routeIp in desired.Where(item => !_syncedPeerRoutes.Contains(item)))
            {
                try
                {
                    await RunCommandAsync(_logger, cancellationToken, "ip", "route", "replace", $"{routeIp}/32", "dev", Name)
                        .ConfigureAwait(false);
                    _syncedPeerRoutes.Add(routeIp);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Peer Mesh Linux TUN add peer route failed: route={Route}/32", routeIp);
                }
            }
        }
        finally
        {
            _routeSync.Release();
        }
    }

    public async ValueTask WritePacketAsync(byte[] packet, CancellationToken cancellationToken)
    {
        if (_stream is null || packet.Length == 0)
        {
            return;
        }
        await _stream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await SyncPeerRoutesAsync([], CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Peer Mesh Linux TUN peer route cleanup failed");
        }
        if (_stream is not null)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
            _stream = null;
        }
    }

    private async Task ReadLoopAsync(Func<byte[], ValueTask> outboundHandler, CancellationToken cancellationToken)
    {
        var buffer = new byte[Math.Max(1500, _config.PeerMeshMtu + 128)];
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var read = await _stream!.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read > 0)
                {
                    await outboundHandler(buffer.AsSpan(0, read).ToArray()).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (IOException ex)
            {
                Status = "ERROR";
                Error = ex.Message;
                _logger.LogWarning(ex, "Peer Mesh Linux TUN read failed");
                return;
            }
        }
    }

    private async Task ConfigureAsync(CancellationToken cancellationToken)
    {
        await RunCommandAsync(_logger, cancellationToken, "ip", "addr", "replace", $"{_peerMesh.VirtualIp}/32", "dev", Name).ConfigureAwait(false);
        await RunCommandAsync(_logger, cancellationToken, "ip", "link", "set", "dev", Name, "mtu", _config.PeerMeshMtu.ToString(System.Globalization.CultureInfo.InvariantCulture), "up").ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(_peerMesh.Cidr))
        {
            await RunCommandQuietAsync(_logger, cancellationToken, "ip", "route", "del", _peerMesh.Cidr!, "dev", Name).ConfigureAwait(false);
        }
    }

    private static string ReadInterfaceName(byte[] ifreq)
    {
        var length = Array.IndexOf(ifreq, (byte)0, 0, InterfaceNameSize);
        if (length < 0)
        {
            length = InterfaceNameSize;
        }
        return Encoding.ASCII.GetString(ifreq, 0, length);
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string pathname, int flags);

    [DllImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static extern int Ioctl(int fd, ulong request, byte[] argp);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int Close(int fd);
}

internal sealed class DarwinUtunPeerVirtualDevice : IPeerVirtualDevice
{
    private const int AfSystem = 32;
    private const int SockDgram = 2;
    private const int SysprotoControl = 2;
    private const int AfSysControl = 2;
    private const int DarwinAfInet = 2;
    private const int DarwinAfInet6 = 30;
    private const ulong CtlIoCgInfo = 0xc0644e03;
    private const int CtlNameSize = 96;
    private const int SockaddrCtlSize = 32;
    private const int PacketInfoBytes = 4;
    private const int UtunOptIfname = 2;
    private const string UtunControlName = "com.apple.net.utun_control";
    private const string UtunDefaultPrefix = "utun";

    private readonly SpecusClientConfig _config;
    private readonly PeerMeshConfig _peerMesh;
    private readonly ILogger _logger;
    private readonly object _sync = new();
    private readonly SemaphoreSlim _routeSync = new(1, 1);
    private readonly HashSet<string> _syncedPeerRoutes = new(StringComparer.Ordinal);
    private int _fd = -1;
    private Task? _readTask;

    public DarwinUtunPeerVirtualDevice(SpecusClientConfig config, PeerMeshConfig peerMesh, ILogger logger)
    {
        _config = config;
        _peerMesh = peerMesh;
        _logger = logger;
        Name = string.IsNullOrWhiteSpace(config.PeerMeshTunName) ? UtunDefaultPrefix : config.PeerMeshTunName;
        Status = "INIT";
        Error = "";
    }

    public string Name { get; private set; }
    public string Status { get; private set; }
    public string Error { get; private set; }

    public async Task StartAsync(Func<byte[], ValueTask> outboundHandler, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_peerMesh.VirtualIp) || string.IsNullOrWhiteSpace(_peerMesh.Cidr))
        {
            throw new InvalidOperationException("peer mesh macOS utun missing virtualIp/cidr");
        }
        var fd = Socket(AfSystem, SockDgram, SysprotoControl);
        if (fd < 0)
        {
            throw new InvalidOperationException($"open utun socket failed: errno={Marshal.GetLastPInvokeError()}");
        }
        try
        {
            ConnectUtun(fd, RequestedUnit());
            var actualName = UtunName(fd);
            if (!string.IsNullOrWhiteSpace(actualName))
            {
                Name = actualName;
            }
            await ConfigureAsync(cancellationToken).ConfigureAwait(false);
            lock (_sync)
            {
                _fd = fd;
                Status = "UP";
                Error = "";
            }
            _readTask = Task.Run(() => ReadLoopAsync(outboundHandler, cancellationToken), CancellationToken.None);
        }
        catch
        {
            _ = Close(fd);
            throw;
        }
    }

    public async Task SyncPeerRoutesAsync(IReadOnlyCollection<string> peerVirtualIps, CancellationToken cancellationToken)
    {
        await _routeSync.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var desired = NormalizePeerRoutes(peerVirtualIps, _peerMesh.VirtualIp);
            foreach (var routeIp in _syncedPeerRoutes.Where(item => !desired.Contains(item)).ToList())
            {
                await RunCommandQuietAsync(_logger, cancellationToken, "route", "-n", "delete", "-host", routeIp)
                    .ConfigureAwait(false);
                _syncedPeerRoutes.Remove(routeIp);
            }
            foreach (var routeIp in desired.Where(item => !_syncedPeerRoutes.Contains(item)))
            {
                await RunCommandQuietAsync(_logger, cancellationToken, "route", "-n", "delete", "-host", routeIp)
                    .ConfigureAwait(false);
                try
                {
                    await RunCommandAsync(_logger, cancellationToken, "route", "-n", "add", "-host", routeIp, "-interface", Name)
                        .ConfigureAwait(false);
                    _syncedPeerRoutes.Add(routeIp);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Peer Mesh macOS utun add peer route failed: route={Route}/32", routeIp);
                }
            }
        }
        finally
        {
            _routeSync.Release();
        }
    }

    public ValueTask WritePacketAsync(byte[] packet, CancellationToken cancellationToken)
    {
        if (packet.Length == 0)
        {
            return ValueTask.CompletedTask;
        }
        int fd;
        lock (_sync)
        {
            fd = _fd;
        }
        if (fd < 0)
        {
            return ValueTask.CompletedTask;
        }
        var frame = new byte[PacketInfoBytes + packet.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(0, PacketInfoBytes),
            (uint)(packet[0] >> 4 == 6 ? DarwinAfInet6 : DarwinAfInet));
        packet.CopyTo(frame.AsSpan(PacketInfoBytes));
        var offset = 0;
        while (offset < frame.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var written = Write(fd, frame.AsSpan(offset).ToArray(), frame.Length - offset);
            if (written <= 0)
            {
                throw new IOException($"utun write failed: errno={Marshal.GetLastPInvokeError()}");
            }
            offset += written;
        }
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await SyncPeerRoutesAsync([], CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Peer Mesh macOS utun peer route cleanup failed");
        }
        int fd;
        lock (_sync)
        {
            fd = _fd;
            _fd = -1;
        }
        if (fd >= 0)
        {
            _ = Close(fd);
        }
    }

    private async Task ReadLoopAsync(Func<byte[], ValueTask> outboundHandler, CancellationToken cancellationToken)
    {
        var buffer = new byte[65535];
        while (!cancellationToken.IsCancellationRequested)
        {
            int fd;
            lock (_sync)
            {
                fd = _fd;
            }
            if (fd < 0)
            {
                return;
            }
            var read = Read(fd, buffer, buffer.Length);
            if (read > PacketInfoBytes)
            {
                await outboundHandler(buffer.AsSpan(PacketInfoBytes, read - PacketInfoBytes).ToArray())
                    .ConfigureAwait(false);
                continue;
            }
            if (read < 0)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
                Status = "ERROR";
                Error = $"read utun packet failed: errno={Marshal.GetLastPInvokeError()}";
                _logger.LogWarning("{Message}", Error);
                return;
            }
        }
    }

    private async Task ConfigureAsync(CancellationToken cancellationToken)
    {
        var mtu = _config.PeerMeshMtu <= 0 ? SpecusClientConfig.DefaultPeerMeshMtu : _config.PeerMeshMtu;
        await RunCommandAsync(_logger, cancellationToken,
            "ifconfig", Name, "inet", _peerMesh.VirtualIp!, _peerMesh.VirtualIp!, "netmask", IPv4Mask(32), "mtu",
            mtu.ToString(System.Globalization.CultureInfo.InvariantCulture), "up").ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(_peerMesh.Cidr))
        {
            await RunCommandQuietAsync(_logger, cancellationToken, "route", "-n", "delete", "-net", _peerMesh.Cidr!)
                .ConfigureAwait(false);
        }
    }

    private uint RequestedUnit()
    {
        var name = Name.Trim().ToLowerInvariant();
        if (!name.StartsWith(UtunDefaultPrefix, StringComparison.Ordinal))
        {
            return 0;
        }
        var text = name[UtunDefaultPrefix.Length..];
        return uint.TryParse(text, out var unit) ? unit + 1 : 0;
    }

    private static void ConnectUtun(int fd, uint unit)
    {
        var info = new byte[4 + CtlNameSize];
        Encoding.ASCII.GetBytes(UtunControlName.AsSpan(), info.AsSpan(4, CtlNameSize));
        if (Ioctl(fd, CtlIoCgInfo, info) < 0)
        {
            throw new InvalidOperationException($"utun CTLIOCGINFO failed: errno={Marshal.GetLastPInvokeError()}");
        }
        var controlId = BitConverter.ToUInt32(info, 0);
        var address = new byte[SockaddrCtlSize];
        address[0] = SockaddrCtlSize;
        address[1] = AfSystem;
        BitConverter.TryWriteBytes(address.AsSpan(2, 2), (ushort)AfSysControl);
        BitConverter.TryWriteBytes(address.AsSpan(4, 4), controlId);
        BitConverter.TryWriteBytes(address.AsSpan(8, 4), unit);
        if (Connect(fd, address, (uint)address.Length) < 0)
        {
            throw new InvalidOperationException($"connect utun failed: errno={Marshal.GetLastPInvokeError()}");
        }
    }

    private static string UtunName(int fd)
    {
        var name = new byte[32];
        var length = (uint)name.Length;
        if (GetSockOpt(fd, SysprotoControl, UtunOptIfname, name, ref length) < 0)
        {
            return "";
        }
        var end = Array.IndexOf(name, (byte)0, 0, Math.Min(name.Length, (int)length));
        if (end < 0)
        {
            end = Math.Min(name.Length, (int)length);
        }
        return Encoding.ASCII.GetString(name, 0, end);
    }

    [DllImport("libc", EntryPoint = "socket", SetLastError = true)]
    private static extern int Socket(int domain, int type, int protocol);

    [DllImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static extern int Ioctl(int fd, ulong request, byte[] argp);

    [DllImport("libc", EntryPoint = "connect", SetLastError = true)]
    private static extern int Connect(int fd, byte[] address, uint addressLength);

    [DllImport("libc", EntryPoint = "getsockopt", SetLastError = true)]
    private static extern int GetSockOpt(int fd, int level, int optionName, byte[] optionValue, ref uint optionLen);

    [DllImport("libc", EntryPoint = "read", SetLastError = true)]
    private static extern int Read(int fd, byte[] buffer, int count);

    [DllImport("libc", EntryPoint = "write", SetLastError = true)]
    private static extern int Write(int fd, byte[] buffer, int count);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int Close(int fd);
}

internal sealed class WindowsWintunPeerVirtualDevice : IPeerVirtualDevice
{
    private const uint RingCapacity = 0x400000;
    private readonly SpecusClientConfig _config;
    private readonly PeerMeshConfig _peerMesh;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _routeSync = new(1, 1);
    private readonly HashSet<string> _syncedPeerRoutes = new(StringComparer.Ordinal);
    private IntPtr _library;
    private IntPtr _adapter;
    private IntPtr _session;
    private WintunApi? _api;
    private Task? _readTask;

    public WindowsWintunPeerVirtualDevice(SpecusClientConfig config, PeerMeshConfig peerMesh, ILogger logger)
    {
        _config = config;
        _peerMesh = peerMesh;
        _logger = logger;
        Name = string.IsNullOrWhiteSpace(config.PeerMeshTunName) ? SpecusClientConfig.DefaultPeerMeshTunName : config.PeerMeshTunName;
        Status = "INIT";
        Error = "";
    }

    public string Name { get; }
    public string Status { get; private set; }
    public string Error { get; private set; }

    public async Task StartAsync(Func<byte[], ValueTask> outboundHandler, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_peerMesh.VirtualIp) || string.IsNullOrWhiteSpace(_peerMesh.Cidr))
        {
            throw new InvalidOperationException("peer mesh Wintun missing virtualIp/cidr");
        }
        (_library, _api) = LoadWintun();
        _adapter = _api.OpenAdapter(Name);
        var openError = Marshal.GetLastWin32Error();
        if (_adapter == IntPtr.Zero)
        {
            _logger.LogInformation("Peer Mesh Wintun adapter not found, creating: name={Name}", Name);
            _adapter = _api.CreateAdapter(Name, "specus", IntPtr.Zero);
        }
        else
        {
            _logger.LogInformation("Peer Mesh Wintun adapter opened: name={Name}", Name);
        }
        var createError = Marshal.GetLastWin32Error();
        if (_adapter == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "Wintun adapter create/open failed; run as administrator and ensure wintun.dll is available. " +
                $"name={Name}, arch={RuntimeInformation.ProcessArchitecture}, baseDir={AppContext.BaseDirectory}, " +
                $"openLastError={openError}, createLastError={createError}");
        }
        _session = _api.StartSession(_adapter, RingCapacity);
        var sessionError = Marshal.GetLastWin32Error();
        if (_session == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                $"Wintun session start failed; name={Name}, lastError={sessionError}");
        }
        _logger.LogInformation("Peer Mesh Wintun session started: name={Name}, virtualIp={VirtualIp}",
            Name, _peerMesh.VirtualIp);
        await ConfigureAsync(cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Peer Mesh Wintun adapter configured: name={Name}, mtu={Mtu}", Name, _config.PeerMeshMtu);
        Status = "UP";
        Error = "";
        _readTask = Task.Run(() => ReadLoopAsync(outboundHandler, cancellationToken), CancellationToken.None);
    }

    public async Task SyncPeerRoutesAsync(IReadOnlyCollection<string> peerVirtualIps, CancellationToken cancellationToken)
    {
        await _routeSync.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var desired = NormalizePeerRoutes(peerVirtualIps, _peerMesh.VirtualIp);
            foreach (var routeIp in _syncedPeerRoutes.Where(item => !desired.Contains(item)).ToList())
            {
                await RunCommandQuietAsync(_logger, cancellationToken, "netsh", "interface", "ipv4", "delete", "route",
                    $"{routeIp}/32", Name, "store=active").ConfigureAwait(false);
                _syncedPeerRoutes.Remove(routeIp);
            }
            foreach (var routeIp in desired.Where(item => !_syncedPeerRoutes.Contains(item)))
            {
                await RunCommandQuietAsync(_logger, cancellationToken, "netsh", "interface", "ipv4", "delete", "route",
                    $"{routeIp}/32", Name, "store=active").ConfigureAwait(false);
                try
                {
                    await RunCommandAsync(_logger, cancellationToken, "netsh", "interface", "ipv4", "add", "route",
                        $"{routeIp}/32", Name, "store=active").ConfigureAwait(false);
                    _syncedPeerRoutes.Add(routeIp);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Peer Mesh Wintun add peer route failed: route={Route}/32", routeIp);
                }
            }
        }
        finally
        {
            _routeSync.Release();
        }
    }

    public ValueTask WritePacketAsync(byte[] packet, CancellationToken cancellationToken)
    {
        if (_api is null || _session == IntPtr.Zero || packet.Length == 0)
        {
            return ValueTask.CompletedTask;
        }
        var sendPacket = _api.AllocateSendPacket(_session, (uint)packet.Length);
        if (sendPacket == IntPtr.Zero)
        {
            throw new InvalidOperationException("Wintun send packet allocation failed");
        }
        Marshal.Copy(packet, 0, sendPacket, packet.Length);
        _api.SendPacket(_session, sendPacket);
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await SyncPeerRoutesAsync([], CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Peer Mesh Wintun peer route cleanup failed");
        }
        if (_api is not null && _session != IntPtr.Zero)
        {
            _api.EndSession(_session);
            _session = IntPtr.Zero;
        }
        if (_api is not null && _adapter != IntPtr.Zero)
        {
            _api.CloseAdapter(_adapter);
            _adapter = IntPtr.Zero;
        }
        if (_library != IntPtr.Zero)
        {
            NativeLibrary.Free(_library);
            _library = IntPtr.Zero;
        }
        _api = null;
    }

    private async Task ReadLoopAsync(Func<byte[], ValueTask> outboundHandler, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            if (_api is null || _session == IntPtr.Zero)
            {
                return;
            }
            var packet = _api.ReceivePacket(_session, out var packetSize);
            if (packet == IntPtr.Zero)
            {
                await Task.Delay(5, cancellationToken).ConfigureAwait(false);
                continue;
            }
            try
            {
                if (packetSize > 0)
                {
                    var data = new byte[packetSize];
                    Marshal.Copy(packet, data, 0, data.Length);
                    await outboundHandler(data).ConfigureAwait(false);
                }
            }
            finally
            {
                _api.ReleaseReceivePacket(_session, packet);
            }
        }
    }

    private async Task ConfigureAsync(CancellationToken cancellationToken)
    {
        await RunCommandAsync(_logger, cancellationToken, "netsh", "interface", "ip", "set", "address",
            $"name={Name}", "static", _peerMesh.VirtualIp!, IPv4Mask(32)).ConfigureAwait(false);
        await RunCommandAsync(_logger, cancellationToken, "netsh", "interface", "ipv4", "set", "subinterface",
            Name, $"mtu={_config.PeerMeshMtu}", "store=active").ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(_peerMesh.Cidr))
        {
            await RunCommandQuietAsync(_logger, cancellationToken, "netsh", "interface", "ipv4", "delete", "route",
                _peerMesh.Cidr!, Name, "store=active").ConfigureAwait(false);
        }
    }

    private static (IntPtr Library, WintunApi Api) LoadWintun()
    {
        var configured = Environment.GetEnvironmentVariable("SPECUS_PEER_MESH_WINTUN_DLL")
            ?? AppContext.GetData("specus.peerMesh.wintunDll") as string;
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(configured))
        {
            candidates.Add(configured);
        }
        var arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x86_64",
            Architecture.Arm64 => "aarch64",
            Architecture.X86 => "x86",
            _ => "",
        };
        if (!string.IsNullOrWhiteSpace(arch))
        {
            candidates.Add(Path.Combine(AppContext.BaseDirectory, "native", "windows", arch, "wintun.dll"));
        }
        candidates.Add("wintun");
        foreach (var candidate in candidates)
        {
            if (NativeLibrary.TryLoad(candidate, out var library))
            {
                return (library, new WintunApi(library));
            }
        }
        throw new InvalidOperationException("load wintun.dll failed; place wintun.dll in PATH/app directory or set SPECUS_PEER_MESH_WINTUN_DLL");
    }

    private sealed class WintunApi
    {
        public WintunApi(IntPtr library)
        {
            OpenAdapter = Load<OpenAdapterDelegate>(library, "WintunOpenAdapter");
            CreateAdapter = Load<CreateAdapterDelegate>(library, "WintunCreateAdapter");
            CloseAdapter = Load<CloseAdapterDelegate>(library, "WintunCloseAdapter");
            StartSession = Load<StartSessionDelegate>(library, "WintunStartSession");
            EndSession = Load<EndSessionDelegate>(library, "WintunEndSession");
            ReceivePacket = Load<ReceivePacketDelegate>(library, "WintunReceivePacket");
            ReleaseReceivePacket = Load<ReleaseReceivePacketDelegate>(library, "WintunReleaseReceivePacket");
            AllocateSendPacket = Load<AllocateSendPacketDelegate>(library, "WintunAllocateSendPacket");
            SendPacket = Load<SendPacketDelegate>(library, "WintunSendPacket");
        }

        public OpenAdapterDelegate OpenAdapter { get; }
        public CreateAdapterDelegate CreateAdapter { get; }
        public CloseAdapterDelegate CloseAdapter { get; }
        public StartSessionDelegate StartSession { get; }
        public EndSessionDelegate EndSession { get; }
        public ReceivePacketDelegate ReceivePacket { get; }
        public ReleaseReceivePacketDelegate ReleaseReceivePacket { get; }
        public AllocateSendPacketDelegate AllocateSendPacket { get; }
        public SendPacketDelegate SendPacket { get; }

        private static T Load<T>(IntPtr library, string name)
            where T : Delegate
        {
            return Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
        public delegate IntPtr OpenAdapterDelegate(string name);
        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
        public delegate IntPtr CreateAdapterDelegate(string name, string specusType, IntPtr requestedGuid);
        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        public delegate void CloseAdapterDelegate(IntPtr adapter);
        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        public delegate IntPtr StartSessionDelegate(IntPtr adapter, uint capacity);
        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        public delegate void EndSessionDelegate(IntPtr session);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate IntPtr ReceivePacketDelegate(IntPtr session, out uint packetSize);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate void ReleaseReceivePacketDelegate(IntPtr session, IntPtr packet);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate IntPtr AllocateSendPacketDelegate(IntPtr session, uint packetSize);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate void SendPacketDelegate(IntPtr session, IntPtr packet);
    }
}

internal static class PeerVirtualDeviceHelpers
{
    public static int CidrPrefix(string? cidr)
    {
        var slash = cidr?.IndexOf('/') ?? -1;
        if (slash < 0 || slash == cidr!.Length - 1)
        {
            throw new ArgumentException($"invalid peer mesh cidr: {cidr}", nameof(cidr));
        }
        return int.Parse(cidr[(slash + 1)..], System.Globalization.CultureInfo.InvariantCulture);
    }

    public static string IPv4Mask(int prefix)
    {
        if (prefix is < 0 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(prefix));
        }
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return string.Join('.',
            (mask >> 24) & 0xff,
            (mask >> 16) & 0xff,
            (mask >> 8) & 0xff,
            mask & 0xff);
    }

    public static string IPv4NetworkAddress(string? cidr)
    {
        var slash = cidr?.IndexOf('/') ?? -1;
        if (slash < 0)
        {
            throw new ArgumentException($"invalid peer mesh cidr: {cidr}", nameof(cidr));
        }
        var prefix = CidrPrefix(cidr);
        var ip = IPAddress.Parse(cidr![..slash]).GetAddressBytes();
        if (ip.Length != 4)
        {
            throw new ArgumentException($"peer mesh CIDR must be IPv4: {cidr}", nameof(cidr));
        }
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var network = BinaryPrimitives.ReadUInt32BigEndian(ip) & mask;
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, network);
        return new IPAddress(bytes.ToArray()).ToString();
    }

    public static HashSet<string> NormalizePeerRoutes(IEnumerable<string?>? peerVirtualIps, string? selfVirtualIp)
    {
        var desired = new HashSet<string>(StringComparer.Ordinal);
        if (peerVirtualIps is null)
        {
            return desired;
        }
        var self = selfVirtualIp?.Trim() ?? "";
        foreach (var peerVirtualIp in peerVirtualIps)
        {
            var normalized = peerVirtualIp?.Trim() ?? "";
            if (IsIPv4(normalized) && !string.Equals(normalized, self, StringComparison.Ordinal))
            {
                desired.Add(normalized);
            }
        }
        return desired;
    }

    public static bool IsIPv4(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }
        var parts = value.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }
        foreach (var part in parts)
        {
            if (!int.TryParse(part, System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out var octet)
                || octet is < 0 or > 255)
            {
                return false;
            }
        }
        return true;
    }

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private static readonly Encoding FallbackOemEncoding = ResolveFallbackOemEncoding();

    public static async Task<bool> RunCommandQuietAsync(ILogger logger, CancellationToken cancellationToken, params string[] command)
    {
        try
        {
            await RunCommandAsync(logger, LogLevel.Debug, cancellationToken, command).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Peer Mesh ignored command failure: {Command}", string.Join(' ', command));
            return false;
        }
    }

    public static Task RunCommandAsync(ILogger logger, CancellationToken cancellationToken, params string[] command)
        => RunCommandAsync(logger, LogLevel.Information, cancellationToken, command);

    private static async Task RunCommandAsync(ILogger logger, LogLevel execLogLevel, CancellationToken cancellationToken, params string[] command)
    {
        logger.Log(execLogLevel, "Peer Mesh exec: {Command}", string.Join(' ', command));
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = command[0],
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        foreach (var argument in command.Skip(1))
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        process.Start();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var outputTask = ReadAllBytesAsync(process.StandardOutput.BaseStream, timeout.Token);
        var errorTask = ReadAllBytesAsync(process.StandardError.BaseStream, timeout.Token);
        await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        var output = DecodeConsoleOutput(await outputTask.ConfigureAwait(false));
        var error = DecodeConsoleOutput(await errorTask.ConfigureAwait(false));
        if (process.ExitCode != 0)
        {
            logger.LogWarning("Peer Mesh command failed ({ExitCode}): {Command}: {Output}",
                process.ExitCode, string.Join(' ', command), $"{output} {error}".Trim());
            throw new InvalidOperationException($"{string.Join(' ', command)} failed ({process.ExitCode}): {output} {error}".Trim());
        }
        var combined = $"{output} {error}".Trim();
        if (!string.IsNullOrWhiteSpace(combined))
        {
            logger.Log(execLogLevel, "Peer Mesh exec output: {Output}", combined);
        }
    }

    private static async Task<byte[]> ReadAllBytesAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
        return buffer.ToArray();
    }

    private static string DecodeConsoleOutput(byte[] bytes)
    {
        if (bytes.Length == 0)
        {
            return "";
        }
        // 现代 Windows 的 netsh 等工具输出 UTF-8，旧系统/旧工具按 OEM 代码页输出；
        // GBK 等 OEM 字节几乎不可能通过严格 UTF-8 校验，先严格 UTF-8，失败再回退 OEM。
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return FallbackOemEncoding.GetString(bytes);
        }
    }

    private static Encoding ResolveFallbackOemEncoding()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Encoding.UTF8;
        }
        try
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            return Encoding.GetEncoding(System.Globalization.CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
        }
        catch
        {
            return Encoding.UTF8;
        }
    }
}
