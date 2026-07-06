using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Client.DirectHttp;
using ShuaiTunnel.Client.Runtime;

namespace ShuaiTunnel.Client.Desktop;

public partial class MainWindow : Window
{
    private static readonly JsonSerializerOptions SettingsJsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private readonly UiTunnelObserver _observer;
    private CancellationTokenSource? _clientCts;
    private TunnelControlClient? _client;
    private Task? _clientTask;
    private ILoggerFactory? _loggerFactory;
    private HttpClient? _httpClient;
    private bool _running;
    private bool _stopping;
    private bool _closing;

    public ObservableCollection<TcpRouteSnapshot> TcpRoutes { get; } = new();

    public ObservableCollection<HttpRouteSnapshot> HttpRoutes { get; } = new();

    public ObservableCollection<PeerRouteSnapshot> PeerRoutes { get; } = new();

    public ObservableCollection<PeerSessionSnapshot> PeerSessions { get; } = new();

    public ObservableCollection<LogLine> Logs { get; } = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        _observer = new UiTunnelObserver(this);
        LoadSettingsIntoForm();
        UpdateStoppedUi("未连接", "填写连接信息后启动客户端");
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ApplyDarkTitleBar();
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (_running)
        {
            await StopClientAsync("用户断开连接").ConfigureAwait(false);
            return;
        }

        await StartClientAsync().ConfigureAwait(false);
    }

    private void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            SaveSettingsFromForm();
            AppendLog(LogLevel.Information, "desktop", "连接配置已保存", null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            MessageBox.Show(this, ex.Message, "保存配置失败", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (_running && !_closing)
        {
            e.Cancel = true;
            _closing = true;
            _ = StopAndCloseAsync();
            return;
        }
        base.OnClosing(e);
    }

    private async Task StopAndCloseAsync()
    {
        await StopClientAsync("窗口关闭").ConfigureAwait(false);
        await Dispatcher.InvokeAsync(Close);
    }

    private async Task StartClientAsync()
    {
        TunnelClientConfig config;
        try
        {
            config = BuildConfigFromForm();
            SaveSettingsFromForm();
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or JsonException)
        {
            MessageBox.Show(this, ex.Message, "连接配置无效", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        await Dispatcher.InvokeAsync(() =>
        {
            ClearRuntimeCollections();
            SetInputsEnabled(false);
            ConnectButton.Content = "断开";
            UpdateStatusText("启动中", "正在启动客户端运行时");
        });

        _clientCts = new CancellationTokenSource();
        _loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Information);
            builder.AddProvider(new UiLoggerProvider(AppendLog));
        });
        _httpClient = DirectHttpForwarder.BuildDefaultClient();
        var auth = new ClientAuthService(
            config,
            _httpClient,
            _loggerFactory.CreateLogger<ClientAuthService>());
        var forwarder = new DirectHttpForwarder(_httpClient);
        _client = new TunnelControlClient(config, auth, forwarder, _loggerFactory, _observer);
        _running = true;
        _stopping = false;

        var cancellationToken = _clientCts.Token;
        _clientTask = Task.Run(async () =>
        {
            try
            {
                await _client.RunAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                await Dispatcher.InvokeAsync(() =>
                    AppendLog(LogLevel.Error, "desktop", "客户端运行异常", ex));
            }
            finally
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    if (!_stopping)
                    {
                        UpdateStoppedUi("已停止", "客户端运行任务已结束");
                    }
                });
            }
        }, CancellationToken.None);
    }

    private async Task StopClientAsync(string reason)
    {
        if (!_running || _stopping)
        {
            return;
        }

        _stopping = true;
        await Dispatcher.InvokeAsync(() =>
        {
            UpdateStatusText("停止中", reason);
            ConnectButton.IsEnabled = false;
        });

        var task = _clientTask;
        try
        {
            _clientCts?.Cancel();
            if (_client is not null)
            {
                await _client.DisposeAsync().ConfigureAwait(false);
            }
            if (task is not null)
            {
                await task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (TimeoutException)
        {
            await Dispatcher.InvokeAsync(() =>
                AppendLog(LogLevel.Warning, "desktop", "等待客户端停止超时，已继续释放桌面资源", null));
        }
        finally
        {
            _clientCts?.Dispose();
            _clientCts = null;
            _client = null;
            _clientTask = null;
            _httpClient?.Dispose();
            _httpClient = null;
            _loggerFactory?.Dispose();
            _loggerFactory = null;

            await Dispatcher.InvokeAsync(() =>
            {
                _running = false;
                _stopping = false;
                SetInputsEnabled(true);
                UpdateStoppedUi("未连接", reason);
            });
        }
    }

    private TunnelClientConfig BuildConfigFromForm()
    {
        var serverBaseUrl = ServerBaseUrlBox.Text.Trim();
        if (!Uri.TryCreate(serverBaseUrl, UriKind.Absolute, out var serverUri)
            || (serverUri.Scheme != Uri.UriSchemeHttp && serverUri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException("服务端地址必须是 http/https 绝对地址。");
        }
        if (string.IsNullOrWhiteSpace(ApiKeyBox.Text))
        {
            throw new ArgumentException("API Key 不能为空。");
        }
        if (string.IsNullOrWhiteSpace(SecretBox.Password))
        {
            throw new ArgumentException("Secret 不能为空。");
        }
        if (!int.TryParse(MtuBox.Text.Trim(), out var mtu))
        {
            mtu = TunnelClientConfig.DefaultPeerMeshMtu;
        }

        var config = new TunnelClientConfig
        {
            ServerBaseUrl = serverBaseUrl,
            ApiKey = ApiKeyBox.Text,
            Secret = SecretBox.Password,
            PeerMeshDevice = string.IsNullOrWhiteSpace(PeerMeshDeviceBox.Text)
                ? "auto"
                : PeerMeshDeviceBox.Text,
            PeerMeshTunName = TunNameBox.Text,
            PeerMeshMtu = mtu,
        };
        config.Normalize();
        return config;
    }

    private void LoadSettingsIntoForm()
    {
        var settings = LoadSettings();
        ServerBaseUrlBox.Text = settings.ServerBaseUrl;
        ApiKeyBox.Text = settings.ApiKey;
        SecretBox.Password = settings.Secret;
        PeerMeshDeviceBox.Text = settings.PeerMeshDevice;
        TunNameBox.Text = settings.PeerMeshTunName;
        MtuBox.Text = settings.PeerMeshMtu.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private static DesktopClientSettings LoadSettings()
    {
        var path = SettingsPath();
        if (!File.Exists(path))
        {
            return DesktopClientSettings.Default();
        }
        try
        {
            var settings = JsonSerializer.Deserialize<DesktopClientSettings>(
                File.ReadAllText(path), SettingsJsonOptions);
            return settings ?? DesktopClientSettings.Default();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return DesktopClientSettings.Default();
        }
    }

    private void SaveSettingsFromForm()
    {
        var config = BuildConfigFromForm();
        var settings = new DesktopClientSettings
        {
            ServerBaseUrl = config.ServerBaseUrl,
            ApiKey = config.ApiKey ?? "",
            Secret = config.Secret ?? "",
            PeerMeshDevice = config.PeerMeshDevice,
            PeerMeshTunName = config.PeerMeshTunName,
            PeerMeshMtu = config.PeerMeshMtu,
        };
        var path = SettingsPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(settings, SettingsJsonOptions));
    }

    private static string SettingsPath()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "ShuaiTunnel",
            "desktop-client.json");
    }

    private void ApplyStatus(TunnelClientStatusSnapshot snapshot)
    {
        UpdateStatusText(StatusTitle(snapshot), snapshot.Detail);
        RuntimeSummaryText.Text = snapshot.ClientName is null
            ? "连接后显示客户端、控制端和 Peer Mesh 信息"
            : $"{snapshot.ClientName} · {snapshot.TunnelEndpoint} · Peer Mesh {(snapshot.PeerMeshEnabled ? "启用" : "关闭")} · {snapshot.VirtualIp ?? "-"}";
    }

    private void ApplyRoutes(TunnelClientRoutesSnapshot snapshot)
    {
        Replace(TcpRoutes, snapshot.TcpRoutes);
        Replace(HttpRoutes, snapshot.HttpRoutes);
        TcpCountText.Text = snapshot.TcpRoutes.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        HttpCountText.Text = snapshot.HttpRoutes.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private void ApplyPeerMesh(TunnelPeerMeshSnapshot snapshot)
    {
        Replace(PeerRoutes, snapshot.Peers);
        Replace(PeerSessions, snapshot.Sessions);
        PeerCountText.Text = snapshot.Peers.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        PeerMeshSummaryText.Text = snapshot.Enabled
            ? $"本机 {snapshot.VirtualIp ?? "-"} · {snapshot.Cidr ?? "-"} · {snapshot.DeviceName} / {snapshot.DeviceStatus} · 会话 {snapshot.Sessions.Count}"
            : $"Peer Mesh 未启动 · {snapshot.DeviceName} / {snapshot.DeviceStatus}";
    }

    private static void Replace<T>(ObservableCollection<T> collection, IEnumerable<T> items)
    {
        collection.Clear();
        foreach (var item in items)
        {
            collection.Add(item);
        }
    }

    private void ClearRuntimeCollections()
    {
        TcpRoutes.Clear();
        HttpRoutes.Clear();
        PeerRoutes.Clear();
        PeerSessions.Clear();
        TcpCountText.Text = "0";
        HttpCountText.Text = "0";
        PeerCountText.Text = "0";
        PeerMeshSummaryText.Text = "Peer Mesh 未启动";
    }

    private void UpdateStoppedUi(string phase, string detail)
    {
        ConnectButton.Content = "连接";
        ConnectButton.IsEnabled = true;
        SetInputsEnabled(true);
        UpdateStatusText(phase, detail);
        RuntimeSummaryText.Text = "连接后显示客户端、控制端和 Peer Mesh 信息";
    }

    private void UpdateStatusText(string phase, string detail)
    {
        StatusPhaseText.Text = phase;
        StatusDetailText.Text = detail;
    }

    private void SetInputsEnabled(bool enabled)
    {
        ServerBaseUrlBox.IsEnabled = enabled;
        ApiKeyBox.IsEnabled = enabled;
        SecretBox.IsEnabled = enabled;
        PeerMeshDeviceBox.IsEnabled = enabled;
        TunNameBox.IsEnabled = enabled;
        MtuBox.IsEnabled = enabled;
        SaveButton.IsEnabled = enabled;
        ConnectButton.IsEnabled = true;
    }

    private void AppendLog(LogLevel level, string category, string message, Exception? exception)
    {
        var text = $"{DateTime.Now:HH:mm:ss} {level,-11} {ShortCategory(category)} {message}";
        if (exception is not null)
        {
            text += $" | {exception.GetType().Name}: {exception.Message}";
        }
        Logs.Add(new LogLine(text));
        while (Logs.Count > 300)
        {
            Logs.RemoveAt(0);
        }
        LogTextBox.Text = string.Join(Environment.NewLine, Logs.Select(line => line.Text));
        LogTextBox.ScrollToEnd();
    }

    private static string StatusTitle(TunnelClientStatusSnapshot snapshot)
    {
        if (snapshot.LoggedIn)
        {
            return "已连接";
        }
        if (!snapshot.Running)
        {
            return "未连接";
        }
        return snapshot.Phase switch
        {
            "HTTP_LOGIN" => "登录中",
            "CONTROL_CONNECTED" => "控制端已连接",
            "RECONNECTING" => "重连中",
            "SESSION_CLOSED" => "会话已关闭",
            _ => snapshot.Phase,
        };
    }

    private static string ShortCategory(string category)
    {
        var index = category.LastIndexOf('.');
        return index >= 0 && index + 1 < category.Length ? category[(index + 1)..] : category;
    }

    private void ApplyDarkTitleBar()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == IntPtr.Zero)
        {
            return;
        }

        var enabled = 1;
        if (DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref enabled, sizeof(int)) != 0)
        {
            _ = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeBefore20H1, ref enabled, sizeof(int));
        }

        var captionColor = ColorRef(0x07, 0x10, 0x18);
        var textColor = ColorRef(0xF4, 0xFA, 0xFF);
        _ = DwmSetWindowAttribute(hwnd, DwmwaCaptionColor, ref captionColor, sizeof(int));
        _ = DwmSetWindowAttribute(hwnd, DwmwaTextColor, ref textColor, sizeof(int));
    }

    private static int ColorRef(byte red, byte green, byte blue)
    {
        return red | (green << 8) | (blue << 16);
    }

    private const int DwmwaUseImmersiveDarkModeBefore20H1 = 19;
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaCaptionColor = 35;
    private const int DwmwaTextColor = 36;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(
        IntPtr hwnd,
        int dwAttribute,
        ref int pvAttribute,
        int cbAttribute);

    private sealed class UiTunnelObserver : ITunnelClientObserver
    {
        private readonly MainWindow _window;

        public UiTunnelObserver(MainWindow window)
        {
            _window = window;
        }

        public void OnStatusChanged(TunnelClientStatusSnapshot snapshot)
        {
            _window.Dispatcher.BeginInvoke(new Action(() => _window.ApplyStatus(snapshot)));
        }

        public void OnRoutesChanged(TunnelClientRoutesSnapshot snapshot)
        {
            _window.Dispatcher.BeginInvoke(new Action(() => _window.ApplyRoutes(snapshot)));
        }

        public void OnPeerMeshChanged(TunnelPeerMeshSnapshot snapshot)
        {
            _window.Dispatcher.BeginInvoke(new Action(() => _window.ApplyPeerMesh(snapshot)));
        }
    }

    private sealed class UiLoggerProvider : ILoggerProvider
    {
        private readonly Action<LogLevel, string, string, Exception?> _sink;

        public UiLoggerProvider(Action<LogLevel, string, string, Exception?> sink)
        {
            _sink = sink;
        }

        public ILogger CreateLogger(string categoryName) => new UiLogger(categoryName, _sink);

        public void Dispose()
        {
        }
    }

    private sealed class UiLogger : ILogger
    {
        private readonly string _category;
        private readonly Action<LogLevel, string, string, Exception?> _sink;

        public UiLogger(string category, Action<LogLevel, string, string, Exception?> sink)
        {
            _category = category;
            _sink = sink;
        }

        public IDisposable BeginScope<TState>(TState state)
            where TState : notnull
        {
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }
            var message = formatter(state, exception);
            Application.Current.Dispatcher.BeginInvoke(new Action(() => _sink(logLevel, _category, message, exception)));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose()
            {
            }
        }
    }

    private sealed class DesktopClientSettings
    {
        public string ServerBaseUrl { get; set; } = "";

        public string ApiKey { get; set; } = "";

        public string Secret { get; set; } = "";

        public string PeerMeshDevice { get; set; } = "";

        public string PeerMeshTunName { get; set; } = "";

        public int PeerMeshMtu { get; set; }

        public static DesktopClientSettings Default()
        {
            return new DesktopClientSettings
            {
                ServerBaseUrl = "https://tunnel.devshuai.com",
                PeerMeshDevice = "auto",
                PeerMeshTunName = TunnelClientConfig.DefaultPeerMeshTunName,
                PeerMeshMtu = TunnelClientConfig.DefaultPeerMeshMtu,
            };
        }
    }
}

public sealed record LogLine(string Text);
