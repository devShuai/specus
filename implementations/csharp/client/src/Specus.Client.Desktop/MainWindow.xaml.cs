using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;
using Microsoft.Extensions.Logging;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;
using Specus.Client.Runtime;
using Specus.Client.Updates;

namespace Specus.Client.Desktop;

public partial class MainWindow : Window
{
    private static readonly JsonSerializerOptions SettingsJsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private const string ThemeModeSystem = "system";
    private const string ThemeModeLight = "light";
    private const string ThemeModeDark = "dark";
    private const string ThemeModeSystemIcon = "M4,5 H20 V15 H4 Z M8,19 H16 M12,15 V19";
    private const string ThemeModeLightIcon = "M12,5 A7,7 0 1 1 12,19 A7,7 0 1 1 12,5 M12,1 V3 M12,21 V23 M4.22,4.22 L5.64,5.64 M18.36,18.36 L19.78,19.78 M1,12 H3 M21,12 H23 M4.22,19.78 L5.64,18.36 M18.36,5.64 L19.78,4.22";
    private const string ThemeModeDarkIcon = "M20,14.5 A8.5,8.5 0 0 1 9.5,4 A7,7 0 1 0 20,14.5 Z";

    private readonly UiSpecusObserver _observer;
    private readonly FileTransferManager _transferManager = FileTransferManager.Instance;
    private readonly ClientUpdateService _updateService = new();
    private readonly CancellationTokenSource _updateCts = new();
    private CancellationTokenSource? _clientCts;
    private SpecusControlClient? _client;
    private Task? _clientTask;
    private ILoggerFactory? _loggerFactory;
    private HttpClient? _authHttpClient;
    private HttpClient? _routeHttpClient;
    private string _themeMode = ThemeModeSystem;
    private bool _effectiveDarkTheme = true;
    private bool _peerMeshEnabled;
    private bool _loadingSettings;
    private bool _running;
    private bool _stopping;
    private bool _closing;
    private bool _logExpanded;
    private bool _clientLoggedIn;
    private bool _updateRestarting;
    private int _updateCheckActive;

    public ObservableCollection<TcpRouteSnapshot> TcpRoutes { get; } = new();

    public ObservableCollection<HttpRouteSnapshot> HttpRoutes { get; } = new();

    public ObservableCollection<PeerRouteSnapshot> PeerRoutes { get; } = new();

    public ObservableCollection<PeerRouteSnapshot> MessagePeerRoutes { get; } = new();

    public ObservableCollection<PeerSessionSnapshot> PeerSessions { get; } = new();

    public ObservableCollection<ClientMessageLine> ClientMessages { get; } = new();

    public ObservableCollection<LogLine> Logs { get; } = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        _observer = new UiSpecusObserver(this);
        _transferManager.TransferEvent += OnTransferEvent;
        SystemEvents.UserPreferenceChanged += SystemEvents_UserPreferenceChanged;
        Loaded += MainWindow_Loaded;
        LoadSettingsIntoForm();
        ApplyConfiguredTheme();
        UpdateStoppedUi("未连接", "填写连接信息后启动客户端");
    }

    protected override void OnClosed(EventArgs e)
    {
        _updateCts.Cancel();
        _updateCts.Dispose();
        _updateService.Dispose();
        SystemEvents.UserPreferenceChanged -= SystemEvents_UserPreferenceChanged;
        _transferManager.TransferEvent -= OnTransferEvent;
        base.OnClosed(e);
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ApplyTitleBar(_effectiveDarkTheme);
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

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        Loaded -= MainWindow_Loaded;
        await RunUpdateLoopAsync(_updateCts.Token);
    }

    private async void CheckUpdateButton_Click(object sender, RoutedEventArgs e)
    {
        await CheckForUpdateAsync(showUpToDate: true, _updateCts.Token);
    }

    private void ThemeModeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_loadingSettings)
        {
            return;
        }
        _themeMode = NextThemeMode(_themeMode);
        ApplyConfiguredTheme();
        try
        {
            SaveSettingsFromForm(validateConnection: false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            AppendLog(LogLevel.Warning, "desktop", $"主题设置保存失败: {ex.Message}", null);
        }
    }

    private void LogExpandButton_Click(object sender, RoutedEventArgs e)
    {
        if (_logExpanded)
        {
            CollapseLogPanel();
        }
        else
        {
            ExpandLogPanel();
        }
    }

    private async void SendMessageButton_Click(object sender, RoutedEventArgs e)
    {
        var client = _client;
        if (client is null)
        {
            return;
        }
        var target = ResolveMessageTarget();
        var body = MessageBodyBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(target) || string.IsNullOrWhiteSpace(body))
        {
            MessageBox.Show(this, "目标客户端和消息内容不能为空。", "发送消息", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!IsKnownMessageTarget(target))
        {
            MessageBox.Show(this, "请选择在线且支持接收消息的客户端。", "发送消息", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SendMessageButton.IsEnabled = false;
        try
        {
            var result = await client.SendClientMessageAsync(
                target,
                body,
                _clientCts?.Token ?? CancellationToken.None);
            MessageBodyBox.Clear();
            AppendLog(LogLevel.Information, "desktop",
                $"消息已提交: {target}, channel={result.Transport}", null);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException)
        {
            AppendLog(LogLevel.Warning, "desktop", $"消息发送失败: {ex.Message}", null);
            MessageBox.Show(this, ex.Message, "发送消息失败", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            AppendLog(LogLevel.Error, "desktop", "消息发送异常", ex);
            MessageBox.Show(this, ex.Message, "发送消息失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            UpdateMessageSendState();
        }
    }

    private void Window_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Escape && _logExpanded)
        {
            CollapseLogPanel();
            e.Handled = true;
        }
    }

    private async void SendFileButton_Click(object sender, RoutedEventArgs e)
    {
        var client = _client;
        if (client is null)
        {
            return;
        }
        var target = ResolveMessageTarget();
        if (string.IsNullOrWhiteSpace(target))
        {
            MessageBox.Show(this, "请先选择或填写目标客户端。", "发送文件", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!IsKnownMessageTarget(target))
        {
            MessageBox.Show(this, "请选择在线且支持接收消息的客户端。", "发送文件", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = "选择要发送的文件（≤ 8 MB）",
            CheckFileExists = true,
            Multiselect = false,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var filePath = dialog.FileName;
        var cancellationToken = _clientCts?.Token ?? CancellationToken.None;
        try
        {
            await _transferManager.SendFileAsync(
                target,
                filePath,
                (to, size) =>
                {
                    client.EnsureAttachmentTargetCanReceive(to, size);
                    AppendLog(LogLevel.Information, "desktop",
                        $"文件发送开始: {Path.GetFileName(filePath)} -> {to}", null);
                },
                (to, body, ct) => client.SendClientMessageAsync(to, body, ct, publishLocalEcho: false),
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            AppendLog(LogLevel.Error, "desktop", "文件发送异常", ex);
            _ = Dispatcher.BeginInvoke(new Action(() =>
                MessageBox.Show(this, ex.Message, "发送文件失败", MessageBoxButton.OK, MessageBoxImage.Error)));
        }
    }

    private bool HandleRawClientMessage(string fromClientName, string body)
    {
        return _transferManager.OnIncomingMessage(fromClientName, body);
    }

    private void OnTransferEvent(string direction, string peer, string text)
    {
        Dispatcher.BeginInvoke(new Action(() =>
        {
            var outbound = string.Equals(direction, "OUT", StringComparison.OrdinalIgnoreCase);
            ClientMessages.Add(new ClientMessageLine
            {
                CreatedAtText = DateTime.Now.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture),
                DirectionText = outbound ? "发送" : "接收",
                Peer = peer,
                TransportText = "文件",
                StatusText = "",
                Message = text,
            });
            while (ClientMessages.Count > 300)
            {
                ClientMessages.RemoveAt(0);
            }
        }));
    }

    /// <summary>
    /// 把日志面板从右侧内容区底部挪到根网格并铺满两列，覆盖整个窗口。
    /// WPF 元素不能同时挂两处，放大/还原通过重挂载实现，日志内容与滚动位置保持不变。
    /// </summary>
    private void ExpandLogPanel()
    {
        if (_logExpanded)
        {
            return;
        }
        MainContentGrid.Children.Remove(LogPanelBorder);
        Grid.SetRow(LogPanelBorder, 0);
        Grid.SetColumn(LogPanelBorder, 0);
        Grid.SetColumnSpan(LogPanelBorder, 2);
        LogPanelBorder.Margin = new Thickness(16);
        Panel.SetZIndex(LogPanelBorder, 10);
        RootLayoutGrid.Children.Add(LogPanelBorder);
        LogExpandButton.Content = "还原";
        _logExpanded = true;
    }

    private void CollapseLogPanel()
    {
        if (!_logExpanded)
        {
            return;
        }
        RootLayoutGrid.Children.Remove(LogPanelBorder);
        Grid.SetRow(LogPanelBorder, 2);
        Grid.SetColumn(LogPanelBorder, 0);
        Grid.SetColumnSpan(LogPanelBorder, 1);
        LogPanelBorder.Margin = new Thickness(0);
        Panel.SetZIndex(LogPanelBorder, 0);
        MainContentGrid.Children.Add(LogPanelBorder);
        LogExpandButton.Content = "放大";
        _logExpanded = false;
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_updateRestarting)
        {
            _updateCts.Cancel();
        }
        if (_running && !_closing)
        {
            e.Cancel = true;
            _closing = true;
            _ = StopAndCloseAsync();
            return;
        }
        base.OnClosing(e);
    }

    private async Task RunUpdateLoopAsync(CancellationToken cancellationToken)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SPECUS_SKIP_UPDATE_ONCE"), "1",
                StringComparison.Ordinal))
        {
            return;
        }
        while (!cancellationToken.IsCancellationRequested)
        {
            if (UpdateCheckEnabledCheckBox.IsChecked == true)
            {
                await CheckForUpdateAsync(showUpToDate: false, cancellationToken);
            }
            try
            {
                await Task.Delay(TimeSpan.FromHours(ParseUpdateIntervalHours()), cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
        }
    }

    private async Task CheckForUpdateAsync(bool showUpToDate, CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _updateCheckActive, 1) != 0)
        {
            return;
        }
        CheckUpdateButton.IsEnabled = false;
        CheckUpdateButton.Content = "检查中…";
        try
        {
            var serverText = ServerBaseUrlBox.Text.Trim();
            if (!Uri.TryCreate(serverText, UriKind.Absolute, out var serverUri))
            {
                if (showUpToDate)
                {
                    MessageBox.Show(this, "请先填写有效的服务端地址。", "检查更新",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
                return;
            }
            var update = await _updateService.CheckAsync(serverUri, ClientUpdateTarget.CSharpDesktop,
                ClientVersion.Current, cancellationToken);
            if (!update.UpdateAvailable)
            {
                if (showUpToDate)
                {
                    MessageBox.Show(this, $"当前已是最新版本（{ClientVersion.Current}）。", "检查更新",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
                return;
            }

            var install = AutoUpdateCheckBox.IsChecked == true;
            if (!install)
            {
                var mandatoryText = update.Mandatory
                    ? "这是必须更新；当前版本低于服务端支持的最低版本。\n\n"
                    : string.Empty;
                var changelog = string.IsNullOrWhiteSpace(update.ChangelogUrl)
                    ? string.Empty
                    : $"\n更新说明：{ClientUpdateDisplay.Sanitize(update.ChangelogUrl)}";
                install = MessageBox.Show(this,
                    $"{mandatoryText}发现新版本 {update.LatestVersion}（{FormatBytes(update.FileSize)}）。" +
                    $"{changelog}\n\n下载并安装后，客户端将自动重启。",
                    "发现客户端更新", MessageBoxButton.YesNo,
                    update.Mandatory ? MessageBoxImage.Warning : MessageBoxImage.Information) ==
                    MessageBoxResult.Yes;
            }
            if (!install)
            {
                return;
            }

            var progress = new Progress<ClientUpdateProgress>(value =>
            {
                var percent = value.TotalBytes <= 0 ? 0 : value.BytesReceived * 100 / value.TotalBytes;
                CheckUpdateButton.Content = $"下载 {percent}%";
            });
            var request = ClientUpdateRuntime.CreateCurrentProcessRequest();
            var plan = await _updateService.DownloadAndPrepareAsync(update, request, progress,
                cancellationToken);
            try
            {
                ClientUpdateService.LaunchPreparedUpdate(plan);
            }
            catch
            {
                ClientUpdateService.CleanupPreparedUpdate(plan);
                throw;
            }

            _updateRestarting = true;
            _closing = true;
            AppendLog(LogLevel.Information, "desktop",
                $"更新 {update.LatestVersion} 已校验，退出后将原子替换并保留 .bak", null);
            if (_running)
            {
                await StopClientAsync("安装客户端更新");
            }
            Application.Current.Shutdown();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            AppendLog(LogLevel.Warning, "desktop", $"检查或安装更新失败: {ex.Message}", ex);
            if (showUpToDate)
            {
                MessageBox.Show(this, ex.Message, "更新失败", MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }
        finally
        {
            Interlocked.Exchange(ref _updateCheckActive, 0);
            if (!_updateRestarting)
            {
                CheckUpdateButton.IsEnabled = true;
                CheckUpdateButton.Content = "检查更新";
            }
        }
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes >= 1024 * 1024)
        {
            return $"{bytes / 1024d / 1024d:F1} MiB";
        }
        if (bytes >= 1024)
        {
            return $"{bytes / 1024d:F1} KiB";
        }
        return $"{bytes} B";
    }

    private async Task StopAndCloseAsync()
    {
        await StopClientAsync("窗口关闭").ConfigureAwait(false);
        await Dispatcher.InvokeAsync(Close);
    }

    private async Task StartClientAsync()
    {
        SpecusClientConfig config;
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
            SetSidebarStatusDot("WarningBrush");
        });

        _clientCts = new CancellationTokenSource();
        _loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Information);
            builder.AddProvider(new UiLoggerProvider(AppendLog));
        });
        _authHttpClient = ClientAuthService.BuildDefaultClient();
        _routeHttpClient = DirectHttpForwarder.BuildDefaultClient();
        var auth = new ClientAuthService(
            config,
            _authHttpClient,
            _loggerFactory.CreateLogger<ClientAuthService>(),
            ClientMessageCapabilities.DesktopFileTransfer());
        var forwarder = new DirectHttpForwarder(_routeHttpClient);
        _client = new SpecusControlClient(config, auth, forwarder, _loggerFactory, _observer);
        _running = true;
        _stopping = false;
        await Dispatcher.InvokeAsync(UpdateMessageSendState);

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
            SetSidebarStatusDot("WarningBrush");
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
            _authHttpClient?.Dispose();
            _authHttpClient = null;
            _routeHttpClient?.Dispose();
            _routeHttpClient = null;
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

    private SpecusClientConfig BuildConfigFromForm()
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
            mtu = SpecusClientConfig.DefaultPeerMeshMtu;
        }

        var config = new SpecusClientConfig
        {
            ServerBaseUrl = serverBaseUrl,
            ApiKey = ApiKeyBox.Text,
            Secret = SecretBox.Password,
            PeerMeshDevice = string.IsNullOrWhiteSpace(PeerMeshDeviceBox.Text)
                ? "auto"
                : PeerMeshDeviceBox.Text,
            PeerMeshTunName = TunNameBox.Text,
            PeerMeshMtu = mtu,
            UpdateEnabled = UpdateCheckEnabledCheckBox.IsChecked == true,
            UpdateCheckIntervalHours = ParseUpdateIntervalHours(),
            AutoUpdate = AutoUpdateCheckBox.IsChecked == true,
        };
        config.Normalize();
        return config;
    }

    private void LoadSettingsIntoForm()
    {
        var settings = LoadSettings();
        _loadingSettings = true;
        ServerBaseUrlBox.Text = settings.ServerBaseUrl;
        ApiKeyBox.Text = settings.ApiKey;
        SecretBox.Password = settings.Secret;
        PeerMeshDeviceBox.Text = settings.PeerMeshDevice;
        UpdateCheckEnabledCheckBox.IsChecked = settings.UpdateCheckEnabled;
        UpdateCheckIntervalHoursBox.Text = settings.UpdateCheckIntervalHours.ToString(
            System.Globalization.CultureInfo.InvariantCulture);
        AutoUpdateCheckBox.IsChecked = settings.AutoUpdate;
        _themeMode = NormalizeThemeMode(settings.ThemeMode);
        UpdateThemeModeButton();
        TunNameBox.Text = settings.PeerMeshTunName;
        MtuBox.Text = settings.PeerMeshMtu.ToString(System.Globalization.CultureInfo.InvariantCulture);
        _loadingSettings = false;
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
            return (settings ?? DesktopClientSettings.Default()).Normalize();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return DesktopClientSettings.Default();
        }
    }

    private void SaveSettingsFromForm(bool validateConnection = true)
    {
        SpecusClientConfig? config = validateConnection ? BuildConfigFromForm() : null;
        var settings = new DesktopClientSettings
        {
            ServerBaseUrl = config?.ServerBaseUrl ?? ServerBaseUrlBox.Text.Trim(),
            ApiKey = config?.ApiKey ?? ApiKeyBox.Text,
            Secret = config?.Secret ?? SecretBox.Password,
            PeerMeshDevice = config?.PeerMeshDevice ?? (string.IsNullOrWhiteSpace(PeerMeshDeviceBox.Text)
                ? "auto"
                : PeerMeshDeviceBox.Text.Trim()),
            ThemeMode = NormalizeThemeMode(_themeMode),
            PeerMeshTunName = config?.PeerMeshTunName ?? TunNameBox.Text.Trim(),
            PeerMeshMtu = config?.PeerMeshMtu ?? ParseMtuOrDefault(),
            UpdateCheckEnabled = UpdateCheckEnabledCheckBox.IsChecked == true,
            UpdateCheckIntervalHours = ParseUpdateIntervalHours(),
            AutoUpdate = AutoUpdateCheckBox.IsChecked == true,
        };
        var path = SettingsPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(settings, SettingsJsonOptions));
    }

    private int ParseMtuOrDefault()
    {
        return int.TryParse(MtuBox.Text.Trim(), out var mtu)
            ? mtu
            : SpecusClientConfig.DefaultPeerMeshMtu;
    }

    private int ParseUpdateIntervalHours()
    {
        return int.TryParse(UpdateCheckIntervalHoursBox.Text.Trim(), out var hours)
            ? Math.Clamp(hours, SpecusClientConfig.MinUpdateCheckIntervalHours,
                SpecusClientConfig.MaxUpdateCheckIntervalHours)
            : SpecusClientConfig.DefaultUpdateCheckIntervalHours;
    }

    private static string SettingsPath()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Specus",
            "desktop-client.json");
    }

    private void SystemEvents_UserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (!string.Equals(_themeMode, ThemeModeSystem, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }
        if (e.Category is UserPreferenceCategory.Color
            or UserPreferenceCategory.General
            or UserPreferenceCategory.VisualStyle)
        {
            Dispatcher.BeginInvoke(new Action(ApplyConfiguredTheme));
        }
    }

    private void ApplyConfiguredTheme()
    {
        var useDark = string.Equals(_themeMode, ThemeModeDark, StringComparison.OrdinalIgnoreCase)
            || (string.Equals(_themeMode, ThemeModeSystem, StringComparison.OrdinalIgnoreCase) && !SystemUsesLightTheme());
        _effectiveDarkTheme = useDark;
        ApplyPalette(useDark ? DarkPalette() : LightPalette());
        ApplyTitleBar(useDark);
        UpdateThemeModeButton();
        UpdatePeerMeshStatusBrush();
    }

    private static bool SystemUsesLightTheme()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return false;
        }
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            var value = key?.GetValue("AppsUseLightTheme");
            return value switch
            {
                int intValue => intValue > 0,
                long longValue => longValue > 0,
                _ => false,
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private void ApplyPalette(IReadOnlyDictionary<string, Color> palette)
    {
        foreach (var (key, color) in palette)
        {
            SetBrush(key, color);
        }

        SetBrush("PanelBrush", palette["SurfaceBrush"]);
        SetBrush("BorderBrush", palette["PanelStrokeBrush"]);
        SetBrush("AccentBrush", palette["PrimaryBrush"]);
        SetBrush("AccentSoftBrush", palette["PrimarySoftBrush"]);
        SetBrush("MutedBrush", palette["TextMutedBrush"]);
    }

    private void SetBrush(string key, Color color)
    {
        Application.Current.Resources[key] = new SolidColorBrush(color);
    }

    private static IReadOnlyDictionary<string, Color> DarkPalette() => new Dictionary<string, Color>
    {
        ["AppBackgroundBrush"] = Rgb(0x07, 0x10, 0x18),
        ["SidebarBrush"] = Rgb(0x09, 0x14, 0x1E),
        ["SurfaceBrush"] = Rgb(0x0D, 0x18, 0x24),
        ["SurfaceAltBrush"] = Rgb(0x10, 0x1D, 0x2B),
        ["SurfaceRaisedBrush"] = Rgb(0x13, 0x23, 0x33),
        ["ControlBrush"] = Rgb(0x12, 0x1F, 0x2D),
        ["ControlHoverBrush"] = Rgb(0x17, 0x28, 0x3A),
        ["PanelStrokeBrush"] = Rgb(0x22, 0x34, 0x47),
        ["PanelStrokeStrongBrush"] = Rgb(0x2E, 0x4B, 0x62),
        ["DividerBrush"] = Rgb(0x18, 0x26, 0x35),
        ["PrimaryBrush"] = Rgb(0x22, 0xD3, 0xEE),
        ["PrimaryHoverBrush"] = Rgb(0x67, 0xE8, 0xF9),
        ["PrimarySoftBrush"] = Rgb(0x12, 0x3B, 0x49),
        ["SecondaryBrush"] = Rgb(0x1A, 0x2A, 0x3A),
        ["SecondaryHoverBrush"] = Rgb(0x24, 0x38, 0x4B),
        ["SuccessBrush"] = Rgb(0x34, 0xD3, 0x99),
        ["WarningBrush"] = Rgb(0xFB, 0xBF, 0x24),
        ["DangerBrush"] = Rgb(0xFB, 0x71, 0x85),
        ["TextPrimaryBrush"] = Rgb(0xF4, 0xFA, 0xFF),
        ["TextSecondaryBrush"] = Rgb(0xB8, 0xC6, 0xD8),
        ["TextMutedBrush"] = Rgb(0x7E, 0x8E, 0xA3),
        ["LogBackgroundBrush"] = Rgb(0x05, 0x0A, 0x10),
        ["LogTextBrush"] = Rgb(0xB9, 0xF6, 0xFF),
        ["TableHeaderBrush"] = Rgb(0x14, 0x22, 0x33),
        ["TableLineBrush"] = Rgb(0x1B, 0x2B, 0x3E),
        ["InfoStripBorderBrush"] = Rgb(0x23, 0x65, 0x79),
        ["ControlFocusBrush"] = Rgb(0x0F, 0x25, 0x30),
        ["ComboSelectedBrush"] = Rgb(0x16, 0x34, 0x45),
        ["TableRowHoverBrush"] = Rgb(0x17, 0x25, 0x36),
        ["ScrollThumbBrush"] = Rgb(0x35, 0x50, 0x6B),
        ["ScrollThumbHoverBrush"] = Rgb(0x4B, 0x6C, 0x8F),
        ["PrimaryButtonTextBrush"] = Rgb(0x04, 0x21, 0x2A),
    };

    private static IReadOnlyDictionary<string, Color> LightPalette() => new Dictionary<string, Color>
    {
        ["AppBackgroundBrush"] = Rgb(0xF4, 0xF8, 0xFB),
        ["SidebarBrush"] = Rgb(0xFF, 0xFF, 0xFF),
        ["SurfaceBrush"] = Rgb(0xFF, 0xFF, 0xFF),
        ["SurfaceAltBrush"] = Rgb(0xEC, 0xF4, 0xFA),
        ["SurfaceRaisedBrush"] = Rgb(0xFF, 0xFF, 0xFF),
        ["ControlBrush"] = Rgb(0xF1, 0xF6, 0xFA),
        ["ControlHoverBrush"] = Rgb(0xE6, 0xF0, 0xF7),
        ["PanelStrokeBrush"] = Rgb(0xC9, 0xD8, 0xE5),
        ["PanelStrokeStrongBrush"] = Rgb(0x82, 0xA8, 0xBE),
        ["DividerBrush"] = Rgb(0xD9, 0xE4, 0xEE),
        ["PrimaryBrush"] = Rgb(0x08, 0x91, 0xB2),
        ["PrimaryHoverBrush"] = Rgb(0x0E, 0x74, 0x90),
        ["PrimarySoftBrush"] = Rgb(0xDE, 0xF7, 0xFB),
        ["SecondaryBrush"] = Rgb(0xE9, 0xF1, 0xF7),
        ["SecondaryHoverBrush"] = Rgb(0xD9, 0xE8, 0xF2),
        ["SuccessBrush"] = Rgb(0x05, 0x96, 0x69),
        ["WarningBrush"] = Rgb(0xB7, 0x79, 0x1F),
        ["DangerBrush"] = Rgb(0xE1, 0x1D, 0x48),
        ["TextPrimaryBrush"] = Rgb(0x10, 0x20, 0x2F),
        ["TextSecondaryBrush"] = Rgb(0x35, 0x51, 0x68),
        ["TextMutedBrush"] = Rgb(0x6B, 0x7E, 0x8F),
        ["LogBackgroundBrush"] = Rgb(0xF7, 0xFB, 0xFE),
        ["LogTextBrush"] = Rgb(0x16, 0x42, 0x59),
        ["TableHeaderBrush"] = Rgb(0xE7, 0xF0, 0xF8),
        ["TableLineBrush"] = Rgb(0xCF, 0xDF, 0xEC),
        ["InfoStripBorderBrush"] = Rgb(0x8D, 0xD6, 0xE7),
        ["ControlFocusBrush"] = Rgb(0xE2, 0xF6, 0xFB),
        ["ComboSelectedBrush"] = Rgb(0xD7, 0xF0, 0xF7),
        ["TableRowHoverBrush"] = Rgb(0xEA, 0xF5, 0xFB),
        ["ScrollThumbBrush"] = Rgb(0x9A, 0xB0, 0xC4),
        ["ScrollThumbHoverBrush"] = Rgb(0x70, 0x8A, 0xA3),
        ["PrimaryButtonTextBrush"] = Rgb(0xFF, 0xFF, 0xFF),
    };

    private static Color Rgb(byte red, byte green, byte blue) => Color.FromRgb(red, green, blue);

    private void UpdateThemeModeButton()
    {
        var normalized = NormalizeThemeMode(_themeMode);
        var (icon, label) = normalized switch
        {
            ThemeModeLight => (ThemeModeLightIcon, "浅色"),
            ThemeModeDark => (ThemeModeDarkIcon, "深色"),
            _ => (ThemeModeSystemIcon, "跟随系统"),
        };
        ThemeModeIcon.Data = Geometry.Parse(icon);
        ThemeModeButton.ToolTip = $"主题：{label}（点击切换）";
    }

    private static string NextThemeMode(string themeMode)
    {
        return NormalizeThemeMode(themeMode) switch
        {
            ThemeModeSystem => ThemeModeLight,
            ThemeModeLight => ThemeModeDark,
            _ => ThemeModeSystem,
        };
    }

    private static string NormalizeThemeMode(string? themeMode)
    {
        return themeMode?.Trim().ToLowerInvariant() switch
        {
            ThemeModeLight => ThemeModeLight,
            ThemeModeDark => ThemeModeDark,
            _ => ThemeModeSystem,
        };
    }

    private void ApplyStatus(SpecusClientStatusSnapshot snapshot)
    {
        UpdateStatusText(StatusTitle(snapshot), snapshot.Detail);
        SetSidebarStatusDot(snapshot.LoggedIn ? "SuccessBrush" : "WarningBrush");
        RuntimeSummaryText.Text = snapshot.ClientName is null
            ? "连接后显示客户端、控制端和 Peer Mesh 信息"
            : $"{snapshot.ClientName} · {snapshot.SpecusEndpoint} · Peer Mesh {(snapshot.PeerMeshEnabled ? "启用" : "关闭")} · {snapshot.VirtualIp ?? "-"}";
        _clientLoggedIn = snapshot.LoggedIn;
        UpdateMessageSendState();
    }

    private void ApplyRoutes(SpecusClientRoutesSnapshot snapshot)
    {
        Replace(TcpRoutes, snapshot.TcpRoutes);
        Replace(HttpRoutes, snapshot.HttpRoutes);
        TcpCountText.Text = snapshot.TcpRoutes.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        HttpCountText.Text = snapshot.HttpRoutes.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private void ApplyPeerMesh(SpecusPeerMeshSnapshot snapshot)
    {
        Replace(PeerRoutes, snapshot.Peers);
        Replace(MessagePeerRoutes, snapshot.Peers
            .Where(peer => peer.Online && peer.MessageReceiveCapable)
            .OrderBy(peer => peer.ClientName, StringComparer.OrdinalIgnoreCase));
        Replace(PeerSessions, snapshot.Sessions);
        PeerCountText.Text = snapshot.Peers.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        _peerMeshEnabled = snapshot.Enabled;
        PeerMeshSummaryText.Text = snapshot.Enabled
            ? $"本机 {snapshot.VirtualIp ?? "-"} · {snapshot.Cidr ?? "-"} · {snapshot.DeviceName} / {snapshot.DeviceStatus} · 会话 {snapshot.Sessions.Count}"
            : $"Peer Mesh 未启动 · {snapshot.DeviceName} / {snapshot.DeviceStatus}";
        UpdatePeerMeshStatusBrush();
        UpdateMessageSendState();
    }

    private void ApplyClientMessage(ClientMessageSnapshot snapshot)
    {
        ClientMessages.Add(ClientMessageLine.FromSnapshot(snapshot));
        while (ClientMessages.Count > 300)
        {
            ClientMessages.RemoveAt(0);
        }
    }

    private string ResolveMessageTarget()
    {
        var text = MessageTargetBox.Text.Trim();
        if (!string.IsNullOrWhiteSpace(text))
        {
            return text;
        }
        if (MessageTargetBox.SelectedItem is PeerRouteSnapshot selectedPeer
            && !string.IsNullOrWhiteSpace(selectedPeer.ClientName))
        {
            return selectedPeer.ClientName.Trim();
        }
        return "";
    }

    private void UpdateMessageSendState()
    {
        var canSend = _running && !_stopping && _clientLoggedIn;
        SendMessageButton.IsEnabled = canSend;
        SendFileButton.IsEnabled = canSend;
    }

    private bool IsKnownMessageTarget(string target)
    {
        if (target.StartsWith("admin:", StringComparison.OrdinalIgnoreCase)
            && target.Length > "admin:".Length)
        {
            return true;
        }
        return MessagePeerRoutes.Any(peer =>
            string.Equals(peer.ClientName?.Trim(), target, StringComparison.Ordinal));
    }

    private void UpdatePeerMeshStatusBrush()
    {
        PeerMeshStatusDot.Background = (Brush)FindResource(_peerMeshEnabled ? "SuccessBrush" : "TextMutedBrush");
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
        MessagePeerRoutes.Clear();
        PeerSessions.Clear();
        ClientMessages.Clear();
        TcpCountText.Text = "0";
        HttpCountText.Text = "0";
        PeerCountText.Text = "0";
        _peerMeshEnabled = false;
        _clientLoggedIn = false;
        PeerMeshSummaryText.Text = "Peer Mesh 未启动";
        UpdatePeerMeshStatusBrush();
        UpdateMessageSendState();
    }

    private void UpdateStoppedUi(string phase, string detail)
    {
        ConnectButton.Content = "连接";
        ConnectButton.IsEnabled = true;
        SetInputsEnabled(true);
        UpdateStatusText(phase, detail);
        SetSidebarStatusDot("TextMutedBrush");
        RuntimeSummaryText.Text = "连接后显示客户端、控制端和 Peer Mesh 信息";
        _peerMeshEnabled = false;
        _clientLoggedIn = false;
        PeerMeshSummaryText.Text = "Peer Mesh 未启动";
        UpdatePeerMeshStatusBrush();
        UpdateMessageSendState();
    }

    private void UpdateStatusText(string phase, string detail)
    {
        StatusPhaseText.Text = phase;
        StatusDetailText.Text = detail;
    }

    private void SetSidebarStatusDot(string brushKey)
    {
        SidebarStatusDot.Background = (Brush)FindResource(brushKey);
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
        UpdateMessageSendState();
    }

    private void AppendLog(LogLevel level, string category, string message, Exception? exception)
    {
        var followTail = LogScrollViewer.ScrollableHeight <= 0
            || LogScrollViewer.VerticalOffset >= LogScrollViewer.ScrollableHeight - 2;
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
        LogTextBox.CaretIndex = LogTextBox.Text.Length;
        LogScrollViewer.UpdateLayout();
        if (followTail)
        {
            LogScrollViewer.ScrollToEnd();
        }
    }

    private static string StatusTitle(SpecusClientStatusSnapshot snapshot)
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

    private void ApplyTitleBar(bool dark)
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

        var enabled = dark ? 1 : 0;
        if (DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref enabled, sizeof(int)) != 0)
        {
            _ = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeBefore20H1, ref enabled, sizeof(int));
        }

        var captionColor = dark
            ? ColorRef(0x07, 0x10, 0x18)
            : ColorRef(0xF4, 0xF8, 0xFB);
        var textColor = dark
            ? ColorRef(0xF4, 0xFA, 0xFF)
            : ColorRef(0x10, 0x20, 0x2F);
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

    private sealed class UiSpecusObserver : ISpecusClientObserver
    {
        private readonly MainWindow _window;

        public UiSpecusObserver(MainWindow window)
        {
            _window = window;
        }

        public void OnStatusChanged(SpecusClientStatusSnapshot snapshot)
        {
            _window.Dispatcher.BeginInvoke(new Action(() => _window.ApplyStatus(snapshot)));
        }

        public void OnRoutesChanged(SpecusClientRoutesSnapshot snapshot)
        {
            _window.Dispatcher.BeginInvoke(new Action(() => _window.ApplyRoutes(snapshot)));
        }

        public void OnPeerMeshChanged(SpecusPeerMeshSnapshot snapshot)
        {
            _window.Dispatcher.BeginInvoke(new Action(() => _window.ApplyPeerMesh(snapshot)));
        }

        public void OnClientMessage(ClientMessageSnapshot snapshot)
        {
            _window.Dispatcher.BeginInvoke(new Action(() => _window.ApplyClientMessage(snapshot)));
        }

        public bool OnRawClientMessage(string fromClientName, string body)
        {
            return _window.HandleRawClientMessage(fromClientName, body);
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

}

public sealed record LogLine(string Text);

public sealed class ClientMessageLine
{
    public string CreatedAtText { get; init; } = "";

    public string DirectionText { get; init; } = "";

    public string Peer { get; init; } = "";

    public string TransportText { get; init; } = "";

    public string StatusText { get; init; } = "";

    public string Message { get; init; } = "";

    public static ClientMessageLine FromSnapshot(ClientMessageSnapshot snapshot)
    {
        var outbound = string.Equals(snapshot.Direction, "OUT", StringComparison.OrdinalIgnoreCase);
        return new ClientMessageLine
        {
            CreatedAtText = snapshot.CreatedAt.LocalDateTime.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture),
            DirectionText = outbound ? "发送" : "接收",
            Peer = outbound ? snapshot.ToClientName : snapshot.FromClientName,
            TransportText = MapTransportText(snapshot.Transport),
            StatusText = MapStatusText(snapshot.Status),
            Message = snapshot.Message,
        };
    }

    private static string MapTransportText(string transport)
    {
        return transport switch
        {
            "peer-direct" => "Peer 直连",
            "peer-relay" => "Peer 中继",
            "server" => "服务端",
            _ => transport,
        };
    }

    private static string MapStatusText(string status)
    {
        return status switch
        {
            "sent" => "已发送",
            "submitted" => "已提交",
            "received" => "已接收",
            _ => status,
        };
    }
}
