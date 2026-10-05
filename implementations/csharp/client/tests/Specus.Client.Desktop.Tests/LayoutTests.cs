using System.IO;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Specus.Client.Desktop;
using Xunit;

namespace Specus.Client.Desktop.Tests;

public class LayoutTests
{
    [Fact]
    public void RealWindowLayoutWithoutUserSettingsOrNetwork()
    {
        bool screenshots = Environment.GetEnvironmentVariable("SPECUS_GUI_TEST_SCREENSHOTS") == "1";
        if (screenshots)
        {
            AppContext.SetSwitch("Switch.System.Windows.Media.ShouldRenderEvenWhenNoDisplayDevicesAreAvailable", true);
            AppContext.SetSwitch("Switch.System.Windows.Media.ShouldNotRenderInNonInteractiveWindowStation", false);
        }
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var source = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "DesktopApp.xaml"));
                var content = source.Split("<Application.Resources>")[1].Split("</Application.Resources>")[0];
                var app = new Application();
                app.Resources = (ResourceDictionary)System.Windows.Markup.XamlReader.Parse(
                    "<ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" "
                    + "xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" "
                    + "xmlns:desktop=\"clr-namespace:Specus.Client.Desktop;assembly=specus-desktop\">"
                    + content + "</ResourceDictionary>");
                app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
                var output = Environment.GetEnvironmentVariable("SPECUS_GUI_TEST_OUTPUT")
                    ?? Path.Combine(Path.GetTempPath(), "specus-gui-tests-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(output);
                foreach (var theme in new[] { "light", "dark" })
                foreach (var size in new[] { new Size(800, 520), new Size(1200, 760) })
                {
                    var settings = Path.Combine(output, $"fixture-{theme}.json");
                    // Three rules the egress page has to tell apart: one waiting for takeover, one it
                    // refuses (a domain), one switched off.
                    File.WriteAllText(settings, "{\"themeMode\":\"" + theme + "\",\"updateCheckEnabled\":false,"
                        + "\"peerEgressRules\":[{\"match\":\"203.0.113.0/24\",\"action\":\"egress\",\"egressClientId\":42},"
                        + "{\"match\":\"example.com\",\"action\":\"direct\"},"
                        + "{\"match\":\"198.51.100.0/24\",\"action\":\"block\",\"enabled\":false}]}");
                    var window = new MainWindow(settings, false);
                    if (screenshots)
                    {
                        window.ShowInTaskbar = false;
                        window.WindowStartupLocation = WindowStartupLocation.Manual;
                        window.Left = -16000; window.Top = -16000;
                        window.Width = size.Width; window.Height = size.Height;
                        window.Show();
                    }
                    var root = (FrameworkElement)window.Content;
                    root.Measure(size);
                    root.Arrange(new Rect(size));
                    root.UpdateLayout();
                    Assert.Equal("未连接", ((TextBlock)window.FindName("StatusPhaseText")).Text);
                    var button = (Button)window.FindName("ConnectButton");
                    Assert.True(button.IsEnabled);
                    Assert.True(button.ActualHeight >= 32);
                    var buttonPosition = button.TransformToAncestor(root).Transform(new Point());
                    Assert.InRange(buttonPosition.Y + button.ActualHeight, 0, size.Height);
                    Assert.True(((Expander)window.FindName("ConnectionSettingsExpander")).IsExpanded);
                    Assert.True(root.ActualWidth <= size.Width);
                    Assert.True(root.ActualHeight <= size.Height);
                    if (screenshots) Capture(root, size, Path.Combine(output, $"windows-{theme}-{size.Width}"));

                    ((TabItem)window.FindName("EgressTab")).IsSelected = true;
                    root.Measure(size);
                    root.Arrange(new Rect(size));
                    root.UpdateLayout();
                    // The grid sizes its star columns on a later pass, once it knows its width.
                    root.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Background);
                    root.UpdateLayout();
                    Assert.Equal(3, window.EgressRules.Count);
                    Assert.Equal("已启用，开启系统接管后生效", window.EgressRules[0].State);
                    Assert.StartsWith("不会生效", window.EgressRules[1].State);
                    Assert.Equal("EGRESS_RULE_DOMAIN_UNSUPPORTED", window.EgressRules[1].Code);
                    Assert.Equal("已停用", window.EgressRules[2].State);
                    Assert.Equal("启用", window.EgressRules[2].ToggleLabel);
                    Assert.False(window.EgressRules[0].CanMoveUp);
                    Assert.False(window.EgressRules[2].CanMoveDown);
                    var takeover = (Button)window.FindName("EgressTakeoverButton");
                    Assert.Equal("开启接管", takeover.Content);
                    Assert.True(takeover.ActualHeight > 0, "the egress page did not lay out");
                    var takeoverPosition = takeover.TransformToAncestor(root).Transform(new Point());
                    Assert.InRange(takeoverPosition.X + takeover.ActualWidth, 0, size.Width);
                    // The add and test buttons stay inside the window at the narrowest size.
                    foreach (var name in new[] { "EgressAddButton", "EgressConnectButton", "EgressPreviewButton" })
                    {
                        var control = (Button)window.FindName(name);
                        var position = control.TransformToAncestor(root).Transform(new Point());
                        Assert.True(position.X + control.ActualWidth <= size.Width - 16, name + " runs past the window edge");
                    }
                    var grid = (DataGrid)window.FindName("EgressRuleGrid");
                    Assert.True(grid.Columns[1].ActualWidth >= 80, "the target column is squeezed: " + grid.Columns[1].ActualWidth);
                    if (screenshots)
                    {
                        Capture(root, size, Path.Combine(output, $"windows-egress-{theme}-{size.Width}"));
                        var scroller = (ScrollViewer)((TabItem)window.FindName("EgressTab")).Content;
                        scroller.ScrollToEnd();
                        root.UpdateLayout();
                        Capture(root, size, Path.Combine(output, $"windows-egress-end-{theme}-{size.Width}"));
                    }

                    // What a running client reports, rendered the way the local page renders it: each
                    // problem listed, a relayed egress noted without counting as one.
                    window.RenderEgressStatus((JsonObject)JsonNode.Parse("""
                        {"consumer":{"enabled":true,"active":true,"flows":3,
                          "rules":[{"index":0,"match":"203.0.113.0/24","action":"egress","inForce":true,"egressClientId":42},
                                   {"index":1,"match":"10.0.0.0/33","action":"direct","inForce":false,"code":"EGRESS_RULE_MALFORMED"}],
                          "routes":[{"cidr":"203.0.113.0/24","kind":"tun","origin":"rule:203.0.113.0/24","installed":false,"conflict":"203.0.113.0/24 via 192.168.1.1"}],
                          "peers":[{"clientId":42,"online":false,"path":"none","flows":0},{"clientId":43,"online":true,"path":"relay","flows":3}],
                          "blocked":{"egress-unavailable":5,"rule":0}},
                         "egress":{"active":true,"flows":2,"totalFlows":9,"refused":{"EGRESS_DEST_DENIED":1}}}
                        """)!);
                    Assert.Equal("3 个问题", ((TextBlock)window.FindName("EgressProblemsText")).Text);
                    Assert.Equal(["规则 #1「10.0.0.0/33」未生效", "路由 203.0.113.0/24 未安装", "出口设备 42 离线", "出口设备 43 经中继连接", "拦截计数"],
                        window.EgressIssues.Select(issue => issue.Title).ToArray());
                    Assert.Equal("egress-unavailable=5", window.EgressIssues[^1].Code);
                    Assert.StartsWith("本机正在作为出口 · 2 个流 · 累计 9 个 · 拒绝：EGRESS_DEST_DENIED=1", ((TextBlock)window.FindName("EgressRoleText")).Text);
                    root.UpdateLayout();
                    if (screenshots) Capture(root, size, Path.Combine(output, $"windows-egress-status-{theme}-{size.Width}"));

                    // The rule tester previews a name through the same judgment as egress test: the
                    // rule that would claim it is named, and since this page has no DNS takeover the
                    // name is left to the system's DNS. A name no domain rule could match is refused,
                    // and a name is never connected to.
                    var testAddress = (TextBox)window.FindName("EgressTestAddressBox");
                    var testResult = (TextBlock)window.FindName("EgressTestResultText");
                    void Click(string name) => ((Button)window.FindName(name)).RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
                    testAddress.Text = "Example.COM.";
                    Click("EgressPreviewButton");
                    Assert.Equal("example.com：命中域名规则 #1；DNS 未接管（DNS 接管未开启），名字由系统 DNS 解析；"
                        + "由系统 DNS 解析，之后的去向请用预演查看解析出的地址。仅按已保存的规则判断，未查询 DNS，也未建立连接。", testResult.Text);
                    testAddress.Text = "www.example.com";
                    Click("EgressPreviewButton");
                    Assert.StartsWith("www.example.com：未命中任何域名规则；DNS 未接管", testResult.Text);
                    foreach (var unusable in new[] { "bad_name.example", "*.example.com" })
                    {
                        testAddress.Text = unusable;
                        Click("EgressPreviewButton");
                        Assert.StartsWith("这个名字不是域名规则能匹配的写法", testResult.Text);
                    }
                    testAddress.Text = "example.com";
                    Click("EgressConnectButton");
                    Assert.StartsWith("连通测试只接受 IPv4 地址", testResult.Text);
                    testAddress.Text = "203.0.113.9";
                    Click("EgressPreviewButton");
                    Assert.StartsWith("203.0.113.9：命中规则 #0，系统接管未开启", testResult.Text);

                    // An edit goes through the plan the commands use: a domain is refused with its
                    // reason, an address range is added and saved.
                    Assert.False(window.AddEgressRule("example.org", "direct", 0, first: false, disabled: false));
                    Assert.Equal(3, window.EgressRules.Count);
                    Assert.Contains("EGRESS_RULE_DOMAIN_UNSUPPORTED", ((TextBlock)window.FindName("EgressNoticeText")).Text);
                    Assert.True(window.AddEgressRule("10.0.0.0/8", "direct", 0, first: true, disabled: false));
                    Assert.Equal("10.0.0.0/8", window.EgressRules[0].Match);
                    Assert.Contains("\"match\": \"10.0.0.0/8\"", File.ReadAllText(settings));
                    window.Close();
                }
                app.Shutdown();
            }
            catch (Exception error) { failure = error; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.IsBackground = true;
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "WPF layout timed out");
        Assert.Null(failure);
    }

    private static void Capture(FrameworkElement root, Size size, string prefix)
    {
        root.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Render);
        foreach (double scale in new[] { 1.0, 1.5, 2.0 })
        {
            var bitmap = new RenderTargetBitmap((int)(size.Width * scale), (int)(size.Height * scale), 96 * scale, 96 * scale, PixelFormats.Pbgra32);
            var drawing = new DrawingVisual();
            using (var context = drawing.RenderOpen()) context.DrawRectangle(new VisualBrush(root), null, new Rect(size));
            bitmap.Render(drawing);
            byte[] pixels = new byte[bitmap.PixelWidth * bitmap.PixelHeight * 4];
            bitmap.CopyPixels(pixels, bitmap.PixelWidth * 4, 0);
            Assert.True(pixels.Any(value => value != 0), "Blank screenshot is not a successful visual check");
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using var file = File.Create($"{prefix}-{scale:F1}.png");
            encoder.Save(file);
        }
    }
}
