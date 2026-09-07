using System.IO;
using System.Windows;
using System.Windows.Controls;
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
                    File.WriteAllText(settings, "{\"themeMode\":\"" + theme + "\",\"updateCheckEnabled\":false}");
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
                    if (screenshots)
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
                            using var file = File.Create(Path.Combine(output, $"windows-{theme}-{size.Width}-{scale:F1}.png"));
                            encoder.Save(file);
                        }
                    }
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
}
