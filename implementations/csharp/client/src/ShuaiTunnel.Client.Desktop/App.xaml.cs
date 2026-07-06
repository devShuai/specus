using System.Globalization;
using System.Windows;

namespace ShuaiTunnel.Client.Desktop;

public partial class App : Application
{
    public App()
    {
        // WPF framework assemblies do not ship zh-CN satellite resources here; using
        // invariant UI culture avoids noisy PresentationFramework*.resources probes.
        CultureInfo.DefaultThreadCurrentUICulture = CultureInfo.InvariantCulture;
        CultureInfo.CurrentUICulture = CultureInfo.InvariantCulture;
    }
}
