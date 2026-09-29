using Specus.Client.Configuration;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Desktop;

internal sealed class DesktopClientSettings
{
    public string ServerBaseUrl { get; set; } = "";
    public string ApiKey { get; set; } = "";
    public string Secret { get; set; } = "";
    public string PeerMeshDevice { get; set; } = "";
    public string ThemeMode { get; set; } = "system";
    public string PeerMeshTunName { get; set; } = "";
    public int PeerMeshMtu { get; set; }
    public bool UpdateCheckEnabled { get; set; } = true;
    public int UpdateCheckIntervalHours { get; set; } =
        SpecusClientConfig.DefaultUpdateCheckIntervalHours;
    public bool AutoUpdate { get; set; }

    /// <summary>The consumer's takeover switch; rules are only saved while it is off.</summary>
    public bool PeerEgressEnabled { get; set; }

    /// <summary>The split-routing rules, in the order they are matched.</summary>
    public List<PeerEgressRule> PeerEgressRules { get; set; } = [];

    public DesktopClientSettings Normalize()
    {
        PeerEgressRules ??= [];
        UpdateCheckIntervalHours = UpdateCheckIntervalHours <= 0
            ? SpecusClientConfig.DefaultUpdateCheckIntervalHours
            : Math.Clamp(UpdateCheckIntervalHours, SpecusClientConfig.MinUpdateCheckIntervalHours,
                SpecusClientConfig.MaxUpdateCheckIntervalHours);
        return this;
    }

    public static DesktopClientSettings Default() => new()
    {
        ServerBaseUrl = "https://specus.devshuai.com",
        PeerMeshDevice = "auto",
        ThemeMode = "system",
        PeerMeshTunName = SpecusClientConfig.DefaultPeerMeshTunName,
        PeerMeshMtu = SpecusClientConfig.DefaultPeerMeshMtu,
    };
}
