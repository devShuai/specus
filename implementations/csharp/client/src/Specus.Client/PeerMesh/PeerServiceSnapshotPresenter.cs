using Specus.Client.Runtime;

namespace Specus.Client.PeerMesh;

/// <summary>
/// Converts the authoritative service runtime into the immutable view model consumed by Desktop.
/// Keeping this mapping outside the WPF window makes service identity and disabled-state semantics
/// testable without starting a UI thread.
/// </summary>
internal static class PeerServiceSnapshotPresenter
{
    public static IReadOnlyList<PeerRemoteServiceSnapshot> Remote(PeerServiceRuntime runtime) =>
        runtime.RemoteServices()
            .Select(item => new PeerRemoteServiceSnapshot
            {
                PublisherClientId = item.PublisherClientId,
                PublisherClientName = item.PublisherClientName,
                PublisherSessionId = item.PublisherSessionId,
                ServiceId = item.Service.ServiceId,
                Name = item.Service.Name,
                Application = item.Service.Application,
                AccessTarget = item.AccessTarget,
                Openable = item.Openable,
                Copyable = item.Copyable,
                UnavailableReason = item.UnavailableReason,
            })
            .ToList();

    public static IReadOnlyList<PeerLocalServiceSnapshot> Local(PeerServiceRuntime runtime) =>
        runtime.LocalServices
            .Select(item =>
            {
                var locallyPublished = runtime.EffectiveSharing && item.Enabled
                    && runtime.IsLocallyPublished(item.ServiceId);
                var status = !item.Enabled ? "配置已关闭"
                    : !runtime.EffectiveSharing ? "已配置但未发布 · 全局共享关闭"
                    : locallyPublished ? "已启用本实例发布资格"
                    : "已配置但未发布 · 本实例已暂停";
                return new PeerLocalServiceSnapshot
                {
                    ServiceId = item.ServiceId,
                    Name = item.Name,
                    Application = item.Application,
                    Target = $"{item.TargetHost}:{item.TargetPort}",
                    PublishedPort = item.PublishedPort,
                    ConfigEnabled = item.Enabled,
                    CanToggle = runtime.EffectiveSharing && item.Enabled,
                    LocallyPublished = locallyPublished,
                    PublicationStatus = status,
                };
            })
            .ToList();
}
