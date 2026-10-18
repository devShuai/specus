using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.ControlChannel;
using Specus.Server.Networking;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

// Lower-level ingress fixtures inject a framed writer, not an authenticated TCP transport.
// Model both physical roles explicitly; do not relax production pairing for synthetic callers.
internal static class SyntheticDataBinding
{
    public static void Bind(SessionRegistry registry, SpecusConnectionContext data)
    {
        Assert.Equal(ConnectionRole.Data, data.ConnectionRole);
        var control = new SpecusConnectionContext(data.ChannelId + "-control", data.RemoteAddress,
            new DiscardingWriter(), data.Lifetime, data.CloseAsync, new ReadGate(data.Lifetime),
            new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        control.OnLoginSuccess(data.ClientName!, data.LoginTimeMs!.Value, data.ClientSessionId,
            ConnectionRole.Control, data.TenantId, data.ClientId);
        registry.Replace(data.ClientName!, control);
        data.PairedControl = control;
        registry.ReplaceData(data.ClientName!, data);
    }

    public static void Unbind(SessionRegistry registry, SpecusConnectionContext data)
    {
        registry.Unbind(data.ClientName!, data);
        if (data.PairedControl is { } control) registry.Unbind(data.ClientName!, control);
    }

    private sealed class DiscardingWriter : IFrameWriter
    {
        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;
    }
}
