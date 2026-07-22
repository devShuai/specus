using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.WebSockets;

namespace ShuaiTunnel.IntegrationTests;

public sealed class PublicTransferCoordinationRedisTests
{
    [Fact]
    public async Task TwoInstancesSharePresenceEventsNamesAndRateLimits()
    {
        var redisUri = Environment.GetEnvironmentVariable("TUNNEL_TEST_REDIS_URI");
        if (string.IsNullOrWhiteSpace(redisUri))
        {
            return;
        }
        var options = Options.Create(new PublicTransferOptions
        {
            ClusterEnabled = true,
            RedisUri = redisUri,
            RedisKeyPrefix = "shuai-tunnel:test:" + Guid.NewGuid().ToString("N"),
            PresenceLeaseSeconds = 30,
            PresenceRefreshIntervalMs = 10_000,
            RedisCommandTimeoutMs = 2_000,
        });
        var first = new PublicTransferCoordinationService(options,
            NullLogger<PublicTransferCoordinationService>.Instance);
        var second = new PublicTransferCoordinationService(options,
            NullLogger<PublicTransferCoordinationService>.Instance);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await first.StartAsync(cancellation.Token);
        await second.StartAsync(cancellation.Token);
        try
        {
            var alpha = Participant("lease-a", "peer-a", "Device Alpha", "room", "key",
                "2026-07-22T00:00:00Z");
            var beta = Participant("lease-b", "peer-b", "Device Beta", "room", "key",
                "2026-07-22T00:00:01Z");
            Assert.True((await first.RegisterAsync(alpha, 2, cancellation.Token)).Accepted);
            Assert.True((await second.RegisterAsync(beta, 2, cancellation.Token)).Accepted);

            var roster = await first.RosterAsync(alpha.GroupId, cancellation.Token);
            Assert.True(roster.Revision >= 2);
            Assert.Equal(["peer-a", "peer-b"], roster.Participants.Select(peer => peer.PeerId));

            var duplicateName = await second.RegisterAsync(Participant("lease-c", "peer-c",
                "device alpha", "other", "key", "2026-07-22T00:00:02Z"), 2,
                cancellation.Token);
            Assert.Equal("client name is already in use", duplicateName.Error);
            var full = await second.RegisterAsync(Participant("lease-d", "peer-d", "Device Delta",
                "room", "key", "2026-07-22T00:00:03Z"), 2, cancellation.Token);
            Assert.Equal("room is full", full.Error);

            Assert.True(await first.AllowRateAsync("integration", "same-source", 1, 60,
                cancellation.Token));
            Assert.False(await second.AllowRateAsync("integration", "same-source", 1, 60,
                cancellation.Token));

            var delivered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            second.AddListener(clusterEvent =>
            {
                if (clusterEvent.Kind == PublicTransferClusterFrame.KindText
                    && clusterEvent.GroupId == alpha.GroupId
                    && System.Text.Encoding.UTF8.GetString(clusterEvent.Payload) == "cross-instance")
                {
                    delivered.TrySetResult();
                }
                return Task.CompletedTask;
            });
            await first.PublishTextAsync(alpha.GroupId, "peer-b", alpha.LeaseId, false,
                "cross-instance"u8.ToArray(), cancellation.Token);
            await delivered.Task.WaitAsync(cancellation.Token);

            var managementDelivered = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var managementPayload = "{\"tenantId\":\"default\",\"type\":\"created\"}"u8.ToArray();
            second.AddListener(clusterEvent =>
            {
                if (clusterEvent.Kind == PublicTransferClusterFrame.KindManagement
                    && clusterEvent.GroupId
                    == PublicTransferCoordinationService.ManagementGroupId("default")
                    && clusterEvent.Payload.SequenceEqual(managementPayload))
                {
                    managementDelivered.TrySetResult();
                }
                return Task.CompletedTask;
            });
            await first.PublishManagementAsync("default", managementPayload, cancellation.Token);
            await managementDelivered.Task.WaitAsync(cancellation.Token);

            Assert.True(await first.UnregisterAsync(alpha, cancellation.Token) > 0);
            Assert.True(await second.UnregisterAsync(beta, cancellation.Token) > 0);
        }
        finally
        {
            await second.StopAsync(CancellationToken.None);
            await first.StopAsync(CancellationToken.None);
            second.Dispose();
            first.Dispose();
        }
    }

    private static PublicTransferClusterParticipant Participant(string leaseId, string peerId,
        string displayName, string roomId, string roomKey, string connectedAt) => new(
        leaseId, peerId, displayName, roomId, "203.0.113.1", roomKey, "EDITOR", true, connectedAt);
}
