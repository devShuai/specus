using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.WebSockets;

namespace Specus.IntegrationTests;

public sealed class PublicTransferCoordinationRedisTests
{
    [Fact]
    public async Task TwoInstancesSharePresenceEventsNamesAndRateLimits()
    {
        var redisUri = Environment.GetEnvironmentVariable("SPECUS_TEST_REDIS_URI");
        if (string.IsNullOrWhiteSpace(redisUri))
        {
            return;
        }
        var options = Options.Create(new PublicTransferOptions
        {
            ClusterEnabled = true,
            RedisUri = redisUri,
            RedisKeyPrefix = "specus:test:" + Guid.NewGuid().ToString("N"),
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

            var roster = await first.RosterAsync(alpha, cancellation.Token);
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
                    && clusterEvent.GroupId == beta.GroupId
                    && System.Text.Encoding.UTF8.GetString(clusterEvent.Payload) == "cross-instance")
                {
                    delivered.TrySetResult();
                }
                return Task.CompletedTask;
            });
            await first.PublishTextAsync(beta.GroupId, "peer-b", alpha.LeaseId, false,
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

    [Fact]
    public async Task MergedScopeRosterUnitesRoomAndNetAndFiltersForeignScopes()
    {
        var redisUri = Environment.GetEnvironmentVariable("SPECUS_TEST_REDIS_URI");
        if (string.IsNullOrWhiteSpace(redisUri))
        {
            return;
        }
        var options = Options.Create(new PublicTransferOptions
        {
            ClusterEnabled = true,
            RedisUri = redisUri,
            RedisKeyPrefix = "specus:test:" + Guid.NewGuid().ToString("N"),
            PresenceLeaseSeconds = 30,
            PresenceRefreshIntervalMs = 10_000,
            RedisCommandTimeoutMs = 2_000,
        });
        var service = new PublicTransferCoordinationService(options,
            NullLogger<PublicTransferCoordinationService>.Instance);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await service.StartAsync(cancellation.Token);
        try
        {
            const string lanAddress = "203.0.113.10";
            const string remoteAddress = "198.51.100.10";
            var lanFirst = Participant("lease-1", "peer-1", "Lan First", "net-room", "key-a",
                "2026-07-22T00:00:00Z", lanAddress);
            var lanSecond = Participant("lease-2", "peer-2", "Lan Second", "net-room", "key-b",
                "2026-07-22T00:00:01Z", lanAddress);
            // Same token room as lanFirst but on another network: merged scope keeps it
            // visible to its room members, but not to the cross-room LAN peer.
            var remote = Participant("lease-3", "peer-3", "Remote", "net-room", "key-a",
                "2026-07-22T00:00:02Z", remoteAddress);
            Assert.True((await service.RegisterAsync(lanFirst, 8, cancellation.Token)).Accepted);
            Assert.True((await service.RegisterAsync(lanSecond, 8, cancellation.Token)).Accepted);
            Assert.True((await service.RegisterAsync(remote, 8, cancellation.Token)).Accepted);
            Assert.NotEqual(lanFirst.NetId, remote.NetId);
            Assert.NotEqual(lanFirst.GroupId, lanSecond.GroupId);

            // lanFirst sees its room across nets plus its net across rooms.
            var lanRoster = await service.RosterAsync(lanFirst, cancellation.Token);
            Assert.Equal(["peer-1", "peer-2", "peer-3"],
                lanRoster.Participants.Select(peer => peer.PeerId));
            // lanSecond (cross-room) sees the LAN only; remote (cross-net) sees its room only.
            var secondRoster = await service.RosterAsync(lanSecond, cancellation.Token);
            Assert.Equal(["peer-1", "peer-2"], secondRoster.Participants.Select(peer => peer.PeerId));
            var remoteRoster = await service.RosterAsync(remote, cancellation.Token);
            Assert.Equal(["peer-1", "peer-3"], remoteRoster.Participants.Select(peer => peer.PeerId));

            // Directed routing resolves the target's own group for a single publish.
            var resolved = await service.FindPeerAsync(lanFirst, "peer-2", cancellation.Token);
            Assert.NotNull(resolved);
            Assert.Equal(lanSecond.GroupId, resolved.GroupId);
            var resolvedRemote = await service.FindPeerAsync(lanFirst, "peer-3", cancellation.Token);
            Assert.NotNull(resolvedRemote);
            Assert.Equal(remote.GroupId, resolvedRemote.GroupId);
            Assert.Null(await service.FindPeerAsync(lanSecond, "peer-3", cancellation.Token));

            // Duplicate peer IDs are rejected across the merged scope, not just one group.
            var duplicate = await service.RegisterAsync(Participant("lease-4", "peer-1",
                "Lan Duplicate", "net-room", "key-b", "2026-07-22T00:00:03Z", lanAddress), 8,
                cancellation.Token);
            Assert.Equal("peer id is already connected", duplicate.Error);

            var revisionAfterRegister = (await service.RosterAsync(lanFirst,
                cancellation.Token)).Revision;
            Assert.True(await service.UnregisterAsync(lanSecond, cancellation.Token) > 0);
            var afterLeave = await service.RosterAsync(lanFirst, cancellation.Token);
            Assert.Equal(["peer-1", "peer-3"], afterLeave.Participants.Select(peer => peer.PeerId));
            Assert.True(afterLeave.Revision > revisionAfterRegister);

            Assert.True(await service.UnregisterAsync(lanFirst, cancellation.Token) > 0);
            Assert.True(await service.UnregisterAsync(remote, cancellation.Token) > 0);
            var empty = await service.RosterAsync(lanSecond, cancellation.Token);
            Assert.Empty(empty.Participants);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            service.Dispose();
        }
    }

    [Fact]
    public async Task MergedScopeRosterMergesSameNetAcrossRoomIds()
    {
        var redisUri = Environment.GetEnvironmentVariable("SPECUS_TEST_REDIS_URI");
        if (string.IsNullOrWhiteSpace(redisUri))
        {
            return;
        }
        var options = Options.Create(new PublicTransferOptions
        {
            ClusterEnabled = true,
            RedisUri = redisUri,
            RedisKeyPrefix = "specus:test:" + Guid.NewGuid().ToString("N"),
            PresenceLeaseSeconds = 30,
            PresenceRefreshIntervalMs = 10_000,
            RedisCommandTimeoutMs = 2_000,
        });
        var service = new PublicTransferCoordinationService(options,
            NullLogger<PublicTransferCoordinationService>.Instance);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await service.StartAsync(cancellation.Token);
        try
        {
            const string lanAddress = "203.0.113.44";
            // Different room ids and different room keys, one LAN: the net is keyed by
            // public address only, so the room name no longer splits same-net devices.
            var alpha = Participant("lease-a", "peer-a", "Device Alpha", "room-original",
                "key-a", "2026-07-22T00:00:00Z", lanAddress);
            var beta = Participant("lease-b", "peer-b", "Device Beta", "room-renamed",
                "key-b", "2026-07-22T00:00:01Z", lanAddress);
            // Unresolvable ("unknown") addresses never form a net, even on one room id.
            var unknownFirst = Participant("lease-c", "peer-c", "Device Gamma", "room-original",
                "key-c", "2026-07-22T00:00:02Z",
                PublicTransferCoordinationService.UnknownPublicAddress);
            var unknownSecond = Participant("lease-d", "peer-d", "Device Delta", "room-original",
                "key-d", "2026-07-22T00:00:03Z",
                PublicTransferCoordinationService.UnknownPublicAddress);
            Assert.True((await service.RegisterAsync(alpha, 8, cancellation.Token)).Accepted);
            Assert.True((await service.RegisterAsync(beta, 8, cancellation.Token)).Accepted);
            Assert.True((await service.RegisterAsync(unknownFirst, 8, cancellation.Token)).Accepted);
            Assert.True((await service.RegisterAsync(unknownSecond, 8, cancellation.Token)).Accepted);
            Assert.Equal(alpha.NetId, beta.NetId);
            Assert.NotEqual(alpha.GroupId, beta.GroupId);

            var alphaRoster = await service.RosterAsync(alpha, cancellation.Token);
            Assert.Equal(["peer-a", "peer-b"],
                alphaRoster.Participants.Select(peer => peer.PeerId));
            var betaRoster = await service.RosterAsync(beta, cancellation.Token);
            Assert.Equal(["peer-a", "peer-b"],
                betaRoster.Participants.Select(peer => peer.PeerId));

            // Directed routing resolves across room ids on the same net.
            var resolved = await service.FindPeerAsync(alpha, "peer-b", cancellation.Token);
            Assert.NotNull(resolved);
            Assert.Equal(beta.GroupId, resolved.GroupId);

            // The unknown-address peers see nobody (not even each other or the LAN).
            var unknownRoster = await service.RosterAsync(unknownFirst, cancellation.Token);
            Assert.Equal(["peer-c"], unknownRoster.Participants.Select(peer => peer.PeerId));
            Assert.Null(await service.FindPeerAsync(unknownFirst, "peer-d", cancellation.Token));

            Assert.True(await service.UnregisterAsync(alpha, cancellation.Token) > 0);
            Assert.True(await service.UnregisterAsync(beta, cancellation.Token) > 0);
            Assert.True(await service.UnregisterAsync(unknownFirst, cancellation.Token) > 0);
            Assert.True(await service.UnregisterAsync(unknownSecond, cancellation.Token) > 0);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            service.Dispose();
        }
    }

    [Fact]
    public async Task RosterReadPrunesStaleMembersBumpsRevisionsAndPublishesBothScopes()
    {
        var redisUri = Environment.GetEnvironmentVariable("SPECUS_TEST_REDIS_URI");
        if (string.IsNullOrWhiteSpace(redisUri))
        {
            return;
        }
        var keyPrefix = "specus:test:" + Guid.NewGuid().ToString("N");
        var options = Options.Create(new PublicTransferOptions
        {
            ClusterEnabled = true,
            RedisUri = redisUri,
            RedisKeyPrefix = keyPrefix,
            PresenceLeaseSeconds = 30,
            PresenceRefreshIntervalMs = 10_000,
            RedisCommandTimeoutMs = 2_000,
        });
        var service = new PublicTransferCoordinationService(options,
            NullLogger<PublicTransferCoordinationService>.Instance);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var raw = await RawRedis.ConnectAsync(redisUri);
        await service.StartAsync(cancellation.Token);
        try
        {
            var alpha = Participant("lease-a", "peer-a", "Device Alpha", "hygiene-room", "key-a",
                "2026-07-22T00:00:00Z");
            var beta = Participant("lease-b", "peer-b", "Device Beta", "hygiene-room", "key-b",
                "2026-07-22T00:00:01Z");
            Assert.True((await service.RegisterAsync(alpha, 8, cancellation.Token)).Accepted);
            Assert.True((await service.RegisterAsync(beta, 8, cancellation.Token)).Accepted);

            var rosterScopes = new List<string>();
            var bothScopesPublished = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            service.AddListener(clusterEvent =>
            {
                if (clusterEvent.Kind == PublicTransferClusterFrame.KindRoster)
                {
                    rosterScopes.Add(clusterEvent.GroupId);
                    if (rosterScopes.Count == 2)
                    {
                        bothScopesPublished.TrySetResult();
                    }
                }
                return Task.CompletedTask;
            });

            var revisionBefore = (await service.RosterAsync(alpha, cancellation.Token)).Revision;

            // A stale member with no presence record, plus an emptied group in the nets index.
            var database = raw.GetDatabase();
            var membersKey = keyPrefix + ":members:" + alpha.GroupId;
            var netsKey = keyPrefix + ":nets:" + alpha.NetId;
            await database.SetAddAsync(membersKey, "deadbeef");
            await database.SetAddAsync(netsKey, "emptied-group");

            var roster = await service.RosterAsync(alpha, cancellation.Token);
            Assert.Equal(["peer-a", "peer-b"], roster.Participants.Select(peer => peer.PeerId));
            // The stale member bumps the group and the net revision once each.
            Assert.Equal(revisionBefore + 2, roster.Revision);

            // The cleanup publishes the roster event to both merged-scope audiences.
            await bothScopesPublished.Task.WaitAsync(cancellation.Token);
            Assert.Equal(new[] { alpha.GroupId, alpha.NetId }.Order().ToArray(),
                rosterScopes.Order().ToArray());

            // The stale member is pruned and the emptied group leaves the nets index.
            Assert.DoesNotContain("deadbeef",
                (await database.SetMembersAsync(membersKey)).Select(value => value.ToString()));
            Assert.DoesNotContain("emptied-group",
                (await database.SetMembersAsync(netsKey)).Select(value => value.ToString()));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            service.Dispose();
        }
    }

    private static PublicTransferClusterParticipant Participant(string leaseId, string peerId,
        string displayName, string roomId, string roomKey, string connectedAt) => new(
        leaseId, peerId, displayName, roomId, "203.0.113.1", roomKey, "EDITOR", true, connectedAt);

    private static PublicTransferClusterParticipant Participant(string leaseId, string peerId,
        string displayName, string roomId, string roomKey, string connectedAt,
        string publicAddress) => new(leaseId, peerId, displayName, roomId, publicAddress, roomKey,
        "EDITOR", true, connectedAt);
}
