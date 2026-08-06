using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using StackExchange.Redis;

namespace Specus.Server.WebSockets;

/// <summary>Redis-backed presence, Pub/Sub, room revision and fixed-window limits.</summary>
public sealed class PublicTransferCoordinationService : BackgroundService
{
    private static readonly TimeSpan RevisionTtl = TimeSpan.FromDays(7);
    // Merged LAN visibility: participants sharing a publicAddress see each other
    // across rooms and token rooms, while same-roomKey members stay visible across nets. Presence and
    // members stay keyed by groupID; nets:<netId> indexes the groupIDs present on a net;
    // roster revisions are the sum of the group and net counters so they stay monotonic
    // whenever either dimension of a recipient's merged roster changes. The scripts and
    // keyspace are aligned with the Go/Java coordination services.
    // KEYS: 1=presence:<group>:<member> 2=name:<digest> 3=members:<group>
    //       4=revision:<group> 5=revision:<net> 6=nets:<net>
    // ARGV: 1=peerValue 2=nameValue 3=memberId 4=leaseMs 5=limit 6=presencePrefix(group)
    //       7=revisionTtlMs 8=groupId 9=presenceBasePrefix
    private const string RegisterScript = """
        local members = redis.call('SMEMBERS', KEYS[3])
        local count = 0
        for _, member in ipairs(members) do
          if redis.call('EXISTS', ARGV[6] .. member) == 1 then
            count = count + 1
          else
            redis.call('SREM', KEYS[3], member)
          end
        end
        if redis.call('EXISTS', KEYS[1]) == 1 then return {-1, 0} end
        for _, group in ipairs(redis.call('SMEMBERS', KEYS[6])) do
          if redis.call('EXISTS', ARGV[9] .. group .. ':' .. ARGV[3]) == 1 then return {-1, 0} end
        end
        if redis.call('EXISTS', KEYS[2]) == 1 then return {-2, 0} end
        if count >= tonumber(ARGV[5]) then return {-3, 0} end
        redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[4])
        redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[4])
        redis.call('SADD', KEYS[3], ARGV[3])
        redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[4]) * 3)
        redis.call('SADD', KEYS[6], ARGV[8])
        redis.call('PEXPIRE', KEYS[6], tonumber(ARGV[4]) * 3)
        local groupRevision = redis.call('INCR', KEYS[4])
        redis.call('PEXPIRE', KEYS[4], ARGV[7])
        local netRevision = redis.call('INCR', KEYS[5])
        redis.call('PEXPIRE', KEYS[5], ARGV[7])
        return {1, groupRevision + netRevision}
        """;
    // KEYS: 1=presence:<group>:<member> 2=name:<digest> 3=members:<group> 4=nets:<net>
    private const string RefreshScript = """
        if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
        if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end
        redis.call('PEXPIRE', KEYS[1], ARGV[3])
        redis.call('PEXPIRE', KEYS[2], ARGV[3])
        redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[3]) * 3)
        redis.call('PEXPIRE', KEYS[4], tonumber(ARGV[3]) * 3)
        return 1
        """;
    // KEYS: 1=presence:<group>:<member> 2=name:<digest> 3=members:<group>
    //       4=revision:<group> 5=revision:<net> 6=nets:<net>
    // ARGV: 1=peerValue 2=nameValue 3=memberId 4=revisionTtlMs 5=groupId
    private const string UnregisterScript = """
        if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
        redis.call('DEL', KEYS[1])
        if redis.call('GET', KEYS[2]) == ARGV[2] then redis.call('DEL', KEYS[2]) end
        redis.call('SREM', KEYS[3], ARGV[3])
        if redis.call('SCARD', KEYS[3]) == 0 then redis.call('SREM', KEYS[6], ARGV[5]) end
        local groupRevision = redis.call('INCR', KEYS[4])
        redis.call('PEXPIRE', KEYS[4], ARGV[4])
        local netRevision = redis.call('INCR', KEYS[5])
        redis.call('PEXPIRE', KEYS[5], ARGV[4])
        return groupRevision + netRevision
        """;
    // KEYS: 1=members:<group> 2=revision:<group> 3=revision:<net> 4=nets:<net>
    // ARGV: 1=presencePrefix(group) 2=revisionTtlMs 3=groupId
    private const string CleanupScript = """
        local removed = 0
        local members = redis.call('SMEMBERS', KEYS[1])
        for _, member in ipairs(members) do
          if redis.call('EXISTS', ARGV[1] .. member) == 0 then
            redis.call('SREM', KEYS[1], member)
            removed = removed + 1
          end
        end
        if redis.call('SCARD', KEYS[1]) == 0 then redis.call('SREM', KEYS[4], ARGV[3]) end
        local groupRevision = tonumber(redis.call('GET', KEYS[2]) or '0')
        local netRevision = tonumber(redis.call('GET', KEYS[3]) or '0')
        if removed > 0 then
          groupRevision = redis.call('INCR', KEYS[2])
          redis.call('PEXPIRE', KEYS[2], ARGV[2])
          netRevision = redis.call('INCR', KEYS[3])
          redis.call('PEXPIRE', KEYS[3], ARGV[2])
        end
        return {removed, groupRevision + netRevision}
        """;
    private const string RateScript = """
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
        if count > tonumber(ARGV[1]) then return 0 end
        return 1
        """;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly PublicTransferOptions _options;
    private readonly ILogger<PublicTransferCoordinationService> _logger;
    private readonly Channel<PublicTransferClusterEvent> _events = Channel.CreateBounded<PublicTransferClusterEvent>(
        new BoundedChannelOptions(4096)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
        });
    private readonly object _listenerGate = new();
    private readonly List<Func<PublicTransferClusterEvent, Task>> _listeners = [];
    private IConnectionMultiplexer? _connection;
    private IDatabase? _database;
    private ISubscriber? _subscriber;

    public PublicTransferCoordinationService(IOptions<PublicTransferOptions> options,
        ILogger<PublicTransferCoordinationService> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public bool Enabled => _options.ClusterEnabled;

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            await base.StartAsync(cancellationToken).ConfigureAwait(false);
            return;
        }
        ValidateConfiguration();
        try
        {
            _connection = await ConnectionMultiplexer.ConnectAsync(CreateRedisConfiguration())
                .WaitAsync(cancellationToken).ConfigureAwait(false);
            _database = _connection.GetDatabase();
            _subscriber = _connection.GetSubscriber();
            await _database.PingAsync().WaitAsync(cancellationToken).ConfigureAwait(false);
            await _subscriber.SubscribeAsync(RedisChannel.Literal(EventChannel()), OnRedisEvent)
                .WaitAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("public transfer Redis coordination enabled: prefix={Prefix}",
                KeyPrefix());
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _connection?.Dispose();
            _connection = null;
            _database = null;
            _subscriber = null;
            throw new InvalidOperationException(
                "could not initialize public transfer Redis coordination", exception);
        }
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _events.Writer.TryComplete();
        if (_subscriber is not null)
        {
            try
            {
                await _subscriber.UnsubscribeAsync(RedisChannel.Literal(EventChannel()))
                    .WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                _logger.LogDebug(exception, "public transfer Redis unsubscribe failed");
            }
        }
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        _connection?.Dispose();
        _connection = null;
        _database = null;
        _subscriber = null;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var clusterEvent in _events.Reader.ReadAllAsync(stoppingToken))
            {
                Func<PublicTransferClusterEvent, Task>[] listeners;
                lock (_listenerGate)
                {
                    listeners = [.. _listeners];
                }
                foreach (var listener in listeners)
                {
                    try
                    {
                        await listener(clusterEvent).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is not OperationCanceledException)
                    {
                        _logger.LogWarning(exception,
                            "public transfer cluster event listener failed");
                    }
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown.
        }
    }

    internal void AddListener(Func<PublicTransferClusterEvent, Task> listener)
    {
        ArgumentNullException.ThrowIfNull(listener);
        lock (_listenerGate)
        {
            _listeners.Add(listener);
        }
    }

    internal async Task<PublicTransferClusterRegistration> RegisterAsync(
        PublicTransferClusterParticipant participant, int configuredLimit,
        CancellationToken cancellationToken)
    {
        var database = RequireDatabase();
        var groupId = participant.GroupId;
        var netId = participant.NetId;
        var memberId = Digest(participant.PeerId);
        var peerValue = EncodeParticipant(participant);
        var nameValue = participant.LeaseId + "\n" + participant.PeerId;
        var result = await database.ScriptEvaluateAsync(RegisterScript,
            [PresenceKey(groupId, memberId), NameKey(participant.DisplayName), MembersKey(groupId),
                RevisionKey(groupId), RevisionKey(netId), NetsKey(netId)],
            [peerValue, nameValue, memberId, LeaseMilliseconds(), Math.Max(1, configuredLimit),
                PresencePrefix(groupId), checked((long)RevisionTtl.TotalMilliseconds), groupId,
                PresenceKeyPrefix()])
            .WaitAsync(cancellationToken).ConfigureAwait(false);
        var values = ResultArray(result);
        var code = ResultInt64(values, 0);
        var revision = ResultRevision(values, 1);
        return code switch
        {
            1 => new PublicTransferClusterRegistration(null, revision),
            -1 => new PublicTransferClusterRegistration("peer id is already connected", 0),
            -2 => new PublicTransferClusterRegistration("client name is already in use", 0),
            -3 => new PublicTransferClusterRegistration("room is full", 0),
            _ => throw new InvalidOperationException(
                "unexpected public transfer registration result"),
        };
    }

    internal async Task<bool> RefreshAsync(PublicTransferClusterParticipant participant,
        CancellationToken cancellationToken)
    {
        var groupId = participant.GroupId;
        var memberId = Digest(participant.PeerId);
        var result = await RequireDatabase().ScriptEvaluateAsync(RefreshScript,
            [PresenceKey(groupId, memberId), NameKey(participant.DisplayName), MembersKey(groupId),
                NetsKey(participant.NetId)],
            [EncodeParticipant(participant), participant.LeaseId + "\n" + participant.PeerId,
                LeaseMilliseconds()]).WaitAsync(cancellationToken).ConfigureAwait(false);
        return (long)result == 1;
    }

    internal async Task<ulong> UnregisterAsync(PublicTransferClusterParticipant participant,
        CancellationToken cancellationToken)
    {
        var groupId = participant.GroupId;
        var memberId = Digest(participant.PeerId);
        var result = await RequireDatabase().ScriptEvaluateAsync(UnregisterScript,
            [PresenceKey(groupId, memberId), NameKey(participant.DisplayName), MembersKey(groupId),
                RevisionKey(groupId), RevisionKey(participant.NetId), NetsKey(participant.NetId)],
            [EncodeParticipant(participant), participant.LeaseId + "\n" + participant.PeerId,
                memberId, checked((long)RevisionTtl.TotalMilliseconds), groupId])
            .WaitAsync(cancellationToken).ConfigureAwait(false);
        return ToRevision((long)result);
    }

    // Reads the merged roster for recipient: everyone in the recipient's token room plus
    // everyone on the recipient's network (same publicAddress, any roomId), deduplicated
    // by peerId. The returned revision is the sum of the group and net counters, so it
    // increases monotonically whenever either dimension changes.
    internal async Task<PublicTransferClusterRoster> RosterAsync(
        PublicTransferClusterParticipant recipient, CancellationToken cancellationToken)
    {
        var groupId = recipient.GroupId;
        var netId = recipient.NetId;
        // Hygiene pass: prune stale members of the own group and of every group on the net
        // (also drops emptied groups from the nets index and bumps both revision counters so
        // presence expiries surface to merged-roster recipients). The reads below self-heal
        // anyway; this pass is what makes expiries visible to push recipients in a timely
        // manner.
        var removedAny = false;
        var cleanupRevision = 0UL;
        foreach (var group in await NetGroupsAsync(netId, groupId, cancellationToken)
                .ConfigureAwait(false))
        {
            var cleanup = await CleanupAsync(group, netId, cancellationToken).ConfigureAwait(false);
            removedAny |= cleanup.Removed > 0;
            cleanupRevision = cleanup.Revision;
        }
        if (removedAny)
        {
            // A merged-scope change has two audiences: the token room and the network.
            await PublishRosterAsync(groupId, cleanupRevision, cancellationToken)
                .ConfigureAwait(false);
            await PublishRosterAsync(netId, cleanupRevision, cancellationToken)
                .ConfigureAwait(false);
        }
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var beforeGroup = await RevisionAsync(groupId, cancellationToken).ConfigureAwait(false);
            var beforeNet = await RevisionAsync(netId, cancellationToken).ConfigureAwait(false);
            var groups = await NetGroupsAsync(netId, groupId, cancellationToken)
                .ConfigureAwait(false);
            var participants = await ReadMergedParticipantsAsync(recipient, groups,
                cancellationToken).ConfigureAwait(false);
            var afterGroup = await RevisionAsync(groupId, cancellationToken).ConfigureAwait(false);
            var afterNet = await RevisionAsync(netId, cancellationToken).ConfigureAwait(false);
            if (attempt == 1 || beforeGroup == afterGroup && beforeNet == afterNet)
            {
                participants.Sort((left, right) => string.CompareOrdinal(
                    left.ConnectedAt, right.ConnectedAt));
                return new PublicTransferClusterRoster(afterGroup + afterNet, participants);
            }
        }
        throw new InvalidOperationException("could not read stable public transfer roster");
    }

    // Locates a visible peer by peerId within the recipient's merged visibility domain
    // (same room or same network). Directed messages are routed to the resolved target's
    // group, exactly once; a null result means the target is not visible to the recipient.
    internal async Task<PublicTransferClusterParticipant?> FindPeerAsync(
        PublicTransferClusterParticipant recipient, string peerId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(peerId))
        {
            return null;
        }
        var groups = await NetGroupsAsync(recipient.NetId, recipient.GroupId, cancellationToken)
            .ConfigureAwait(false);
        var participants = await ReadMergedParticipantsAsync(recipient, groups, cancellationToken)
            .ConfigureAwait(false);
        return participants.FirstOrDefault(participant => string.Equals(
            participant.PeerId, peerId, StringComparison.Ordinal));
    }

    internal async Task<ulong> SweepAsync(string groupId, string netId,
        CancellationToken cancellationToken)
    {
        var cleanup = await CleanupAsync(groupId, netId, cancellationToken).ConfigureAwait(false);
        if (cleanup.Removed > 0)
        {
            // A merged-scope change has two audiences: the token room and the network.
            await PublishRosterAsync(groupId, cleanup.Revision, cancellationToken)
                .ConfigureAwait(false);
            await PublishRosterAsync(netId, cleanup.Revision, cancellationToken)
                .ConfigureAwait(false);
        }
        return cleanup.Revision;
    }

    internal async Task<bool> IsClientNameAvailableAsync(string displayName, string? excludePeerId,
        CancellationToken cancellationToken)
    {
        var owner = await RequireDatabase().StringGetAsync(NameKey(displayName))
            .WaitAsync(cancellationToken).ConfigureAwait(false);
        if (!owner.HasValue)
        {
            return true;
        }
        var value = owner.ToString();
        var separator = value.IndexOf('\n', StringComparison.Ordinal);
        var peerId = separator < 0 ? string.Empty : value[(separator + 1)..];
        return !string.IsNullOrWhiteSpace(excludePeerId)
            && string.Equals(peerId, excludePeerId.Trim(), StringComparison.Ordinal);
    }

    internal async Task<bool> AllowRateAsync(string bucket, string identity, int configuredLimit,
        long configuredWindowSeconds, CancellationToken cancellationToken = default)
    {
        var result = await RequireDatabase().ScriptEvaluateAsync(RateScript,
            [RateKey(bucket, identity)],
            [Math.Max(1, configuredLimit), Math.Max(1L, configuredWindowSeconds) * 1000L])
            .WaitAsync(cancellationToken).ConfigureAwait(false);
        return (long)result == 1;
    }

    // Publish scope is a groupID or a netID riding in the event's opaque group field:
    // roster publishes go to both audiences of a merged-scope change; directed
    // text/binary publishes go to the resolved target's group; room broadcasts go to the
    // source's group.
    internal Task PublishRosterAsync(string scopeId, ulong revision,
        CancellationToken cancellationToken) => PublishAsync(new PublicTransferClusterEvent(
            PublicTransferClusterFrame.KindRoster, false, revision, scopeId, string.Empty,
            string.Empty, []), cancellationToken);

    internal Task PublishTextAsync(string scopeId, string targetPeerId, string sourceLeaseId,
        bool excludeSource, byte[] payload, CancellationToken cancellationToken) =>
        PublishAsync(new PublicTransferClusterEvent(PublicTransferClusterFrame.KindText,
            excludeSource, 0, scopeId, targetPeerId, sourceLeaseId, payload), cancellationToken);

    internal Task PublishBinaryAsync(string scopeId, string targetPeerId, byte[] payload,
        CancellationToken cancellationToken) => PublishAsync(new PublicTransferClusterEvent(
            PublicTransferClusterFrame.KindBinary, false, 0, scopeId, targetPeerId, string.Empty,
            payload), cancellationToken);

    internal Task PublishManagementAsync(string tenantId, byte[] payload,
        CancellationToken cancellationToken) => PublishAsync(new PublicTransferClusterEvent(
            PublicTransferClusterFrame.KindManagement, false, 0, ManagementGroupId(tenantId),
            string.Empty, string.Empty, payload), cancellationToken);

    internal static string GroupId(string roomId, string roomKey) =>
        Digest((roomId ?? string.Empty) + "\0" + (roomKey ?? string.Empty));

    // Fallback PublicAddress when no usable client address could be resolved; the same
    // literal is produced by WebSocketTicketService.RequestAddress and the discovery
    // hub's address resolution. Peers with this (or a blank) address are never grouped
    // into a net, so an address-resolution failure cannot lump strangers together.
    internal const string UnknownPublicAddress = "unknown";

    // A net is one public egress address: the room id is deliberately not part of the
    // digest, so same-net devices stay grouped no matter which room name they picked.
    internal static string NetId(string publicAddress) =>
        Digest(publicAddress ?? string.Empty);

    internal static string ManagementGroupId(string? tenantId) =>
        Digest(tenantId?.Trim() ?? string.Empty);

    private async Task PublishAsync(PublicTransferClusterEvent clusterEvent,
        CancellationToken cancellationToken)
    {
        var encoded = PublicTransferClusterFrame.Encode(clusterEvent);
        var subscriber = _subscriber
            ?? throw new InvalidOperationException("public transfer Redis coordination is not enabled");
        await subscriber.PublishAsync(RedisChannel.Literal(EventChannel()), encoded)
            .WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<CleanupResult> CleanupAsync(string groupId, string netId,
        CancellationToken cancellationToken)
    {
        var result = await RequireDatabase().ScriptEvaluateAsync(CleanupScript,
            [MembersKey(groupId), RevisionKey(groupId), RevisionKey(netId), NetsKey(netId)],
            [PresencePrefix(groupId), checked((long)RevisionTtl.TotalMilliseconds), groupId])
            .WaitAsync(cancellationToken).ConfigureAwait(false);
        var values = ResultArray(result);
        return new CleanupResult(ResultInt64(values, 0), ResultRevision(values, 1));
    }

    // Lists the groups readable for one net: every group indexed under nets:<netId>, plus
    // groupId itself (a group always spans the nets of its members even when the nets
    // index entry aged out).
    private async Task<string[]> NetGroupsAsync(string netId, string groupId,
        CancellationToken cancellationToken)
    {
        var groups = await RequireDatabase().SetMembersAsync(NetsKey(netId))
            .WaitAsync(cancellationToken).ConfigureAwait(false);
        var result = new List<string>(groups.Length + 1);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var group in groups)
        {
            if (seen.Add(group.ToString()))
            {
                result.Add(group.ToString());
            }
        }
        if (seen.Add(groupId))
        {
            result.Add(groupId);
        }
        return [.. result];
    }

    // Unions the live presence of the given groups and keeps only records visible to
    // recipient: same group (roomId + roomKey) or same real publicAddress. The presence
    // JSON carries roomKey/publicAddress, so visibility is re-checked in memory rather
    // than trusting the members sets (a group's members can span nets).
    private async Task<List<PublicTransferClusterParticipant>> ReadMergedParticipantsAsync(
        PublicTransferClusterParticipant recipient, IReadOnlyList<string> groups,
        CancellationToken cancellationToken)
    {
        var database = RequireDatabase();
        var participants = new List<PublicTransferClusterParticipant>();
        var seenPeerIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var groupId in groups)
        {
            var members = await database.SetMembersAsync(MembersKey(groupId))
                .WaitAsync(cancellationToken).ConfigureAwait(false);
            if (members.Length == 0)
            {
                continue;
            }
            var keys = members.Select(member => (RedisKey)PresenceKey(groupId,
                member.ToString())).ToArray();
            var values = await database.StringGetAsync(keys).WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            foreach (var value in values)
            {
                if (!value.HasValue || DecodeParticipant(value.ToString()) is not { } participant
                    || !string.Equals(participant.GroupId, groupId, StringComparison.Ordinal))
                {
                    continue;
                }
                // Same merged visibility as the hub's SameGroup || SameNet: same room key
                // inside the room, or the same real public address regardless of room id
                // (blank/"unknown" addresses never form a net).
                var sameNet = recipient.PublicAddress.Length > 0
                    && !string.Equals(recipient.PublicAddress, UnknownPublicAddress,
                        StringComparison.Ordinal)
                    && string.Equals(participant.PublicAddress, recipient.PublicAddress,
                        StringComparison.Ordinal);
                var visible = sameNet
                    || string.Equals(participant.RoomId, recipient.RoomId,
                        StringComparison.Ordinal)
                    && string.Equals(participant.RoomKey, recipient.RoomKey,
                        StringComparison.Ordinal);
                if (visible && seenPeerIds.Add(participant.PeerId))
                {
                    participants.Add(participant);
                }
            }
        }
        return participants;
    }

    private async Task<ulong> RevisionAsync(string groupId, CancellationToken cancellationToken)
    {
        var value = await RequireDatabase().StringGetAsync(RevisionKey(groupId))
            .WaitAsync(cancellationToken).ConfigureAwait(false);
        if (!value.HasValue)
        {
            return 0;
        }
        if (!long.TryParse(value.ToString(), System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var revision)
            || revision < 0)
        {
            throw new InvalidOperationException("invalid public transfer room revision");
        }
        return (ulong)revision;
    }

    private void OnRedisEvent(RedisChannel channel, RedisValue message)
    {
        if (!channel.Equals(RedisChannel.Literal(EventChannel())) || !message.HasValue)
        {
            return;
        }
        try
        {
            var encoded = (byte[]?)message;
            if (encoded is null || !_events.Writer.TryWrite(PublicTransferClusterFrame.Decode(encoded)))
            {
                _logger.LogWarning("public transfer cluster event queue is full");
            }
        }
        catch (ArgumentException exception)
        {
            _logger.LogWarning("discarding invalid public transfer cluster event: {Message}",
                exception.Message);
        }
    }

    private void ValidateConfiguration()
    {
        if (string.IsNullOrWhiteSpace(_options.RedisUri))
        {
            throw new InvalidOperationException(
                "Specus:PublicTransfer:RedisUri is required when ClusterEnabled=true");
        }
        if (_options.PresenceRefreshIntervalMs <= 0
            || _options.PresenceRefreshIntervalMs * 2 >= LeaseMilliseconds())
        {
            throw new InvalidOperationException(
                "public transfer presence refresh interval must be positive and less than half the lease TTL");
        }
    }

    private ConfigurationOptions CreateRedisConfiguration()
    {
        if (!Uri.TryCreate(_options.RedisUri.Trim(), UriKind.Absolute, out var uri)
            || uri.Scheme is not ("redis" or "rediss") || string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new InvalidOperationException("public transfer Redis URI is invalid");
        }
        var timeout = checked((int)Math.Clamp(_options.RedisCommandTimeoutMs, 100, int.MaxValue));
        var configuration = new ConfigurationOptions
        {
            AbortOnConnectFail = true,
            ConnectTimeout = timeout,
            AsyncTimeout = timeout,
            SyncTimeout = timeout,
            Ssl = uri.Scheme == "rediss",
        };
        configuration.EndPoints.Add(uri.Host, uri.Port > 0 ? uri.Port : 6379);
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            var parts = uri.UserInfo.Split(':', 2);
            if (parts.Length == 2)
            {
                configuration.User = Uri.UnescapeDataString(parts[0]);
                configuration.Password = Uri.UnescapeDataString(parts[1]);
            }
            else
            {
                configuration.Password = Uri.UnescapeDataString(parts[0]);
            }
        }
        var path = uri.AbsolutePath.Trim('/');
        if (path.Length > 0 && int.TryParse(path,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var database))
        {
            configuration.DefaultDatabase = database;
        }
        return configuration;
    }

    private IDatabase RequireDatabase() => _database
        ?? throw new InvalidOperationException("public transfer Redis coordination is not enabled");

    private string EncodeParticipant(PublicTransferClusterParticipant participant) =>
        participant.LeaseId + "\n" + JsonSerializer.Serialize(participant, JsonOptions);

    private PublicTransferClusterParticipant? DecodeParticipant(string encoded)
    {
        try
        {
            var separator = encoded.IndexOf('\n', StringComparison.Ordinal);
            if (separator <= 0)
            {
                return null;
            }
            var participant = JsonSerializer.Deserialize<PublicTransferClusterParticipant>(
                encoded[(separator + 1)..], JsonOptions);
            return participant is not null
                && string.Equals(encoded[..separator], participant.LeaseId, StringComparison.Ordinal)
                    ? participant
                    : null;
        }
        catch (JsonException exception)
        {
            _logger.LogWarning("discarding invalid public transfer presence record: {Message}",
                exception.Message);
            return null;
        }
    }

    private string PresenceKeyPrefix() => $"{KeyPrefix()}:presence:";
    private string PresencePrefix(string groupId) => $"{KeyPrefix()}:presence:{groupId}:";
    private string PresenceKey(string groupId, string memberId) => PresencePrefix(groupId) + memberId;
    private string MembersKey(string groupId) => $"{KeyPrefix()}:members:{groupId}";
    private string NetsKey(string netId) => $"{KeyPrefix()}:nets:{netId}";
    private string RevisionKey(string scopeId) => $"{KeyPrefix()}:revision:{scopeId}";
    private string NameKey(string displayName) => $"{KeyPrefix()}:name:{Digest(
        displayName.Trim().Normalize(NormalizationForm.FormC).ToLowerInvariant())}";
    private string RateKey(string bucket, string identity) => $"{KeyPrefix()}:rate:{Digest(
        bucket + "\0" + identity)}";
    private string EventChannel() => KeyPrefix() + ":events";
    // Deployment constraint: merged net visibility changed the keyspace semantics (new
    // nets:<netId> index, dual group/net revision counters, scope-based pub/sub routing).
    // Old and new nodes sharing one keyspace would corrupt rosters and routing — upgrade
    // every cluster node together, or bump RedisKeyPrefix for the new fleet.
    private string KeyPrefix() => string.IsNullOrWhiteSpace(_options.RedisKeyPrefix)
        ? "specus:v2:public-transfer"
        : _options.RedisKeyPrefix.Trim().TrimEnd(':');
    private long LeaseMilliseconds() => Math.Max(5L, _options.PresenceLeaseSeconds) * 1000L;

    private static RedisResult[] ResultArray(RedisResult result) => (RedisResult[]?)result
        ?? throw new InvalidOperationException("invalid Redis script result");

    private static long ResultInt64(IReadOnlyList<RedisResult> values, int index)
    {
        if (index >= values.Count)
        {
            throw new InvalidOperationException("invalid Redis script result");
        }
        return (long)values[index];
    }

    private static ulong ResultRevision(IReadOnlyList<RedisResult> values, int index) =>
        ToRevision(ResultInt64(values, index));

    private static ulong ToRevision(long revision)
    {
        if (revision < 0)
        {
            throw new InvalidOperationException("invalid public transfer room revision");
        }
        return (ulong)revision;
    }

    private static string Digest(string value) => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private sealed record CleanupResult(long Removed, ulong Revision);
}

internal sealed record PublicTransferClusterParticipant(string LeaseId, string PeerId,
    string DisplayName, string RoomId, string PublicAddress, string RoomKey, string RoomRole,
    bool SharedRoom, string ConnectedAt)
{
    internal string GroupId => PublicTransferCoordinationService.GroupId(RoomId, RoomKey);
    internal string NetId => PublicTransferCoordinationService.NetId(PublicAddress);
}

internal sealed record PublicTransferClusterRegistration(string? Error, ulong Revision)
{
    internal bool Accepted => Error is null;
}

internal sealed record PublicTransferClusterRoster(ulong Revision,
    IReadOnlyList<PublicTransferClusterParticipant> Participants);
