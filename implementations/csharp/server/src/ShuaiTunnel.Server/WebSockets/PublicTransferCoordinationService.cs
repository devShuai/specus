using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using StackExchange.Redis;

namespace ShuaiTunnel.Server.WebSockets;

/// <summary>Redis-backed presence, Pub/Sub, room revision and fixed-window limits.</summary>
public sealed class PublicTransferCoordinationService : BackgroundService
{
    private static readonly TimeSpan RevisionTtl = TimeSpan.FromDays(7);
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
        if redis.call('EXISTS', KEYS[2]) == 1 then return {-2, 0} end
        if count >= tonumber(ARGV[5]) then return {-3, 0} end
        redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[4])
        redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[4])
        redis.call('SADD', KEYS[3], ARGV[3])
        redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[4]) * 3)
        local revision = redis.call('INCR', KEYS[4])
        redis.call('PEXPIRE', KEYS[4], ARGV[7])
        return {1, revision}
        """;
    private const string RefreshScript = """
        if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
        if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end
        redis.call('PEXPIRE', KEYS[1], ARGV[3])
        redis.call('PEXPIRE', KEYS[2], ARGV[3])
        redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[3]) * 3)
        return 1
        """;
    private const string UnregisterScript = """
        if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
        redis.call('DEL', KEYS[1])
        if redis.call('GET', KEYS[2]) == ARGV[2] then redis.call('DEL', KEYS[2]) end
        redis.call('SREM', KEYS[3], ARGV[3])
        local revision = redis.call('INCR', KEYS[4])
        redis.call('PEXPIRE', KEYS[4], ARGV[4])
        return revision
        """;
    private const string CleanupScript = """
        local removed = 0
        local members = redis.call('SMEMBERS', KEYS[1])
        for _, member in ipairs(members) do
          if redis.call('EXISTS', ARGV[1] .. member) == 0 then
            redis.call('SREM', KEYS[1], member)
            removed = removed + 1
          end
        end
        local revision = tonumber(redis.call('GET', KEYS[2]) or '0')
        if removed > 0 then
          revision = redis.call('INCR', KEYS[2])
          redis.call('PEXPIRE', KEYS[2], ARGV[2])
        end
        return {removed, revision}
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
        var memberId = Digest(participant.PeerId);
        var peerValue = EncodeParticipant(participant);
        var nameValue = participant.LeaseId + "\n" + participant.PeerId;
        var result = await database.ScriptEvaluateAsync(RegisterScript,
            [PresenceKey(groupId, memberId), NameKey(participant.DisplayName), MembersKey(groupId),
                RevisionKey(groupId)],
            [peerValue, nameValue, memberId, LeaseMilliseconds(), Math.Max(1, configuredLimit),
                PresencePrefix(groupId), checked((long)RevisionTtl.TotalMilliseconds)])
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
            [PresenceKey(groupId, memberId), NameKey(participant.DisplayName), MembersKey(groupId)],
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
                RevisionKey(groupId)],
            [EncodeParticipant(participant), participant.LeaseId + "\n" + participant.PeerId,
                memberId, checked((long)RevisionTtl.TotalMilliseconds)])
            .WaitAsync(cancellationToken).ConfigureAwait(false);
        return ToRevision((long)result);
    }

    internal async Task<PublicTransferClusterRoster> RosterAsync(string groupId,
        CancellationToken cancellationToken)
    {
        var cleanup = await CleanupAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (cleanup.Removed > 0)
        {
            await PublishRosterAsync(groupId, cleanup.Revision, cancellationToken)
                .ConfigureAwait(false);
        }
        var database = RequireDatabase();
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var before = await RevisionAsync(groupId, cancellationToken).ConfigureAwait(false);
            var members = await database.SetMembersAsync(MembersKey(groupId))
                .WaitAsync(cancellationToken).ConfigureAwait(false);
            var participants = new List<PublicTransferClusterParticipant>(members.Length);
            if (members.Length > 0)
            {
                var keys = members.Select(member => (RedisKey)PresenceKey(groupId,
                    member.ToString())).ToArray();
                var values = await database.StringGetAsync(keys).WaitAsync(cancellationToken)
                    .ConfigureAwait(false);
                foreach (var value in values)
                {
                    if (value.HasValue && DecodeParticipant(value.ToString()) is { } participant
                        && string.Equals(participant.GroupId, groupId, StringComparison.Ordinal))
                    {
                        participants.Add(participant);
                    }
                }
            }
            var after = await RevisionAsync(groupId, cancellationToken).ConfigureAwait(false);
            if (attempt == 1 || before == after)
            {
                participants.Sort((left, right) => string.CompareOrdinal(
                    left.ConnectedAt, right.ConnectedAt));
                return new PublicTransferClusterRoster(after, participants);
            }
        }
        throw new InvalidOperationException("could not read stable public transfer roster");
    }

    internal async Task<ulong> SweepAsync(string groupId, CancellationToken cancellationToken)
    {
        var cleanup = await CleanupAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (cleanup.Removed > 0)
        {
            await PublishRosterAsync(groupId, cleanup.Revision, cancellationToken)
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

    internal Task PublishRosterAsync(string groupId, ulong revision,
        CancellationToken cancellationToken) => PublishAsync(new PublicTransferClusterEvent(
            PublicTransferClusterFrame.KindRoster, false, revision, groupId, string.Empty,
            string.Empty, []), cancellationToken);

    internal Task PublishTextAsync(string groupId, string targetPeerId, string sourceLeaseId,
        bool excludeSource, byte[] payload, CancellationToken cancellationToken) =>
        PublishAsync(new PublicTransferClusterEvent(PublicTransferClusterFrame.KindText,
            excludeSource, 0, groupId, targetPeerId, sourceLeaseId, payload), cancellationToken);

    internal Task PublishBinaryAsync(string groupId, string targetPeerId, byte[] payload,
        CancellationToken cancellationToken) => PublishAsync(new PublicTransferClusterEvent(
            PublicTransferClusterFrame.KindBinary, false, 0, groupId, targetPeerId, string.Empty,
            payload), cancellationToken);

    internal Task PublishManagementAsync(string tenantId, byte[] payload,
        CancellationToken cancellationToken) => PublishAsync(new PublicTransferClusterEvent(
            PublicTransferClusterFrame.KindManagement, false, 0, ManagementGroupId(tenantId),
            string.Empty, string.Empty, payload), cancellationToken);

    internal static string GroupId(string roomId, string roomKey) =>
        Digest((roomId ?? string.Empty) + "\0" + (roomKey ?? string.Empty));

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

    private async Task<CleanupResult> CleanupAsync(string groupId,
        CancellationToken cancellationToken)
    {
        var result = await RequireDatabase().ScriptEvaluateAsync(CleanupScript,
            [MembersKey(groupId), RevisionKey(groupId)],
            [PresencePrefix(groupId), checked((long)RevisionTtl.TotalMilliseconds)])
            .WaitAsync(cancellationToken).ConfigureAwait(false);
        var values = ResultArray(result);
        return new CleanupResult(ResultInt64(values, 0), ResultRevision(values, 1));
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
                "Tunnel:PublicTransfer:RedisUri is required when ClusterEnabled=true");
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

    private string PresencePrefix(string groupId) => $"{KeyPrefix()}:presence:{groupId}:";
    private string PresenceKey(string groupId, string memberId) => PresencePrefix(groupId) + memberId;
    private string MembersKey(string groupId) => $"{KeyPrefix()}:members:{groupId}";
    private string RevisionKey(string groupId) => $"{KeyPrefix()}:revision:{groupId}";
    private string NameKey(string displayName) => $"{KeyPrefix()}:name:{Digest(
        displayName.Trim().Normalize(NormalizationForm.FormC).ToLowerInvariant())}";
    private string RateKey(string bucket, string identity) => $"{KeyPrefix()}:rate:{Digest(
        bucket + "\0" + identity)}";
    private string EventChannel() => KeyPrefix() + ":events";
    private string KeyPrefix() => string.IsNullOrWhiteSpace(_options.RedisKeyPrefix)
        ? "shuai-tunnel:v2:public-transfer"
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
}

internal sealed record PublicTransferClusterRegistration(string? Error, ulong Revision)
{
    internal bool Accepted => Error is null;
}

internal sealed record PublicTransferClusterRoster(ulong Revision,
    IReadOnlyList<PublicTransferClusterParticipant> Participants);
