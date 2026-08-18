using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Specus.Server.Data.Entities;

namespace Specus.Server.Authentication;

public sealed class ClientAuthSessionStore
{
    private readonly ConcurrentDictionary<string, ClientAuthSession> _byTokenHash = new();
    private readonly ConcurrentDictionary<long, string> _tokenHashBySessionId = new();

    public ClientAuthSession Create(ClientCredential credential, ClientIdentity identity,
        ClientAccount account, TimeSpan ttl, ClientEnvironmentInfo environment)
    {
        var accessToken = "cs_" + Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var session = new ClientAuthSession
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = credential.TenantId,
            CredentialId = credential.Id,
            IdentityId = identity.Id,
            ClientId = account.Id,
            ClientName = account.ClientName,
            AccessToken = accessToken,
            TokenHash = TokenHash(accessToken),
            ExpiresAt = DateTimeOffset.UtcNow.Add(ttl),
            MachineFingerprint = environment.MachineFingerprint ?? "",
            OsUser = environment.OsUser ?? "",
            Hostname = environment.Hostname ?? "",
            Status = ClientAuthSessionStatus.HttpAuthenticated,
        };
        _byTokenHash[session.TokenHash] = session;
        _tokenHashBySessionId[session.Id] = session.TokenHash;
        return session;
    }

    public ClientAuthSession? Find(long? sessionId, string? accessToken)
    {
        if (sessionId is null or <= 0 || string.IsNullOrWhiteSpace(accessToken))
        {
            return null;
        }
        var hash = TokenHash(accessToken);
        if (!_tokenHashBySessionId.TryGetValue(sessionId.Value, out var storedHash)
            || !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(hash), Encoding.ASCII.GetBytes(storedHash)))
        {
            return null;
        }
        return _byTokenHash.TryGetValue(hash, out var session) ? session : null;
    }

    /// <summary>
    /// Resolves non-secret session metadata for audit attribution. Authentication must still use
    /// <see cref="Find"/>; this lookup deliberately does not validate the supplied access token.
    /// </summary>
    public ClientAuthSession? FindById(long? sessionId)
    {
        if (sessionId is null or <= 0
            || !_tokenHashBySessionId.TryGetValue(sessionId.Value, out var hash))
        {
            return null;
        }
        return _byTokenHash.TryGetValue(hash, out var session) ? session : null;
    }

    public int CountOnlineByCredential(long credentialId) =>
        _byTokenHash.Values.Count(s => s.CredentialId == credentialId
            && s.Status == ClientAuthSessionStatus.NettyOnline);

    public int CountOnlineByMachineUser(long credentialId, string machineFingerprint, string osUser) =>
        _byTokenHash.Values.Count(s => s.CredentialId == credentialId
            && s.Status == ClientAuthSessionStatus.NettyOnline
            && string.Equals(s.MachineFingerprint, machineFingerprint, StringComparison.Ordinal)
            && string.Equals(s.OsUser, osUser, StringComparison.Ordinal));

    public void MarkOnline(ClientAuthSession session, string channelId, string? remoteAddress)
    {
        session.Status = ClientAuthSessionStatus.NettyOnline;
        session.ChannelId = channelId;
        session.RemoteAddress = remoteAddress;
        session.NettyConnectedAt = DateTimeOffset.UtcNow;
        session.DisconnectedAt = null;
    }

    public void MarkDisconnected(long? sessionId)
    {
        if (sessionId is null or <= 0
            || !_tokenHashBySessionId.TryGetValue(sessionId.Value, out var hash)
            || !_byTokenHash.TryGetValue(hash, out var session))
        {
            return;
        }
        session.Status = ClientAuthSessionStatus.Disconnected;
        session.DisconnectedAt = DateTimeOffset.UtcNow;
    }

    private static string TokenHash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();
}

public sealed class ClientAuthSession
{
    public long Id { get; init; }
    public string TenantId { get; init; } = "default";
    public long CredentialId { get; init; }
    public long IdentityId { get; init; }
    public long ClientId { get; init; }
    public string ClientName { get; init; } = "";
    public string AccessToken { get; init; } = "";
    public string TokenHash { get; init; } = "";
    public DateTimeOffset ExpiresAt { get; init; }
    public string MachineFingerprint { get; init; } = "";
    public string OsUser { get; init; } = "";
    public string Hostname { get; init; } = "";
    public ClientAuthSessionStatus Status { get; set; }
    public string? ChannelId { get; set; }
    public string? RemoteAddress { get; set; }
    public DateTimeOffset? NettyConnectedAt { get; set; }
    public DateTimeOffset? DisconnectedAt { get; set; }
}

public enum ClientAuthSessionStatus
{
    HttpAuthenticated,
    NettyOnline,
    Disconnected,
}
