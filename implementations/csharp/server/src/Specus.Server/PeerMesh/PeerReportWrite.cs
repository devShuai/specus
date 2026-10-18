using Microsoft.EntityFrameworkCore;
using Specus.Server.ControlChannel;
using Specus.Server.Data.Entities;
using Specus.Server.Persistence;

namespace Specus.Server.PeerMesh;

public sealed partial class PeerMeshService
{
    private PeerReceiver RequireOriginalPeerReporter(ClientAccount hint, long? sessionId, SpecusConnectionContext? transport)
    {
        var origin = CapturePeerReceiver(hint);
        if (origin is null || (sessionId is not null && origin.SessionId != sessionId)
            || (transport is not null && !ReferenceEquals(origin.Transport, transport)))
            throw new ArgumentException("reporter control session is not current");
        return origin;
    }

    private static void RequireReportParticipant(PeerMeshSession session, PeerReceiver origin)
    {
        if (session.TenantId != origin.Tenant || (session.SourceClientId != origin.ClientId && session.TargetClientId != origin.ClientId))
            throw new ArgumentException("peer session report source mismatch");
    }

    private async Task ApplyAuthorizedPeerReportAsync(ClientAccount hint, PeerControlMessage report, long? sessionId,
        SpecusConnectionContext? transport, CancellationToken ct)
    {
        var origin = RequireOriginalPeerReporter(hint, sessionId, transport);
        PeerMeshSession? sessionHint = null;
        if (report.Type != TypeDeviceReport)
        {
            if (report.SessionId is null or <= 0) throw new ArgumentException("sessionId is required");
            sessionHint = await _db.PeerMeshSessions.AsNoTracking().SingleOrDefaultAsync(s => s.Id == report.SessionId, ct).ConfigureAwait(false)
                ?? throw new ArgumentException("peer session not found");
            RequireReportParticipant(sessionHint, origin);
        }
        await using var transaction = await BeginPeerWriteAsync(ct).ConfigureAwait(false);
        var parents = sessionHint is null ? Array.Empty<long>() : new[] { sessionHint.SourceClientId, sessionHint.TargetClientId };
        var reporter = await LockAndReadPeerReceiverAsync(origin, ct, parents).ConfigureAwait(false)
            ?? throw new ArgumentException("reporter control session is not current");
        if (report.Type == TypeDeviceReport)
        {
            var deviceHint = await _db.PeerMeshDevices.AsNoTracking().SingleOrDefaultAsync(d => d.TenantId == origin.Tenant && d.ClientId == origin.ClientId, ct).ConfigureAwait(false)
                ?? throw new ArgumentException("peer device no longer exists");
            await ClientOwnershipWrite.LockAsync<PeerMeshDevice>(_db, deviceHint.Id, origin.Tenant, ct).ConfigureAwait(false);
            var current = await _db.PeerMeshDevices.AsNoTracking().SingleOrDefaultAsync(d => d.Id == deviceHint.Id, ct).ConfigureAwait(false);
            if (current is null || current.TenantId != origin.Tenant || current.ClientId != origin.ClientId)
                throw new ArgumentException("peer device no longer exists");
            if (!PeerReceiverIsCurrent(origin)) throw new ArgumentException("reporter control session is not current");
            // Only coordinated HTTP startup creates devices. A late status report cannot
            // recreate a device removed by a deletion/management transaction.
            await ReportDeviceAsync(reporter.Account, TrackPeerCurrent(current, current.Id), report, ct).ConfigureAwait(false);
        }
        else
        {
            await ClientOwnershipWrite.LockAsync<PeerMeshSession>(_db, sessionHint!.Id, origin.Tenant, ct).ConfigureAwait(false);
            var current = await _db.PeerMeshSessions.AsNoTracking().SingleOrDefaultAsync(s => s.Id == sessionHint.Id, ct).ConfigureAwait(false)
                ?? throw new ArgumentException("peer session not found");
            RequireReportParticipant(current, origin);
            if (current.SourceClientId != sessionHint.SourceClientId || current.TargetClientId != sessionHint.TargetClientId)
                throw new ArgumentException("peer session participants changed");
            if (report.Type != TypeClose && current.Status != StatusClosed && current.ExpiresAt > DateTimeOffset.UtcNow)
            {
                var otherId = current.SourceClientId == origin.ClientId ? current.TargetClientId : current.SourceClientId;
                var other = await _db.ClientAccounts.AsNoTracking().SingleOrDefaultAsync(a => a.Id == otherId, ct).ConfigureAwait(false);
                if (other is not { Enabled: true } || other.TenantId != origin.Tenant
                    || !await CanPeerAsync(reporter.Account, other, ct).ConfigureAwait(false))
                    throw new PeerSignalUndeliverableException("peer report access is no longer allowed");
            }
            if (!PeerReceiverIsCurrent(origin)) throw new ArgumentException("reporter control session is not current");
            var tracked = TrackPeerCurrent(current, current.Id);
            switch (report.Type)
            {
                case TypePathReport: await ReportPathAsync(tracked, report, ct).ConfigureAwait(false); break;
                case TypeTrafficReport: await ReportTrafficAsync(tracked, report, ct).ConfigureAwait(false); break;
                case TypeClose: await CloseSessionFromClientAsync(tracked, ct).ConfigureAwait(false); break;
            }
        }
        if (!PeerReceiverIsCurrent(origin)) throw new ArgumentException("reporter control session is not current");
        await transaction.CommitAsync(ct).ConfigureAwait(false);
    }
}
