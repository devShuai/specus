using Microsoft.EntityFrameworkCore;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Http;
using Specus.Server.Nat;
using Specus.Server.Sessions;

namespace Specus.Server.Connectivity;

/// <summary>Reads the route and its client account from the management database.</summary>
internal sealed class DbConnectivityRouteSource(SpecusDbContext db) : IConnectivityRouteSource
{
    public async Task<ConnectivityRouteTarget?> FindAsync(long routeId, CancellationToken cancellationToken)
    {
        var route = await db.HttpRouteMappings.AsNoTracking()
            .FirstOrDefaultAsync(r => r.Id == routeId, cancellationToken)
            .ConfigureAwait(false);
        if (route is null)
        {
            return null;
        }
        var account = await db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(a => a.Id == route.ClientId, cancellationToken)
            .ConfigureAwait(false);
        return account is null ? null : new ConnectivityRouteTarget(route, account);
    }
}

/// <summary>
/// The device side over this process's connections: presence from the session registry, probes on
/// the NAT data connection through <see cref="DirectHttpDispatcher"/>, the same HTTP stream the
/// public ingress uses, but without its Basic auth, path rewrite, traffic accounting, traffic
/// detail or media capture.
/// </summary>
internal sealed class NatConnectivityDeviceGateway(
    SessionRegistry sessions,
    DirectHttpDispatcher dispatcher,
    ClientAuthSessionStore clientSessions) : IConnectivityDeviceGateway
{
    private static readonly TimeSpan ResetWriteTimeout = TimeSpan.FromSeconds(5);

    public ConnectivityDevicePresence Presence(string clientName)
    {
        var control = sessions.Find(clientName);
        if (control is null)
        {
            return ConnectivityDevicePresence.Offline;
        }
        var data = sessions.FindData(clientName);
        return data is null
               || data.ClientSessionId != control.ClientSessionId
               || data.Lifetime.IsCancellationRequested
            ? ConnectivityDevicePresence.DataChannelDown
            : ConnectivityDevicePresence.Online;
    }

    public async Task<ConnectivityProbeAnswer> ProbeAsync(string clientName,
        Dictionary<string, object?> metadata, TimeSpan budget, CancellationToken cancellationToken)
    {
        using var budgetCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budgetCts.CancelAfter(budget);

        HttpSpecusStream stream;
        try
        {
            stream = await dispatcher.OpenAsync(clientName, metadata, budgetCts.Token).ConfigureAwait(false);
        }
        catch (DirectHttpSpecusException)
        {
            // The data connection vanished after the presence check, or writing OPEN failed. This
            // server has no per-connection HTTP stream cap, so there is no stream-limit outcome.
            return ConnectivityProbeAnswer.NotOpened(ConnectivityOpenFailure.WriteFailed);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ConnectivityProbeAnswer.NoAnswer();
        }

        // Only the head matters: a body relayed before the RST lands is dropped, never queued and
        // never credited back.
        stream.DiscardResponseBody();
        // The session owning the connection this probe actually runs on decides whether its RST
        // classification is trusted, not whichever session is current by the time it answers.
        var capability = clientSessions.FindById(stream.ConnectionSessionId)?.HttpRouteCapabilityVersion ?? 0;
        try
        {
            try
            {
                await stream.FinishRequestAsync(null, budgetCts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return ConnectivityProbeAnswer.NotOpened(ConnectivityOpenFailure.WriteFailed);
            }

            var head = await stream.WaitResponseHeadAsync(budgetCts.Token).ConfigureAwait(false);
            var status = DirectHttpEndpoints.AsInt(head, "statusCode");
            // The exchange is over with the head: the body is never read and no credit is granted.
            if (!stream.ResponseEnded)
            {
                await ResetQuietlyAsync(stream, "connectivity check finished").ConfigureAwait(false);
            }
            return ConnectivityProbeAnswer.Response(status);
        }
        catch (HttpStreamResetException reset) when (reset.LinkLost)
        {
            return ConnectivityProbeAnswer.LinkLost();
        }
        catch (HttpStreamResetException reset)
        {
            // Only the classification travels on; the reason text never leaves the stream.
            return ConnectivityProbeAnswer.Reset(reset.Failure, capability);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            await ResetQuietlyAsync(stream, "connectivity check budget expired").ConfigureAwait(false);
            return ConnectivityProbeAnswer.NoAnswer();
        }
        catch (OperationCanceledException)
        {
            await ResetQuietlyAsync(stream, "connectivity check cancelled").ConfigureAwait(false);
            throw;
        }
        catch (InvalidOperationException)
        {
            // The event channel completed without any event: the stream was closed underneath us
            // because its connection went away.
            return ConnectivityProbeAnswer.LinkLost();
        }
        finally
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task ResetQuietlyAsync(HttpSpecusStream stream, string reason)
    {
        using var timeout = new CancellationTokenSource(ResetWriteTimeout);
        try
        {
            await stream.ResetAsync(ConnectivityCheck.ProbeResetCode, reason, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException
                                       or InvalidOperationException)
        {
            // Best effort: the connection is going away, which ends the stream for the client too.
        }
    }
}
