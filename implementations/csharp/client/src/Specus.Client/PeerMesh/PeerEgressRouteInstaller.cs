using System.Text;
using System.Text.Json;

namespace Specus.Client.PeerMesh;

/// <summary>Whether a prefix is already taken, and by what.</summary>
internal readonly record struct PeerEgressRouteConflictCheck(bool Present, string Existing)
{
    public static PeerEgressRouteConflictCheck None { get; } = new(false, string.Empty);
}

/// <summary>A route refused because something else already owns the prefix.</summary>
internal readonly record struct PeerEgressRouteConflict(PeerEgressRoute Route, string Existing);

/// <summary>
/// What happened, in enough detail for an operator to act.
/// </summary>
/// <param name="Conflicts">
/// Routes refused because something else already owns the prefix. The rest of the plan is applied
/// regardless: one contested prefix should not disable every other rule.
/// </param>
/// <param name="RolledBack">
/// Set when an install failed for a reason other than a conflict and the additions from this call
/// were undone.
/// </param>
internal sealed record PeerEgressRouteApplyResult(
    IReadOnlyList<PeerEgressRoute> Added,
    IReadOnlyList<PeerEgressRoute> Removed,
    IReadOnlyList<PeerEgressRouteConflict> Conflicts,
    bool RolledBack,
    Exception? Error);

/// <summary>
/// The platform's routing table. Injected so the failure and rollback paths can be driven without
/// touching the real one.
/// </summary>
internal interface IPeerEgressRouteCommander
{
    /// <summary>
    /// Reports an existing route for this exact prefix that this feature does not own. The
    /// description is what an operator reads, so it should say what is already there.
    /// </summary>
    PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route);

    void Install(PeerEgressRoute route);

    void Remove(PeerEgressRoute route);
}

/// <summary>
/// Installing routes without leaving any behind.
/// </summary>
/// <remarks>
/// Two problems this class exists to solve. A partial install has to come back out, or a failure
/// halfway through a rule set leaves the machine routing some traffic into a tunnel that was never
/// finished being set up. And a route this feature owns has to be distinguishable from one the user
/// or another tool installed, across a clean exit, a crash and a restart, because withdrawing
/// someone else's route is worse than leaving our own behind.
///
/// <para>The journal is what answers the second question. It records what was installed, on disk,
/// before the install is attempted. Written first on purpose: a journal entry for a route that
/// failed to install costs one harmless removal attempt at cleanup, while a route installed without
/// a journal entry is one nobody will ever take back.</para>
///
/// <para>Its on-disk shape is shared with the Go and Java consumers, and pinned by
/// <c>protocol/test-vectors/peer-egress-routes-v1.json</c>. A user who switches implementations on
/// one machine has to have their routes adopted and withdrawn rather than left behind by a reader
/// that did not recognise the file.</para>
///
/// <para>Not safe for concurrent use; the caller that owns the rule configuration drives it.</para>
/// </remarks>
internal sealed class PeerEgressRouteInstaller(IPeerEgressRouteCommander commander, string? journalPath)
{
    public const int JournalVersion = 1;

    private readonly List<PeerEgressRoute> _installed = [];

    /// <summary>The routes this feature currently owns.</summary>
    public IReadOnlyList<PeerEgressRoute> Installed => _installed;

    /// <summary>
    /// Reads the journal from a previous run.
    /// </summary>
    /// <remarks>
    /// A missing journal yields an empty set: there is nothing to be gained by refusing to start,
    /// and the alternative to an empty set is guessing which of the machine's routes might have
    /// been ours. A journal that exists but cannot be read throws rather than yielding an empty
    /// set, because treating it as empty would mean the routes it describes are never taken back.
    /// </remarks>
    public void Load()
    {
        _installed.Clear();
        if (string.IsNullOrEmpty(journalPath) || !File.Exists(journalPath))
        {
            return;
        }

        using var journal = JsonDocument.Parse(File.ReadAllText(journalPath));
        var root = journal.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("egress route journal is not an object");
        }
        var version = root.TryGetProperty("version", out var declared) && declared.TryGetInt32(out var value)
            ? value
            : -1;
        if (version != JournalVersion)
        {
            // A journal from a version that wrote entries differently cannot be trusted to describe
            // what is actually installed, and acting on it would mean removing prefixes by guess.
            throw new InvalidDataException(
                $"egress route journal version {version} is not {JournalVersion}");
        }

        var adopted = new List<PeerEgressRoute>();
        if (root.TryGetProperty("routes", out var routes) && routes.ValueKind == JsonValueKind.Array)
        {
            foreach (var node in routes.EnumerateArray())
            {
                var cidr = node.TryGetProperty("cidr", out var prefix) ? prefix.GetString() : null;
                var kind = node.TryGetProperty("kind", out var name) ? name.GetString() : null;
                if (string.IsNullOrEmpty(cidr))
                {
                    throw new InvalidDataException("egress route journal carries a route with no prefix");
                }
                if (kind is not ("tun" or "bypass"))
                {
                    // Refused rather than defaulted: guessing would mean withdrawing a prefix the
                    // previous run may have installed as the other kind.
                    throw new InvalidDataException($"unknown egress route kind {kind}");
                }
                var origin = node.TryGetProperty("origin", out var source) ? source.GetString() : null;
                adopted.Add(new PeerEgressRoute(
                    cidr, PeerEgressRoutePlanner.KindFromWireName(kind), origin ?? string.Empty));
            }
        }
        PeerEgressRoutePlanner.Sort(adopted);
        _installed.AddRange(adopted);
    }

    private void Save()
    {
        if (string.IsNullOrEmpty(journalPath))
        {
            return;
        }
        if (_installed.Count == 0)
        {
            File.Delete(journalPath);
            return;
        }
        PeerEgressRoutePlanner.Sort(_installed);
        // Written through a temporary file and renamed into place: a journal truncated by a crash
        // mid-write would describe fewer routes than are installed, and the difference is what gets
        // left behind.
        SecretFileWriter.WriteSecret(journalPath, Render(_installed));
    }

    /// <summary>
    /// Renders the journal.
    /// </summary>
    /// <remarks>
    /// Assembled by hand rather than through a serializer's indentation settings, so that the bytes
    /// are the ones the shared vector pins whatever a JSON library's default spacing happens to be
    /// this year. The values still go through the encoder, because an origin carries a rule's match
    /// string.
    /// </remarks>
    public static string Render(IReadOnlyList<PeerEgressRoute> routes)
    {
        var text = new StringBuilder(128);
        text.Append("{\n  \"version\": ").Append(JournalVersion).Append(",\n  \"routes\": [");
        for (var index = 0; index < routes.Count; index++)
        {
            var route = routes[index];
            text.Append(index == 0 ? "\n" : ",\n")
                .Append("    {\n      \"cidr\": ").Append(JsonSerializer.Serialize(route.Cidr))
                .Append(",\n      \"kind\": ")
                .Append(JsonSerializer.Serialize(PeerEgressRoutePlanner.WireName(route.Kind)))
                .Append(",\n      \"origin\": ").Append(JsonSerializer.Serialize(route.Origin))
                .Append("\n    }");
        }
        return text.Append(routes.Count == 0 ? "]" : "\n  ]").Append("\n}").ToString();
    }

    /// <summary>
    /// Moves the routing table to the desired set.
    /// </summary>
    /// <remarks>
    /// Withdrawals happen first, so a prefix that changed kind loses its old entry before the new
    /// one goes in. Then additions, each preceded by a conflict check.
    /// </remarks>
    public PeerEgressRouteApplyResult Apply(IReadOnlyList<PeerEgressRoute> desired)
    {
        var added = new List<PeerEgressRoute>();
        var removed = new List<PeerEgressRoute>();
        var conflicts = new List<PeerEgressRouteConflict>();
        Exception? error = null;

        var difference = PeerEgressRoutePlanner.Diff([.. _installed], desired);
        foreach (var route in difference.Remove)
        {
            try
            {
                commander.Remove(route);
            }
            catch (Exception failure)
            {
                // A route we cannot remove is dropped from the journal anyway. Keeping it would
                // mean retrying forever against a table that no longer has it, which is the more
                // likely explanation than a table refusing us.
                error = failure;
            }
            Forget(route);
            removed.Add(route);
        }

        var appliedThisCall = new List<PeerEgressRoute>();
        foreach (var route in difference.Add)
        {
            var conflict = commander.Conflict(route);
            if (conflict.Present)
            {
                // Phase one does not preempt and does not compare metrics. Refusing one prefix and
                // telling the operator beats quietly winning an argument with their own routing.
                conflicts.Add(new PeerEgressRouteConflict(route, conflict.Existing));
                continue;
            }
            // Journal before install, so a crash between the two leaves a removable record rather
            // than an unowned route.
            _installed.Add(route);
            try
            {
                Save();
            }
            catch (Exception failure)
            {
                Forget(route);
                Rollback(appliedThisCall);
                return new PeerEgressRouteApplyResult([], removed, conflicts, true, failure);
            }
            try
            {
                commander.Install(route);
            }
            catch (Exception failure)
            {
                Forget(route);
                SaveQuietly();
                Rollback(appliedThisCall);
                return new PeerEgressRouteApplyResult([], removed, conflicts, true, failure);
            }
            appliedThisCall.Add(route);
            added.Add(route);
        }

        try
        {
            Save();
        }
        catch (Exception failure)
        {
            error ??= failure;
        }
        return new PeerEgressRouteApplyResult(added, removed, conflicts, false, error);
    }

    /// <summary>
    /// Withdraws the additions from the current call only.
    /// </summary>
    /// <remarks>
    /// Only this call's, because routes from earlier calls are still wanted; a failure now is not a
    /// reason to tear down a configuration that was working a minute ago.
    /// </remarks>
    private void Rollback(List<PeerEgressRoute> applied)
    {
        for (var index = applied.Count - 1; index >= 0; index--)
        {
            try
            {
                commander.Remove(applied[index]);
            }
            catch (Exception)
            {
                // Already failing; the journal entry is what makes a retry possible.
            }
            Forget(applied[index]);
        }
        SaveQuietly();
    }

    /// <summary>
    /// Removes every route this feature owns, for shutdown or for a restart that found a journal
    /// from a previous run.
    /// </summary>
    public IReadOnlyList<PeerEgressRoute> WithdrawAll()
    {
        var owned = new List<PeerEgressRoute>(_installed);
        // Reverse order, so the bypass entries that keep the transport working outlive the routes
        // that point into the tunnel.
        PeerEgressRoutePlanner.Sort(owned);
        for (var index = owned.Count - 1; index >= 0; index--)
        {
            try
            {
                commander.Remove(owned[index]);
            }
            catch (Exception)
            {
                // Shutdown path: a route the table no longer has is the common reason to fail.
            }
        }
        _installed.Clear();
        SaveQuietly();
        return owned;
    }

    /// <summary>
    /// Reports whether a prefix is one of ours, which is what keeps a conflict check from treating
    /// this feature's own route as somebody else's.
    /// </summary>
    public bool Owns(string cidr) => _installed.Exists(route => route.Cidr == cidr);

    private void Forget(PeerEgressRoute route) => _installed.RemoveAll(existing => existing.Cidr == route.Cidr);

    private void SaveQuietly()
    {
        try
        {
            Save();
        }
        catch (Exception)
        {
            // The caller is already on a failure path and has an error to report.
        }
    }
}
