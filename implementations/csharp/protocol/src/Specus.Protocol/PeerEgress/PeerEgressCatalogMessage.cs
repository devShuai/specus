using System.Text.Json;

namespace Specus.Protocol.PeerEgress;

/// <summary>
/// The <c>egress-catalog</c> push, as a consumer reads it: which egress devices resolve names.
/// </summary>
/// <remarks>
/// Only <c>domainTargetCapable</c> is read. Nothing else in the catalogue changes what a consumer
/// does today -- whether an egress is reachable comes from Peer Mesh's own view of the peer, not
/// from the catalogue's <c>online</c> -- and a field that is decoded but unused is one more thing
/// for the three clients to disagree about.
///
/// <para>Shared vector: <c>protocol/test-vectors/peer-egress-dns-v1.json</c>, section
/// <c>catalog</c>; rules in protocol/spec/peer-egress-dns.md.</para>
/// </remarks>
/// <param name="Revision">The snapshot number, for the caller's monotonic guard.</param>
/// <param name="DomainTargetCapable">
/// Every listed egress with a usable id, and whether it announced that it resolves names. An egress
/// the catalogue does not list does not resolve names either.
/// </param>
public sealed record PeerEgressCatalogMessage(long Revision, IReadOnlyDictionary<long, bool> DomainTargetCapable)
{
    public const string Type = "egress-catalog";

    /// <summary>
    /// Reads a push, returning null for one to refuse whole: not a JSON object, a type naming
    /// something else, a revision that is not a positive integer, or <c>egresses</c> present and not
    /// a list.
    /// </summary>
    /// <remarks>
    /// Entries are forgiven one at a time. One whose <c>clientId</c> is not a positive integer is
    /// skipped rather than refusing the rest, and only a JSON <c>true</c> counts as capable: the
    /// string "true" and the number 1 are a server bug, and reading them as yes would send names to
    /// an egress that may not resolve them. Unknown keys are ignored, so a server that adds one does
    /// not stop every older client from reading the catalogue. An absent <c>egresses</c> is an
    /// empty list.
    ///
    /// <para>The revision guard is not here; it is the caller's state, per control session.</para>
    /// </remarks>
    public static PeerEgressCatalogMessage? Decode(string? payload)
    {
        if (string.IsNullOrEmpty(payload))
        {
            return null;
        }
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(payload);
        }
        catch (JsonException)
        {
            return null;
        }
        using (document)
        {
            var message = document.RootElement;
            if (message.ValueKind != JsonValueKind.Object
                || !message.TryGetProperty("type", out var type)
                || type.ValueKind != JsonValueKind.String
                || type.GetString() != Type)
            {
                return null;
            }
            if (!message.TryGetProperty("revision", out var revisionElement)
                || PositiveInteger(revisionElement) is not { } revision)
            {
                return null;
            }
            var capable = new Dictionary<long, bool>();
            if (message.TryGetProperty("egresses", out var egresses))
            {
                if (egresses.ValueKind != JsonValueKind.Array)
                {
                    return null;
                }
                foreach (var entry in egresses.EnumerateArray())
                {
                    if (entry.ValueKind != JsonValueKind.Object
                        || !entry.TryGetProperty("clientId", out var id)
                        || PositiveInteger(id) is not { } clientId)
                    {
                        continue;
                    }
                    capable[clientId] = entry.TryGetProperty("domainTargetCapable", out var flag)
                        && flag.ValueKind == JsonValueKind.True;
                }
            }
            return new PeerEgressCatalogMessage(revision, capable);
        }
    }

    /// <summary>A JSON integer above zero. A string of digits, a fraction or a boolean is not one.</summary>
    private static long? PositiveInteger(JsonElement value) =>
        value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number) && number > 0
            ? number
            : null;
}
