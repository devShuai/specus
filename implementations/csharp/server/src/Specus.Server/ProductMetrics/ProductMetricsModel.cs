using System.Globalization;
using System.Text.Json;
using System.Text.Unicode;

namespace Specus.Server.ProductMetrics;

/// <summary>
/// The closed vocabulary, buckets, rates and request schemas of the opt-in product metrics
/// (protocol/spec/product-metrics.md sections 4, 5 and 7). Pure functions only.
/// </summary>
public static class ProductMetricsModel
{
    public const int SchemaVersion = 1;
    public const int DisclosureVersion = 1;
    public const int RetentionDays = 180;
    public const int WindowDays = 14;
    public const int MaxBodyBytes = 4096;
    public const int MaxEvents = 20;
    public const int MaxRangeDays = 180;
    public const int DefaultPerUserEventsPerMinute = 120;
    public const int DefaultPerTenantEventsPerMinute = 3000;
    public const string CacheControl = "private, no-store";

    public const string StepAccountCreated = "account_created";
    public const string StepSignedIn = "signed_in";
    public const string StepCredentialCreated = "credential_created";
    public const string StepClientOnline = "client_online";
    public const string StepServicePublished = "service_published";
    public const string NoDuration = "none";

    public const long DayMs = 86_400_000L;
    public const long WindowMs = WindowDays * DayMs;

    public static readonly IReadOnlyList<string> Steps =
        [StepAccountCreated, StepSignedIn, StepCredentialCreated, StepClientOnline, StepServicePublished];
    public static readonly IReadOnlyList<string> Modes = ["device", "link"];
    public static readonly IReadOnlyList<string> Paths = ["direct", "turn", "cloud", "unestablished"];
    public static readonly IReadOnlyList<string> Attempts = ["first", "retry_after_failure", "retry_after_cancel"];
    public static readonly IReadOnlyList<string> Outcomes = ["success", "failure", "cancelled"];
    public static readonly IReadOnlyList<string> SizeBuckets = ["lt1m", "1m-16m", "16m-128m", "128m-512m", "gt512m"];
    public static readonly IReadOnlyList<string> DurationBuckets =
        ["lt10m", "10m-30m", "30m-2h", "2h-24h", "1d-3d", "3d-14d"];

    private const long Mib = 1L << 20;
    private static readonly long[] DurationUpperBounds = [600, 1800, 7200, 86400, 259200, WindowDays * 86400L];
    private static readonly string[] EventKeys = ["mode", "path", "sizeBucket", "attempt", "outcome"];

    /// <summary>Bucket of a file size; an empty or negative size has none.</summary>
    public static string? SizeBucket(long size) => size switch
    {
        < 1 => null,
        < Mib => "lt1m",
        < 16 * Mib => "1m-16m",
        <= 128 * Mib => "16m-128m",
        <= 512 * Mib => "128m-512m",
        _ => "gt512m",
    };

    /// <summary>Completion-time bucket (negative counts as zero); none at or past the window.</summary>
    public static string? DurationBucket(long seconds)
    {
        var clamped = Math.Max(0, seconds);
        for (var i = 0; i < DurationUpperBounds.Length; i++)
        {
            if (clamped < DurationUpperBounds[i])
            {
                return DurationBuckets[i];
            }
        }
        return null;
    }

    /// <summary>numerator/denominator in basis points rounded half up; null without a denominator.</summary>
    public static long? RateBp(long numerator, long denominator) =>
        denominator == 0 ? null : (20_000L * numerator + denominator) / (2 * denominator);

    public sealed record Event(string Mode, string Path, string SizeBucket, string Attempt, string Outcome)
    {
        internal bool IsValid()
        {
            if (!Modes.Contains(Mode) || !Paths.Contains(Path) || !SizeBuckets.Contains(SizeBucket)
                || !Attempts.Contains(Attempt) || !Outcomes.Contains(Outcome))
            {
                return false;
            }
            if (Mode == "link" && Path is not ("cloud" or "unestablished"))
            {
                return false;
            }
            return !(Outcome == "success" && Path == "unestablished");
        }
    }

    public enum IngestRefusal
    {
        None,
        TooLarge,
        Invalid,
    }

    /// <summary>
    /// Validates a transfer-outcome body against the closed schema of section 7.4. The size is
    /// checked on the raw bytes first; any extra, missing or duplicated key, any value of the wrong
    /// JSON type, invalid UTF-8 and any trailing content refuse the whole request.
    /// </summary>
    public static IngestRefusal ParseIngest(ReadOnlySpan<byte> body, out List<Event> events)
    {
        events = [];
        if (body.Length > MaxBodyBytes)
        {
            return IngestRefusal.TooLarge;
        }
        if (!Utf8.IsValid(body))
        {
            return IngestRefusal.Invalid;
        }
        try
        {
            var reader = new Utf8JsonReader(body, new JsonReaderOptions { MaxDepth = 8 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return IngestRefusal.Invalid;
            }
            var version = false;
            List<Event>? parsed = null;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var name = reader.GetString();
                reader.Read();
                if (name == "schemaVersion" && !version)
                {
                    if (reader.TokenType != JsonTokenType.Number || !reader.ValueSpan.SequenceEqual("1"u8))
                    {
                        return IngestRefusal.Invalid;
                    }
                    version = true;
                }
                else if (name == "events" && parsed is null)
                {
                    parsed = ReadEvents(ref reader);
                    if (parsed is null)
                    {
                        return IngestRefusal.Invalid;
                    }
                }
                else
                {
                    return IngestRefusal.Invalid;
                }
            }
            if (reader.TokenType != JsonTokenType.EndObject || reader.Read() || !version || parsed is null)
            {
                return IngestRefusal.Invalid;
            }
            events = parsed;
            return IngestRefusal.None;
        }
        catch (JsonException)
        {
            return IngestRefusal.Invalid;
        }
        catch (InvalidOperationException)
        {
            return IngestRefusal.Invalid;
        }
    }

    private static List<Event>? ReadEvents(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.StartArray)
        {
            return null;
        }
        var events = new List<Event>();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if (events.Count == MaxEvents || reader.TokenType != JsonTokenType.StartObject)
            {
                return null;
            }
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var name = reader.GetString()!;
                reader.Read();
                if (!EventKeys.Contains(name) || values.ContainsKey(name) || reader.TokenType != JsonTokenType.String)
                {
                    return null;
                }
                values[name] = reader.GetString()!;
            }
            if (reader.TokenType != JsonTokenType.EndObject || values.Count != EventKeys.Length)
            {
                return null;
            }
            var item = new Event(values["mode"], values["path"], values["sizeBucket"], values["attempt"],
                values["outcome"]);
            if (!item.IsValid())
            {
                return null;
            }
            events.Add(item);
        }
        return reader.TokenType == JsonTokenType.EndArray && events.Count > 0 ? events : null;
    }

    /// <summary>A validated PUT /settings body; <c>Disclosure</c> is the integer literal or null.</summary>
    public sealed record SettingsUpdate(bool Enabled, string? Disclosure);

    /// <summary>Validates the closed PUT body: enabled (boolean, required), disclosureVersion (integer).</summary>
    public static SettingsUpdate? ParseSettingsUpdate(ReadOnlySpan<byte> body)
    {
        if (!Utf8.IsValid(body))
        {
            return null;
        }
        try
        {
            var reader = new Utf8JsonReader(body, new JsonReaderOptions { MaxDepth = 4 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return null;
            }
            bool? enabled = null;
            string? disclosure = null;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var name = reader.GetString();
                reader.Read();
                if (name == "enabled" && enabled is null
                    && reader.TokenType is JsonTokenType.True or JsonTokenType.False)
                {
                    enabled = reader.GetBoolean();
                }
                else if (name == "disclosureVersion" && disclosure is null && reader.TokenType == JsonTokenType.Number
                         && IsIntegerLiteral(reader.ValueSpan))
                {
                    disclosure = System.Text.Encoding.ASCII.GetString(reader.ValueSpan);
                }
                else
                {
                    return null;
                }
            }
            if (reader.TokenType != JsonTokenType.EndObject || reader.Read() || enabled is null)
            {
                return null;
            }
            return new SettingsUpdate(enabled.Value, disclosure);
        }
        catch (JsonException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static bool IsIntegerLiteral(ReadOnlySpan<byte> number)
    {
        foreach (var b in number)
        {
            if (b is not ((>= (byte)'0' and <= (byte)'9') or (byte)'-'))
            {
                return false;
            }
        }
        return number.Length > 0;
    }

    /// <summary>UTC calendar date of an epoch-millisecond instant.</summary>
    public static string DayOf(long epochMs) =>
        DateTimeOffset.FromUnixTimeMilliseconds(epochMs).UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    /// <summary>An epoch-millisecond instant to the second, as the contract's examples spell it.</summary>
    public static string Instant(long epochMs) =>
        DateTimeOffset.FromUnixTimeMilliseconds(epochMs).UtcDateTime
            .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
