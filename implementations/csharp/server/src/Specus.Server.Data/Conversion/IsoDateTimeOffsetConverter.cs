using System.Globalization;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Specus.Server.Data.Conversion;

/// <summary>
/// Stores <see cref="DateTimeOffset"/> as the canonical ISO-8601 UTC string Java's
/// <c>Instant.toString()</c> emits — e.g. <c>2026-06-19T12:34:56.789012345Z</c> — so SQLite TEXT
/// columns sort by time when sorted alphabetically. The frontend (<c>app.js</c>) and Java
/// queries both rely on this property.
///
/// <para>Read path tolerates trailing-zero variants and slightly different fractional widths
/// because Java's <c>Instant</c> output truncates trailing-zero subseconds.</para>
/// </summary>
public sealed class IsoDateTimeOffsetConverter : ValueConverter<DateTimeOffset, string>
{
    /// <summary>
    /// Round-trip ISO format with explicit Z. We use <c>"u"</c>'s structure but always force UTC and
    /// include sub-second precision so two timestamps generated within the same second remain
    /// orderable.
    /// </summary>
    private const string IsoFormat = "yyyy-MM-ddTHH:mm:ss.fffffffZ";

    public IsoDateTimeOffsetConverter()
        : base(
            v => Format(v),
            v => Parse(v))
    {
    }

    public static string Format(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(IsoFormat, CultureInfo.InvariantCulture);

    public static DateTimeOffset Parse(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
}

/// <summary>Same shape, but allows null for columns like <c>DisconnectedAt</c>.</summary>
public sealed class IsoNullableDateTimeOffsetConverter : ValueConverter<DateTimeOffset?, string?>
{
    public IsoNullableDateTimeOffsetConverter()
        : base(
            v => v.HasValue ? IsoDateTimeOffsetConverter.Format(v.Value) : null,
            v => string.IsNullOrEmpty(v) ? null : IsoDateTimeOffsetConverter.Parse(v))
    {
    }
}
