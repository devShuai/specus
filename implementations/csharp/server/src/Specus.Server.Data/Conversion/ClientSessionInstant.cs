namespace Specus.Server.Data.Conversion;

/// <summary>A persisted session instant without DateTimeOffset's sub-tick rounding.</summary>
public readonly record struct ClientSessionInstant(long UnixSeconds, int Nanoseconds)
    : IComparable<ClientSessionInstant>
{
    public int CompareTo(ClientSessionInstant other)
    {
        var seconds = UnixSeconds.CompareTo(other.UnixSeconds);
        return seconds != 0 ? seconds : Nanoseconds.CompareTo(other.Nanoseconds);
    }

    public static bool TryParse(string? text, out ClientSessionInstant instant)
    {
        instant = default;
        var value = text.AsSpan();
        if (value.Length < 19 || value[4] != '-' || value[7] != '-'
            || (value[10] != 'T' && value[10] != ' ') || value[13] != ':' || value[16] != ':'
            || !Digits(value[..4], out var year) || year < 1
            || !Digits(value.Slice(5, 2), out var month) || month is < 1 or > 12
            || !Digits(value.Slice(8, 2), out var day) || day < 1 || day > DateTime.DaysInMonth(year, month)
            || !Digits(value.Slice(11, 2), out var hour) || hour > 23
            || !Digits(value.Slice(14, 2), out var minute) || minute > 59
            || !Digits(value.Slice(17, 2), out var second) || second > 59)
            return false;
        var position = 19;
        var nanos = 0;
        if (position < value.Length && value[position] == '.')
        {
            position++;
            var digits = 0;
            while (position < value.Length && value[position] is >= '0' and <= '9')
            {
                if (digits == 9) return false;
                nanos = nanos * 10 + value[position++] - '0';
                digits++;
            }
            if (digits == 0) return false;
            while (digits++ < 9) nanos *= 10;
        }
        var offset = 0;
        if (value[10] == ' ')
        {
            // Legacy SQL timestamps are UTC and have no suffix.
            if (position != value.Length) return false;
        }
        else if (position + 1 != value.Length || value[position] != 'Z')
        {
            var zone = value[position..];
            if (zone.Length != 6 || (zone[0] != '+' && zone[0] != '-') || zone[3] != ':'
                || !Digits(zone.Slice(1, 2), out var hours) || hours > 23
                || !Digits(zone.Slice(4, 2), out var minutes) || minutes > 59)
                return false;
            offset = (hours * 60 + minutes) * 60;
            if (zone[0] == '-') offset = -offset;
        }
        var localSeconds = (new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc).Ticks
            - DateTime.UnixEpoch.Ticks) / TimeSpan.TicksPerSecond;
        instant = new ClientSessionInstant(localSeconds - offset, nanos);
        return true;
    }

    private static bool Digits(ReadOnlySpan<char> value, out int number)
    {
        number = 0;
        foreach (var digit in value)
        {
            if (digit is < '0' or > '9') return false;
            number = number * 10 + digit - '0';
        }
        return true;
    }
}
