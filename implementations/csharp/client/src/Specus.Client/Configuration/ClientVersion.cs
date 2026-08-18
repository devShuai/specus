using System.Reflection;
using System.Globalization;
using System.Text;

namespace Specus.Client.Configuration;

/// <summary>Provides the release version injected by the build pipeline.</summary>
public static class ClientVersion
{
    private static readonly Lazy<string> Resolved = new(() => Resolve(typeof(ClientVersion).Assembly));

    public static string Current => Resolved.Value;

    internal static string Resolve(Assembly assembly)
    {
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;
        var normalized = Normalize(informational);
        if (normalized is not null)
        {
            return normalized;
        }

        var version = assembly.GetName().Version;
        if (version is null)
        {
            return "0.0.0-dev";
        }
        return $"{Math.Max(0, version.Major)}.{Math.Max(0, version.Minor)}.{Math.Max(0, version.Build)}";
    }

    internal static string? Normalize(string? value)
    {
        var trimmed = value?.Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            return null;
        }
        if (!ClientSemanticVersion.TryNormalize(trimmed, out var canonical))
        {
            return null;
        }
        var buildMetadata = canonical.IndexOf('+');
        return buildMetadata < 0 ? canonical : canonical[..buildMetadata];
    }
}

/// <summary>Strict SemVer 2.0 validation shared by update metadata and build-version reporting.</summary>
internal static class ClientSemanticVersion
{
    internal static bool TryNormalize(string? value, out string canonical)
    {
        canonical = string.Empty;
        var text = value?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }
        if (text.StartsWith('v'))
        {
            text = text[1..];
        }
        if (text.Length is 0 or > 32)
        {
            return false;
        }

        var buildAt = text.IndexOf('+');
        string[] build = [];
        if (buildAt >= 0)
        {
            build = text[(buildAt + 1)..].Split('.');
            text = text[..buildAt];
        }
        var dashAt = text.IndexOf('-');
        var core = dashAt < 0 ? text : text[..dashAt];
        string[] pre = dashAt < 0 ? [] : text[(dashAt + 1)..].Split('.');
        var parts = core.Split('.');
        if (parts.Length != 3
            || parts.Any(part => !ValidCoreNumber(part))
            || pre.Any(identifier => !ValidIdentifier(identifier)
                || IsNumeric(identifier) && identifier.Length > 1 && identifier[0] == '0')
            || build.Any(identifier => !ValidIdentifier(identifier)))
        {
            return false;
        }

        canonical = value!.Trim().StartsWith('v') ? value.Trim()[1..] : value.Trim();
        return canonical.Length <= 32;
    }

    private static bool ValidCoreNumber(string text) => IsNumeric(text)
        && (text.Length == 1 || text[0] != '0');

    private static bool IsNumeric(string identifier) => identifier.Length > 0
        && identifier.All(character => character is >= '0' and <= '9');

    private static bool ValidIdentifier(string identifier) => identifier.Length > 0
        && identifier.All(character => char.IsAsciiLetterOrDigit(character) || character == '-');
}

public static class ClientUpdateDisplay
{
    internal const int MaxDisplayTextLength = 1024;

    /// <summary>Neutralizes terminal/UI control sequences before remote text reaches logs or prompts.</summary>
    public static string? Sanitize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var builder = new StringBuilder(Math.Min(value.Length, MaxDisplayTextLength));
        var pendingSpace = false;
        for (var index = 0; index < value.Length && builder.Length < MaxDisplayTextLength; index++)
        {
            var character = value[index];
            if (character == '\u001b')
            {
                if (index + 1 < value.Length && value[index + 1] == '[')
                {
                    index += 2;
                    while (index < value.Length && value[index] is not (>= '@' and <= '~'))
                    {
                        index++;
                    }
                }
                continue;
            }
            var category = char.GetUnicodeCategory(character);
            if (character is <= '\u001f' or >= '\u007f' and <= '\u009f'
                || character is '\u2028' or '\u2029'
                || category == UnicodeCategory.Format
                || char.IsWhiteSpace(character))
            {
                pendingSpace = builder.Length > 0;
                continue;
            }
            if (pendingSpace && builder.Length < MaxDisplayTextLength)
            {
                builder.Append(' ');
                pendingSpace = false;
            }
            builder.Append(character);
        }
        return builder.ToString().Trim();
    }
}
