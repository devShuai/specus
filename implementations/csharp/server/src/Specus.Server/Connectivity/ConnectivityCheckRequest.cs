using System.Text;
using System.Text.Json;

namespace Specus.Server.Connectivity;

/// <summary>
/// The request body of <c>POST /api/admin/http-routes/{routeId}/connectivity-check</c>: empty, or a
/// JSON object whose only key is an optional string <c>path</c> (service-connectivity-check.md
/// section 3.1). Anything else is <c>CHECK_REQUEST_INVALID</c>.
/// </summary>
internal static class ConnectivityCheckRequest
{
    private const string PathKey = "path";

    /// <summary>
    /// Parses a body of at most <see cref="ConnectivityCheck.MaxBodyBytes"/> bytes. Returns the probe
    /// path, <see cref="ConnectivityCheck.DefaultPath"/> when absent, or null when the body is invalid.
    /// </summary>
    public static string? ParsePath(ReadOnlySpan<byte> body)
    {
        if (body.Length > ConnectivityCheck.MaxBodyBytes)
        {
            return null;
        }
        if (IsJsonWhitespace(body))
        {
            return ConnectivityCheck.DefaultPath;
        }

        string? path = null;
        var seenPath = false;
        try
        {
            var reader = new Utf8JsonReader(body, new JsonReaderOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
                MaxDepth = 4,
            });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return null;
            }
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    break;
                }
                if (reader.TokenType != JsonTokenType.PropertyName
                    || !reader.ValueTextEquals(PathKey) || seenPath)
                {
                    // Unknown keys, and a repeated "path" whose meaning would depend on the parser.
                    return null;
                }
                seenPath = true;
                if (!reader.Read() || reader.TokenType != JsonTokenType.String)
                {
                    return null;
                }
                path = reader.GetString();
            }
            if (reader.TokenType != JsonTokenType.EndObject || reader.Read())
            {
                return null;
            }
        }
        catch (JsonException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }

        if (!seenPath)
        {
            return ConnectivityCheck.DefaultPath;
        }
        return path is not null && IsValidPath(path) ? path : null;
    }

    /// <summary>
    /// 1..256 bytes, starting with one '/', made of RFC 3986 <c>pchar</c> and '/' (a '%' only as a
    /// valid <c>%XX</c>), and no '.' or '..' segment, also when spelled <c>%2e</c>.
    /// </summary>
    public static bool IsValidPath(string path)
    {
        var bytes = Encoding.UTF8.GetByteCount(path);
        if (bytes is < 1 or > ConnectivityCheck.MaxPathBytes
            || path[0] != '/'
            || (path.Length > 1 && path[1] == '/'))
        {
            return false;
        }
        for (var i = 0; i < path.Length; i++)
        {
            var ch = path[i];
            if (ch == '%')
            {
                if (i + 2 >= path.Length || !char.IsAsciiHexDigit(path[i + 1]) || !char.IsAsciiHexDigit(path[i + 2]))
                {
                    return false;
                }
                i += 2;
                continue;
            }
            if (!IsPathChar(ch))
            {
                return false;
            }
        }
        foreach (var segment in path.Split('/'))
        {
            var decoded = segment.Replace("%2e", ".", StringComparison.Ordinal)
                .Replace("%2E", ".", StringComparison.Ordinal);
            if (decoded is "." or "..")
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsPathChar(char ch) =>
        char.IsAsciiLetterOrDigit(ch)
        || ch is '-' or '.' or '_' or '~' or '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+'
            or ',' or ';' or '=' or ':' or '@' or '/';

    private static bool IsJsonWhitespace(ReadOnlySpan<byte> body)
    {
        foreach (var b in body)
        {
            if (b is not ((byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n'))
            {
                return false;
            }
        }
        return true;
    }
}
