using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Specus.Server.Management;

/// <summary>
/// Reconstructs an HTTP body for the detail API from the stored wire bytes. The database and
/// Elasticsearch representations deliberately retain the original compressed/binary payload;
/// this codec only decodes it when an operator opens a detail record.
/// </summary>
internal static partial class HttpBodyDataCodec
{
    public static string ToDisplayText(byte[]? bodyData, string? contentType,
        string? headers, string? fallbackText)
    {
        if (bodyData is null || bodyData.Length == 0)
        {
            return fallbackText ?? string.Empty;
        }

        var contentEncoding = HeaderValue(headers, "content-encoding");
        if (HasEncodedBody(contentEncoding))
        {
            var decoded = DecodeContentEncoding(bodyData, contentEncoding!);
            if (decoded is not null)
            {
                return ToDisplayText(decoded, contentType);
            }

            return DataUrl("application/octet-stream", bodyData);
        }
        return ToDisplayText(bodyData, contentType);
    }

    private static string ToDisplayText(byte[] bodyData, string? contentType)
    {
        if (!IsTextBody(contentType) && !LooksLikeText(bodyData))
        {
            return DataUrl(MediaType(contentType), bodyData);
        }
        return SanitizeText(Encoding.UTF8.GetString(bodyData));
    }

    private static byte[]? DecodeContentEncoding(byte[] bodyData, string contentEncoding)
    {
        var current = bodyData;
        try
        {
            foreach (var token in contentEncoding
                         .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                         .Reverse())
            {
                if (token.Equals("identity", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                current = DecodeOne(current, token) ?? throw new InvalidDataException();
            }
            return current;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or ArgumentException)
        {
            return null;
        }
    }

    private static byte[]? DecodeOne(byte[] data, string token)
    {
        if (token.Equals("gzip", StringComparison.OrdinalIgnoreCase)
            || token.Equals("x-gzip", StringComparison.OrdinalIgnoreCase))
        {
            return ReadDecoded(data, source => new GZipStream(source, CompressionMode.Decompress));
        }
        if (token.Equals("deflate", StringComparison.OrdinalIgnoreCase)
            || token.Equals("x-deflate", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                return ReadDecoded(data, source => new ZLibStream(source, CompressionMode.Decompress));
            }
            catch (InvalidDataException)
            {
                return ReadDecoded(data, source => new DeflateStream(source, CompressionMode.Decompress));
            }
        }
        if (token.Equals("br", StringComparison.OrdinalIgnoreCase))
        {
            return ReadDecoded(data, source => new BrotliStream(source, CompressionMode.Decompress));
        }
        return null;
    }

    /// <summary>
    /// Reading a decompressor to the end lets a few kilobytes of crafted input cost gigabytes of
    /// memory, so both an absolute size and an expansion ratio are enforced.
    /// </summary>
    private static byte[] ReadDecoded(byte[] data, Func<Stream, Stream> decoderFactory)
    {
        using var source = new MemoryStream(data);
        using var decoder = decoderFactory(source);
        return Specus.Server.Http.DecompressionLimits.ReadAllBounded(decoder, data.Length);
    }

    private static string? HeaderValue(string? headers, string name)
    {
        if (string.IsNullOrWhiteSpace(headers))
        {
            return null;
        }
        foreach (var header in headers.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = header.IndexOf(':', StringComparison.Ordinal);
            if (separator > 0 && header[..separator].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return header[(separator + 1)..].Trim();
            }
        }
        return null;
    }

    private static bool HasEncodedBody(string? contentEncoding) =>
        !string.IsNullOrWhiteSpace(contentEncoding)
        && contentEncoding.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Any(token => !token.Equals("identity", StringComparison.OrdinalIgnoreCase));

    private static bool IsTextBody(string? contentType)
    {
        var media = MediaType(contentType);
        return media.StartsWith("text/", StringComparison.Ordinal)
               || media == "application/json"
               || media.EndsWith("+json", StringComparison.Ordinal)
               || media == "application/xml"
               || media.EndsWith("+xml", StringComparison.Ordinal)
               || media == "application/x-www-form-urlencoded"
               || media == "application/graphql"
               || media == "application/javascript"
               || media == "application/ecmascript"
               || media == "application/x-yaml"
               || media == "application/yaml";
    }

    private static bool LooksLikeText(byte[] data)
    {
        var inspected = Math.Min(data.Length, 512);
        var controls = 0;
        for (var index = 0; index < inspected; index++)
        {
            var value = data[index];
            if (value == 0)
            {
                return false;
            }
            if (value < 0x20 && value is not (byte)'\r' and not (byte)'\n' and not (byte)'\t')
            {
                controls++;
            }
        }
        return inspected == 0 || controls * 10 <= inspected;
    }

    private static string MediaType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            return "application/octet-stream";
        }
        var media = contentType.Split(';', 2)[0].Trim().ToLowerInvariant();
        return MediaTypePattern().IsMatch(media) ? media : "application/octet-stream";
    }

    private static string DataUrl(string mediaType, byte[] bodyData) =>
        $"data:{mediaType};base64,{Convert.ToBase64String(bodyData)}";

    private static string SanitizeText(string text)
    {
        if (text.Length == 0)
        {
            return string.Empty;
        }
        var result = new StringBuilder(text.Length);
        foreach (var character in text)
        {
            result.Append(char.IsControl(character) && character is not '\r' and not '\n' and not '\t'
                || char.IsSurrogate(character)
                    ? '.'
                    : character);
        }
        return result.ToString();
    }

    [GeneratedRegex("^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex MediaTypePattern();
}
