using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShuaiTunnel.Client.PeerMesh;

internal static class PeerAppMessageCodec
{
    public const string TypeMessage = "message";
    public const string TypeAck = "ack";

    private static readonly byte[] PrefixV1 = Encoding.ASCII.GetBytes("STMSG1\n");
    private static readonly byte[] PrefixV2 = Encoding.ASCII.GetBytes("STMSG2\n");

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
    };

    public static bool LooksLike(byte[] payload)
    {
        return payload.Length >= PrefixV1.Length
            && (payload.AsSpan(0, PrefixV1.Length).SequenceEqual(PrefixV1)
                || payload.AsSpan(0, PrefixV2.Length).SequenceEqual(PrefixV2));
    }

    public static bool TryDecode(byte[] payload, out PeerAppMessage message)
    {
        message = default!;
        if (!LooksLike(payload))
        {
            return false;
        }
        try
        {
            var decoded = JsonSerializer.Deserialize<PeerAppMessage>(
                payload.AsSpan(PrefixLength(payload)),
                JsonOptions);
            if (decoded is null || string.IsNullOrWhiteSpace(decoded.Type))
            {
                return false;
            }
            message = decoded;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public static byte[] Encode(PeerAppMessage message)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions);
        var payload = new byte[PrefixV2.Length + json.Length];
        PrefixV2.CopyTo(payload, 0);
        json.CopyTo(payload.AsSpan(PrefixV2.Length));
        return payload;
    }

    public static string DisplayText(PeerAppMessage message)
    {
        if (message.Attachment is null)
        {
            return message.Message ?? "";
        }
        var size = message.Attachment.SizeBytes > 0 ? FormatBytes(message.Attachment.SizeBytes) : "-";
        var text = string.IsNullOrWhiteSpace(message.Message) ? "" : $"{message.Message} ";
        return $"{text}[附件] {FirstNonEmpty(message.Attachment.FileName, message.Attachment.ObjectId, "attachment")} · {FirstNonEmpty(message.Attachment.MimeType, "application/octet-stream")} · {size}";
    }

    private static int PrefixLength(byte[] payload) =>
        payload.AsSpan(0, PrefixV2.Length).SequenceEqual(PrefixV2) ? PrefixV2.Length : PrefixV1.Length;

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)Math.Max(0L, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return unit == 0 ? $"{value:0} {units[unit]}" : $"{value:0.##} {units[unit]}";
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? "";
    }
}

internal sealed class PeerAppMessage
{
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("fromClientId")]
    public long FromClientId { get; set; }

    [JsonPropertyName("fromClientName")]
    public string? FromClientName { get; set; }

    [JsonPropertyName("toClientId")]
    public long ToClientId { get; set; }

    [JsonPropertyName("toClientName")]
    public string? ToClientName { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    [JsonPropertyName("attachment")]
    public PeerAppAttachment? Attachment { get; set; }

    [JsonPropertyName("createdAtMillis")]
    public long CreatedAtMillis { get; set; }
}

internal sealed class PeerAppAttachment
{
    [JsonPropertyName("objectId")]
    public string? ObjectId { get; set; }

    [JsonPropertyName("attachmentId")]
    public long AttachmentId { get; set; }

    [JsonPropertyName("fileName")]
    public string? FileName { get; set; }

    [JsonPropertyName("mimeType")]
    public string? MimeType { get; set; }

    [JsonPropertyName("sizeBytes")]
    public long SizeBytes { get; set; }

    [JsonPropertyName("sha256")]
    public string? Sha256 { get; set; }
}
