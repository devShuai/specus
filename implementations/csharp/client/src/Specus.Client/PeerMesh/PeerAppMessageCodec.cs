using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Specus.Client.PeerMesh;

internal static class PeerAppMessageCodec
{
    public const string TypeMessage = "message";
    public const string TypeAck = "ack";

    private static readonly byte[] Prefix = Encoding.ASCII.GetBytes("STMSG2\n");

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
    };

    public static bool LooksLike(byte[] payload)
    {
        return payload.Length >= Prefix.Length
            && payload.AsSpan(0, Prefix.Length).SequenceEqual(Prefix);
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
                payload.AsSpan(Prefix.Length),
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
        var wireMessage = string.Equals(message.Type, TypeMessage, StringComparison.OrdinalIgnoreCase)
            ? message : WithoutAttachment(message);
        var json = JsonSerializer.SerializeToUtf8Bytes(wireMessage, JsonOptions);
        var payload = new byte[Prefix.Length + json.Length];
        Prefix.CopyTo(payload, 0);
        json.CopyTo(payload.AsSpan(Prefix.Length));
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

    private static PeerAppMessage WithoutAttachment(PeerAppMessage message) => new()
    {
        Type = message.Type,
        Id = message.Id,
        FromClientId = message.FromClientId,
        FromClientName = message.FromClientName,
        ToClientId = message.ToClientId,
        ToClientName = message.ToClientName,
        Message = message.Message,
        CreatedAtMillis = message.CreatedAtMillis,
    };

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
