using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShuaiTunnel.Client.PeerMesh;

internal static class PeerAppMessageCodec
{
    public const string TypeMessage = "message";
    public const string TypeAck = "ack";

    private static readonly byte[] Prefix = Encoding.ASCII.GetBytes("STMSG1\n");

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
        var json = JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions);
        var payload = new byte[Prefix.Length + json.Length];
        Prefix.CopyTo(payload, 0);
        json.CopyTo(payload.AsSpan(Prefix.Length));
        return payload;
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

    [JsonPropertyName("createdAtMillis")]
    public long CreatedAtMillis { get; set; }
}
