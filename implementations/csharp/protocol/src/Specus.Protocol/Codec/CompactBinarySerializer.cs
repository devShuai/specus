using System.Reflection;
using Specus.Protocol.Packets;

namespace Specus.Protocol.Codec;

/// <summary>
/// Compact-binary serializer port — see <c>com.theshuai.common.serialize.impl.CompactBinarySerializer</c>.
/// Field order in <see cref="Schemas"/> MUST match the Java <c>createSchemas()</c> registration order
/// or the wire layout drifts and clients fail to decode.
/// </summary>
public static class CompactBinarySerializer
{
    private static readonly IValueCodec StringCodec = new StringValueCodec();
    private static readonly IValueCodec BooleanCodec = new BooleanValueCodec();
    private static readonly IValueCodec IntegerCodec = new IntegerValueCodec();
    private static readonly IValueCodec LongCodec = new LongValueCodec();
    private static readonly IValueCodec ByteArrayCodec = new ByteArrayValueCodec();
    private static readonly IValueCodec NumericStringCodec = new NumericStringValueCodec();
    private static readonly IValueCodec UuidStringCodec = new UuidStringValueCodec();
    private static readonly IValueCodec HttpMethodCodec = new HttpMethodValueCodec();

    private static readonly IValueCodec MessageTypeCodec = new MessageTypeValueCodec();

    private static readonly IValueCodec StringMapCodec = new StringMapValueCodec();
    private static readonly IValueCodec StringListCodec = new StringListValueCodec();

    private static readonly Dictionary<Type, ObjectSchema> Schemas = BuildSchemas();

    public static byte[] Serialize(Packet packet)
    {
        if (packet is null)
        {
            throw new ArgumentNullException(nameof(packet));
        }
        if (!Schemas.TryGetValue(packet.GetType(), out var schema))
        {
            throw new ArgumentException($"unsupported compact binary type: {packet.GetType().FullName}");
        }
        return schema.Serialize(packet);
    }

    public static T Deserialize<T>(byte[] bytes) where T : Packet, new()
    {
        if (bytes is null)
        {
            throw new ArgumentNullException(nameof(bytes));
        }
        if (!Schemas.TryGetValue(typeof(T), out var schema))
        {
            throw new ArgumentException($"unsupported compact binary type: {typeof(T).FullName}");
        }
        return (T)schema.Deserialize(bytes);
    }

    public static Packet Deserialize(Type type, byte[] bytes)
    {
        if (!Schemas.TryGetValue(type, out var schema))
        {
            throw new ArgumentException($"unsupported compact binary type: {type.FullName}");
        }
        return schema.Deserialize(bytes);
    }

    private static Dictionary<Type, ObjectSchema> BuildSchemas()
    {
        var schemas = new Dictionary<Type, ObjectSchema>();
        Register(schemas, ObjectSchema.Build<LoginRequestPacket>(
            Field<LoginRequestPacket>(nameof(LoginRequestPacket.ClientName), StringCodec),
            Field<LoginRequestPacket>(nameof(LoginRequestPacket.ClientSessionId), LongCodec),
            Field<LoginRequestPacket>(nameof(LoginRequestPacket.AccessToken), StringCodec),
            Field<LoginRequestPacket>(nameof(LoginRequestPacket.ConnectionRole), StringCodec)));
        Register(schemas, ObjectSchema.Build<LoginResponsePacket>(
            Field<LoginResponsePacket>(nameof(LoginResponsePacket.ClientName), StringCodec),
            Field<LoginResponsePacket>(nameof(LoginResponsePacket.Success), BooleanCodec),
            Field<LoginResponsePacket>(nameof(LoginResponsePacket.Reason), StringCodec)));
        Register(schemas, ObjectSchema.Build<MessageRequestPacket>(
            Field<MessageRequestPacket>(nameof(MessageRequestPacket.ClientName), StringCodec),
            Field<MessageRequestPacket>(nameof(MessageRequestPacket.ToClientName), StringCodec),
            Field<MessageRequestPacket>(nameof(MessageRequestPacket.MessageType), MessageTypeCodec),
            Field<MessageRequestPacket>(nameof(MessageRequestPacket.Message), StringCodec)));
        Register(schemas, ObjectSchema.Build<MessageResponsePacket>(
            Field<MessageResponsePacket>(nameof(MessageResponsePacket.ClientName), StringCodec),
            Field<MessageResponsePacket>(nameof(MessageResponsePacket.ToClientName), StringCodec),
            Field<MessageResponsePacket>(nameof(MessageResponsePacket.MessageType), MessageTypeCodec),
            Field<MessageResponsePacket>(nameof(MessageResponsePacket.Message), StringCodec)));
        Register(schemas, ObjectSchema.Build<LogoutRequestPacket>());
        Register(schemas, ObjectSchema.Build<LogoutResponsePacket>(
            Field<LogoutResponsePacket>(nameof(LogoutResponsePacket.Success), BooleanCodec),
            Field<LogoutResponsePacket>(nameof(LogoutResponsePacket.Reason), StringCodec)));
        Register(schemas, ObjectSchema.Build<HeartbeatRequestPacket>());
        Register(schemas, ObjectSchema.Build<HeartbeatResponsePacket>());
        return schemas;
    }

    private static void Register(Dictionary<Type, ObjectSchema> schemas, ObjectSchema schema)
        => schemas[schema.Type] = schema;

    private static FieldBinding Field<TPacket>(string propertyName, IValueCodec codec)
    {
        var prop = typeof(TPacket).GetProperty(propertyName,
            BindingFlags.Public | BindingFlags.Instance)
            ?? throw new InvalidOperationException($"missing property {typeof(TPacket).Name}.{propertyName}");
        return new FieldBinding(prop, codec);
    }
}

internal sealed class ObjectSchema
{
    private readonly List<FieldBinding> _fields;
    private readonly Func<Packet> _factory;

    internal Type Type { get; }

    private ObjectSchema(Type type, Func<Packet> factory, List<FieldBinding> fields)
    {
        Type = type;
        _factory = factory;
        _fields = fields;
    }

    internal static ObjectSchema Build<T>(params FieldBinding[] fields) where T : Packet, new()
        => new(typeof(T), () => new T(), fields.ToList());

    internal byte[] Serialize(Packet packet)
    {
        var writer = new CompactWriter();
        foreach (var field in _fields)
        {
            field.Write(writer, packet);
        }
        return writer.ToByteArray();
    }

    internal Packet Deserialize(byte[] bytes)
    {
        var packet = _factory();
        var reader = new CompactReader(bytes);
        foreach (var field in _fields)
        {
            field.Read(reader, packet);
        }
        if (reader.HasRemaining)
        {
            throw new InvalidDataException("compact binary payload has trailing bytes");
        }
        return packet;
    }
}

internal sealed class FieldBinding
{
    private readonly PropertyInfo _property;
    private readonly IValueCodec _codec;

    internal FieldBinding(PropertyInfo property, IValueCodec codec)
    {
        _property = property;
        _codec = codec;
    }

    internal void Write(CompactWriter writer, Packet packet)
    {
        var value = _property.GetValue(packet);
        // bool is unboxed via IValueCodec semantics — codec receives the boxed bool/Int32 etc.
        _codec.Write(writer, value);
    }

    internal void Read(CompactReader reader, Packet packet)
    {
        var value = _codec.Read(reader);
        _property.SetValue(packet, value);
    }
}
