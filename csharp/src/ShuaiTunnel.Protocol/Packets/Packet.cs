namespace ShuaiTunnel.Protocol.Packets;

/// <summary>
/// Base type for every wire packet. The <see cref="Command"/> byte is what gets serialized
/// into the frame header; concrete subclasses pin theirs in the constructor.
///
/// We use mutable classes (not records) because the Java side relies on field reflection
/// after no-arg construction — the codec writes fields in a fixed order. Mutating shape ==
/// breaking the wire.
/// </summary>
public abstract class Packet
{
    public byte Version { get; set; } = 1;

    public abstract sbyte Command { get; }
}
