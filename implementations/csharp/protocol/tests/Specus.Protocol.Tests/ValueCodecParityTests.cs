using System.Reflection;
using Specus.Protocol.Codec;

namespace Specus.Protocol.Tests;

public class ValueCodecParityTests
{
    [Fact]
    public void NumericStringCodec_DoesNotTrimWhitespaceLikeJava()
    {
        var assembly = typeof(PacketCodec).Assembly;
        var codecType = assembly.GetType("Specus.Protocol.Codec.NumericStringValueCodec", throwOnError: true)!;
        var writerType = assembly.GetType("Specus.Protocol.Codec.CompactWriter", throwOnError: true)!;
        var codec = Activator.CreateInstance(codecType, nonPublic: true)!;
        var writer = Activator.CreateInstance(writerType, nonPublic: true)!;

        codecType.GetMethod("Write")!.Invoke(codec, new[] { writer, " 123" });
        var bytes = (byte[])writerType.GetMethod("ToByteArray", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(writer, null)!;

        Assert.Equal(2, bytes[0]);
        Assert.Equal(5, bytes[1]);
        Assert.Equal(" 123"u8.ToArray(), bytes[2..]);
    }
}
