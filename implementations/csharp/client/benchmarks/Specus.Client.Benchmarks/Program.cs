using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Specus.Client.PeerMesh;

BenchmarkSwitcher.FromAssembly(typeof(PeerDataFrameCodecBenchmark).Assembly).Run(args);

[MemoryDiagnoser]
public class PeerDataFrameCodecBenchmark
{
    private const string SenderKeyEpoch = "epoch-a";
    private readonly byte[] _key = Enumerable.Repeat((byte)7, 32).ToArray();
    private byte[] _payload = [];
    private byte[] _frame = [];
    private long _sequence;
    private PeerDataFrameCodec.TrafficCodec? _encoder;
    private PeerDataFrameCodec.TrafficCodec? _decoder;

    [Params(64, 512, 1200)]
    public int PayloadBytes { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _payload = new byte[PayloadBytes];
        _frame = PeerDataFrameCodec.Encode(_key, 1001, 1, 2, SenderKeyEpoch, 1, _payload);
        _encoder = PeerDataFrameCodec.CreateTrafficCodec(_key, 1001, 1, 2, SenderKeyEpoch);
        _decoder = PeerDataFrameCodec.CreateTrafficCodec(_key, 1001, 1, 2, SenderKeyEpoch);
        _sequence = 1;
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _encoder?.Dispose();
        _decoder?.Dispose();
    }

    [Benchmark]
    public byte[] Encode() =>
        _encoder!.Encode(1001, ++_sequence, _payload);

    [Benchmark]
    public int Decode() => _decoder!.Decode(1001, _frame).Payload.Length;
}
