using System.Diagnostics;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

/// <summary>
/// The shared adversarial corpus in <c>protocol/test-vectors/adversarial-inputs.json</c>.
///
/// <para>One implementation rejecting a hostile input does not mean the input is handled: an
/// attacker picks whichever node runs the most permissive implementation. Java, Go, .NET and
/// Android all run this same file, so a gap in one of them shows up as a failure rather than as a
/// difference nobody thought to look for.</para>
///
/// <para>The requirement per case is either a clean rejection or a value the caller can safely
/// use — never an unhandled exception, and never so slow that a hostile packet could stall a
/// receive loop.</para>
/// </summary>
public sealed class SharedAdversarialVectorTests
{
    [Fact]
    public void EverySharedCaseIsHandled()
    {
        var document = ProtocolVectorTestHelper.Read<AdversarialVectors>(
            "protocol/test-vectors/adversarial-inputs.json");

        Assert.NotEmpty(document.Cases);

        foreach (var testCase in document.Cases)
        {
            var payload = Convert.FromHexString(testCase.PayloadHex);

            var stopwatch = Stopwatch.StartNew();
            DecodeAllReachable(payload);
            stopwatch.Stop();

            Assert.True(stopwatch.ElapsedMilliseconds < 1_000,
                $"{testCase.Name} took {stopwatch.ElapsedMilliseconds}ms to decide; a hostile "
                + "input must not stall a receive loop");
        }
    }

    /// <summary>
    /// Feeds one payload to every decoder a datagram can reach before anything has authenticated
    /// it. An unhandled exception here fails the test, which is the outcome being ruled out.
    /// </summary>
    private static void DecodeAllReachable(byte[] payload)
    {
        PeerAppMessageCodec.LooksLike(payload);
        PeerAppMessageCodec.TryDecode(payload, out _);
        PeerPathMtu.LooksLike(payload);
        PeerPathMtu.Decode(payload);
    }

    private sealed class AdversarialVectors
    {
        public required string Name { get; init; }
        public required string Comment { get; init; }
        public required List<AdversarialCase> Cases { get; init; }
    }

    private sealed class AdversarialCase
    {
        public required string Name { get; init; }
        public required string Kind { get; init; }
        public required string PayloadHex { get; init; }
        public required string Expect { get; init; }
        public required string Why { get; init; }
    }
}
