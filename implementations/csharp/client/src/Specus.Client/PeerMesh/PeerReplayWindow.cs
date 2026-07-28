namespace Specus.Client.PeerMesh;

internal sealed class PeerReplayWindow
{
    internal const int WindowSize = 4096;
    private const int WindowMask = WindowSize - 1;
    private readonly ulong[] _sequences = new ulong[WindowSize];
    private ulong _highest;

    public bool Accept(long sequence)
    {
        if (sequence <= 0)
        {
            return false;
        }
        var value = (ulong)sequence;
        if (_highest >= WindowSize && value <= _highest - WindowSize)
        {
            return false;
        }
        var slot = (int)value & WindowMask;
        if (_sequences[slot] == value)
        {
            return false;
        }
        _sequences[slot] = value;
        if (value > _highest)
        {
            _highest = value;
        }
        return true;
    }
}
