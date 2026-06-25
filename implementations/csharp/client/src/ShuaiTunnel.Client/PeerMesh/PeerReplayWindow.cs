namespace ShuaiTunnel.Client.PeerMesh;

internal sealed class PeerReplayWindow
{
    private ulong _highest;
    private ulong _bits;

    public bool Accept(long sequence)
    {
        if (sequence <= 0)
        {
            return false;
        }
        var value = (ulong)sequence;
        if (_highest == 0)
        {
            _highest = value;
            _bits = 1;
            return true;
        }
        if (value > _highest)
        {
            var shift = value - _highest;
            _bits = shift >= 64 ? 1 : (_bits << (int)shift) | 1;
            _highest = value;
            return true;
        }
        var offset = _highest - value;
        if (offset >= 64)
        {
            return false;
        }
        var mask = 1UL << (int)offset;
        if ((_bits & mask) != 0)
        {
            return false;
        }
        _bits |= mask;
        return true;
    }
}
