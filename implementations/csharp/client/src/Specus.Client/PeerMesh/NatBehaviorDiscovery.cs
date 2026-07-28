using System.Net;

namespace Specus.Client.PeerMesh;

internal static class NatBehavior
{
    public const string DiscoveryRfc5780 = "RFC5780";
    public const string DiscoveryBasic = "BASIC";

    public const string EndpointIndependent = "ENDPOINT_INDEPENDENT";
    public const string AddressDependent = "ADDRESS_DEPENDENT";
    public const string AddressAndPortDependent = "ADDRESS_AND_PORT_DEPENDENT";
    public const string Unknown = "UNKNOWN";
    public const string Unsupported = "UNSUPPORTED";
}

internal enum NatBehaviorProbe
{
    FilterChangeIpAndPort,
    FilterChangePort,
    MappingAlternateIp,
    MappingAlternateIpAndPort,
}

internal sealed record NatBehaviorProbeRequest(
    int Generation,
    NatBehaviorProbe Probe,
    IPEndPoint TargetEndpoint,
    IPEndPoint ExpectedResponseEndpoint,
    bool ChangeIp,
    bool ChangePort);

internal sealed record NatBehaviorSnapshot(
    int Generation,
    string Discovery,
    string MappingBehavior,
    string FilteringBehavior,
    IPEndPoint? MappedEndpoint,
    bool Complete);

internal sealed record NatBehaviorTransition(
    bool Accepted,
    NatBehaviorProbeRequest? NextProbe,
    NatBehaviorSnapshot Snapshot);

internal sealed class NatBehaviorDiscovery
{
    private readonly object _sync = new();
    private int _generation;
    private NatBehaviorProbe? _pendingProbe;
    private IPEndPoint? _primaryEndpoint;
    private IPEndPoint? _otherEndpoint;
    private IPEndPoint? _primaryMappedEndpoint;
    private IPEndPoint? _alternateIpMappedEndpoint;
    private string _mappingBehavior = "";
    private string _filteringBehavior = "";
    private bool _complete;

    public NatBehaviorTransition Begin(
        IPEndPoint primaryEndpoint,
        IPEndPoint primaryMappedEndpoint,
        IPEndPoint otherEndpoint)
    {
        lock (_sync)
        {
            RequireEndpoint(primaryEndpoint, nameof(primaryEndpoint));
            RequireEndpoint(primaryMappedEndpoint, nameof(primaryMappedEndpoint));
            RequireEndpoint(otherEndpoint, nameof(otherEndpoint));
            if (primaryEndpoint.Address.Equals(otherEndpoint.Address)
                || primaryEndpoint.Port == otherEndpoint.Port)
            {
                throw new ArgumentException(
                    "RFC 5780 discovery requires another IP address and another UDP port");
            }

            _generation++;
            _primaryEndpoint = Clone(primaryEndpoint);
            _primaryMappedEndpoint = Clone(primaryMappedEndpoint);
            _otherEndpoint = Clone(otherEndpoint);
            _alternateIpMappedEndpoint = null;
            _mappingBehavior = "";
            _filteringBehavior = "";
            _complete = false;
            return Next(NatBehaviorProbe.FilterChangeIpAndPort);
        }
    }

    public NatBehaviorTransition Succeeded(
        int expectedGeneration,
        NatBehaviorProbe probe,
        IPEndPoint mappedEndpoint)
    {
        lock (_sync)
        {
            if (!Accepts(expectedGeneration, probe))
            {
                return Ignored();
            }
            RequireEndpoint(mappedEndpoint, nameof(mappedEndpoint));
            return probe switch
            {
                NatBehaviorProbe.FilterChangeIpAndPort => SetFilteringAndNext(
                    NatBehavior.EndpointIndependent,
                    NatBehaviorProbe.MappingAlternateIp),
                NatBehaviorProbe.FilterChangePort => SetFilteringAndNext(
                    NatBehavior.AddressDependent,
                    NatBehaviorProbe.MappingAlternateIp),
                NatBehaviorProbe.MappingAlternateIp => SetAlternateMappingAndNext(mappedEndpoint),
                NatBehaviorProbe.MappingAlternateIpAndPort => FinishMapping(mappedEndpoint),
                _ => Ignored(),
            };
        }
    }

    public NatBehaviorTransition TimedOut(int expectedGeneration, NatBehaviorProbe probe)
    {
        lock (_sync)
        {
            if (!Accepts(expectedGeneration, probe))
            {
                return Ignored();
            }
            return probe switch
            {
                NatBehaviorProbe.FilterChangeIpAndPort => Next(NatBehaviorProbe.FilterChangePort),
                NatBehaviorProbe.FilterChangePort => SetFilteringAndNext(
                    NatBehavior.AddressAndPortDependent,
                    NatBehaviorProbe.MappingAlternateIp),
                NatBehaviorProbe.MappingAlternateIp or NatBehaviorProbe.MappingAlternateIpAndPort =>
                    FinishMappingFailure(),
                _ => Ignored(),
            };
        }
    }

    public NatBehaviorTransition Failed(
        int expectedGeneration,
        NatBehaviorProbe probe,
        bool unsupported)
    {
        lock (_sync)
        {
            if (!Accepts(expectedGeneration, probe))
            {
                return Ignored();
            }
            return probe switch
            {
                NatBehaviorProbe.FilterChangeIpAndPort or NatBehaviorProbe.FilterChangePort =>
                    SetFilteringAndNext(
                        unsupported ? NatBehavior.Unsupported : NatBehavior.Unknown,
                        NatBehaviorProbe.MappingAlternateIp),
                NatBehaviorProbe.MappingAlternateIp or NatBehaviorProbe.MappingAlternateIpAndPort =>
                    FinishMappingFailure(),
                _ => Ignored(),
            };
        }
    }

    public NatBehaviorSnapshot Snapshot()
    {
        lock (_sync)
        {
            return SnapshotLocked();
        }
    }

    private NatBehaviorTransition SetFilteringAndNext(string filtering, NatBehaviorProbe next)
    {
        _filteringBehavior = filtering;
        return Next(next);
    }

    private NatBehaviorTransition SetAlternateMappingAndNext(IPEndPoint mappedEndpoint)
    {
        _alternateIpMappedEndpoint = Clone(mappedEndpoint);
        return Next(NatBehaviorProbe.MappingAlternateIpAndPort);
    }

    private NatBehaviorTransition FinishMapping(IPEndPoint alternateIpAndPortMappedEndpoint)
    {
        _mappingBehavior = SameEndpoint(_primaryMappedEndpoint, _alternateIpMappedEndpoint)
            ? NatBehavior.EndpointIndependent
            : SameEndpoint(_alternateIpMappedEndpoint, alternateIpAndPortMappedEndpoint)
                ? NatBehavior.AddressDependent
                : NatBehavior.AddressAndPortDependent;
        _pendingProbe = null;
        _complete = true;
        return Accepted(null);
    }

    private NatBehaviorTransition FinishMappingFailure()
    {
        _mappingBehavior = NatBehavior.Unknown;
        if (!string.Equals(_filteringBehavior, NatBehavior.EndpointIndependent, StringComparison.Ordinal)
            && !string.Equals(_filteringBehavior, NatBehavior.Unsupported, StringComparison.Ordinal))
        {
            _filteringBehavior = NatBehavior.Unknown;
        }
        _pendingProbe = null;
        _complete = true;
        return Accepted(null);
    }

    private NatBehaviorTransition Next(NatBehaviorProbe probe)
    {
        _pendingProbe = probe;
        return Accepted(Request(probe));
    }

    private NatBehaviorProbeRequest Request(NatBehaviorProbe probe)
    {
        var primary = _primaryEndpoint!;
        var other = _otherEndpoint!;
        var alternateIpPrimaryPort = new IPEndPoint(other.Address, primary.Port);
        var primaryIpAlternatePort = new IPEndPoint(primary.Address, other.Port);
        return probe switch
        {
            NatBehaviorProbe.FilterChangeIpAndPort => new(
                _generation,
                probe,
                Clone(primary),
                Clone(other),
                true,
                true),
            NatBehaviorProbe.FilterChangePort => new(
                _generation,
                probe,
                Clone(primary),
                primaryIpAlternatePort,
                false,
                true),
            NatBehaviorProbe.MappingAlternateIp => new(
                _generation,
                probe,
                alternateIpPrimaryPort,
                Clone(alternateIpPrimaryPort),
                false,
                false),
            NatBehaviorProbe.MappingAlternateIpAndPort => new(
                _generation,
                probe,
                Clone(other),
                Clone(other),
                false,
                false),
            _ => throw new ArgumentOutOfRangeException(nameof(probe)),
        };
    }

    private bool Accepts(int expectedGeneration, NatBehaviorProbe probe) =>
        expectedGeneration == _generation && _pendingProbe == probe && !_complete;

    private NatBehaviorTransition Accepted(NatBehaviorProbeRequest? nextProbe) =>
        new(true, nextProbe, SnapshotLocked());

    private NatBehaviorTransition Ignored() =>
        new(false, null, SnapshotLocked());

    private NatBehaviorSnapshot SnapshotLocked() =>
        new(
            _generation,
            NatBehavior.DiscoveryRfc5780,
            _mappingBehavior,
            _filteringBehavior,
            _primaryMappedEndpoint is null ? null : Clone(_primaryMappedEndpoint),
            _complete);

    private static void RequireEndpoint(IPEndPoint? endpoint, string name)
    {
        if (endpoint is null || endpoint.Port <= 0 || IsUnspecified(endpoint.Address))
        {
            throw new ArgumentException($"{name} must be a resolved UDP endpoint", name);
        }
    }

    private static bool IsUnspecified(IPAddress address) =>
        address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

    private static bool SameEndpoint(IPEndPoint? first, IPEndPoint? second) =>
        first is not null
        && second is not null
        && first.Port == second.Port
        && first.Address.Equals(second.Address);

    private static IPEndPoint Clone(IPEndPoint endpoint) =>
        new(new IPAddress(endpoint.Address.GetAddressBytes()), endpoint.Port);
}
