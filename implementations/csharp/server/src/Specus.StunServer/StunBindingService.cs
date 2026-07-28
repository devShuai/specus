using System.Buffers.Binary;
using System.Net;

namespace Specus.StunServer;

public sealed record StunBindingResult(
    StunEndpointId ResponseEndpoint,
    IPEndPoint ResponseTarget,
    StunMessage Response);

public sealed class StunBindingService
{
    private const uint ChangeRequestMask = 0x06;

    private readonly StunTopology _topology;
    private readonly string _software;
    private readonly bool _legacySingleIpOtherAddress;
    private readonly int _maxPaddingResponseBytes;

    public StunBindingService(
        StunTopology topology,
        string software,
        bool legacySingleIpOtherAddress,
        int maxPaddingResponseBytes)
    {
        _topology = topology;
        _software = string.IsNullOrWhiteSpace(software)
            ? StunServerConfig.DefaultSoftware
            : software.Trim();
        _legacySingleIpOtherAddress = legacySingleIpOtherAddress;
        _maxPaddingResponseBytes = Math.Clamp(maxPaddingResponseBytes, 0, 65_503);
    }

    public StunBindingResult Process(
        StunMessage request,
        IPEndPoint remote,
        StunEndpointId incomingEndpoint,
        int receivedBytes)
    {
        if (request.Type != StunMessage.BindingRequest)
        {
            throw new ArgumentException("only STUN Binding requests are supported", nameof(request));
        }

        var responseTarget = new IPEndPoint(remote.Address, remote.Port);
        var hasResponsePort = request.Has(StunMessage.AttrResponsePort);
        var hasPadding = request.Has(StunMessage.AttrPadding);
        if (hasResponsePort && hasPadding)
        {
            return Error(
                incomingEndpoint,
                remote,
                request,
                400,
                "response-port-and-padding-are-mutually-exclusive");
        }
        if (hasResponsePort)
        {
            var attribute = request.First(StunMessage.AttrResponsePort);
            var responsePort = request.ResponsePortValue();
            if (attribute?.Value.Length != 2 || responsePort is null or 0)
            {
                return Error(incomingEndpoint, remote, request, 400, "invalid-response-port");
            }
            responseTarget = new IPEndPoint(remote.Address, responsePort.Value);
        }

        var changeRequest = new ChangeRequest(false, false);
        if (request.Has(StunMessage.AttrChangeRequest))
        {
            var attribute = request.First(StunMessage.AttrChangeRequest);
            if (attribute?.Value.Length != 4)
            {
                return Error(
                    incomingEndpoint,
                    responseTarget,
                    request,
                    400,
                    "invalid-change-request");
            }
            var flags = BinaryPrimitives.ReadUInt32BigEndian(attribute.Value);
            if ((flags & ~ChangeRequestMask) != 0)
            {
                return Error(
                    incomingEndpoint,
                    responseTarget,
                    request,
                    400,
                    "invalid-change-request-flags");
            }
            changeRequest = request.ChangeRequestValue()
                ?? throw new InvalidOperationException("validated change request was not decoded");
            if (!_topology.SupportsRfc5780)
            {
                return Error(
                    incomingEndpoint,
                    responseTarget,
                    request,
                    420,
                    "unsupported-change-request",
                    StunMessage.UnknownAttributes(StunMessage.AttrChangeRequest));
            }
        }

        var responseEndpoint = _topology.ResponseEndpoint(incomingEndpoint, changeRequest);
        var responseOrigin = _topology.Endpoint(responseEndpoint).Advertised;
        var attributes = new List<StunAttribute>
        {
            StunMessage.MappedAddress(remote),
            StunMessage.XorMappedAddress(remote, request.TransactionId),
            StunMessage.Software(_software),
        };
        if (_topology.SupportsRfc5780)
        {
            attributes.Add(StunMessage.ResponseOrigin(responseOrigin));
            var otherEndpoint = _topology.OtherEndpoint(incomingEndpoint);
            if (otherEndpoint is not null)
            {
                attributes.Add(StunMessage.OtherAddress(_topology.Endpoint(otherEndpoint.Value).Advertised));
            }
        }
        else if (_legacySingleIpOtherAddress)
        {
            attributes.Add(new StunAttribute(
                StunMessage.AttrResponseOrigin,
                StunMessage.XorAddressValue(responseOrigin, request.TransactionId)));
            var alternateEndpoint = _topology.LegacyAlternatePortEndpoint(incomingEndpoint);
            if (alternateEndpoint is not null)
            {
                attributes.Add(new StunAttribute(
                    StunMessage.AttrOtherAddress,
                    StunMessage.XorAddressValue(
                        _topology.Endpoint(alternateEndpoint.Value).Advertised,
                        request.TransactionId)));
            }
        }
        else
        {
            attributes.Add(StunMessage.ResponseOrigin(responseOrigin));
        }
        if (hasPadding)
        {
            var requestPaddingBytes = request.First(StunMessage.AttrPadding)?.Value.Length ?? 0;
            var boundedByDatagram = Math.Max(0, receivedBytes - StunMessage.HeaderBytes);
            attributes.Add(StunMessage.Padding(
                Math.Min(
                    requestPaddingBytes,
                    Math.Min(_maxPaddingResponseBytes, boundedByDatagram))));
        }

        return new StunBindingResult(
            responseEndpoint,
            responseTarget,
            new StunMessage(StunMessage.BindingSuccess, request.TransactionId, attributes));
    }

    private StunBindingResult Error(
        StunEndpointId endpoint,
        IPEndPoint target,
        StunMessage request,
        int code,
        string reason,
        params StunAttribute[] extras)
    {
        var attributes = new List<StunAttribute>
        {
            StunMessage.ErrorCode(code, reason),
            StunMessage.Software(_software),
        };
        attributes.AddRange(extras);
        return new StunBindingResult(
            endpoint,
            new IPEndPoint(target.Address, target.Port),
            new StunMessage(StunMessage.BindingError, request.TransactionId, attributes));
    }
}
