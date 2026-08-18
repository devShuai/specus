using System.Net;
using Microsoft.AspNetCore.Http;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

public sealed class ClientAddressResolverTests
{
    [Fact]
    public void DirectClientCannotSpoofItsAddressWithForwardedHeaders()
    {
        // No trusted proxy configured: forwarded headers must be ignored entirely.
        var resolver = ClientAddressResolver.ForRanges([]);
        var context = Context("203.0.113.50", ("X-Forwarded-For", "1.2.3.4"), ("X-Real-IP", "5.6.7.8"));

        Assert.Equal("203.0.113.50", resolver.Resolve(context));
    }

    [Fact]
    public void UntrustedPeerIsUsedEvenWhenOtherProxiesAreTrusted()
    {
        var resolver = ClientAddressResolver.ForRanges(["10.0.0.0/8"]);
        var context = Context("203.0.113.50", ("X-Forwarded-For", "1.2.3.4"), ("X-Real-IP", "5.6.7.8"));

        Assert.Equal("203.0.113.50", resolver.Resolve(context));
    }

    [Fact]
    public void TrustedProxyResolvesTheForwardedClient()
    {
        var resolver = ClientAddressResolver.ForRanges(["10.0.0.0/8"]);
        var context = Context("10.1.2.3", ("X-Forwarded-For", "203.0.113.9"));

        Assert.Equal("203.0.113.9", resolver.Resolve(context));
    }

    [Fact]
    public void MultiHopChainSkipsTrailingTrustedProxiesRightToLeft()
    {
        var resolver = ClientAddressResolver.ForRanges(["10.0.0.0/8", "192.168.0.0/16"]);
        // client, edge proxy, internal proxy — the two right-most hops are trusted infrastructure.
        var context = Context("10.1.2.3", ("X-Forwarded-For", "203.0.113.9, 192.168.1.1, 10.9.9.9"));

        Assert.Equal("203.0.113.9", resolver.Resolve(context));
    }

    [Fact]
    public void SpoofedLeadingHopsCannotEscapeTheTrustedChain()
    {
        var resolver = ClientAddressResolver.ForRanges(["10.0.0.0/8"]);
        var context = Context("10.1.2.3", ("X-Forwarded-For", "9.9.9.9, 203.0.113.9"));

        Assert.Equal("203.0.113.9", resolver.Resolve(context));
    }

    [Fact]
    public void MalformedForwardedEntriesAreSkipped()
    {
        var resolver = ClientAddressResolver.ForRanges(["10.0.0.0/8"]);
        var context = Context("10.1.2.3", ("X-Forwarded-For", "203.0.113.9, not-an-ip, "));

        Assert.Equal("203.0.113.9", resolver.Resolve(context));
    }

    [Fact]
    public void RealIpIsUsedOnlyWhenTheWholeForwardedChainIsTrusted()
    {
        var resolver = ClientAddressResolver.ForRanges(["10.0.0.0/8"]);
        var context = Context("10.1.2.3", ("X-Forwarded-For", "10.9.9.9"), ("X-Real-IP", "203.0.113.9"));

        Assert.Equal("203.0.113.9", resolver.Resolve(context));
    }

    [Fact]
    public void FallsBackToPeerWhenTrustedProxySendsNothingUsable()
    {
        var resolver = ClientAddressResolver.ForRanges(["10.0.0.0/8"]);
        var context = Context("10.1.2.3", ("X-Forwarded-For", "not-an-ip"));

        Assert.Equal("10.1.2.3", resolver.Resolve(context));
    }

    [Fact]
    public void SupportsIpv6PeersAndForwardedEntries()
    {
        var resolver = ClientAddressResolver.ForRanges(["2001:db8::/32"]);
        // 2001:db8:1234::9 would still fall inside 2001:db8::/32, so use an address outside it.
        var trusted = Context("2001:db8::1", ("X-Forwarded-For", "2001:dead:1234::9, 2001:db8::2"));
        Assert.Equal("2001:dead:1234::9", resolver.Resolve(trusted));

        var untrusted = Context("2001:dead::1", ("X-Forwarded-For", "203.0.113.9"));
        Assert.Equal("2001:dead::1", resolver.Resolve(untrusted));
    }

    [Fact]
    public void Ipv4MappedPeerIsComparedAndReportedAsPlainIpv4()
    {
        var resolver = ClientAddressResolver.ForRanges(["10.0.0.0/8"]);
        var context = Context("::ffff:10.1.2.3", ("X-Forwarded-For", "203.0.113.9"));

        Assert.Equal("203.0.113.9", resolver.Resolve(context));
    }

    [Fact]
    public void InvalidTrustedProxyEntriesAreIgnoredWithoutTrustingEverything()
    {
        var resolver = ClientAddressResolver.ForRanges(["not-a-cidr", "10.0.0.0/99", " "]);
        var context = Context("10.1.2.3", ("X-Forwarded-For", "203.0.113.9"));

        Assert.Equal("10.1.2.3", resolver.Resolve(context));
    }

    [Fact]
    public void MissingContextOrAddressResolvesToUnknown()
    {
        var resolver = ClientAddressResolver.ForRanges([]);
        Assert.Equal(ClientAddressResolver.Unknown, resolver.Resolve(null));

        var context = new DefaultHttpContext();
        Assert.Equal(ClientAddressResolver.Unknown, resolver.Resolve(context));
    }

    private static HttpContext Context(string remoteAddress, params (string Name, string Value)[] headers)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(remoteAddress);
        foreach (var (name, value) in headers)
        {
            context.Request.Headers[name] = value;
        }
        return context;
    }
}
