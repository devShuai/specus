package com.theshuai.specusserver.security;

import com.theshuai.specusserver.config.TrustedProxyProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ClientAddressResolverTests {

    @Test
    void directClientCannotSpoofItsAddressWithForwardedHeaders() {
        // No trusted proxy configured: forwarded headers must be ignored entirely.
        ClientAddressResolver resolver = resolver();
        MockHttpServletRequest request = request("203.0.113.50");
        request.addHeader("X-Forwarded-For", "1.2.3.4");
        request.addHeader("X-Real-IP", "5.6.7.8");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.50");
    }

    @Test
    void untrustedPeerIsUsedEvenWhenOtherProxiesAreTrusted() {
        ClientAddressResolver resolver = resolver("10.0.0.0/8");
        MockHttpServletRequest request = request("203.0.113.50");
        request.addHeader("X-Forwarded-For", "1.2.3.4");
        request.addHeader("X-Real-IP", "5.6.7.8");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.50");
    }

    @Test
    void singleTrustedProxyResolvesTheForwardedClient() {
        ClientAddressResolver resolver = resolver("10.0.0.0/8");
        MockHttpServletRequest request = request("10.1.2.3");
        request.addHeader("X-Forwarded-For", "203.0.113.9");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.9");
    }

    @Test
    void multiHopChainSkipsTrailingTrustedProxiesRightToLeft() {
        ClientAddressResolver resolver = resolver("10.0.0.0/8", "192.168.0.0/16");
        MockHttpServletRequest request = request("10.1.2.3");
        // client, edge proxy, internal proxy — the two right-most hops are trusted infrastructure.
        request.addHeader("X-Forwarded-For", "203.0.113.9, 192.168.1.1, 10.9.9.9");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.9");
    }

    @Test
    void spoofedLeadingHopsCannotEscapeTheTrustedChain() {
        ClientAddressResolver resolver = resolver("10.0.0.0/8");
        MockHttpServletRequest request = request("10.1.2.3");
        // The client prepended a fake hop; the right-most untrusted entry is still the real peer
        // as observed by our own trusted proxy.
        request.addHeader("X-Forwarded-For", "9.9.9.9, 203.0.113.9");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.9");
    }

    @Test
    void malformedForwardedEntriesAreSkipped() {
        ClientAddressResolver resolver = resolver("10.0.0.0/8");
        MockHttpServletRequest request = request("10.1.2.3");
        request.addHeader("X-Forwarded-For", "203.0.113.9, not-an-ip, ");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.9");
    }

    @Test
    void realIpIsUsedOnlyWhenTheWholeForwardedChainIsTrusted() {
        ClientAddressResolver resolver = resolver("10.0.0.0/8");
        MockHttpServletRequest request = request("10.1.2.3");
        request.addHeader("X-Forwarded-For", "10.9.9.9");
        request.addHeader("X-Real-IP", "203.0.113.9");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.9");
    }

    @Test
    void fallsBackToPeerWhenTrustedProxySendsNothingUsable() {
        ClientAddressResolver resolver = resolver("10.0.0.0/8");
        MockHttpServletRequest request = request("10.1.2.3");
        request.addHeader("X-Forwarded-For", "not-an-ip");

        assertThat(resolver.resolve(request)).isEqualTo("10.1.2.3");
    }

    @Test
    void supportsIpv6PeersAndForwardedEntries() {
        ClientAddressResolver resolver = resolver("2001:db8::/32");
        MockHttpServletRequest request = request("2001:db8::1");
        // 2001:db8:1234::9 would still fall inside 2001:db8::/32, so use an address outside it.
        request.addHeader("X-Forwarded-For", "2001:dead:1234::9, 2001:db8::2");
        assertThat(resolver.resolve(request)).isEqualTo("2001:dead:1234::9");

        // An IPv6 peer outside the trusted range keeps its own address.
        MockHttpServletRequest untrusted = request("2001:dead::1");
        untrusted.addHeader("X-Forwarded-For", "203.0.113.9");
        assertThat(resolver.resolve(untrusted)).isEqualTo("2001:dead::1");
    }

    @Test
    void invalidTrustedProxyEntriesAreIgnoredWithoutTrustingEverything() {
        ClientAddressResolver resolver = resolver("not-a-cidr", "10.0.0.0/99", "");
        MockHttpServletRequest request = request("10.1.2.3");
        request.addHeader("X-Forwarded-For", "203.0.113.9");

        assertThat(resolver.resolve(request)).isEqualTo("10.1.2.3");
    }

    @Test
    void missingRequestOrAddressResolvesToUnknown() {
        ClientAddressResolver resolver = resolver();
        assertThat(resolver.resolve((jakarta.servlet.http.HttpServletRequest) null))
                .isEqualTo(ClientAddressResolver.UNKNOWN);
        assertThat(resolver.resolve("", null, null)).isEqualTo(ClientAddressResolver.UNKNOWN);
    }

    private ClientAddressResolver resolver(String... trustedProxies) {
        TrustedProxyProperties properties = new TrustedProxyProperties();
        properties.setTrustedProxies(List.of(trustedProxies));
        return new ClientAddressResolver(properties);
    }

    private MockHttpServletRequest request(String remoteAddr) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(remoteAddr);
        return request;
    }
}
