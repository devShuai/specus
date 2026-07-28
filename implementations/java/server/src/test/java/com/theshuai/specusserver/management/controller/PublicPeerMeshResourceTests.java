package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.config.PeerMeshProperties;
import com.theshuai.specusserver.peer.TurnCredentialService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class PublicPeerMeshResourceTests {
    @Test
    void publicStunConfigPrefersStandaloneEndpoint() {
        PeerMeshProperties properties = new PeerMeshProperties();
        properties.setEnabled(true);
        properties.setPublicAddress("turn.example.com");
        properties.setStandaloneStunAddress("stun.example.com");
        properties.setStandaloneStunPort(5349);
        properties.setStandaloneStunAlternateAddress("stun-backup.example.com");
        properties.setStandaloneStunAlternatePort(5350);
        PublicPeerMeshResource resource =
                new PublicPeerMeshResource(properties, mock(TurnCredentialService.class));

        var config = resource.stunConfig(mock(HttpServletRequest.class));

        assertThat(config.peerMeshEnabled()).isTrue();
        assertThat(config.selfHostedStunServer()).isEqualTo("stun:stun.example.com:5349");
        assertThat(config.stunServers()).containsExactly(
                "stun:stun.example.com:5349",
                "stun:stun-backup.example.com:5349"
        );
        assertThat(config.stunTurnPort()).isEqualTo(3478);
    }

    @Test
    void standaloneStunCanBePublishedWhenPeerMeshIsDisabled() {
        PeerMeshProperties properties = new PeerMeshProperties();
        properties.setEnabled(false);
        properties.setStandaloneStunAddress("stun.example.com");
        PublicPeerMeshResource resource =
                new PublicPeerMeshResource(properties, mock(TurnCredentialService.class));

        var config = resource.stunConfig(mock(HttpServletRequest.class));

        assertThat(config.peerMeshEnabled()).isFalse();
        assertThat(config.selfHostedStunServer()).isEqualTo("stun:stun.example.com:3478");
    }

    @Test
    void incompleteStandaloneStunFallsBackToEmbeddedEndpoint() {
        PeerMeshProperties properties = new PeerMeshProperties();
        properties.setEnabled(true);
        properties.setPublicAddress("relay.example.com");
        properties.setStunTurnPort(4444);
        properties.setStandaloneStunAddress("stun.example.com");
        properties.setStandaloneStunPort(0);
        PublicPeerMeshResource resource =
                new PublicPeerMeshResource(properties, mock(TurnCredentialService.class));

        var config = resource.stunConfig(mock(HttpServletRequest.class));

        assertThat(config.selfHostedStunServer()).isEqualTo("stun:relay.example.com:4444");
        assertThat(config.stunTurnPort()).isEqualTo(4444);
    }

    @Test
    void publishesStandaloneRfc5780TopologyForBrowserMappingDiscovery() {
        PeerMeshProperties properties = new PeerMeshProperties();
        properties.setEnabled(true);
        properties.setStandaloneStunAddress("stun-a.example.com");
        properties.setStandaloneStunPort(34780);
        properties.setStandaloneStunAlternateAddress("203.0.113.20");
        properties.setStandaloneStunAlternatePort(34781);
        PublicPeerMeshResource resource =
                new PublicPeerMeshResource(properties, mock(TurnCredentialService.class));

        var config = resource.natProbeConfig(mock(HttpServletRequest.class));

        assertThat(config.available()).isTrue();
        assertThat(config.protocol()).isEqualTo("RFC8489");
        assertThat(config.discoveryMethod()).isEqualTo("RFC5780");
        assertThat(config.endpoints())
                .extracting("id", "url")
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple("A1P1", "stun:stun-a.example.com:34780"),
                        org.assertj.core.groups.Tuple.tuple("A1P2", "stun:stun-a.example.com:34781"),
                        org.assertj.core.groups.Tuple.tuple("A2P1", "stun:203.0.113.20:34780"),
                        org.assertj.core.groups.Tuple.tuple("A2P2", "stun:203.0.113.20:34781")
                );
        assertThat(config.capabilities().changeRequest()).isTrue();
        assertThat(config.capabilities().padding()).isTrue();
        assertThat(config.capabilities().browserMappingObservation()).isTrue();
        assertThat(config.capabilities().browserFilteringObservation()).isFalse();
    }

    @Test
    void fallsBackToBasicStunProbeConfigWithoutAlternateAddress() {
        PeerMeshProperties properties = new PeerMeshProperties();
        properties.setStandaloneStunAddress("stun.example.com");
        properties.setStandaloneStunPort(34780);
        PublicPeerMeshResource resource =
                new PublicPeerMeshResource(properties, mock(TurnCredentialService.class));

        var config = resource.natProbeConfig(mock(HttpServletRequest.class));

        assertThat(config.discoveryMethod()).isEqualTo("BASIC_STUN");
        assertThat(config.endpoints())
                .extracting("id", "url")
                .containsExactly(org.assertj.core.groups.Tuple.tuple(
                        "A1P1", "stun:stun.example.com:34780"));
        assertThat(config.capabilities().changeRequest()).isFalse();
    }
}
