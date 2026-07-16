package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.config.PeerMeshProperties;
import com.theshuai.tunnelserver.peer.TurnCredentialService;
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
        PublicPeerMeshResource resource =
                new PublicPeerMeshResource(properties, mock(TurnCredentialService.class));

        var config = resource.stunConfig(mock(HttpServletRequest.class));

        assertThat(config.peerMeshEnabled()).isTrue();
        assertThat(config.selfHostedStunServer()).isEqualTo("stun:stun.example.com:5349");
        assertThat(config.stunServers()).contains("stun:stun.example.com:5349");
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
}
