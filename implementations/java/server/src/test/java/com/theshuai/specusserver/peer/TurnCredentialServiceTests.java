package com.theshuai.specusserver.peer;

import com.theshuai.specusserver.config.PeerMeshProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TurnCredentialServiceTests {

    @Test
    void peerMeshSubjectCarriesClientIdAndIsNotGeneralRelay() {
        TurnCredentialService service = service();

        TurnCredentialService.TurnCredential credential = service.issue("pm-4242");

        assertThat(service.peerMeshClientId(credential.username())).isEqualTo(4242L);
        assertThat(service.isGeneralRelaySubject(credential.username())).isFalse();
        assertThat(service.usernameCredentialValid(credential.username(), credential.credential())).isTrue();
    }

    @Test
    void publicTransferSubjectIsGeneralRelayWithoutClientId() {
        // 浏览器 WebRTC 经 TURN 转发的是 DTLS/SRTP，无法通过 Peer Mesh 专用校验，
        // 因此这类凭证必须被识别为通用中继，否则中继载荷会被全部拒绝。
        TurnCredentialService service = service();

        TurnCredentialService.TurnCredential credential =
                service.issue(TurnCredentialService.GENERAL_SUBJECT_PREFIX);

        assertThat(service.isGeneralRelaySubject(credential.username())).isTrue();
        assertThat(service.peerMeshClientId(credential.username())).isZero();
    }

    @Test
    void unknownSubjectIsNeitherPeerMeshNorGeneralRelay() {
        TurnCredentialService service = service();

        TurnCredentialService.TurnCredential credential = service.issue("something-else");

        assertThat(service.isGeneralRelaySubject(credential.username())).isFalse();
        assertThat(service.peerMeshClientId(credential.username())).isZero();
    }

    private TurnCredentialService service() {
        PeerMeshProperties properties = new PeerMeshProperties();
        properties.setTurnSharedSecret("test-secret");
        return new TurnCredentialService(properties);
    }
}
