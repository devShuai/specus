package com.theshuai.specusclient.peer;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.stun.StunMessage;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TurnLongTermAuthenticatorTests {
    private static final String USERNAME = "1900000000:client-a:01020304";
    private static final String CREDENTIAL = "turn-credential";
    private static final String REALM = "specus";
    private static final String NONCE = "login-nonce";

    @Test
    void signsAllAuthenticatedTurnRequestTypesWithLongTermKey() throws Exception {
        TurnLongTermAuthenticator authenticator = authenticator();
        InetSocketAddress peer = new InetSocketAddress(InetAddress.getByName("192.0.2.30"), 3478);

        StunMessage[] requests = {
                StunMessage.of(
                        StunMessage.ALLOCATE_REQUEST,
                        transactionId(1),
                        StunMessage.requestedUdpTransportAttribute()),
                StunMessage.of(
                        StunMessage.REFRESH_REQUEST,
                        transactionId(2),
                        StunMessage.lifetime(300)),
                StunMessage.of(
                        StunMessage.CREATE_PERMISSION_REQUEST,
                        transactionId(3),
                        StunMessage.xorPeerAddress(peer, transactionId(3)))
        };

        for (StunMessage request : requests) {
            byte[] encoded = authenticator.encode(request);
            StunMessage parsed = StunMessage.parse(encoded, 0, encoded.length);

            assertEquals(USERNAME, parsed.username().orElseThrow());
            assertEquals(REALM, parsed.realm().orElseThrow());
            assertEquals(NONCE, parsed.nonce().orElseThrow());
            assertTrue(parsed.first(StunMessage.ATTR_MESSAGE_INTEGRITY).isPresent());
            assertTrue(StunMessage.verifyMessageIntegrity(encoded, 0, encoded.length, longTermKey(REALM)));
        }
    }

    @Test
    void bindingAndSendIndicationRemainUnsigned() throws Exception {
        TurnLongTermAuthenticator authenticator = authenticator();
        InetSocketAddress peer = new InetSocketAddress(InetAddress.getByName("192.0.2.31"), 3478);
        byte[] bindingTx = transactionId(4);
        byte[] indicationTx = transactionId(5);
        StunMessage binding = StunMessage.of(
                StunMessage.BINDING_REQUEST,
                bindingTx,
                StunMessage.software("test"));
        StunMessage indication = StunMessage.of(
                StunMessage.SEND_INDICATION,
                indicationTx,
                StunMessage.xorPeerAddress(peer, indicationTx),
                StunMessage.data(new byte[]{1, 2, 3}));

        assertArrayEquals(binding.toBytes(), authenticator.encode(binding));
        assertArrayEquals(indication.toBytes(), authenticator.encode(indication));
        assertUnsigned(authenticator.encode(binding));
        assertUnsigned(authenticator.encode(indication));
    }

    @Test
    void appliesUnauthorizedAndStaleNonceChallengesButIgnoresOtherErrors() throws Exception {
        TurnLongTermAuthenticator authenticator = authenticator();

        assertFalse(authenticator.applyChallenge(StunMessage.of(
                StunMessage.ALLOCATE_ERROR,
                transactionId(6),
                StunMessage.errorCode(400, "bad-request"),
                StunMessage.realm("ignored-realm"),
                StunMessage.nonce("ignored-nonce"))));

        for (int code : new int[]{401, 438}) {
            String challengedRealm = "challenge-realm-" + code;
            String challengedNonce = "challenge-nonce-" + code;
            assertTrue(authenticator.applyChallenge(StunMessage.of(
                    StunMessage.ALLOCATE_ERROR,
                    transactionId(code),
                    StunMessage.errorCode(code, "challenge"),
                    StunMessage.realm(challengedRealm),
                    StunMessage.nonce(challengedNonce))));

            StunMessage request = StunMessage.of(
                    StunMessage.ALLOCATE_REQUEST,
                    transactionId(code + 1),
                    StunMessage.requestedUdpTransportAttribute());
            byte[] encoded = authenticator.encode(request);
            StunMessage parsed = StunMessage.parse(encoded, 0, encoded.length);
            assertEquals(challengedRealm, parsed.realm().orElseThrow());
            assertEquals(challengedNonce, parsed.nonce().orElseThrow());
            assertTrue(StunMessage.verifyMessageIntegrity(
                    encoded, 0, encoded.length, longTermKey(challengedRealm)));
        }
    }

    private TurnLongTermAuthenticator authenticator() {
        ClientAuthLoginResponse.PeerMeshConfig config = new ClientAuthLoginResponse.PeerMeshConfig();
        config.setIceUsername(USERNAME);
        config.setIceCredential(CREDENTIAL);
        config.setIceRealm(REALM);
        config.setIceNonce(NONCE);
        TurnLongTermAuthenticator authenticator = new TurnLongTermAuthenticator();
        assertTrue(authenticator.update(config));
        assertTrue(authenticator.canAuthenticate());
        return authenticator;
    }

    private void assertUnsigned(byte[] packet) {
        StunMessage parsed = StunMessage.parse(packet, 0, packet.length);
        assertFalse(parsed.first(StunMessage.ATTR_MESSAGE_INTEGRITY).isPresent());
        assertFalse(parsed.username().isPresent());
        assertFalse(parsed.realm().isPresent());
        assertFalse(parsed.nonce().isPresent());
    }

    private byte[] longTermKey(String realm) throws Exception {
        return MessageDigest.getInstance("MD5").digest(
                (USERNAME + ":" + realm + ":" + CREDENTIAL).getBytes(StandardCharsets.UTF_8));
    }

    private byte[] transactionId(int seed) {
        byte[] value = new byte[StunMessage.TRANSACTION_ID_BYTES];
        for (int i = 0; i < value.length; i++) {
            value[i] = (byte) (seed + i);
        }
        return value;
    }
}
