package com.theshuai.common.peermesh;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class PeerCryptoTests {

    @Test
    void shouldDeriveSameSessionKeyFromBothSides() throws Exception {
        KeyPair alice = x25519();
        KeyPair bob = x25519();

        byte[] aliceKey = PeerCrypto.deriveAes256Key(
                privateKey(alice),
                publicKey(bob),
                1001L,
                "session-token",
                1L,
                2L
        );
        byte[] bobKey = PeerCrypto.deriveAes256Key(
                privateKey(bob),
                publicKey(alice),
                1001L,
                "session-token",
                2L,
                1L
        );

        assertArrayEquals(aliceKey, bobKey);
    }

    @Test
    void shouldBindSessionKeyToSessionToken() throws Exception {
        KeyPair alice = x25519();
        KeyPair bob = x25519();

        byte[] first = PeerCrypto.deriveAes256Key(privateKey(alice), publicKey(bob), 1001L, "a", 1L, 2L);
        byte[] second = PeerCrypto.deriveAes256Key(privateKey(alice), publicKey(bob), 1001L, "b", 1L, 2L);

        assertFalse(Arrays.equals(first, second));
    }

    private KeyPair x25519() throws Exception {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    private String publicKey(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    private String privateKey(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }
}
