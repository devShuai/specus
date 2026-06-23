package com.theshuai.common.peermesh;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public final class PeerCrypto {
    private static final String X25519 = "X25519";
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final int AES_256_KEY_BYTES = 32;

    private PeerCrypto() {
    }

    public static byte[] deriveAes256Key(String localPrivateKeyBase64,
                                         String remotePublicKeyBase64,
                                         long sessionId,
                                         String sessionToken,
                                         long localClientId,
                                         long remoteClientId) {
        try {
            KeyAgreement agreement = KeyAgreement.getInstance(X25519);
            agreement.init(privateKey(localPrivateKeyBase64));
            agreement.doPhase(publicKey(remotePublicKeyBase64), true);
            byte[] sharedSecret = agreement.generateSecret();
            byte[] salt = sha256("shuai-peer-mesh\n"
                    + sessionId + "\n"
                    + (sessionToken == null ? "" : sessionToken) + "\n"
                    + Math.min(localClientId, remoteClientId) + "\n"
                    + Math.max(localClientId, remoteClientId));
            byte[] prk = hmac(salt, sharedSecret);
            return hkdfExpand(prk, "shuai-peer-mesh/aes-gcm/v1", AES_256_KEY_BYTES);
        } catch (Exception e) {
            throw new IllegalStateException("derive peer mesh session key failed: " + e.getMessage(), e);
        }
    }

    public static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("sha256 failed", e);
        }
    }

    private static PrivateKey privateKey(String base64) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance(X25519).generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    private static PublicKey publicKey(String base64) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance(X25519).generatePublic(new X509EncodedKeySpec(bytes));
    }

    private static byte[] hkdfExpand(byte[] prk, String info, int length) throws Exception {
        byte[] infoBytes = info.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[length];
        byte[] previous = new byte[0];
        int copied = 0;
        int counter = 1;
        while (copied < length) {
            ByteBuffer input = ByteBuffer.allocate(previous.length + infoBytes.length + 1);
            input.put(previous);
            input.put(infoBytes);
            input.put((byte) counter);
            previous = hmac(prk, input.array());
            int toCopy = Math.min(previous.length, length - copied);
            System.arraycopy(previous, 0, result, copied, toCopy);
            copied += toCopy;
            counter++;
        }
        Arrays.fill(previous, (byte) 0);
        return result;
    }

    private static byte[] hmac(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(new SecretKeySpec(key, HMAC_SHA256));
        return mac.doFinal(data);
    }
}
