package com.theshuai.tunnelclient.peer;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

final class PeerDataFrameCodec {
    private static final int MAGIC = 0x53504D31; // SPM1
    private static final byte VERSION = 1;
    private static final byte TYPE_DATA = 1;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int AAD_BYTES = Integer.BYTES + 2 + Long.BYTES * 4 + NONCE_BYTES;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PeerDataFrameCodec() {
    }

    static byte[] encode(byte[] aesKey,
                         long sessionId,
                         long fromClientId,
                         long toClientId,
                         long sequence,
                         byte[] plaintext) {
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            SECURE_RANDOM.nextBytes(nonce);
            byte[] aad = aad(sessionId, fromClientId, toClientId, sequence, nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad);
            byte[] ciphertext = cipher.doFinal(plaintext == null ? new byte[0] : plaintext);
            ByteBuffer buffer = ByteBuffer.allocate(aad.length + Integer.BYTES + ciphertext.length);
            buffer.put(aad);
            buffer.putInt(ciphertext.length);
            buffer.put(ciphertext);
            return buffer.array();
        } catch (Exception e) {
            throw new IllegalStateException("encode peer data frame failed: " + e.getMessage(), e);
        }
    }

    static PeerDataFrame decode(byte[] aesKey, byte[] packet, long expectedSessionId, long expectedToClientId) {
        try {
            if (packet == null || packet.length < AAD_BYTES + Integer.BYTES) {
                return null;
            }
            ByteBuffer buffer = ByteBuffer.wrap(packet);
            byte[] aad = new byte[AAD_BYTES];
            buffer.get(aad);
            ByteBuffer header = ByteBuffer.wrap(aad);
            int magic = header.getInt();
            byte version = header.get();
            byte type = header.get();
            long sessionId = header.getLong();
            long fromClientId = header.getLong();
            long toClientId = header.getLong();
            long sequence = header.getLong();
            byte[] nonce = new byte[NONCE_BYTES];
            header.get(nonce);
            if (magic != MAGIC || version != VERSION || type != TYPE_DATA
                    || sessionId != expectedSessionId
                    || toClientId != expectedToClientId) {
                return null;
            }
            int ciphertextLength = buffer.getInt();
            if (ciphertextLength < 0 || ciphertextLength > buffer.remaining()) {
                return null;
            }
            byte[] ciphertext = new byte[ciphertextLength];
            buffer.get(ciphertext);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad);
            byte[] plaintext = cipher.doFinal(ciphertext);
            return new PeerDataFrame(sessionId, fromClientId, toClientId, sequence, plaintext);
        } catch (Exception e) {
            return null;
        }
    }

    static Long sessionId(byte[] packet) {
        if (packet == null || packet.length < AAD_BYTES + Integer.BYTES) {
            return null;
        }
        ByteBuffer header = ByteBuffer.wrap(packet, 0, AAD_BYTES);
        int magic = header.getInt();
        byte version = header.get();
        byte type = header.get();
        if (magic != MAGIC || version != VERSION || type != TYPE_DATA) {
            return null;
        }
        return header.getLong();
    }

    static boolean looksLikeDataFrame(byte[] packet, int offset, int length) {
        if (packet == null || length < Integer.BYTES) {
            return false;
        }
        byte[] magic = Arrays.copyOfRange(packet, offset, offset + Integer.BYTES);
        return ByteBuffer.wrap(magic).getInt() == MAGIC;
    }

    private static byte[] aad(long sessionId, long fromClientId, long toClientId, long sequence, byte[] nonce) {
        ByteBuffer buffer = ByteBuffer.allocate(AAD_BYTES);
        buffer.putInt(MAGIC);
        buffer.put(VERSION);
        buffer.put(TYPE_DATA);
        buffer.putLong(sessionId);
        buffer.putLong(fromClientId);
        buffer.putLong(toClientId);
        buffer.putLong(sequence);
        buffer.put(nonce);
        return buffer.array();
    }
}
