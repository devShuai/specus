package com.theshuai.tunnelclient.peer;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

final class PeerDataFrameCodec {
    static final int MAGIC = 0x53504D32; // SPM2
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int TAG_BYTES = TAG_BITS / Byte.SIZE;
    static final int HEADER_BYTES = Integer.BYTES + Long.BYTES * 2;
    private static final int MIN_BYTES = HEADER_BYTES + TAG_BYTES;
    private static final int MAX_BYTES = 65_535;
    private static final byte[] INFO_PREFIX = "shuai-peer-mesh/spm2/aes-gcm\n"
            .getBytes(StandardCharsets.US_ASCII);
    private static final byte[] EMPTY = new byte[0];
    private static final ThreadLocal<Cipher> ENCRYPT_CIPHER = ThreadLocal.withInitial(PeerDataFrameCodec::newCipher);
    private static final ThreadLocal<Cipher> DECRYPT_CIPHER = ThreadLocal.withInitial(PeerDataFrameCodec::newCipher);

    private PeerDataFrameCodec() {
    }

    /**
     * 派生单向 traffic key。方向由 {@code fromClientId -> toClientId} 决定，
     * {@code senderKeyEpoch} 是**发送方**本次运行实例的随机 epoch。
     *
     * <p>epoch 是 AES-GCM nonce 唯一性的必要前提：sessionId/token 在服务端 TTL 内会被复用，
     * X25519 密钥又持久化在磁盘上，而 sequence 在进程重启后从 1 重新开始。没有 epoch 时，
     * 客户端重启会在同一 key 下重放同一段 nonce 空间，直接摧毁 GCM 的认证性。
     */
    static TrafficKey trafficKey(SecretKeySpec sessionKey,
                                 long sessionId,
                                 long fromClientId,
                                 long toClientId,
                                 String senderKeyEpoch) {
        if (sessionKey == null || sessionId <= 0 || fromClientId <= 0 || toClientId <= 0
                || fromClientId == toClientId) {
            throw new IllegalArgumentException("SPM2 traffic key requires a valid session and direction");
        }
        if (senderKeyEpoch == null || senderKeyEpoch.isBlank()) {
            throw new IllegalArgumentException("SPM2 traffic key requires the sender key epoch");
        }
        try {
            byte[] sessionBytes = ByteBuffer.allocate(Long.BYTES).putLong(sessionId).array();
            Mac extract = Mac.getInstance("HmacSHA256");
            extract.init(new SecretKeySpec(sessionBytes, "HmacSHA256"));
            byte[] prk = extract.doFinal(sessionKey.getEncoded());

            byte[] suffix = (sessionId + "\n" + fromClientId + "\n" + toClientId + "\n" + senderKeyEpoch)
                    .getBytes(StandardCharsets.US_ASCII);
            byte[] info = new byte[INFO_PREFIX.length + suffix.length];
            System.arraycopy(INFO_PREFIX, 0, info, 0, INFO_PREFIX.length);
            System.arraycopy(suffix, 0, info, INFO_PREFIX.length, suffix.length);

            Mac expand = Mac.getInstance("HmacSHA256");
            expand.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] firstInput = new byte[info.length + 1];
            System.arraycopy(info, 0, firstInput, 0, info.length);
            firstInput[firstInput.length - 1] = 1;
            byte[] key = expand.doFinal(firstInput);

            expand.reset();
            byte[] secondInput = new byte[key.length + info.length + 1];
            System.arraycopy(key, 0, secondInput, 0, key.length);
            System.arraycopy(info, 0, secondInput, key.length, info.length);
            secondInput[secondInput.length - 1] = 2;
            byte[] nonceMaterial = expand.doFinal(secondInput);
            return new TrafficKey(new SecretKeySpec(key, "AES"), ByteBuffer.wrap(nonceMaterial).getInt());
        } catch (Exception e) {
            throw new IllegalStateException("derive SPM2 traffic key failed", e);
        }
    }

    static byte[] encode(TrafficKey trafficKey,
                         long sessionId,
                         long sequence,
                         byte[] plaintext) {
        byte[] input = plaintext == null ? EMPTY : plaintext;
        return encode(trafficKey, sessionId, sequence, input, 0, input.length);
    }

    static byte[] encode(TrafficKey trafficKey,
                         long sessionId,
                         long sequence,
                         byte[] plaintext,
                         int offset,
                         int length) {
        if (trafficKey == null || sessionId <= 0 || sequence <= 0) {
            throw new IllegalArgumentException("invalid SPM2 key, session, or sequence");
        }
        byte[] input = plaintext == null ? EMPTY : plaintext;
        checkInputRange(input, offset, length);
        if (HEADER_BYTES + length + TAG_BYTES > MAX_BYTES) {
            throw new IllegalArgumentException("SPM2 peer data frame is too large");
        }
        try {
            byte[] frame = new byte[HEADER_BYTES + length + TAG_BYTES];
            ByteBuffer header = ByteBuffer.wrap(frame);
            header.putInt(MAGIC);
            header.putLong(sessionId);
            header.putLong(sequence);
            byte[] nonce = nonce(trafficKey.noncePrefix(), sequence);

            Cipher cipher = ENCRYPT_CIPHER.get();
            cipher.init(Cipher.ENCRYPT_MODE, trafficKey.key(), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(frame, 0, HEADER_BYTES);
            int written = cipher.doFinal(input, offset, length, frame, HEADER_BYTES);
            if (written != length + TAG_BYTES) {
                throw new IllegalStateException("unexpected SPM2 AES-GCM output length: " + written);
            }
            return frame;
        } catch (Exception e) {
            throw new IllegalStateException("encode SPM2 peer data frame failed: " + e.getMessage(), e);
        }
    }

    static PeerDataFrame decode(TrafficKey trafficKey,
                                byte[] packet,
                                long expectedSessionId) {
        try {
            if (trafficKey == null || packet == null || packet.length < MIN_BYTES || packet.length > MAX_BYTES) {
                return null;
            }
            ByteBuffer header = ByteBuffer.wrap(packet);
            if (header.getInt() != MAGIC) {
                return null;
            }
            long sessionId = header.getLong();
            long sequence = header.getLong();
            if (sessionId != expectedSessionId || sequence <= 0) {
                return null;
            }
            byte[] nonce = nonce(trafficKey.noncePrefix(), sequence);
            Cipher cipher = DECRYPT_CIPHER.get();
            cipher.init(Cipher.DECRYPT_MODE, trafficKey.key(), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(packet, 0, HEADER_BYTES);
            byte[] plaintext = cipher.doFinal(packet, HEADER_BYTES, packet.length - HEADER_BYTES);
            return new PeerDataFrame(sessionId, sequence, plaintext);
        } catch (Exception e) {
            return null;
        }
    }

    static Long sessionId(byte[] packet) {
        return packet == null ? null : sessionId(packet, 0, packet.length);
    }

    static Long sessionId(byte[] packet, int offset, int length) {
        if (packet == null
                || offset < 0
                || length < MIN_BYTES
                || length > MAX_BYTES
                || offset > packet.length - length) {
            return null;
        }
        ByteBuffer header = ByteBuffer.wrap(packet, offset, length);
        return header.getInt() == MAGIC ? header.getLong() : null;
    }

    static boolean looksLikeDataFrame(byte[] packet, int offset, int length) {
        return packet != null
                && offset >= 0
                && length >= Integer.BYTES
                && offset <= packet.length - length
                && ByteBuffer.wrap(packet, offset, Integer.BYTES).getInt() == MAGIC;
    }

    private static Cipher newCipher() {
        try {
            return Cipher.getInstance("AES/GCM/NoPadding");
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM is unavailable", e);
        }
    }

    private static void checkInputRange(byte[] input, int offset, int length) {
        if (offset < 0 || length < 0 || offset > input.length - length) {
            throw new IndexOutOfBoundsException("invalid peer data frame payload range");
        }
    }

    private static byte[] nonce(int prefix, long sequence) {
        return ByteBuffer.allocate(NONCE_BYTES).putInt(prefix).putLong(sequence).array();
    }

    record TrafficKey(SecretKeySpec key, int noncePrefix) {
    }
}
