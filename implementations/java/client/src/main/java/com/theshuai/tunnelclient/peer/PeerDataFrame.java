package com.theshuai.tunnelclient.peer;

public record PeerDataFrame(
        long sessionId,
        long fromClientId,
        long toClientId,
        long sequence,
        byte[] plaintext
) {
}
