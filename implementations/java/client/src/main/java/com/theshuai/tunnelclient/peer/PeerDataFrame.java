package com.theshuai.tunnelclient.peer;

public record PeerDataFrame(
        long sessionId,
        long sequence,
        byte[] plaintext
) {
}
