package com.theshuai.specusclient.peer;

public record PeerDataFrame(
        long sessionId,
        long sequence,
        byte[] plaintext
) {
}
