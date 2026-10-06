package com.theshuai.specusserver.httpshare;

/** Source of the share id and secret bytes. Production uses the platform CSPRNG only. */
@FunctionalInterface
public interface HttpShareRandom {
    void nextBytes(byte[] bytes);
}
