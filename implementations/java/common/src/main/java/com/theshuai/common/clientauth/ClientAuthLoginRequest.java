package com.theshuai.common.clientauth;

import lombok.Data;

@Data
public class ClientAuthLoginRequest {
    /**
     * apiKey + timestamp + nonce + environment are signed with the client secret.
     */
    private String apiKey;
    private String timestamp;
    private String nonce;
    private String signature;
    private ClientEnvironmentInfo environment;
}
