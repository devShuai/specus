package com.theshuai.common.clientauth;

import lombok.Data;

@Data
public class ClientAuthLoginRequest {
    /**
     * apiKey: apiKey + timestamp + nonce + HMAC signature.
     * password: username + password.
     */
    private String authType;
    private String apiKey;
    private String secret;
    private String username;
    private String password;
    private String timestamp;
    private String nonce;
    private String signature;
    private ClientEnvironmentInfo environment;
}
