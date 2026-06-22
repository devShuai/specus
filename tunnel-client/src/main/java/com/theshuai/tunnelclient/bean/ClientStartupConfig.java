package com.theshuai.tunnelclient.bean;

import lombok.Data;

@Data
public class ClientStartupConfig {
    private String serverBaseUrl;
    private String authType;
    private String apiKey;
    private String secret;
    private String username;
    private String password;
}
