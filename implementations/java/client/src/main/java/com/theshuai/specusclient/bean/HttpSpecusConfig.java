package com.theshuai.specusclient.bean;

import lombok.Data;

@Data
public class HttpSpecusConfig {
    private String route;
    private String targetBaseUrl;
    /** Route-level opt-out for self-signed or otherwise untrusted HTTPS/WSS targets. */
    private boolean insecureSkipVerify;
}
