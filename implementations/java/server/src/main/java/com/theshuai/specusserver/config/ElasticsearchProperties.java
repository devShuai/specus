package com.theshuai.specusserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "specus.elasticsearch")
@Data
public class ElasticsearchProperties {
    private String uris = "";
    private String username = "";
    private String password = "";
    private String apiKey = "";
    private String index = "specus-http-traffic";
    private String tcpIndex = "specus-tcp-traffic";
    private DataSize httpMaxStoreSize = DataSize.ofGigabytes(100);
    private DataSize tcpMaxStoreSize = DataSize.ofGigabytes(10);

    public boolean isConfigured() {
        return uris != null && !uris.isBlank();
    }

    public List<URI> endpointUris() {
        if (!isConfigured()) {
            return List.of();
        }
        return Arrays.stream(uris.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .map(ElasticsearchProperties::normalizeUri)
                .toList();
    }

    private static URI normalizeUri(String value) {
        String normalized = value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
        return URI.create(normalized);
    }
}
