package com.theshuai.tunnelserver.config;

import org.springframework.boot.elasticsearch.autoconfigure.ElasticsearchConnectionDetails;
import org.springframework.boot.elasticsearch.autoconfigure.ElasticsearchConnectionDetails.Node;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.util.List;

@Configuration
public class ElasticsearchConnectionDetailsConfig {
    @Bean
    @Conditional(ElasticsearchConfiguredCondition.class)
    public ElasticsearchConnectionDetails tunnelElasticsearchConnectionDetails(ElasticsearchProperties properties) {
        return new TunnelElasticsearchConnectionDetails(properties);
    }

    private static class TunnelElasticsearchConnectionDetails implements ElasticsearchConnectionDetails {
        private final ElasticsearchProperties properties;

        private TunnelElasticsearchConnectionDetails(ElasticsearchProperties properties) {
            this.properties = properties;
        }

        @Override
        public List<Node> getNodes() {
            return properties.endpointUris().stream()
                    .map(this::toNode)
                    .toList();
        }

        @Override
        public String getUsername() {
            return StringUtils.hasText(properties.getUsername()) ? properties.getUsername() : null;
        }

        @Override
        public String getPassword() {
            return StringUtils.hasText(properties.getPassword()) ? properties.getPassword() : null;
        }

        @Override
        public String getApiKey() {
            return StringUtils.hasText(properties.getApiKey()) ? properties.getApiKey() : null;
        }

        private Node toNode(URI uri) {
            String scheme = uri.getScheme() == null ? "http" : uri.getScheme().toLowerCase();
            Node.Protocol protocol = "https".equals(scheme) ? Node.Protocol.HTTPS : Node.Protocol.HTTP;
            int port = uri.getPort();
            if (port < 0) {
                port = protocol == Node.Protocol.HTTPS ? 443 : 9200;
            }
            return new Node(uri.getHost(), port, protocol);
        }
    }
}
