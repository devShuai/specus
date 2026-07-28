package com.theshuai.specusserver.config;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import com.theshuai.specusserver.management.repository.HttpTrafficExchangeRepository;
import com.theshuai.specusserver.management.repository.TcpTrafficFrameRepository;
import com.theshuai.specusserver.management.storage.HttpTrafficExchangeStore;
import com.theshuai.specusserver.management.storage.JpaHttpTrafficExchangeStore;
import com.theshuai.specusserver.management.storage.JpaTcpTrafficFrameStore;
import com.theshuai.specusserver.management.storage.SpringDataElasticsearchHttpTrafficExchangeStore;
import com.theshuai.specusserver.management.storage.SpringDataElasticsearchTcpTrafficFrameStore;
import com.theshuai.specusserver.management.storage.TcpTrafficFrameStore;
import jakarta.persistence.EntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;

@Configuration
public class HttpTrafficExchangeStoreConfig {
    private static final Logger log = LoggerFactory.getLogger(HttpTrafficExchangeStoreConfig.class);

    @Bean
    public HttpTrafficExchangeStore httpTrafficExchangeStore(ElasticsearchProperties elasticsearchProperties,
                                                             ObjectProvider<ElasticsearchOperations> elasticsearchOperations,
                                                             ObjectProvider<ElasticsearchClient> elasticsearchClient,
                                                             HttpTrafficExchangeRepository repository,
                                                             EntityManager entityManager) {
        if (elasticsearchProperties.isConfigured()) {
            ElasticsearchOperations operations = elasticsearchOperations.getIfAvailable();
            if (operations == null) {
                throw new IllegalStateException("specus.elasticsearch.uris configured but ElasticsearchOperations is unavailable");
            }
            log.info("HTTP traffic exchange store: Elasticsearch index={}", elasticsearchProperties.getIndex());
            return new SpringDataElasticsearchHttpTrafficExchangeStore(
                    operations,
                    elasticsearchClient.getIfAvailable(),
                    elasticsearchProperties);
        }
        log.info("HTTP traffic exchange store: database");
        return new JpaHttpTrafficExchangeStore(repository, entityManager);
    }

    @Bean
    public TcpTrafficFrameStore tcpTrafficFrameStore(ElasticsearchProperties elasticsearchProperties,
                                                     ObjectProvider<ElasticsearchOperations> elasticsearchOperations,
                                                     ObjectProvider<ElasticsearchClient> elasticsearchClient,
                                                     TcpTrafficFrameRepository repository) {
        if (elasticsearchProperties.isConfigured()) {
            ElasticsearchOperations operations = elasticsearchOperations.getIfAvailable();
            if (operations == null) {
                throw new IllegalStateException("specus.elasticsearch.uris configured but ElasticsearchOperations is unavailable");
            }
            ElasticsearchClient client = elasticsearchClient.getIfAvailable();
            log.info("TCP traffic frame store: Elasticsearch index={}", elasticsearchProperties.getTcpIndex());
            return new SpringDataElasticsearchTcpTrafficFrameStore(operations, client, elasticsearchProperties);
        }
        log.info("TCP traffic frame store: database");
        return new JpaTcpTrafficFrameStore(repository);
    }
}
