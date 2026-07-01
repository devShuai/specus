package com.theshuai.tunnelserver.config;

import org.hibernate.boot.model.relational.Namespace;
import org.hibernate.boot.model.relational.Sequence;
import org.hibernate.cfg.SchemaToolingSettings;
import org.hibernate.mapping.Table;
import org.hibernate.tool.schema.spi.SchemaFilter;
import org.hibernate.tool.schema.spi.SchemaFilterProvider;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Locale;
import java.util.Set;

@Configuration
public class TrafficDetailSchemaFilterConfig {
    private static final Set<String> ES_BACKED_TRAFFIC_TABLES = Set.of(
            "tunnel_http_traffic_exchange",
            "tunnel_tcp_traffic_frame"
    );

    @Bean
    public HibernatePropertiesCustomizer trafficDetailSchemaFilterCustomizer(ElasticsearchProperties elasticsearchProperties) {
        return hibernateProperties -> {
            if (elasticsearchProperties.isConfigured()) {
                hibernateProperties.put(
                        SchemaToolingSettings.HBM2DDL_FILTER_PROVIDER,
                        new EsBackedTrafficSchemaFilterProvider());
            }
        };
    }

    private static class EsBackedTrafficSchemaFilterProvider implements SchemaFilterProvider {
        private final SchemaFilter filter = new EsBackedTrafficSchemaFilter();

        @Override
        public SchemaFilter getCreateFilter() {
            return filter;
        }

        @Override
        public SchemaFilter getDropFilter() {
            return filter;
        }

        @Override
        public SchemaFilter getTruncatorFilter() {
            return filter;
        }

        @Override
        public SchemaFilter getMigrateFilter() {
            return filter;
        }

        @Override
        public SchemaFilter getValidateFilter() {
            return filter;
        }
    }

    private static class EsBackedTrafficSchemaFilter implements SchemaFilter {
        @Override
        public boolean includeNamespace(Namespace namespace) {
            return true;
        }

        @Override
        public boolean includeTable(Table table) {
            if (table == null || table.getName() == null) {
                return true;
            }
            String tableName = table.getName().toLowerCase(Locale.ROOT);
            return !ES_BACKED_TRAFFIC_TABLES.contains(tableName);
        }

        @Override
        public boolean includeSequence(Sequence sequence) {
            return true;
        }
    }
}
