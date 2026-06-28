package com.theshuai.tunnelserver.management.storage;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.CommonStatsFlag;
import co.elastic.clients.elasticsearch._types.FieldValue;
import co.elastic.clients.elasticsearch._types.SortOrder;
import co.elastic.clients.elasticsearch._types.query_dsl.BoolQuery;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;
import co.elastic.clients.elasticsearch.indices.IndicesStatsResponse;
import co.elastic.clients.elasticsearch.indices.stats.IndicesStats;
import com.theshuai.tunnelserver.config.ElasticsearchProperties;
import com.theshuai.tunnelserver.management.model.HttpBodyTypeClassifier;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchange;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchangeView;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.elasticsearch.client.elc.NativeQuery;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.IndexOperations;
import org.springframework.data.elasticsearch.core.SearchHit;
import org.springframework.data.elasticsearch.core.SearchHits;
import org.springframework.util.unit.DataSize;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

public class SpringDataElasticsearchHttpTrafficExchangeStore implements HttpTrafficExchangeStore {
    private static final Logger log = LoggerFactory.getLogger(SpringDataElasticsearchHttpTrafficExchangeStore.class);
    private static final int TRIM_BATCH_SIZE = 500;
    private static final int MAX_TRIM_BATCHES = 20;
    private static final long TRIM_INTERVAL_NANOS = Duration.ofMinutes(1).toNanos();

    private final ElasticsearchOperations operations;
    private final ElasticsearchClient client;
    private final ElasticsearchProperties properties;
    private final long maxStoreBytes;
    private final AtomicLong idSequence = new AtomicLong();
    private final AtomicLong lastTrimNanos = new AtomicLong();
    private volatile boolean indexReady;

    public SpringDataElasticsearchHttpTrafficExchangeStore(ElasticsearchOperations operations,
                                                           ElasticsearchClient client,
                                                           ElasticsearchProperties properties) {
        this.operations = operations;
        this.client = client;
        this.properties = properties;
        DataSize maxStoreSize = properties.getHttpMaxStoreSize();
        this.maxStoreBytes = maxStoreSize == null ? 0 : maxStoreSize.toBytes();
    }

    @Override
    public void saveAll(List<HttpTrafficExchange> exchanges) {
        if (exchanges == null || exchanges.isEmpty()) {
            return;
        }
        ensureIndex();
        operations.save(exchanges.stream().map(this::toDocument).toList());
        trimIfNecessary();
    }

    @Override
    public Page<HttpTrafficExchangeView> search(TenantContext tenant,
                                                Long clientId,
                                                Set<Long> visibleClientIds,
                                                String route,
                                                String responseBodyType,
                                                HttpTrafficSearchField searchField,
                                                String keyword,
                                                Pageable pageable) {
        if (isDenied(clientId, visibleClientIds)) {
            return Page.empty(pageable);
        }
        ensureIndex();
        NativeQuery query = NativeQuery.builder()
                .withQuery(buildQuery(tenant, clientId, visibleClientIds, normalizeRoute(route),
                        HttpBodyTypeClassifier.normalize(responseBodyType), searchField, normalizeKeyword(keyword)))
                .withPageable(pageable)
                .withSort(sort -> sort.field(sortField -> sortField.field("id").order(SortOrder.Desc)))
                .build();
        SearchHits<HttpTrafficExchangeDocument> hits = operations.search(query, HttpTrafficExchangeDocument.class);
        List<HttpTrafficExchangeView> items = hits.getSearchHits().stream()
                .map(SearchHit::getContent)
                .map(SpringDataElasticsearchHttpTrafficExchangeStore::toView)
                .toList();
        return new PageImpl<>(items, pageable, hits.getTotalHits());
    }

    @Override
    public String backend() {
        return "elasticsearch";
    }

    private void ensureIndex() {
        if (indexReady) {
            return;
        }
        synchronized (this) {
            if (indexReady) {
                return;
            }
            IndexOperations indexOperations = operations.indexOps(HttpTrafficExchangeDocument.class);
            if (!indexOperations.exists()) {
                indexOperations.create();
                indexOperations.putMapping(indexOperations.createMapping(HttpTrafficExchangeDocument.class));
            } else {
                log.debug("Elasticsearch index {} already exists, skip mapping update", properties.getIndex());
            }
            indexReady = true;
        }
    }

    private Query buildQuery(TenantContext tenant,
                             Long clientId,
                             Set<Long> visibleClientIds,
                             String route,
                             String responseBodyType,
                             HttpTrafficSearchField field,
                             String keyword) {
        HttpTrafficSearchField searchField = field == null ? HttpTrafficSearchField.SUMMARY : field;
        BoolQuery.Builder bool = new BoolQuery.Builder()
                .filter(term("tenantId", tenant.tenantId()));
        if (clientId != null) {
            bool.filter(term("clientId", clientId));
        } else if (visibleClientIds != null) {
            bool.filter(terms("clientId", visibleClientIds));
        }
        if (route != null) {
            bool.filter(term("route", route));
        }
        if (responseBodyType != null) {
            bool.filter(responseBodyTypeQuery(responseBodyType));
        }
        for (String token : keywordTokens(keyword)) {
            bool.must(keywordTokenQuery(searchField, token));
        }
        return bool.build()._toQuery();
    }

    private boolean isDenied(Long clientId, Set<Long> visibleClientIds) {
        if (visibleClientIds == null) {
            return false;
        }
        if (visibleClientIds.isEmpty()) {
            return true;
        }
        return clientId != null && !visibleClientIds.contains(clientId);
    }

    private Query responseBodyTypeQuery(String responseBodyType) {
        BoolQuery.Builder bool = new BoolQuery.Builder()
                .should(term("responseBodyType", responseBodyType));
        if (HttpBodyTypeClassifier.EMPTY.equals(responseBodyType)) {
            bool.should(term("responseBytes", 0));
        } else {
            for (String pattern : responseContentTypePatterns(responseBodyType)) {
                bool.should(wildcard("responseContentType", pattern));
            }
        }
        bool.minimumShouldMatch("1");
        return bool.build()._toQuery();
    }

    private List<String> responseContentTypePatterns(String responseBodyType) {
        return switch (responseBodyType) {
            case HttpBodyTypeClassifier.JSON -> List.of("application/json", "+json");
            case HttpBodyTypeClassifier.HTML -> List.of("text/html");
            case HttpBodyTypeClassifier.XML -> List.of("application/xml", "text/xml", "+xml");
            case HttpBodyTypeClassifier.IMAGE -> List.of("image/");
            case HttpBodyTypeClassifier.VIDEO -> List.of("video/");
            case HttpBodyTypeClassifier.AUDIO -> List.of("audio/");
            case HttpBodyTypeClassifier.FORM -> List.of("application/x-www-form-urlencoded", "multipart/form-data");
            case HttpBodyTypeClassifier.SCRIPT -> List.of("javascript", "ecmascript");
            case HttpBodyTypeClassifier.TEXT -> List.of("text/");
            case HttpBodyTypeClassifier.BINARY -> List.of("application/octet-stream", "application/pdf",
                    "application/zip", "application/x-", "application/vnd.");
            default -> List.of();
        };
    }

    private Query keywordTokenQuery(HttpTrafficSearchField field, String token) {
        if (field == HttpTrafficSearchField.METHOD) {
            return term("method", token.toUpperCase(Locale.ROOT));
        }
        BoolQuery.Builder bool = new BoolQuery.Builder();
        if (!field.elasticTextFields().isEmpty()) {
            bool.should(Query.of(q -> q.multiMatch(match -> match
                    .query(token)
                    .fields(field.elasticTextFields()))));
        }
        for (String keywordField : field.elasticKeywordFields()) {
            bool.should(wildcard(keywordField, token));
        }
        Long number = parseLong(token);
        if (number != null) {
            if (field.searchId()) {
                bool.should(term("id", number));
            }
            if (field.searchClientId()) {
                bool.should(term("clientId", number));
            }
            if (field.searchStatusCode() && number >= Integer.MIN_VALUE && number <= Integer.MAX_VALUE) {
                bool.should(term("statusCode", number.intValue()));
            }
            if (field.searchResourceId()) {
                bool.should(term("resourceId", number));
            }
        }
        if (field.elasticTextFields().isEmpty()
                && field.elasticKeywordFields().isEmpty()
                && number == null) {
            return noMatch();
        }
        bool.minimumShouldMatch("1");
        return bool.build()._toQuery();
    }

    private List<String> keywordTokens(String keyword) {
        if (keyword == null || keyword.isBlank()) {
            return List.of();
        }
        return Arrays.stream(keyword.trim().split("\\s+"))
                .filter(token -> !token.isBlank())
                .toList();
    }

    private Query term(String field, String value) {
        return Query.of(q -> q.term(term -> term.field(field).value(value)));
    }

    private Query term(String field, long value) {
        return Query.of(q -> q.term(term -> term.field(field).value(FieldValue.of(value))));
    }

    private Query terms(String field, Set<Long> values) {
        return Query.of(q -> q.terms(terms -> terms
                .field(field)
                .terms(v -> v.value(values.stream().map(FieldValue::of).toList()))));
    }

    private Query wildcard(String field, String value) {
        return Query.of(q -> q.wildcard(wildcard -> wildcard
                .field(field)
                .value("*" + escapeWildcard(value) + "*")
                .caseInsensitive(true)));
    }

    private Query noMatch() {
        return term("_id", "__shuai_tunnel_no_match__");
    }

    private String escapeWildcard(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("*", "\\*")
                .replace("?", "\\?");
    }

    private HttpTrafficExchangeDocument toDocument(HttpTrafficExchange exchange) {
        long id = documentId(exchange);
        HttpTrafficExchangeDocument document = new HttpTrafficExchangeDocument();
        document.setDocumentId(Long.toString(id));
        document.setExchangeId(id);
        document.setTenantId(exchange.getTenantId());
        document.setClientId(exchange.getClientId());
        document.setClientName(exchange.getClientName());
        document.setRoute(exchange.getRoute());
        document.setResourceId(exchange.getResourceId());
        document.setResourceName(exchange.getResourceName());
        document.setMethod(exchange.getMethod());
        document.setRelativePath(exchange.getRelativePath());
        document.setRawQuery(exchange.getRawQuery());
        document.setStatusCode(exchange.getStatusCode());
        document.setSuccess(exchange.isSuccess());
        document.setError(exchange.getError());
        document.setRemoteAddress(exchange.getRemoteAddress());
        document.setRequestBytes(exchange.getRequestBytes());
        document.setResponseBytes(exchange.getResponseBytes());
        document.setElapsedMs(exchange.getElapsedMs());
        document.setRequestContentType(exchange.getRequestContentType());
        document.setResponseContentType(exchange.getResponseContentType());
        document.setResponseBodyType(HttpBodyTypeClassifier.normalizeOrClassify(
                exchange.getResponseBodyType(), exchange.getResponseContentType(), exchange.getResponseBytes()));
        document.setRequestHeaders(exchange.getRequestHeaders());
        document.setResponseHeaders(exchange.getResponseHeaders());
        document.setRequestPreviewHex(exchange.getRequestPreviewHex());
        document.setRequestPreviewText(exchange.getRequestPreviewText());
        document.setResponsePreviewHex(exchange.getResponsePreviewHex());
        document.setResponsePreviewText(exchange.getResponsePreviewText());
        document.setRequestTruncated(exchange.isRequestTruncated());
        document.setResponseTruncated(exchange.isResponseTruncated());
        document.setCapturedAt(exchange.getCapturedAt());
        return document;
    }

    private static HttpTrafficExchangeView toView(HttpTrafficExchangeDocument document) {
        return new HttpTrafficExchangeView(
                document.getExchangeId(),
                document.getClientId(),
                document.getClientName(),
                document.getRoute(),
                document.getResourceId(),
                document.getResourceName(),
                document.getMethod(),
                document.getRelativePath(),
                document.getRawQuery(),
                document.getStatusCode(),
                document.isSuccess(),
                document.getError(),
                document.getRemoteAddress(),
                document.getRequestBytes(),
                document.getResponseBytes(),
                document.getElapsedMs(),
                document.getRequestContentType(),
                document.getResponseContentType(),
                HttpBodyTypeClassifier.normalizeOrClassify(
                        document.getResponseBodyType(), document.getResponseContentType(), document.getResponseBytes()),
                document.getRequestHeaders(),
                document.getResponseHeaders(),
                document.getRequestPreviewHex(),
                document.getRequestPreviewText(),
                document.getResponsePreviewHex(),
                document.getResponsePreviewText(),
                document.isRequestTruncated(),
                document.isResponseTruncated(),
                document.getCapturedAt()
        );
    }

    private long documentId(HttpTrafficExchange exchange) {
        if (exchange.getId() != null) {
            return exchange.getId();
        }
        long millis = System.currentTimeMillis();
        long sequence = idSequence.getAndIncrement() & 0xfffffL;
        return (millis << 20) | sequence;
    }

    private String normalizeRoute(String route) {
        if (route == null || route.isBlank()) {
            return null;
        }
        return route.trim();
    }

    private String normalizeKeyword(String keyword) {
        if (keyword == null || keyword.isBlank()) {
            return null;
        }
        return keyword.trim();
    }

    private Long parseLong(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private void trimIfNecessary() {
        if (client == null || maxStoreBytes <= 0) {
            return;
        }
        long now = System.nanoTime();
        long last = lastTrimNanos.get();
        if (last != 0 && now - last < TRIM_INTERVAL_NANOS) {
            return;
        }
        if (!lastTrimNanos.compareAndSet(last, now)) {
            return;
        }
        try {
            long storeBytes = currentStoreBytes();
            if (storeBytes <= maxStoreBytes) {
                return;
            }
            int deleted = 0;
            int batches = 0;
            while (storeBytes > maxStoreBytes && batches < MAX_TRIM_BATCHES) {
                List<HttpTrafficExchangeDocument> oldest = oldestDocuments();
                if (oldest.isEmpty()) {
                    break;
                }
                for (HttpTrafficExchangeDocument document : oldest) {
                    operations.delete(document.getDocumentId(), HttpTrafficExchangeDocument.class);
                    deleted++;
                }
                storeBytes = currentStoreBytes();
                batches++;
            }
            if (deleted > 0) {
                log.info("HTTP traffic Elasticsearch index retention deleted {} old exchanges, storeBytes={}, maxStoreBytes={}",
                        deleted, storeBytes, maxStoreBytes);
            }
        } catch (Exception ex) {
            log.warn("Failed to enforce HTTP traffic Elasticsearch index size limit", ex);
        }
    }

    private long currentStoreBytes() throws IOException {
        IndicesStatsResponse response = client.indices().stats(request -> request
                .index(properties.getIndex())
                .metric(CommonStatsFlag.Store));
        IndicesStats stats = response.indices().get(properties.getIndex());
        if (stats == null || stats.total() == null || stats.total().store() == null) {
            return 0;
        }
        Long totalDataSetSize = stats.total().store().totalDataSetSizeInBytes();
        if (totalDataSetSize != null) {
            return Math.max(0, totalDataSetSize);
        }
        return Math.max(0, stats.total().store().sizeInBytes());
    }

    private List<HttpTrafficExchangeDocument> oldestDocuments() {
        NativeQuery query = NativeQuery.builder()
                .withQuery(Query.of(q -> q.matchAll(matchAll -> matchAll)))
                .withPageable(PageRequest.of(0, TRIM_BATCH_SIZE))
                .withSort(sort -> sort.field(field -> field.field("id").order(SortOrder.Asc)))
                .build();
        SearchHits<HttpTrafficExchangeDocument> hits = operations.search(query, HttpTrafficExchangeDocument.class);
        return hits.getSearchHits().stream()
                .map(SearchHit::getContent)
                .toList();
    }
}
