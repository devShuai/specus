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
import com.theshuai.tunnelserver.management.model.TcpTrafficFrame;
import com.theshuai.tunnelserver.management.model.TcpTrafficFrameView;
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
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

public class SpringDataElasticsearchTcpTrafficFrameStore implements TcpTrafficFrameStore {
    private static final Logger log = LoggerFactory.getLogger(SpringDataElasticsearchTcpTrafficFrameStore.class);
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

    public SpringDataElasticsearchTcpTrafficFrameStore(ElasticsearchOperations operations,
                                                       ElasticsearchClient client,
                                                       ElasticsearchProperties properties) {
        this.operations = operations;
        this.client = client;
        this.properties = properties;
        DataSize maxStoreSize = properties.getTcpMaxStoreSize();
        this.maxStoreBytes = maxStoreSize == null ? 0 : maxStoreSize.toBytes();
    }

    @Override
    public void saveAll(List<TcpTrafficFrame> frames) {
        if (frames == null || frames.isEmpty()) {
            return;
        }
        ensureIndex();
        operations.save(frames.stream().map(this::toDocument).toList());
        trimIfNecessary();
    }

    @Override
    public Page<TcpTrafficFrameView> search(TenantContext tenant, Long clientId, Set<Long> visibleClientIds,
                                            Integer listenPort, Pageable pageable) {
        if (isDenied(clientId, visibleClientIds)) {
            return Page.empty(pageable);
        }
        ensureIndex();
        NativeQuery query = NativeQuery.builder()
                .withQuery(buildQuery(tenant, clientId, visibleClientIds, listenPort))
                .withPageable(pageable)
                .withSort(sort -> sort.field(field -> field.field("id").order(SortOrder.Desc)))
                .build();
        SearchHits<TcpTrafficFrameDocument> hits = operations.search(query, TcpTrafficFrameDocument.class);
        List<TcpTrafficFrameView> items = hits.getSearchHits().stream()
                .map(SearchHit::getContent)
                .map(document -> toView(document, false))
                .toList();
        return new PageImpl<>(items, pageable, hits.getTotalHits());
    }

    @Override
    public Optional<TcpTrafficFrameView> findById(TenantContext tenant, long id, Set<Long> visibleClientIds) {
        if (visibleClientIds != null && visibleClientIds.isEmpty()) {
            return Optional.empty();
        }
        ensureIndex();
        BoolQuery.Builder bool = new BoolQuery.Builder()
                .filter(term("tenantId", tenant.tenantId()))
                .filter(term("id", id));
        if (visibleClientIds != null) {
            bool.filter(terms("clientId", visibleClientIds));
        }
        NativeQuery nativeQuery = NativeQuery.builder()
                .withQuery(bool.build()._toQuery())
                .withPageable(PageRequest.of(0, 1))
                .build();
        SearchHits<TcpTrafficFrameDocument> hits = operations.search(nativeQuery, TcpTrafficFrameDocument.class);
        return hits.getSearchHits().stream()
                .findFirst()
                .map(SearchHit::getContent)
                .map(document -> toView(document, true));
    }

    @Override
    public Page<TcpTrafficFrameView> findStream(TenantContext tenant, String channelId, Set<Long> visibleClientIds,
                                                Pageable pageable) {
        if (channelId == null || channelId.isBlank()) {
            return Page.empty(pageable);
        }
        if (visibleClientIds != null && visibleClientIds.isEmpty()) {
            return Page.empty(pageable);
        }
        ensureIndex();
        String normalizedChannelId = channelId.trim();
        BoolQuery.Builder bool = new BoolQuery.Builder()
                .filter(term("tenantId", tenant.tenantId()))
                .filter(exactText("channelId", normalizedChannelId));
        if (visibleClientIds != null) {
            bool.filter(terms("clientId", visibleClientIds));
        }
        NativeQuery nativeQuery = NativeQuery.builder()
                .withQuery(bool.build()._toQuery())
                .withPageable(pageable)
                .withSort(sort -> sort.field(field -> field.field("id").order(SortOrder.Asc)))
                .build();
        SearchHits<TcpTrafficFrameDocument> hits = operations.search(nativeQuery, TcpTrafficFrameDocument.class);
        List<TcpTrafficFrameView> items = hits.getSearchHits().stream()
                .map(SearchHit::getContent)
                .map(document -> toView(document, true))
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
            IndexOperations indexOperations = operations.indexOps(TcpTrafficFrameDocument.class);
            if (!indexOperations.exists()) {
                indexOperations.create();
                indexOperations.putMapping(indexOperations.createMapping(TcpTrafficFrameDocument.class));
            } else {
                log.debug("Elasticsearch index {} already exists, skip mapping update", properties.getTcpIndex());
            }
            indexReady = true;
        }
    }

    private Query buildQuery(TenantContext tenant, Long clientId, Set<Long> visibleClientIds, Integer listenPort) {
        BoolQuery.Builder bool = new BoolQuery.Builder()
                .filter(term("tenantId", tenant.tenantId()));
        if (clientId != null) {
            bool.filter(term("clientId", clientId));
        } else if (visibleClientIds != null) {
            bool.filter(terms("clientId", visibleClientIds));
        }
        if (listenPort != null) {
            bool.filter(term("listenPort", listenPort));
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

    private Query term(String field, String value) {
        return Query.of(q -> q.term(term -> term.field(field).value(value)));
    }

    private Query exactText(String field, String value) {
        return Query.of(q -> q.bool(bool -> bool
                .minimumShouldMatch("1")
                .should(term(field, value))
                .should(term(field + ".keyword", value))
                .should(phrase(field, value))));
    }

    private Query phrase(String field, String value) {
        return Query.of(q -> q.matchPhrase(match -> match.field(field).query(value)));
    }

    private Query term(String field, long value) {
        return Query.of(q -> q.term(term -> term.field(field).value(FieldValue.of(value))));
    }

    private Query terms(String field, Set<Long> values) {
        return Query.of(q -> q.terms(terms -> terms
                .field(field)
                .terms(v -> v.value(values.stream().map(FieldValue::of).toList()))));
    }

    private TcpTrafficFrameDocument toDocument(TcpTrafficFrame frame) {
        long id = documentId(frame);
        TcpTrafficFrameDocument document = new TcpTrafficFrameDocument();
        document.setDocumentId(Long.toString(id));
        document.setFrameId(id);
        document.setTenantId(frame.getTenantId());
        document.setClientId(frame.getClientId());
        document.setClientName(frame.getClientName());
        document.setListenPort(frame.getListenPort());
        document.setResourceId(frame.getResourceId());
        document.setResourceName(frame.getResourceName());
        document.setChannelId(frame.getChannelId());
        document.setDirection(frame.getDirection());
        document.setRemoteAddress(frame.getRemoteAddress());
        document.setSourceAddress(frame.getSourceAddress());
        document.setSourcePort(frame.getSourcePort());
        document.setDestinationAddress(frame.getDestinationAddress());
        document.setDestinationPort(frame.getDestinationPort());
        document.setStreamOffset(frame.getStreamOffset());
        document.setStreamEndOffset(frame.getStreamEndOffset());
        document.setFrameIndex(frame.getFrameIndex());
        document.setPayloadBytes(frame.getPayloadBytes());
        document.setPayloadData(frame.getPayloadData());
        document.setPayloadPreviewHex(frame.getPayloadPreviewHex());
        document.setPayloadPreviewText(frame.getPayloadPreviewText());
        document.setTruncated(frame.isTruncated());
        document.setFrameTime(frame.getFrameTime());
        return document;
    }

    private static TcpTrafficFrameView toView(TcpTrafficFrameDocument document, boolean includePayload) {
        return new TcpTrafficFrameView(
                Long.toString(document.getFrameId()),
                document.getClientId(),
                document.getClientName(),
                document.getListenPort(),
                document.getResourceId(),
                document.getResourceName(),
                document.getChannelId(),
                document.getDirection(),
                document.getRemoteAddress(),
                document.getSourceAddress(),
                document.getSourcePort(),
                document.getDestinationAddress(),
                document.getDestinationPort(),
                longValue(document.getStreamOffset()),
                longValue(document.getStreamEndOffset()),
                longValue(document.getFrameIndex()),
                document.getPayloadBytes(),
                includePayload ? payloadBase64(document.getPayloadData()) : "",
                document.getPayloadPreviewHex(),
                document.getPayloadPreviewText(),
                document.isTruncated(),
                document.getFrameTime()
        );
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
                List<TcpTrafficFrameDocument> oldest = oldestDocuments();
                if (oldest.isEmpty()) {
                    break;
                }
                for (TcpTrafficFrameDocument document : oldest) {
                    operations.delete(document.getDocumentId(), TcpTrafficFrameDocument.class);
                    deleted++;
                }
                storeBytes = currentStoreBytes();
                batches++;
            }
            if (deleted > 0) {
                log.info("TCP traffic Elasticsearch index retention deleted {} old frames, storeBytes={}, maxStoreBytes={}",
                        deleted, storeBytes, maxStoreBytes);
            }
        } catch (Exception ex) {
            log.warn("Failed to enforce TCP traffic Elasticsearch index size limit", ex);
        }
    }

    private long currentStoreBytes() throws IOException {
        IndicesStatsResponse response = client.indices().stats(request -> request
                .index(properties.getTcpIndex())
                .metric(CommonStatsFlag.Store));
        IndicesStats stats = response.indices().get(properties.getTcpIndex());
        if (stats == null || stats.total() == null || stats.total().store() == null) {
            return 0;
        }
        Long totalDataSetSize = stats.total().store().totalDataSetSizeInBytes();
        if (totalDataSetSize != null) {
            return Math.max(0, totalDataSetSize);
        }
        return Math.max(0, stats.total().store().sizeInBytes());
    }

    private List<TcpTrafficFrameDocument> oldestDocuments() {
        NativeQuery query = NativeQuery.builder()
                .withQuery(Query.of(q -> q.matchAll(matchAll -> matchAll)))
                .withPageable(PageRequest.of(0, TRIM_BATCH_SIZE))
                .withSort(sort -> sort.field(field -> field.field("id").order(SortOrder.Asc)))
                .build();
        SearchHits<TcpTrafficFrameDocument> hits = operations.search(query, TcpTrafficFrameDocument.class);
        return hits.getSearchHits().stream()
                .map(SearchHit::getContent)
                .toList();
    }

    private static String payloadBase64(byte[] payloadData) {
        if (payloadData == null || payloadData.length == 0) {
            return "";
        }
        return Base64.getEncoder().encodeToString(payloadData);
    }

    private static long longValue(Long value) {
        return value == null ? 0 : value;
    }

    private long documentId(TcpTrafficFrame frame) {
        if (frame.getId() != null) {
            return frame.getId();
        }
        long millis = System.currentTimeMillis();
        long sequence = idSequence.getAndIncrement() & 0xfffffL;
        return (millis << 20) | sequence;
    }
}
