package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.HttpBodyTypeClassifier;
import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchange;
import com.theshuai.tunnelserver.management.model.TcpTrafficFrame;
import com.theshuai.tunnelserver.management.model.TunnelMapping;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.repository.TunnelMappingRepository;
import com.theshuai.tunnelserver.management.storage.HttpTrafficExchangeStore;
import com.theshuai.tunnelserver.management.storage.TcpTrafficFrameStore;
import jakarta.annotation.PreDestroy;
import org.brotli.dec.BrotliInputStream;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

@Service
public class TrafficInspectionService {
    public static final String DIRECTION_PUBLIC_TO_CLIENT = "PUBLIC_TO_CLIENT";
    public static final String DIRECTION_CLIENT_TO_PUBLIC = "CLIENT_TO_PUBLIC";
    private static final long CAPTURE_DECISION_TTL_NANOS = TimeUnit.SECONDS.toNanos(2);

    private final ClientAccountService clientAccountService;
    private final TunnelMappingRepository tunnelMappingRepository;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final HttpTrafficExchangeStore httpTrafficExchangeStore;
    private final TcpTrafficFrameStore tcpTrafficFrameStore;
    private final Queue<PendingHttpExchange> pendingHttpExchanges = new ConcurrentLinkedQueue<>();
    private final Queue<PendingTcpFrame> pendingTcpFrames = new ConcurrentLinkedQueue<>();
    private final Map<String, CaptureDecision> detailCaptureDecisionCache = new ConcurrentHashMap<>();
    private final Map<String, StreamCursor> tcpStreamCursors = new ConcurrentHashMap<>();
    private final AtomicInteger pendingHttpCount = new AtomicInteger();
    private final AtomicInteger pendingTcpCount = new AtomicInteger();
    private final AtomicLong droppedHttpCount = new AtomicLong();
    private final AtomicLong droppedTcpCount = new AtomicLong();
    private final boolean captureEnabled;
    private final int previewBytes;
    private final int headerChars;
    private final int decodeMaxBytes;
    private final int maxPending;
    private final int flushBatchSize;
    /** S4.2 帧采样率 0.0-1.0；每个方向的首帧始终捕获，其余帧按采样率决定 */
    private final double sampleRate;
    private volatile Instant lastFlushedAt;

    public TrafficInspectionService(ClientAccountService clientAccountService,
                                    TunnelMappingRepository tunnelMappingRepository,
                                    HttpRouteMappingRepository httpRouteMappingRepository,
                                    HttpTrafficExchangeStore httpTrafficExchangeStore,
                                    TcpTrafficFrameStore tcpTrafficFrameStore,
                                    @Value("${tunnel.traffic.capture-detail-enabled:false}") boolean captureEnabled,
                                    @Value("${tunnel.traffic.capture-preview-bytes:256}") int previewBytes,
                                    @Value("${tunnel.traffic.capture-header-chars:8192}") int headerChars,
                                    @Value("${tunnel.traffic.capture-decode-max-bytes:1048576}") int decodeMaxBytes,
                                    @Value("${tunnel.traffic.capture-max-pending:20000}") int maxPending,
                                    @Value("${tunnel.traffic.capture-flush-batch-size:1000}") int flushBatchSize,
                                    @Value("${tunnel.traffic.capture-sample-rate:1.0}") double sampleRate) {
        this.clientAccountService = clientAccountService;
        this.tunnelMappingRepository = tunnelMappingRepository;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.httpTrafficExchangeStore = httpTrafficExchangeStore;
        this.tcpTrafficFrameStore = tcpTrafficFrameStore;
        this.captureEnabled = captureEnabled;
        this.previewBytes = Math.max(0, previewBytes);
        this.headerChars = Math.max(0, headerChars);
        this.decodeMaxBytes = Math.max(1024, decodeMaxBytes);
        this.maxPending = Math.max(0, maxPending);
        this.flushBatchSize = Math.max(1, flushBatchSize);
        this.sampleRate = Math.max(0.0, Math.min(1.0, sampleRate));
    }

    public void recordHttpExchange(String clientName,
                                   String route,
                                   String method,
                                   String relativePath,
                                   String rawQuery,
                                   List<String> requestHeaders,
                                   byte[] requestBody,
                                   int statusCode,
                                   List<String> responseHeaders,
                                   byte[] responseBody,
                                   long startedAtMillis,
                                   String remoteAddress,
                                   String error) {
        recordHttpExchange(
                clientName,
                route,
                method,
                relativePath,
                rawQuery,
                requestHeaders,
                requestBody,
                length(requestBody),
                statusCode,
                responseHeaders,
                responseBody,
                length(responseBody),
                startedAtMillis,
                remoteAddress,
                error);
    }

    public void recordHttpExchange(String clientName,
                                   String route,
                                   String method,
                                   String relativePath,
                                   String rawQuery,
                                   List<String> requestHeaders,
                                   byte[] requestBody,
                                   long requestBytes,
                                   int statusCode,
                                   List<String> responseHeaders,
                                   byte[] responseBody,
                                   long responseBytes,
                                   long startedAtMillis,
                                   String remoteAddress,
                                   String error) {
        if (!shouldCaptureHttpExchange(clientName, route)
                || !acquireSlot(pendingHttpCount, droppedHttpCount)) {
            return;
        }

        String requestContentType = contentType(requestHeaders);
        String responseContentType = contentType(responseHeaders);
        String responseBodyType = HttpBodyTypeClassifier.classify(responseContentType, responseBytes);
        String requestContentEncoding = contentEncoding(requestHeaders);
        String responseContentEncoding = contentEncoding(responseHeaders);
        HttpBodyCapture requestCapture = captureHttpBody(requestBody, requestContentType, requestContentEncoding);
        HttpBodyCapture responseCapture = captureHttpBody(responseBody, responseContentType, responseContentEncoding);
        pendingHttpExchanges.add(new PendingHttpExchange(
                clientName,
                blankToEmpty(route),
                blankToEmpty(method),
                blankToDefault(relativePath, "/"),
                cap(rawQuery, 2048),
                statusCode,
                error == null,
                cap(error, 2048),
                cap(remoteAddress, 255),
                Math.max(0, requestBytes),
                Math.max(0, responseBytes),
                Math.max(0, System.currentTimeMillis() - startedAtMillis),
                requestContentType,
                responseContentType,
                responseBodyType,
                cap(joinHeaders(requestHeaders), headerChars),
                cap(joinHeaders(responseHeaders), headerChars),
                requestCapture.previewHex(),
                requestCapture.bodyData(),
                requestCapture.searchText(),
                responseCapture.previewHex(),
                responseCapture.bodyData(),
                responseCapture.searchText(),
                requestCapture.truncated(),
                responseCapture.truncated(),
                Instant.now().toString()
        ));
    }

    /**
     * Lets the HTTP forwarding hot path decide whether it must retain complete request and
     * response bodies. Disabled routes return false before any unbounded body buffer is allocated.
     */
    public boolean shouldCaptureHttpExchange(String clientName, String route) {
        return captureEnabled && clientName != null && shouldCaptureHttpDetail(clientName, route);
    }

    public void recordTcpFrame(String clientName,
                               int listenPort,
                               String channelId,
                               String direction,
                               String remoteAddress,
                               byte[] payload) {
        recordTcpFrame(clientName, listenPort, channelId, direction, remoteAddress,
                null, null, null, null, payload);
    }

    public void recordTcpFrame(String clientName,
                               int listenPort,
                               String channelId,
                               String direction,
                               String sourceAddress,
                               Integer sourcePort,
                               String destinationAddress,
                               Integer destinationPort,
                               byte[] payload) {
        recordTcpFrame(clientName, listenPort, channelId, direction,
                peerAddress(direction, sourceAddress, sourcePort, destinationAddress, destinationPort),
                sourceAddress, sourcePort, destinationAddress, destinationPort, payload);
    }

    private void recordTcpFrame(String clientName,
                                int listenPort,
                                String channelId,
                                String direction,
                                String remoteAddress,
                                String sourceAddress,
                                Integer sourcePort,
                                String destinationAddress,
                                Integer destinationPort,
                                byte[] payload) {
        if (!captureEnabled || clientName == null || listenPort <= 0 || !shouldCaptureTcpDetail(clientName, listenPort)) {
            return;
        }

        // S4.2 采样：首帧始终捕获，后续按采样率随机抽样
        FramePosition framePosition = nextFramePosition(clientName, listenPort, channelId, direction, payload == null ? 0 : payload.length);
        if (framePosition.frameIndex() > 0 && sampleRate < 1.0 && Math.random() >= sampleRate) {
            return;
        }

        if (!acquireSlot(pendingTcpCount, droppedTcpCount)) {
            return;
        }

        Preview preview = preview(payload);
        long payloadBytes = length(payload);
        byte[] payloadData = payload == null || payload.length == 0 ? new byte[0] : Arrays.copyOf(payload, payload.length);
        pendingTcpFrames.add(new PendingTcpFrame(
                clientName,
                listenPort,
                cap(blankToEmpty(channelId), 120),
                cap(blankToEmpty(direction), 32),
                cap(remoteAddress, 255),
                cap(sourceAddress, 255),
                sourcePort,
                cap(destinationAddress, 255),
                destinationPort,
                framePosition.streamOffset(),
                framePosition.streamEndOffset(),
                framePosition.frameIndex(),
                payloadBytes,
                payloadData,
                preview.hex(),
                preview.text(),
                false,
                Instant.now().toString()
        ));
    }

    public void releaseTcpStream(String channelId) {
        if (channelId == null || channelId.isBlank()) {
            return;
        }
        String token = "|" + channelId + "|";
        tcpStreamCursors.keySet().removeIf(key -> key.contains(token));
    }

    /**
     * S1.4 把原本单个 {@code synchronized flush()} 拆成两个独立 {@code @Scheduled} 方法。
     * 原实现里 HTTP 与 TCP 共用一把 monitor 锁：一旦 TCP 落库慢（大帧写 ES/DB），
     * HTTP 落库会被整段阻塞，反过来也一样。拆开之后两条路径互不阻塞；drain 本身走
     * {@link ConcurrentLinkedQueue#poll()} + {@link AtomicInteger#decrementAndGet()}，天然线程安全，
     * 不需要 {@code synchronized} 保护。
     *
     * <p>两个方法各自独立 {@code @Transactional}，事务粒度更小。{@link #lastFlushedAt} 是
     * {@code volatile} 的展示字段，两个方法都更新，last-write-wins 即可。
     *
     * <p>保留无注解的 {@link #flush()} 给 {@link #flushBeforeShutdown()} 与单测调用。
     */
    @Scheduled(fixedDelayString = "${tunnel.traffic.capture-flush-interval-ms:2000}")
    @Transactional
    public void flushHttp() {
        flushHttpInternal();
        lastFlushedAt = Instant.now();
    }

    @Scheduled(fixedDelayString = "${tunnel.traffic.capture-flush-interval-ms:2000}")
    @Transactional
    public void flushTcp() {
        flushTcpInternal();
        lastFlushedAt = Instant.now();
    }

    public void flush() {
        flushHttpInternal();
        flushTcpInternal();
        lastFlushedAt = Instant.now();
    }

    @PreDestroy
    public void flushBeforeShutdown() {
        flush();
    }

    private void flushHttpInternal() {
        List<PendingHttpExchange> pending = drain(pendingHttpExchanges, pendingHttpCount);
        if (pending.isEmpty()) {
            return;
        }

        Map<String, ClientAccount> accounts = new HashMap<>();
        List<HttpTrafficExchange> entities = new ArrayList<>(pending.size());
        for (PendingHttpExchange item : pending) {
            ClientAccount account = accounts.computeIfAbsent(item.clientName(),
                    key -> clientAccountService.findClientByName(key).orElse(null));
            if (account == null) {
                continue;
            }
            ResourceDescriptor descriptor = resolveHttpResource(account, item.route());
            HttpTrafficExchange exchange = new HttpTrafficExchange();
            exchange.setTenantId(account.getTenantId());
            exchange.setClientId(account.getId());
            exchange.setClientName(account.getClientName());
            exchange.setRoute(item.route());
            exchange.setResourceId(descriptor.resourceId());
            exchange.setResourceName(descriptor.resourceName());
            exchange.setMethod(item.method());
            exchange.setRelativePath(item.relativePath());
            exchange.setRawQuery(item.rawQuery());
            exchange.setStatusCode(item.statusCode());
            exchange.setSuccess(item.success());
            exchange.setError(item.error());
            exchange.setRemoteAddress(item.remoteAddress());
            exchange.setRequestBytes(item.requestBytes());
            exchange.setResponseBytes(item.responseBytes());
            exchange.setElapsedMs(item.elapsedMs());
            exchange.setRequestContentType(item.requestContentType());
            exchange.setResponseContentType(item.responseContentType());
            exchange.setResponseBodyType(item.responseBodyType());
            exchange.setRequestHeaders(item.requestHeaders());
            exchange.setResponseHeaders(item.responseHeaders());
            exchange.setRequestPreviewHex(item.requestPreviewHex());
            exchange.setRequestBodyData(item.requestBodyData());
            exchange.setRequestPreviewText(item.requestPreviewText());
            exchange.setResponsePreviewHex(item.responsePreviewHex());
            exchange.setResponseBodyData(item.responseBodyData());
            exchange.setResponsePreviewText(item.responsePreviewText());
            exchange.setRequestTruncated(item.requestTruncated());
            exchange.setResponseTruncated(item.responseTruncated());
            exchange.setCapturedAt(item.capturedAt());
            entities.add(exchange);
        }
        httpTrafficExchangeStore.saveAll(entities);
    }

    private void flushTcpInternal() {
        List<PendingTcpFrame> pending = drain(pendingTcpFrames, pendingTcpCount);
        if (pending.isEmpty()) {
            return;
        }

        Map<String, ClientAccount> accounts = new HashMap<>();
        List<TcpTrafficFrame> entities = new ArrayList<>(pending.size());
        for (PendingTcpFrame item : pending) {
            ClientAccount account = accounts.computeIfAbsent(item.clientName(),
                    key -> clientAccountService.findClientByName(key).orElse(null));
            if (account == null) {
                continue;
            }
            ResourceDescriptor descriptor = resolveTcpResource(account, item.listenPort());
            TcpTrafficFrame frame = new TcpTrafficFrame();
            frame.setTenantId(account.getTenantId());
            frame.setClientId(account.getId());
            frame.setClientName(account.getClientName());
            frame.setListenPort(item.listenPort());
            frame.setResourceId(descriptor.resourceId());
            frame.setResourceName(descriptor.resourceName());
            frame.setChannelId(item.channelId());
            frame.setDirection(item.direction());
            frame.setRemoteAddress(item.remoteAddress());
            frame.setSourceAddress(item.sourceAddress());
            frame.setSourcePort(item.sourcePort());
            frame.setDestinationAddress(item.destinationAddress());
            frame.setDestinationPort(item.destinationPort());
            frame.setStreamOffset(item.streamOffset());
            frame.setStreamEndOffset(item.streamEndOffset());
            frame.setFrameIndex(item.frameIndex());
            frame.setPayloadBytes(item.payloadBytes());
            frame.setPayloadData(item.payloadData());
            frame.setPayloadPreviewHex(item.payloadPreviewHex());
            frame.setPayloadPreviewText(item.payloadPreviewText());
            frame.setTruncated(item.truncated());
            frame.setFrameTime(item.frameTime());
            entities.add(frame);
        }
        tcpTrafficFrameStore.saveAll(entities);
    }

    private ResourceDescriptor resolveTcpResource(ClientAccount account, int listenPort) {
        TunnelMapping mapping = tunnelMappingRepository.findByListenPort(listenPort)
                .filter(row -> Objects.equals(row.getClientId(), account.getId()))
                .filter(row -> Objects.equals(row.getTenantId(), account.getTenantId()))
                .orElse(null);
        if (mapping != null) {
            return new ResourceDescriptor(mapping.getId(),
                    mapping.getListenPort() + " -> " + mapping.getTargetAddress() + ":" + mapping.getTargetPort());
        }
        return new ResourceDescriptor(null, "端口 " + listenPort);
    }

    private ResourceDescriptor resolveHttpResource(ClientAccount account, String route) {
        HttpRouteMapping mapping = httpRouteMappingRepository
                .findByTenantIdAndClientIdAndRoute(account.getTenantId(), account.getId(), route)
                .orElse(null);
        if (mapping != null) {
            return new ResourceDescriptor(mapping.getId(), mapping.getRoute() + " -> " + mapping.getTargetBaseUrl());
        }
        return new ResourceDescriptor(null, route);
    }

    private <T> List<T> drain(Queue<T> queue, AtomicInteger count) {
        List<T> items = new ArrayList<>(Math.min(flushBatchSize, count.get()));
        for (int i = 0; i < flushBatchSize; i++) {
            T item = queue.poll();
            if (item == null) {
                break;
            }
            count.decrementAndGet();
            items.add(item);
        }
        return items;
    }

    public Snapshot snapshot() {
        Instant flushedAt = lastFlushedAt;
        return new Snapshot(
                captureEnabled,
                pendingHttpCount.get(),
                pendingTcpCount.get(),
                droppedHttpCount.get(),
                droppedTcpCount.get(),
                flushedAt == null ? null : flushedAt.toString()
        );
    }

    private boolean acquireSlot(AtomicInteger count, AtomicLong droppedCount) {
        if (maxPending <= 0) {
            droppedCount.incrementAndGet();
            return false;
        }
        int value = count.incrementAndGet();
        if (value > maxPending) {
            count.decrementAndGet();
            droppedCount.incrementAndGet();
            return false;
        }
        return true;
    }

    private boolean shouldCaptureHttpDetail(String clientName, String route) {
        String normalizedRoute = blankToEmpty(route);
        return cachedCaptureDecision("http:" + clientName + ":" + normalizedRoute, () -> {
            ClientAccount account = clientAccountService.findClientByName(clientName).orElse(null);
            if (account == null) {
                return false;
            }
            return httpRouteMappingRepository
                    .findByTenantIdAndClientIdAndRoute(account.getTenantId(), account.getId(), normalizedRoute)
                    .map(row -> Boolean.TRUE.equals(row.getDetailCaptureEnabled()))
                    .orElse(false);
        });
    }

    private boolean shouldCaptureTcpDetail(String clientName, int listenPort) {
        return cachedCaptureDecision("tcp:" + clientName + ":" + listenPort, () -> tunnelMappingRepository
                .findByListenPort(listenPort)
                .filter(row -> Objects.equals(row.getClientName(), clientName))
                .map(row -> Boolean.TRUE.equals(row.getDetailCaptureEnabled()))
                .orElse(false));
    }

    private boolean cachedCaptureDecision(String key, java.util.function.BooleanSupplier loader) {
        long now = System.nanoTime();
        CaptureDecision cached = detailCaptureDecisionCache.get(key);
        if (cached != null && cached.expiresAtNanos() > now) {
            return cached.enabled();
        }
        boolean enabled = loader.getAsBoolean();
        detailCaptureDecisionCache.put(key, new CaptureDecision(enabled, now + CAPTURE_DECISION_TTL_NANOS));
        return enabled;
    }

    private FramePosition nextFramePosition(String clientName,
                                            int listenPort,
                                            String channelId,
                                            String direction,
                                            long payloadBytes) {
        String key = streamKey(clientName, listenPort, channelId, direction);
        return tcpStreamCursors.computeIfAbsent(key, ignored -> new StreamCursor())
                .next(Math.max(0, payloadBytes));
    }

    private String streamKey(String clientName, int listenPort, String channelId, String direction) {
        return blankToEmpty(clientName) + "|" + listenPort + "|" + blankToEmpty(channelId) + "|" + blankToEmpty(direction);
    }

    private static String peerAddress(String direction,
                                      String sourceAddress,
                                      Integer sourcePort,
                                      String destinationAddress,
                                      Integer destinationPort) {
        if (DIRECTION_PUBLIC_TO_CLIENT.equals(direction)) {
            return endpoint(sourceAddress, sourcePort);
        }
        if (DIRECTION_CLIENT_TO_PUBLIC.equals(direction)) {
            return endpoint(destinationAddress, destinationPort);
        }
        String source = endpoint(sourceAddress, sourcePort);
        return source == null ? endpoint(destinationAddress, destinationPort) : source;
    }

    private static String endpoint(String address, Integer port) {
        if (address == null || address.isBlank()) {
            return port == null ? null : ":" + port;
        }
        return port == null ? address : address + ":" + port;
    }

    private Preview preview(byte[] data) {
        int totalLength = length(data);
        int previewLength = Math.min(totalLength, previewBytes);
        if (data == null || previewLength == 0) {
            return new Preview("", "", totalLength > previewLength);
        }

        StringBuilder hex = new StringBuilder(previewLength * 3);
        for (int i = 0; i < previewLength; i++) {
            if (i > 0) {
                hex.append(' ');
            }
            int b = data[i] & 0xff;
            if (b < 0x10) {
                hex.append('0');
            }
            hex.append(Integer.toHexString(b).toUpperCase(Locale.ROOT));
        }

        String text = sanitizeText(new String(data, 0, previewLength, StandardCharsets.UTF_8));
        return new Preview(hex.toString(), text, totalLength > previewLength);
    }

    private HttpBodyCapture captureHttpBody(byte[] data, String contentType, String contentEncoding) {
        if (data == null || data.length == 0) {
            return new HttpBodyCapture("", new byte[0], "", false);
        }
        Preview rawPreview = preview(data);
        byte[] bodyData = Arrays.copyOf(data, data.length);
        String searchText = searchableBodyText(data, contentType, contentEncoding);
        return new HttpBodyCapture(rawPreview.hex(), bodyData, searchText, false);
    }

    private String searchableBodyText(byte[] data, String contentType, String contentEncoding) {
        DecodedBody decoded = decodeContentEncoding(data, contentEncoding);
        byte[] displayData = decoded.data();
        if (!isTextBody(contentType) && !looksLikeText(displayData)) {
            return "";
        }
        String text = sanitizeText(new String(displayData, StandardCharsets.UTF_8));
        if (previewBytes <= 0) {
            return "";
        }
        return cap(text, previewBytes);
    }

    private DecodedBody decodeContentEncoding(byte[] data, String contentEncoding) {
        if (!hasEncodedBody(contentEncoding)) {
            return new DecodedBody(data, false, false);
        }
        String[] tokens = contentEncoding.split(",");
        byte[] current = data;
        boolean decoded = false;
        boolean truncated = false;
        try {
            for (int i = tokens.length - 1; i >= 0; i--) {
                String token = tokens[i].trim().toLowerCase(Locale.ROOT);
                if (token.isBlank() || token.equals("identity")) {
                    continue;
                }
                if (token.equals("gzip") || token.equals("x-gzip")) {
                    LimitedBytes result = gunzip(current);
                    current = result.data();
                    truncated = truncated || result.truncated();
                    decoded = true;
                    if (truncated) {
                        break;
                    }
                    continue;
                }
                if (token.equals("deflate") || token.equals("x-deflate")) {
                    LimitedBytes result = inflate(current);
                    current = result.data();
                    truncated = truncated || result.truncated();
                    decoded = true;
                    if (truncated) {
                        break;
                    }
                    continue;
                }
                if (token.equals("br")) {
                    LimitedBytes result = brotli(current);
                    current = result.data();
                    truncated = truncated || result.truncated();
                    decoded = true;
                    if (truncated) {
                        break;
                    }
                    continue;
                }
                return new DecodedBody(data, false, false);
            }
            return new DecodedBody(current, decoded, truncated);
        } catch (IOException | IllegalArgumentException ignored) {
            return new DecodedBody(data, false, false);
        }
    }

    private LimitedBytes gunzip(byte[] data) throws IOException {
        try (GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(data))) {
            return readLimited(input);
        }
    }

    private LimitedBytes inflate(byte[] data) throws IOException {
        try {
            try (InflaterInputStream input = new InflaterInputStream(new ByteArrayInputStream(data))) {
                return readLimited(input);
            }
        } catch (IOException first) {
            try (InflaterInputStream input = new InflaterInputStream(new ByteArrayInputStream(data), new Inflater(true))) {
                return readLimited(input);
            }
        }
    }

    private LimitedBytes brotli(byte[] data) throws IOException {
        try (BrotliInputStream input = new BrotliInputStream(new ByteArrayInputStream(data))) {
            return readLimited(input);
        }
    }

    private LimitedBytes readLimited(java.io.InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(decodeMaxBytes, 8192));
        byte[] buffer = new byte[8192];
        int remaining = decodeMaxBytes;
        while (remaining > 0) {
            int read = input.read(buffer, 0, Math.min(buffer.length, remaining));
            if (read < 0) {
                return new LimitedBytes(output.toByteArray(), false);
            }
            output.write(buffer, 0, read);
            remaining -= read;
        }
        return new LimitedBytes(output.toByteArray(), input.read() >= 0);
    }

    private boolean hasEncodedBody(String contentEncoding) {
        if (contentEncoding == null || contentEncoding.isBlank()) {
            return false;
        }
        for (String token : contentEncoding.split(",")) {
            String normalized = token.trim().toLowerCase(Locale.ROOT);
            if (!normalized.isBlank() && !normalized.equals("identity")) {
                return true;
            }
        }
        return false;
    }

    private boolean isTextBody(String contentType) {
        String mediaType = mediaType(contentType);
        return mediaType.startsWith("text/")
                || mediaType.equals("application/json")
                || mediaType.endsWith("+json")
                || mediaType.equals("application/xml")
                || mediaType.endsWith("+xml")
                || mediaType.equals("application/x-www-form-urlencoded")
                || mediaType.equals("application/graphql")
                || mediaType.equals("application/javascript")
                || mediaType.equals("application/ecmascript")
                || mediaType.equals("application/x-yaml")
                || mediaType.equals("application/yaml");
    }

    private boolean looksLikeText(byte[] data) {
        int inspected = Math.min(data.length, 512);
        int controls = 0;
        for (int i = 0; i < inspected; i++) {
            int value = data[i] & 0xff;
            if (value == 0) {
                return false;
            }
            if (value < 0x20 && value != '\r' && value != '\n' && value != '\t') {
                controls++;
            }
        }
        return inspected == 0 || controls * 10 <= inspected;
    }

    private String mediaType(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            return "application/octet-stream";
        }
        String mediaType = contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        return mediaType.matches("[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+") ? mediaType : "application/octet-stream";
    }

    private String sanitizeText(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        StringBuilder result = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if ((Character.isISOControl(ch) || Character.isSurrogate(ch)) && ch != '\r' && ch != '\n' && ch != '\t') {
                result.append('.');
            } else {
                result.append(ch);
            }
        }
        return result.toString();
    }

    private String joinHeaders(List<String> headers) {
        if (headers == null || headers.isEmpty()) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (String header : headers) {
            if (header == null) {
                continue;
            }
            if (result.length() > 0) {
                result.append('\n');
            }
            result.append(maskHeader(header));
        }
        return result.toString();
    }

    private String maskHeader(String header) {
        int separator = header.indexOf(':');
        if (separator <= 0) {
            return header;
        }
        String name = header.substring(0, separator).trim();
        if (!isSensitiveHeader(name)) {
            return header;
        }
        return header.substring(0, separator + 1) + "***";
    }

    private boolean isSensitiveHeader(String name) {
        String normalized = name.toLowerCase(Locale.ROOT);
        return normalized.equals("authorization")
                || normalized.equals("proxy-authorization")
                || normalized.equals("cookie")
                || normalized.equals("set-cookie")
                || normalized.equals("x-api-key")
                || normalized.equals("x-auth-token")
                || normalized.equals("x-csrf-token");
    }

    private String contentType(List<String> headers) {
        return headerValue(headers, "content-type");
    }

    private String contentEncoding(List<String> headers) {
        return headerValue(headers, "content-encoding");
    }

    private String headerValue(List<String> headers, String name) {
        if (headers == null) {
            return null;
        }
        for (String header : headers) {
            if (header == null) {
                continue;
            }
            int separator = header.indexOf(':');
            if (separator > 0 && name.equals(header.substring(0, separator).trim().toLowerCase(Locale.ROOT))) {
                return cap(header.substring(separator + 1).trim(), 255);
            }
        }
        return null;
    }

    private static int length(byte[] data) {
        return data == null ? 0 : data.length;
    }

    private static String cap(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        if (maxLength <= 0) {
            return "";
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    private static String blankToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String blankToDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private record Preview(String hex, String text, boolean truncated) {
    }

    private record HttpBodyCapture(String previewHex, byte[] bodyData, String searchText, boolean truncated) {
    }

    public record Snapshot(boolean enabled,
                           int pendingHttp,
                           int pendingTcp,
                           long droppedHttp,
                           long droppedTcp,
                           String lastFlushedAt) {
    }

    private record DecodedBody(byte[] data, boolean decoded, boolean truncated) {
    }

    private record LimitedBytes(byte[] data, boolean truncated) {
    }

    private record CaptureDecision(boolean enabled, long expiresAtNanos) {
    }

    private record ResourceDescriptor(Long resourceId, String resourceName) {
    }

    private record PendingHttpExchange(
            String clientName,
            String route,
            String method,
            String relativePath,
            String rawQuery,
            int statusCode,
            boolean success,
            String error,
            String remoteAddress,
            long requestBytes,
            long responseBytes,
            long elapsedMs,
            String requestContentType,
            String responseContentType,
            String responseBodyType,
            String requestHeaders,
            String responseHeaders,
            String requestPreviewHex,
            byte[] requestBodyData,
            String requestPreviewText,
            String responsePreviewHex,
            byte[] responseBodyData,
            String responsePreviewText,
            boolean requestTruncated,
            boolean responseTruncated,
            String capturedAt
    ) {
    }

    private record PendingTcpFrame(
            String clientName,
            int listenPort,
            String channelId,
            String direction,
            String remoteAddress,
            String sourceAddress,
            Integer sourcePort,
            String destinationAddress,
            Integer destinationPort,
            long streamOffset,
            long streamEndOffset,
            long frameIndex,
            long payloadBytes,
            byte[] payloadData,
            String payloadPreviewHex,
            String payloadPreviewText,
            boolean truncated,
            String frameTime
    ) {
    }

    private static final class StreamCursor {
        private final AtomicLong offset = new AtomicLong();
        private final AtomicLong index = new AtomicLong();

        private FramePosition next(long payloadBytes) {
            long start = offset.getAndAdd(payloadBytes);
            long frameIndex = index.getAndIncrement();
            return new FramePosition(start, start + payloadBytes, frameIndex);
        }
    }

    private record FramePosition(long streamOffset, long streamEndOffset, long frameIndex) {
    }
}
