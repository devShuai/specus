package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchange;
import com.theshuai.tunnelserver.management.model.TcpTrafficFrame;
import com.theshuai.tunnelserver.management.model.TunnelMapping;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.repository.HttpTrafficExchangeRepository;
import com.theshuai.tunnelserver.management.repository.TcpTrafficFrameRepository;
import com.theshuai.tunnelserver.management.repository.TunnelMappingRepository;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class TrafficInspectionService {
    public static final String DIRECTION_PUBLIC_TO_CLIENT = "PUBLIC_TO_CLIENT";
    public static final String DIRECTION_CLIENT_TO_PUBLIC = "CLIENT_TO_PUBLIC";

    private final ClientAccountService clientAccountService;
    private final TunnelMappingRepository tunnelMappingRepository;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final HttpTrafficExchangeRepository httpTrafficExchangeRepository;
    private final TcpTrafficFrameRepository tcpTrafficFrameRepository;
    private final Queue<PendingHttpExchange> pendingHttpExchanges = new ConcurrentLinkedQueue<>();
    private final Queue<PendingTcpFrame> pendingTcpFrames = new ConcurrentLinkedQueue<>();
    private final AtomicInteger pendingHttpCount = new AtomicInteger();
    private final AtomicInteger pendingTcpCount = new AtomicInteger();
    private final boolean captureEnabled;
    private final int previewBytes;
    private final int headerChars;
    private final int maxPending;
    private final int flushBatchSize;

    public TrafficInspectionService(ClientAccountService clientAccountService,
                                    TunnelMappingRepository tunnelMappingRepository,
                                    HttpRouteMappingRepository httpRouteMappingRepository,
                                    HttpTrafficExchangeRepository httpTrafficExchangeRepository,
                                    TcpTrafficFrameRepository tcpTrafficFrameRepository,
                                    @Value("${tunnel.traffic.capture-detail-enabled:true}") boolean captureEnabled,
                                    @Value("${tunnel.traffic.capture-preview-bytes:256}") int previewBytes,
                                    @Value("${tunnel.traffic.capture-header-chars:8192}") int headerChars,
                                    @Value("${tunnel.traffic.capture-max-pending:20000}") int maxPending,
                                    @Value("${tunnel.traffic.capture-flush-batch-size:1000}") int flushBatchSize) {
        this.clientAccountService = clientAccountService;
        this.tunnelMappingRepository = tunnelMappingRepository;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.httpTrafficExchangeRepository = httpTrafficExchangeRepository;
        this.tcpTrafficFrameRepository = tcpTrafficFrameRepository;
        this.captureEnabled = captureEnabled;
        this.previewBytes = Math.max(0, previewBytes);
        this.headerChars = Math.max(0, headerChars);
        this.maxPending = Math.max(0, maxPending);
        this.flushBatchSize = Math.max(1, flushBatchSize);
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
        if (!captureEnabled || clientName == null || !acquireSlot(pendingHttpCount)) {
            return;
        }

        Preview requestPreview = fullText(requestBody);
        Preview responsePreview = textPreview(responseBody);
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
                length(requestBody),
                length(responseBody),
                Math.max(0, System.currentTimeMillis() - startedAtMillis),
                contentType(requestHeaders),
                contentType(responseHeaders),
                cap(joinHeaders(requestHeaders), headerChars),
                cap(joinHeaders(responseHeaders), headerChars),
                requestPreview.hex(),
                requestPreview.text(),
                responsePreview.hex(),
                responsePreview.text(),
                requestPreview.truncated(),
                responsePreview.truncated(),
                Instant.now().toString()
        ));
    }

    public void recordTcpFrame(String clientName,
                               int listenPort,
                               String channelId,
                               String direction,
                               String remoteAddress,
                               byte[] payload) {
        if (!captureEnabled || clientName == null || listenPort <= 0 || !acquireSlot(pendingTcpCount)) {
            return;
        }

        Preview preview = preview(payload);
        pendingTcpFrames.add(new PendingTcpFrame(
                clientName,
                listenPort,
                cap(blankToEmpty(channelId), 120),
                cap(blankToEmpty(direction), 32),
                cap(remoteAddress, 255),
                length(payload),
                preview.hex(),
                preview.text(),
                preview.truncated(),
                Instant.now().toString()
        ));
    }

    @Scheduled(fixedDelayString = "${tunnel.traffic.capture-flush-interval-ms:2000}")
    @Transactional
    public synchronized void flush() {
        flushHttp();
        flushTcp();
    }

    @PreDestroy
    public void flushBeforeShutdown() {
        flush();
    }

    private void flushHttp() {
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
            exchange.setRequestHeaders(item.requestHeaders());
            exchange.setResponseHeaders(item.responseHeaders());
            exchange.setRequestPreviewHex(item.requestPreviewHex());
            exchange.setRequestPreviewText(item.requestPreviewText());
            exchange.setResponsePreviewHex(item.responsePreviewHex());
            exchange.setResponsePreviewText(item.responsePreviewText());
            exchange.setRequestTruncated(item.requestTruncated());
            exchange.setResponseTruncated(item.responseTruncated());
            exchange.setCapturedAt(item.capturedAt());
            entities.add(exchange);
        }
        httpTrafficExchangeRepository.saveAll(entities);
    }

    private void flushTcp() {
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
            frame.setPayloadBytes(item.payloadBytes());
            frame.setPayloadPreviewHex(item.payloadPreviewHex());
            frame.setPayloadPreviewText(item.payloadPreviewText());
            frame.setTruncated(item.truncated());
            frame.setFrameTime(item.frameTime());
            entities.add(frame);
        }
        tcpTrafficFrameRepository.saveAll(entities);
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

    private boolean acquireSlot(AtomicInteger count) {
        if (maxPending <= 0) {
            return false;
        }
        int value = count.incrementAndGet();
        if (value > maxPending) {
            count.decrementAndGet();
            return false;
        }
        return true;
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

    private Preview textPreview(byte[] data) {
        int totalLength = length(data);
        int previewLength = Math.min(totalLength, previewBytes);
        if (data == null || previewLength == 0) {
            return new Preview("", "", totalLength > previewLength);
        }
        String text = sanitizeText(new String(data, 0, previewLength, StandardCharsets.UTF_8));
        return new Preview("", text, totalLength > previewLength);
    }

    private Preview fullText(byte[] data) {
        if (data == null || data.length == 0) {
            return new Preview("", "", false);
        }
        return new Preview("", sanitizeText(new String(data, StandardCharsets.UTF_8)), false);
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
        if (headers == null) {
            return null;
        }
        for (String header : headers) {
            if (header == null) {
                continue;
            }
            int separator = header.indexOf(':');
            if (separator > 0 && "content-type".equals(header.substring(0, separator).trim().toLowerCase(Locale.ROOT))) {
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
            String requestHeaders,
            String responseHeaders,
            String requestPreviewHex,
            String requestPreviewText,
            String responsePreviewHex,
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
            long payloadBytes,
            String payloadPreviewHex,
            String payloadPreviewText,
            boolean truncated,
            String frameTime
    ) {
    }
}
