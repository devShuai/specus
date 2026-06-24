package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import com.theshuai.tunnelserver.management.model.ResourceTrafficUsage;
import com.theshuai.tunnelserver.management.model.TrafficUsage;
import com.theshuai.tunnelserver.management.model.TunnelMapping;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.repository.ResourceTrafficUsageRepository;
import com.theshuai.tunnelserver.management.repository.TrafficUsageRepository;
import com.theshuai.tunnelserver.management.repository.TunnelMappingRepository;
import jakarta.annotation.PreDestroy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

@Service
public class TrafficUsageService {
    public static final String RESOURCE_TYPE_TCP_TUNNEL = "TCP_TUNNEL";
    public static final String RESOURCE_TYPE_HTTP_ROUTE = "HTTP_ROUTE";

    private final ClientAccountService clientAccountService;
    private final TrafficUsageRepository trafficUsageRepository;
    private final ResourceTrafficUsageRepository resourceTrafficUsageRepository;
    private final TunnelMappingRepository tunnelMappingRepository;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final Map<String, TrafficCounter> counters = new ConcurrentHashMap<>();
    private final Map<ResourceCounterKey, TrafficCounter> resourceCounters = new ConcurrentHashMap<>();

    public TrafficUsageService(ClientAccountService clientAccountService,
                               TrafficUsageRepository trafficUsageRepository,
                               ResourceTrafficUsageRepository resourceTrafficUsageRepository,
                               TunnelMappingRepository tunnelMappingRepository,
                               HttpRouteMappingRepository httpRouteMappingRepository) {
        this.clientAccountService = clientAccountService;
        this.trafficUsageRepository = trafficUsageRepository;
        this.resourceTrafficUsageRepository = resourceTrafficUsageRepository;
        this.tunnelMappingRepository = tunnelMappingRepository;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
    }

    public void recordUpload(String clientName, long bytes) {
        if (clientName != null && bytes > 0) {
            counters.computeIfAbsent(clientName, key -> new TrafficCounter()).upload.add(bytes);
        }
    }

    public void recordDownload(String clientName, long bytes) {
        if (clientName != null && bytes > 0) {
            counters.computeIfAbsent(clientName, key -> new TrafficCounter()).download.add(bytes);
        }
    }

    public void recordTcpUpload(String clientName, int listenPort, long bytes) {
        recordUpload(clientName, bytes);
        if (listenPort > 0) {
            recordResourceUpload(clientName, RESOURCE_TYPE_TCP_TUNNEL, tcpKey(listenPort), bytes);
        }
    }

    public void recordTcpDownload(String clientName, int listenPort, long bytes) {
        recordDownload(clientName, bytes);
        if (listenPort > 0) {
            recordResourceDownload(clientName, RESOURCE_TYPE_TCP_TUNNEL, tcpKey(listenPort), bytes);
        }
    }

    public void recordHttpUpload(String clientName, String route, long bytes) {
        recordUpload(clientName, bytes);
        recordResourceUpload(clientName, RESOURCE_TYPE_HTTP_ROUTE, httpKey(route), bytes);
    }

    public void recordHttpDownload(String clientName, String route, long bytes) {
        recordDownload(clientName, bytes);
        recordResourceDownload(clientName, RESOURCE_TYPE_HTTP_ROUTE, httpKey(route), bytes);
    }

    @Scheduled(fixedDelayString = "${tunnel.traffic.flush-interval-ms:5000}")
    @Transactional
    public synchronized void flush() {
        counters.forEach(this::flushCounter);
        resourceCounters.forEach(this::flushResourceCounter);
    }

    @PreDestroy
    public void flushBeforeShutdown() {
        flush();
    }

    private void flushCounter(String clientName, TrafficCounter counter) {
        long uploadBytes = counter.upload.sumThenReset();
        long downloadBytes = counter.download.sumThenReset();
        if (uploadBytes == 0 && downloadBytes == 0) {
            return;
        }

        try {
            ClientAccount account = clientAccountService.findClientByName(clientName).orElse(null);
            if (account == null) {
                return;
            }
            String usageDate = LocalDate.now(ZoneOffset.UTC).toString();
            TrafficUsage usage = trafficUsageRepository
                    .findByTenantIdAndClientIdAndUsageDate(account.getTenantId(), account.getId(), usageDate)
                    .orElseGet(TrafficUsage::new);
            usage.setTenantId(account.getTenantId());
            usage.setClientId(account.getId());
            usage.setClientName(account.getClientName());
            usage.setUsageDate(usageDate);
            usage.setUploadBytes(usage.getUploadBytes() + uploadBytes);
            usage.setDownloadBytes(usage.getDownloadBytes() + downloadBytes);
            usage.setUpdatedAt(Instant.now().toString());
            trafficUsageRepository.save(usage);
        } catch (RuntimeException e) {
            counter.upload.add(uploadBytes);
            counter.download.add(downloadBytes);
            throw e;
        }
    }

    private void recordResourceUpload(String clientName, String resourceType, String resourceKey, long bytes) {
        if (clientName != null && bytes > 0) {
            resourceCounters.computeIfAbsent(new ResourceCounterKey(clientName, resourceType, resourceKey),
                    key -> new TrafficCounter()).upload.add(bytes);
        }
    }

    private void recordResourceDownload(String clientName, String resourceType, String resourceKey, long bytes) {
        if (clientName != null && bytes > 0) {
            resourceCounters.computeIfAbsent(new ResourceCounterKey(clientName, resourceType, resourceKey),
                    key -> new TrafficCounter()).download.add(bytes);
        }
    }

    private void flushResourceCounter(ResourceCounterKey key, TrafficCounter counter) {
        long uploadBytes = counter.upload.sumThenReset();
        long downloadBytes = counter.download.sumThenReset();
        if (uploadBytes == 0 && downloadBytes == 0) {
            return;
        }

        try {
            ClientAccount account = clientAccountService.findClientByName(key.clientName()).orElse(null);
            if (account == null) {
                return;
            }
            ResourceDescriptor descriptor = resolveResource(account, key.resourceType(), key.resourceKey());
            String usageDate = LocalDate.now(ZoneOffset.UTC).toString();
            ResourceTrafficUsage usage = resourceTrafficUsageRepository
                    .findByTenantIdAndClientIdAndResourceTypeAndResourceKeyAndUsageDate(
                            account.getTenantId(), account.getId(), key.resourceType(), key.resourceKey(), usageDate)
                    .orElseGet(ResourceTrafficUsage::new);
            usage.setTenantId(account.getTenantId());
            usage.setClientId(account.getId());
            usage.setClientName(account.getClientName());
            usage.setResourceType(key.resourceType());
            usage.setResourceKey(key.resourceKey());
            usage.setResourceId(descriptor.resourceId());
            usage.setResourceName(descriptor.resourceName());
            usage.setUsageDate(usageDate);
            usage.setUploadBytes(usage.getUploadBytes() + uploadBytes);
            usage.setDownloadBytes(usage.getDownloadBytes() + downloadBytes);
            usage.setUpdatedAt(Instant.now().toString());
            resourceTrafficUsageRepository.save(usage);
        } catch (RuntimeException e) {
            counter.upload.add(uploadBytes);
            counter.download.add(downloadBytes);
            throw e;
        }
    }

    private ResourceDescriptor resolveResource(ClientAccount account, String resourceType, String resourceKey) {
        if (RESOURCE_TYPE_TCP_TUNNEL.equals(resourceType)) {
            int listenPort = parseTcpKey(resourceKey);
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
        if (RESOURCE_TYPE_HTTP_ROUTE.equals(resourceType)) {
            String route = parseHttpKey(resourceKey);
            HttpRouteMapping mapping = httpRouteMappingRepository
                    .findByTenantIdAndClientIdAndRoute(account.getTenantId(), account.getId(), route)
                    .orElse(null);
            if (mapping != null) {
                return new ResourceDescriptor(mapping.getId(), mapping.getRoute() + " -> " + mapping.getTargetBaseUrl());
            }
            return new ResourceDescriptor(null, route);
        }
        return new ResourceDescriptor(null, resourceKey);
    }

    private static String tcpKey(int listenPort) {
        return "tcp:" + listenPort;
    }

    private static int parseTcpKey(String resourceKey) {
        if (resourceKey != null && resourceKey.startsWith("tcp:")) {
            return Integer.parseInt(resourceKey.substring("tcp:".length()));
        }
        return 0;
    }

    private static String httpKey(String route) {
        return "http:" + (route == null ? "" : route);
    }

    private static String parseHttpKey(String resourceKey) {
        if (resourceKey != null && resourceKey.startsWith("http:")) {
            return resourceKey.substring("http:".length());
        }
        return resourceKey == null ? "" : resourceKey;
    }

    private record ResourceCounterKey(String clientName, String resourceType, String resourceKey) {
    }

    private record ResourceDescriptor(Long resourceId, String resourceName) {
    }

    private static class TrafficCounter {
        private final LongAdder upload = new LongAdder();
        private final LongAdder download = new LongAdder();
    }
}
