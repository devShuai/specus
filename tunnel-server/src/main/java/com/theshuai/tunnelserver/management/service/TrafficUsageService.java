package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.TrafficUsage;
import com.theshuai.tunnelserver.management.repository.TrafficUsageRepository;
import jakarta.annotation.PreDestroy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

@Service
public class TrafficUsageService {
    private final ClientManagementService clientManagementService;
    private final TrafficUsageRepository trafficUsageRepository;
    private final Map<String, TrafficCounter> counters = new ConcurrentHashMap<>();

    public TrafficUsageService(ClientManagementService clientManagementService,
                               TrafficUsageRepository trafficUsageRepository) {
        this.clientManagementService = clientManagementService;
        this.trafficUsageRepository = trafficUsageRepository;
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

    @Scheduled(fixedDelayString = "${tunnel.traffic.flush-interval-ms:5000}")
    @Transactional
    public synchronized void flush() {
        counters.forEach(this::flushCounter);
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
            ClientAccount account = clientManagementService.findClientByName(clientName).orElse(null);
            if (account == null) {
                return;
            }
            String usageDate = LocalDate.now(ZoneOffset.UTC).toString();
            TrafficUsage usage = trafficUsageRepository.findByClientIdAndUsageDate(account.getId(), usageDate)
                    .orElseGet(TrafficUsage::new);
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

    private static class TrafficCounter {
        private final LongAdder upload = new LongAdder();
        private final LongAdder download = new LongAdder();
    }
}
