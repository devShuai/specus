package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.TrafficUsage;
import com.theshuai.tunnelserver.management.model.TrafficUsageView;
import com.theshuai.tunnelserver.management.repository.TrafficUsageRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * 流量记录的只读视图查询。和 {@link TrafficUsageService}（写入累计 + 周期 flush）解耦——
 * 那个类是热路径写入器，这里是冷路径管理面板查询。
 */
@Service
public class TrafficViewService {
    private final TrafficUsageRepository trafficUsageRepository;

    public TrafficViewService(TrafficUsageRepository trafficUsageRepository) {
        this.trafficUsageRepository = trafficUsageRepository;
    }

    @Transactional(readOnly = true)
    public List<TrafficUsageView> listTraffic(Long clientId, int limit) {
        PageRequest pageRequest = PageRequest.of(0, Math.clamp(limit, 1, 500));
        List<TrafficUsage> usages = clientId == null
                ? trafficUsageRepository.findAllByOrderByUsageDateDescIdDesc(pageRequest)
                : trafficUsageRepository.findByClientIdOrderByUsageDateDescIdDesc(clientId, pageRequest);
        return usages.stream().map(this::toView).toList();
    }

    private TrafficUsageView toView(TrafficUsage usage) {
        return new TrafficUsageView(
                usage.getId(),
                usage.getClientId(),
                usage.getClientName(),
                usage.getUsageDate(),
                usage.getUploadBytes(),
                usage.getDownloadBytes(),
                usage.getUpdatedAt()
        );
    }
}
