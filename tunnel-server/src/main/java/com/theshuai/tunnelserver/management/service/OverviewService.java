package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ClientAccountView;
import com.theshuai.tunnelserver.management.repository.ConnectionRecordRepository;
import com.theshuai.tunnelserver.server.RemotePortServerManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 管理后台 Overview 卡片的聚合数据。组合 {@link ClientAccountService}、连接计数与
 * {@link RemotePortServerManager} 的实时计数器，输出给前端。
 */
@Service
public class OverviewService {
    private final ClientAccountService clientAccountService;
    private final ConnectionRecordRepository connectionRecordRepository;
    private final RemotePortServerManager remotePortServerManager;

    public OverviewService(ClientAccountService clientAccountService,
                           ConnectionRecordRepository connectionRecordRepository,
                           RemotePortServerManager remotePortServerManager) {
        this.clientAccountService = clientAccountService;
        this.connectionRecordRepository = connectionRecordRepository;
        this.remotePortServerManager = remotePortServerManager;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> overview() {
        List<ClientAccountView> clients = clientAccountService.listClients();
        Map<String, Object> overview = new LinkedHashMap<>();
        overview.put("clients", clients.size());
        overview.put("onlineClients", clients.stream().filter(ClientAccountView::online).count());
        overview.put("successfulConnections", connectionRecordRepository.countBySuccess(true));
        overview.put("failedConnections", connectionRecordRepository.countBySuccess(false));
        overview.put("uploadBytes", clients.stream().mapToLong(ClientAccountView::uploadBytes).sum());
        overview.put("downloadBytes", clients.stream().mapToLong(ClientAccountView::downloadBytes).sum());
        overview.put("externalConnections", remotePortServerManager.activeExternalConnections());
        overview.put("rejectedExternalConnections", remotePortServerManager.rejectedExternalConnections());
        return overview;
    }
}
