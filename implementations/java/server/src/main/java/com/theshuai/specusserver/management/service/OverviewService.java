package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ClientAccountView;
import com.theshuai.specusserver.management.repository.ConnectionRecordRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.server.RemotePortServerManager;
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
        return overview(TenantContext.defaultTenant());
    }

    @Transactional(readOnly = true)
    public Map<String, Object> overview(TenantContext tenant) {
        List<ClientAccountView> clients = clientAccountService.listClients(tenant);
        return overviewForClients(tenant, clients, true, null);
    }

    @Transactional(readOnly = true)
    public Map<String, Object> overview(ManagementContext context) {
        List<ClientAccountView> clients = clientAccountService.listClients(context);
        List<Long> visibleClientIds = context.isAdmin()
                ? null
                : clients.stream().map(ClientAccountView::id).toList();
        return overviewForClients(context.tenant(), clients, context.isAdmin(), visibleClientIds);
    }

    private Map<String, Object> overviewForClients(TenantContext tenant,
                                                   List<ClientAccountView> clients,
                                                   boolean admin,
                                                   List<Long> visibleClientIds) {
        long successfulConnections;
        long failedConnections;
        if (admin) {
            successfulConnections = connectionRecordRepository.countByTenantIdAndSuccess(tenant.tenantId(), true);
            failedConnections = connectionRecordRepository.countByTenantIdAndSuccess(tenant.tenantId(), false);
        } else if (visibleClientIds == null || visibleClientIds.isEmpty()) {
            successfulConnections = 0;
            failedConnections = 0;
        } else {
            successfulConnections = connectionRecordRepository.countByTenantIdAndClientIdInAndSuccess(
                    tenant.tenantId(), visibleClientIds, true);
            failedConnections = connectionRecordRepository.countByTenantIdAndClientIdInAndSuccess(
                    tenant.tenantId(), visibleClientIds, false);
        }
        Map<String, Object> overview = new LinkedHashMap<>();
        overview.put("clients", clients.size());
        overview.put("onlineClients", clients.stream().filter(ClientAccountView::online).count());
        overview.put("successfulConnections", successfulConnections);
        overview.put("failedConnections", failedConnections);
        overview.put("uploadBytes", clients.stream().mapToLong(ClientAccountView::uploadBytes).sum());
        overview.put("downloadBytes", clients.stream().mapToLong(ClientAccountView::downloadBytes).sum());
        overview.put("externalConnections", admin ? remotePortServerManager.activeExternalConnections(tenant.tenantId()) : 0);
        overview.put("rejectedExternalConnections", admin ? remotePortServerManager.rejectedExternalConnections(tenant.tenantId()) : 0);
        return overview;
    }
}
