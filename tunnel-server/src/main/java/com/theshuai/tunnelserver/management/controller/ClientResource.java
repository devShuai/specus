package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.ClientAccountView;
import com.theshuai.tunnelserver.management.service.ClientAccountService;
import com.theshuai.tunnelserver.management.service.ClientAccountService.ClientMutation;
import com.theshuai.tunnelserver.management.service.ClientAccountService.CredentialResult;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 客户端账号 CRUD。流量统计 flush 触发放在列表读取路径上，确保管理面板看到的上下行总量是当前秒级新鲜的。
 */
@RestController
@RequestMapping("/api/admin/clients")
public class ClientResource {
    private final ClientAccountService clientAccountService;
    private final TrafficUsageService trafficUsageService;

    public ClientResource(ClientAccountService clientAccountService,
                          TrafficUsageService trafficUsageService) {
        this.clientAccountService = clientAccountService;
        this.trafficUsageService = trafficUsageService;
    }

    @GetMapping
    public List<ClientAccountView> listClients() {
        trafficUsageService.flush();
        return clientAccountService.listClients();
    }

    @PostMapping
    public ResponseEntity<CredentialResult> createClient(@RequestBody ClientMutation request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(clientAccountService.createClient(request));
    }

    @PutMapping("/{id}")
    public CredentialResult updateClient(@PathVariable long id, @RequestBody ClientMutation request) {
        return clientAccountService.updateClient(id, request);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteClient(@PathVariable long id) {
        clientAccountService.deleteClient(id);
        return ResponseEntity.noContent().build();
    }
}
