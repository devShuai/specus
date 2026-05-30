package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.database.DatabaseInitializer;
import com.theshuai.tunnelserver.management.model.ClientAccountView;
import com.theshuai.tunnelserver.management.model.ConnectionRecordView;
import com.theshuai.tunnelserver.management.model.TrafficUsageView;
import com.theshuai.tunnelserver.management.service.ClientManagementService;
import com.theshuai.tunnelserver.management.service.ClientManagementService.ClientMutation;
import com.theshuai.tunnelserver.management.service.ClientManagementService.CredentialResult;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {
    private final ClientManagementService clientManagementService;
    private final TrafficUsageService trafficUsageService;
    private final DatabaseInitializer databaseInitializer;

    public AdminController(ClientManagementService clientManagementService,
                           TrafficUsageService trafficUsageService,
                           DatabaseInitializer databaseInitializer) {
        this.clientManagementService = clientManagementService;
        this.trafficUsageService = trafficUsageService;
        this.databaseInitializer = databaseInitializer;
    }

    @GetMapping("/overview")
    public Map<String, Object> overview() {
        trafficUsageService.flush();
        return clientManagementService.overview();
    }

    @GetMapping("/clients")
    public List<ClientAccountView> listClients() {
        trafficUsageService.flush();
        return clientManagementService.listClients();
    }

    @PostMapping("/clients")
    public ResponseEntity<CredentialResult> createClient(@RequestBody ClientMutation request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(clientManagementService.createClient(request));
    }

    @PutMapping("/clients/{id}")
    public CredentialResult updateClient(@PathVariable long id, @RequestBody ClientMutation request) {
        return clientManagementService.updateClient(id, request);
    }

    @DeleteMapping("/clients/{id}")
    public ResponseEntity<Void> deleteClient(@PathVariable long id) {
        clientManagementService.deleteClient(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/connections")
    public List<ConnectionRecordView> listConnections(@RequestParam(required = false) Long clientId,
                                                      @RequestParam(defaultValue = "100") int limit) {
        return clientManagementService.listConnections(clientId, limit);
    }

    @GetMapping("/traffic")
    public List<TrafficUsageView> listTraffic(@RequestParam(required = false) Long clientId,
                                              @RequestParam(defaultValue = "100") int limit) {
        trafficUsageService.flush();
        return clientManagementService.listTraffic(clientId, limit);
    }

    @PostMapping("/database/initialize")
    public Map<String, Object> initializeDatabase() {
        return databaseInitializer.initialize();
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgument(IllegalArgumentException exception) {
        return ResponseEntity.badRequest().body(Map.of("error", exception.getMessage()));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, String>> handleDataIntegrityViolation(DataIntegrityViolationException exception) {
        return ResponseEntity.badRequest().body(Map.of("error", "客户端名称已存在或数据不符合约束"));
    }
}
