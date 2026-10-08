package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.ManagementUserView;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.service.ManagementUserService.UserMutation;
import com.theshuai.specusserver.productmetrics.ProductMetricsModel;
import com.theshuai.specusserver.productmetrics.ProductMetricsService;
import com.theshuai.specusserver.websocket.ClientMessagesWebSocketHandler;
import com.theshuai.specusserver.websocket.ConnectionEventsWebSocketHandler;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
public class UserResource {
    private final ManagementContextResolver contextResolver;
    private final ManagementUserService userService;
    private final ProductMetricsService productMetrics;
    private final ClientMessagesWebSocketHandler clientMessages;
    private final ConnectionEventsWebSocketHandler connectionEvents;

    public UserResource(ManagementContextResolver contextResolver,
                        ManagementUserService userService,
                        ProductMetricsService productMetrics,
                        ClientMessagesWebSocketHandler clientMessages,
                        ConnectionEventsWebSocketHandler connectionEvents) {
        this.contextResolver = contextResolver;
        this.userService = userService;
        this.productMetrics = productMetrics;
        this.clientMessages = clientMessages;
        this.connectionEvents = connectionEvents;
    }

    @GetMapping("/me")
    public ManagementUserView me(@AuthenticationPrincipal Jwt jwt) {
        return userService.currentUser(contextResolver.resolve(jwt));
    }

    @GetMapping("/users")
    public List<ManagementUserView> listUsers(@AuthenticationPrincipal Jwt jwt) {
        return userService.listUsers(contextResolver.resolve(jwt));
    }

    @PostMapping("/users")
    public ResponseEntity<ManagementUserView> createUser(@AuthenticationPrincipal Jwt jwt,
                                                         @RequestBody UserMutation request) {
        ManagementContext context = contextResolver.resolve(jwt);
        ManagementUserView created = userService.createUser(context, request);
        productMetrics.milestone(created.tenantId(), created.username(), ProductMetricsModel.STEP_ACCOUNT_CREATED);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/users/{username}")
    public ManagementUserView updateUser(@AuthenticationPrincipal Jwt jwt,
                                         @PathVariable String username,
                                         @RequestBody UserMutation request) {
        return userService.updateUser(contextResolver.resolve(jwt), username, request);
    }

    @DeleteMapping("/users/{username}")
    public ResponseEntity<Void> deleteUser(@AuthenticationPrincipal Jwt jwt, @PathVariable String username) {
        ManagementContext context = contextResolver.resolve(jwt);
        String deleted = userService.deleteUser(context, username);
        // Committed: the identity's open management WebSockets end (management-accounts.md 7.1).
        clientMessages.closeIdentity(context.tenant().tenantId(), deleted);
        connectionEvents.closeIdentity(context.tenant().tenantId(), deleted);
        productMetrics.userDeleted(context.tenant().tenantId(), deleted);
        return ResponseEntity.noContent().build();
    }
}
