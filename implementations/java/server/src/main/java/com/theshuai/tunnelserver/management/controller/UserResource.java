package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.ManagementUserView;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.management.security.ManagementContextResolver;
import com.theshuai.tunnelserver.management.service.ManagementUserService;
import com.theshuai.tunnelserver.management.service.ManagementUserService.UserMutation;
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

    public UserResource(ManagementContextResolver contextResolver,
                        ManagementUserService userService) {
        this.contextResolver = contextResolver;
        this.userService = userService;
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
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(context, request));
    }

    @PutMapping("/users/{username}")
    public ManagementUserView updateUser(@AuthenticationPrincipal Jwt jwt,
                                         @PathVariable String username,
                                         @RequestBody UserMutation request) {
        return userService.updateUser(contextResolver.resolve(jwt), username, request);
    }

    @DeleteMapping("/users/{username}")
    public ResponseEntity<Void> deleteUser(@AuthenticationPrincipal Jwt jwt, @PathVariable String username) {
        userService.deleteUser(contextResolver.resolve(jwt), username);
        return ResponseEntity.noContent().build();
    }
}
