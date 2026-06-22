package com.theshuai.tunnelserver.management.controller;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.tunnelserver.management.service.ClientAuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/client/auth")
public class ClientAuthResource {
    private final ClientAuthService clientAuthService;

    public ClientAuthResource(ClientAuthService clientAuthService) {
        this.clientAuthService = clientAuthService;
    }

    @PostMapping("/login")
    public ClientAuthLoginResponse login(@RequestBody ClientAuthLoginRequest request,
                                         HttpServletRequest servletRequest) {
        return clientAuthService.login(request, servletRequest.getServerName());
    }
}
