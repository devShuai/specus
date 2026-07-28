package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.websocket.PublicTransferDiscoveryWebSocketHandler;
import com.theshuai.specusserver.websocket.PublicTransferDiscoveryWebSocketHandler.ClientNameAvailability;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/public/transfer/clients")
public class PublicTransferClientResource {
    private final PublicTransferDiscoveryWebSocketHandler discoveryHandler;

    public PublicTransferClientResource(PublicTransferDiscoveryWebSocketHandler discoveryHandler) {
        this.discoveryHandler = discoveryHandler;
    }

    @GetMapping("/name-availability")
    public ClientNameAvailability checkNameAvailability(@RequestParam String clientName,
                                                        @RequestParam(required = false) String excludePeerId) {
        return discoveryHandler.checkClientNameAvailability(clientName, excludePeerId);
    }
}
