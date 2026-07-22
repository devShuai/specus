package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.management.security.ManagementContextResolver;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService;
import com.theshuai.tunnelserver.websocket.WebSocketRequestAddress;
import com.theshuai.tunnelserver.websocket.WebSocketTicketHandshakeInterceptor;
import com.theshuai.tunnelserver.websocket.WebSocketTicketService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class WebSocketTicketResource {
    private static final int MAX_ROOM_ID_LENGTH = 120;
    private static final int MAX_PEER_ID_LENGTH = 120;
    private static final int MAX_DISPLAY_NAME_LENGTH = 120;
    private static final int MAX_ROOM_TOKEN_LENGTH = 512;

    private final WebSocketTicketService ticketService;
    private final ManagementContextResolver contextResolver;
    private final PublicTransferRoomService roomService;

    public WebSocketTicketResource(WebSocketTicketService ticketService,
                                   ManagementContextResolver contextResolver,
                                   PublicTransferRoomService roomService) {
        this.ticketService = ticketService;
        this.contextResolver = contextResolver;
        this.roomService = roomService;
    }

    @PostMapping("/api/admin/ws-tickets")
    public WebSocketTicketService.IssuedTicket issueAdminTicket(@AuthenticationPrincipal Jwt jwt,
                                                                 @RequestBody AdminTicketRequest request,
                                                                 HttpServletRequest servletRequest) {
        ManagementContext context = contextResolver.resolve(jwt);
        WebSocketTicketService.Scope scope = WebSocketTicketService.Scope.adminEndpoint(
                request == null ? null : request.endpoint());
        String remoteAddress = WebSocketRequestAddress.resolve(servletRequest);
        return ticketService.issue(scope, Map.of(
                WebSocketTicketHandshakeInterceptor.ATTR_USER, context.username(),
                WebSocketTicketHandshakeInterceptor.ATTR_TENANT_ID, context.tenant().tenantId(),
                WebSocketTicketHandshakeInterceptor.ATTR_ADMIN, context.isAdmin()
        ), remoteAddress);
    }

    @PostMapping("/api/public/transfer/ws-tickets")
    public WebSocketTicketService.IssuedTicket issuePublicTransferTicket(
            @RequestBody PublicTransferTicketRequest request,
            HttpServletRequest servletRequest) {
        if (request == null) {
            throw new IllegalArgumentException("ticket request is required");
        }
        String roomId = text(request.roomId(), "nearby", MAX_ROOM_ID_LENGTH);
        String peerId = text(request.peerId(), "", MAX_PEER_ID_LENGTH);
        String displayName = text(request.displayName(), "web", MAX_DISPLAY_NAME_LENGTH);
        String roomToken = text(request.roomToken(), "", MAX_ROOM_TOKEN_LENGTH);
        String publicAddress = WebSocketRequestAddress.resolve(servletRequest);
        boolean sharedRoom = StringUtils.hasText(roomToken);

        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("roomId", roomId);
        attributes.put("peerId", peerId);
        attributes.put("displayName", displayName);
        attributes.put("publicAddress", publicAddress);
        attributes.put("sharedRoom", sharedRoom);
        if (sharedRoom) {
            PublicTransferRoomService.RoomAccess access = roomService.resolve(roomId, roomToken, peerId);
            attributes.put("roomKey", "room:" + access.roomId());
            attributes.put("roomRole", access.role().name());
        } else {
            attributes.put("roomKey", "public:" + publicAddress);
            attributes.put("roomRole", PublicTransferRoomService.Role.EDITOR.name());
        }
        return ticketService.issue(WebSocketTicketService.Scope.PUBLIC_TRANSFER, attributes, publicAddress);
    }

    private static String text(String value, String fallback, int maxLength) {
        if (!StringUtils.hasText(value)) {
            return fallback;
        }
        String normalized = value.trim();
        if (normalized.length() <= maxLength) {
            return normalized;
        }
        int end = maxLength;
        if (Character.isHighSurrogate(normalized.charAt(end - 1))
                && end < normalized.length()
                && Character.isLowSurrogate(normalized.charAt(end))) {
            end--;
        }
        return normalized.substring(0, end);
    }

    public record AdminTicketRequest(String endpoint) { }

    public record PublicTransferTicketRequest(String roomId,
                                              String roomToken,
                                              String peerId,
                                              String displayName) { }
}
