package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.TransferAttachmentView;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.PublicTransferRateLimiter;
import com.theshuai.specusserver.management.service.TransferAttachmentService;
import com.theshuai.specusserver.management.service.TransferAttachmentService.CompleteAttachmentRequest;
import com.theshuai.specusserver.management.service.TransferAttachmentService.PresignDownloadRequest;
import com.theshuai.specusserver.management.service.TransferAttachmentService.PresignDownloadResponse;
import com.theshuai.specusserver.management.service.TransferAttachmentService.PresignUploadRequest;
import com.theshuai.specusserver.management.service.TransferAttachmentService.PresignUploadResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

@RestController
public class TransferAttachmentResource {
    private final TransferAttachmentService service;
    private final ManagementContextResolver contextResolver;
    private final PublicTransferRateLimiter rateLimiter;

    public TransferAttachmentResource(TransferAttachmentService service,
                                      ManagementContextResolver contextResolver,
                                      PublicTransferRateLimiter rateLimiter) {
        this.service = service;
        this.contextResolver = contextResolver;
        this.rateLimiter = rateLimiter;
    }

    @PostMapping("/api/public/transfer/attachments/presign-upload")
    public PresignUploadResponse publicPresignUpload(HttpServletRequest httpRequest,
                                                     @AuthenticationPrincipal Jwt jwt,
                                                     @RequestBody PresignUploadRequest request) {
        rateLimiter.checkPresignUpload(clientIp(httpRequest));
        return service.createPublicUpload(contextResolver.resolve(jwt), request);
    }

    @PostMapping("/api/public/transfer/oss-callback")
    public Map<String, Object> ossUploadCallback(HttpServletRequest request) {
        byte[] body;
        try {
            body = request.getInputStream().readNBytes(64 * 1024 + 1);
        } catch (IOException exception) {
            throw new IllegalArgumentException("failed to read OSS upload callback", exception);
        }
        if (body.length > 64 * 1024) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                    "OSS upload callback body is too large");
        }
        String requestTarget = request.getRequestURI();
        if (StringUtils.hasText(request.getQueryString())) {
            requestTarget += "?" + request.getQueryString();
        }
        TransferAttachmentView attachment = service.completeUploadCallback(
                requestTarget,
                body,
                request.getHeader(HttpHeaders.AUTHORIZATION),
                request.getHeader("x-oss-pub-key-url")
        );
        return Map.of(
                "Status", "OK",
                "attachmentId", attachment.attachmentId(),
                "objectId", attachment.objectId()
        );
    }

    /**
     * 取来源 IP:优先可信反代覆写的 X-Real-IP,退而取 X-Forwarded-For 末位,均无则用连接对端。
     * 与发现信令握手的取值口径一致,避免客户端自带的 XFF 首段伪造。
     */
    private static String clientIp(HttpServletRequest request) {
        String realIp = request.getHeader("X-Real-IP");
        if (StringUtils.hasText(realIp)) {
            return realIp.trim();
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(forwarded)) {
            String[] parts = forwarded.split(",");
            String last = parts[parts.length - 1].trim();
            if (StringUtils.hasText(last)) {
                return last;
            }
        }
        return request.getRemoteAddr();
    }

    @PostMapping("/api/public/transfer/attachments/{attachmentId}/complete")
    public TransferAttachmentView publicComplete(@PathVariable long attachmentId,
                                                 @AuthenticationPrincipal Jwt jwt,
                                                 @RequestBody CompleteAttachmentRequest request) {
        return service.completePublic(contextResolver.resolve(jwt), attachmentId, request);
    }

    @PostMapping("/api/public/transfer/attachments/{attachmentId}/presign-download")
    public PresignDownloadResponse publicPresignDownload(@PathVariable long attachmentId,
                                                         @AuthenticationPrincipal Jwt jwt,
                                                         @RequestBody PresignDownloadRequest request) {
        return service.createPublicDownload(contextResolver.resolve(jwt), attachmentId, request);
    }

    @PostMapping("/api/admin/client-messages/attachments/presign-upload")
    public PresignUploadResponse adminPresignUpload(@AuthenticationPrincipal Jwt jwt,
                                                    @RequestBody PresignUploadRequest request) {
        return service.createAdminUpload(contextResolver.resolve(jwt), request);
    }

    @PostMapping("/api/admin/client-messages/attachments/{attachmentId}/complete")
    public TransferAttachmentView adminComplete(@AuthenticationPrincipal Jwt jwt,
                                                @PathVariable long attachmentId) {
        return service.completeAdmin(contextResolver.resolve(jwt), attachmentId);
    }

    @PostMapping("/api/admin/client-messages/attachments/{attachmentId}/presign-download")
    public PresignDownloadResponse adminPresignDownload(@AuthenticationPrincipal Jwt jwt,
                                                        @PathVariable long attachmentId) {
        return service.createAdminDownload(contextResolver.resolve(jwt), attachmentId);
    }

    @GetMapping("/api/public/transfer/downloads/{token}")
    public ResponseEntity<?> consumeDownload(HttpServletRequest request, @PathVariable String token) {
        if (!"GET".equalsIgnoreCase(request.getMethod())) {
            return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                    .header(HttpHeaders.ALLOW, "GET")
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .build();
        }
        var directUrl = service.consumeDownloadGrant(token);
        if (directUrl.isEmpty()) {
            return ResponseEntity.status(HttpStatus.GONE)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(Map.of("error", "download link is expired or already used"));
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(directUrl.get()))
                .header(HttpHeaders.CACHE_CONTROL, "private, no-store")
                .header("Pragma", "no-cache")
                .header("Referrer-Policy", "no-referrer")
                .build();
    }
}
