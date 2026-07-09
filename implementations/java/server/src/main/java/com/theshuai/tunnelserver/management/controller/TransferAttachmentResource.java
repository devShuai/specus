package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.TransferAttachmentView;
import com.theshuai.tunnelserver.management.security.ManagementContextResolver;
import com.theshuai.tunnelserver.management.service.PublicTransferRateLimiter;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService.CompleteAttachmentRequest;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService.PresignDownloadRequest;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService.PresignDownloadResponse;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService.PresignUploadRequest;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService.PresignUploadResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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
                                                     @RequestBody PresignUploadRequest request) {
        rateLimiter.checkPresignUpload(clientIp(httpRequest));
        return service.createPublicUpload(request);
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
                                                 @RequestBody CompleteAttachmentRequest request) {
        return service.completePublic(attachmentId, request);
    }

    @PostMapping("/api/public/transfer/attachments/{attachmentId}/presign-download")
    public PresignDownloadResponse publicPresignDownload(@PathVariable long attachmentId,
                                                         @RequestBody PresignDownloadRequest request) {
        return service.createPublicDownload(attachmentId, request);
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
}
