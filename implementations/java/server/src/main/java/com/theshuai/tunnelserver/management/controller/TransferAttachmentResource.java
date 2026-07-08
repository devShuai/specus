package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.TransferAttachmentView;
import com.theshuai.tunnelserver.management.security.ManagementContextResolver;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService.CompleteAttachmentRequest;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService.PresignDownloadRequest;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService.PresignDownloadResponse;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService.PresignUploadRequest;
import com.theshuai.tunnelserver.management.service.TransferAttachmentService.PresignUploadResponse;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TransferAttachmentResource {
    private final TransferAttachmentService service;
    private final ManagementContextResolver contextResolver;

    public TransferAttachmentResource(TransferAttachmentService service,
                                      ManagementContextResolver contextResolver) {
        this.service = service;
        this.contextResolver = contextResolver;
    }

    @PostMapping("/api/public/transfer/attachments/presign-upload")
    public PresignUploadResponse publicPresignUpload(@RequestBody PresignUploadRequest request) {
        return service.createPublicUpload(request);
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
