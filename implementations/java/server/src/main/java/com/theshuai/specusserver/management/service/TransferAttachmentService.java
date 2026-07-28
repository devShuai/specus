package com.theshuai.specusserver.management.service;

import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.config.ObjectStorageProperties;
import com.theshuai.specusserver.config.PublicTransferProperties;
import com.theshuai.specusserver.management.model.TransferAttachment;
import com.theshuai.specusserver.management.model.TransferAttachmentDownloadGrant;
import com.theshuai.specusserver.management.model.TransferAttachmentDownloadUsage;
import com.theshuai.specusserver.management.model.TransferAttachmentView;
import com.theshuai.specusserver.management.repository.TransferAttachmentDownloadGrantRepository;
import com.theshuai.specusserver.management.repository.TransferAttachmentDownloadUsageRepository;
import com.theshuai.specusserver.management.repository.TransferAttachmentRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.storage.object.ObjectStorageService;
import com.theshuai.specusserver.management.storage.object.PresignedObjectUrl;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.RoomAccess;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
public class TransferAttachmentService {
    public static final String SCOPE_PUBLIC_TRANSFER = "PUBLIC_TRANSFER";
    public static final String SCOPE_ADMIN_CLIENT_MESSAGE = "ADMIN_CLIENT_MESSAGE";
    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_UPLOADED = "UPLOADED";
    public static final String STATUS_EXPIRED = "EXPIRED";

    private static final Pattern SHA256_PATTERN = Pattern.compile("^[a-fA-F0-9]{64}$");
    private static final DateTimeFormatter OBJECT_DATE =
            DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);
    private static final long DEFAULT_PER_USER_QUOTA_BYTES = 1024L * 1024L * 1024L;

    private final TransferAttachmentRepository repository;
    private final TransferAttachmentDownloadGrantRepository downloadGrantRepository;
    private final TransferAttachmentDownloadUsageRepository downloadUsageRepository;
    private final ObjectStorageService objectStorageService;
    private final ObjectStorageProperties properties;
    private final PublicTransferProperties publicTransferProperties;
    private final ClientAccountService clientAccountService;
    private final PublicTransferRoomService publicTransferRoomService;
    private final Object[] quotaLocks = new Object[64];
    private final SecureRandom secureRandom = new SecureRandom();

    public TransferAttachmentService(TransferAttachmentRepository repository,
                                     TransferAttachmentDownloadGrantRepository downloadGrantRepository,
                                     TransferAttachmentDownloadUsageRepository downloadUsageRepository,
                                     ObjectStorageService objectStorageService,
                                     ObjectStorageProperties properties,
                                     PublicTransferProperties publicTransferProperties,
                                     ClientAccountService clientAccountService,
                                     PublicTransferRoomService publicTransferRoomService) {
        this.repository = repository;
        this.downloadGrantRepository = downloadGrantRepository;
        this.downloadUsageRepository = downloadUsageRepository;
        this.objectStorageService = objectStorageService;
        this.properties = properties;
        this.publicTransferProperties = publicTransferProperties;
        this.clientAccountService = clientAccountService;
        this.publicTransferRoomService = publicTransferRoomService;
        for (int i = 0; i < quotaLocks.length; i++) {
            quotaLocks[i] = new Object();
        }
    }

    public PresignUploadResponse createPublicUpload(ManagementContext context, PresignUploadRequest request) {
        String roomId = normalizeRoomId(request.roomId());
        RoomAccess access = publicTransferRoomService.resolve(roomId, request.roomToken(), "attachment-upload");
        if (!access.role().canEdit()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "访客不能上传文件");
        }
        String roomTokenHash = roomTokenHash(requireText(request.roomToken(), "roomToken"));
        int maxPending = Math.max(1, publicTransferProperties.getMaxPendingUploadsPerRoom());
        if (repository.countByScopeAndPublicTransferRoomIdAndStatus(
                SCOPE_PUBLIC_TRANSFER, access.roomId(), STATUS_PENDING) >= maxPending) {
            throw new RateLimitedException("当前房间待上传文件过多,请稍后再试");
        }
        synchronized (quotaLock(context.tenant().tenantId(), context.username())) {
            return createUpload(
                    SCOPE_PUBLIC_TRANSFER,
                    context.tenant().tenantId(),
                    roomId,
                    roomTokenHash,
                    access.roomId(),
                    context.username(),
                    null,
                    request
            );
        }
    }

    public PresignUploadResponse createAdminUpload(ManagementContext context, PresignUploadRequest request) {
        Long targetClientId = request.targetClientId();
        if (targetClientId == null) {
            throw new IllegalArgumentException("targetClientId is required");
        }
        if (!clientAccountService.canAccessClient(context, targetClientId)) {
            throw new IllegalArgumentException("target client is not accessible");
        }
        synchronized (quotaLock(context.tenant().tenantId(), context.username())) {
            return createUpload(
                    SCOPE_ADMIN_CLIENT_MESSAGE,
                    context.tenant().tenantId(),
                    null,
                    null,
                    null,
                    context.username(),
                    targetClientId,
                    request
            );
        }
    }

    public TransferAttachmentView completePublic(ManagementContext context, long attachmentId,
                                                 CompleteAttachmentRequest request) {
        TransferAttachment attachment = repository.findByIdAndScope(attachmentId, SCOPE_PUBLIC_TRANSFER)
                .orElseThrow(() -> new IllegalArgumentException("attachment not found: " + attachmentId));
        requireRoomAccess(attachment, request.roomToken(), true);
        assignOwnerWhenMissing(attachment, context);
        return completeWithinQuota(attachment);
    }

    public TransferAttachmentView completeAdmin(ManagementContext context, long attachmentId) {
        TransferAttachment attachment = repository
                .findByIdAndTenantIdAndScope(attachmentId, context.tenant().tenantId(), SCOPE_ADMIN_CLIENT_MESSAGE)
                .orElseThrow(() -> new IllegalArgumentException("attachment not found: " + attachmentId));
        requireAdminClientAccess(context, attachment);
        return completeWithinQuota(attachment);
    }

    public PresignDownloadResponse createPublicDownload(ManagementContext context, long attachmentId,
                                                        PresignDownloadRequest request) {
        TransferAttachment attachment = repository.findByIdAndScope(attachmentId, SCOPE_PUBLIC_TRANSFER)
                .orElseThrow(() -> new IllegalArgumentException("attachment not found: " + attachmentId));
        requireRoomAccess(attachment, request.roomToken(), false);
        return createDownload(context, attachment);
    }

    public PresignDownloadResponse createAdminDownload(ManagementContext context, long attachmentId) {
        TransferAttachment attachment = repository
                .findByIdAndTenantIdAndScope(attachmentId, context.tenant().tenantId(), SCOPE_ADMIN_CLIENT_MESSAGE)
                .orElseThrow(() -> new IllegalArgumentException("attachment not found: " + attachmentId));
        requireAdminClientAccess(context, attachment);
        return createDownload(context, attachment);
    }

    @Transactional
    public Optional<String> consumeDownloadGrant(String token) {
        if (!StringUtils.hasText(token) || token.length() > 128) {
            return Optional.empty();
        }
        String tokenHash = sha256Hex(token.trim());
        TransferAttachmentDownloadGrant grant = downloadGrantRepository.findByTokenHash(tokenHash)
                .orElse(null);
        Instant now = Instant.now();
        if (grant == null || StringUtils.hasText(grant.getConsumedAt())
                || !Instant.parse(grant.getExpiresAt()).isAfter(now)) {
            return Optional.empty();
        }
        TransferAttachment attachment = repository.findById(grant.getAttachmentId()).orElse(null);
        if (attachment == null || !STATUS_UPLOADED.equals(attachment.getStatus())
                || !Instant.parse(attachment.getExpiresAt()).isAfter(now)
                || !objectStorageService.isEnabled()) {
            return Optional.empty();
        }

        String tenantId = requireAccountText(grant.getTenantId(), "tenantId");
        String username = requireAccountText(grant.getUsername(), "username");
        synchronized (quotaLock(tenantId, username)) {
            String usageMonth = YearMonth.now(ZoneOffset.UTC).toString();
            long usedBytes = downloadUsageRepository.sumBytesByAccountAndMonth(
                    tenantId, username, usageMonth);
            ensureWithinQuota(usedBytes, attachment.getSizeBytes(),
                    properties.getPerUserMonthlyDownloadQuotaBytes(),
                    "本月 OSS 下载流量额度不足");

            String consumedAt = now.toString();
            if (downloadGrantRepository.consume(grant.getId(), tokenHash, consumedAt, consumedAt) != 1) {
                return Optional.empty();
            }
            PresignedObjectUrl direct = objectStorageService.presignDownload(
                    attachment.getObjectKey(),
                    Duration.ofSeconds(Math.max(1L, properties.getDownloadObjectUrlTtlSeconds())),
                    String.valueOf(grant.getId())
            );
            recordDownloadUsage(tenantId, username, usageMonth, attachment);
            return Optional.of(direct.url());
        }
    }

    @Transactional
    public TransferAttachmentView completeUploadCallback(String requestTarget, byte[] body,
                                                         String authorization, String publicKeyUrl) {
        if (!objectStorageService.verifyUploadCallback(
                requestTarget, body, authorization, publicKeyUrl)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "invalid OSS upload callback signature");
        }
        OssUploadCallback callback = JsonUtil.stringToObject(
                new String(body, StandardCharsets.UTF_8), OssUploadCallback.class);
        if (callback == null || !StringUtils.hasText(callback.bucket())
                || !StringUtils.hasText(callback.object()) || callback.size() == null
                || callback.size() < 0L) {
            throw new IllegalArgumentException("invalid OSS upload callback body");
        }
        if (!callback.bucket().equals(properties.getBucket())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "OSS callback bucket mismatch");
        }
        String objectKey = callback.object().trim();
        objectStorageService.validateObjectKey(objectKey);
        TransferAttachment attachment = repository.findByObjectKey(objectKey)
                .orElseThrow(() -> new IllegalArgumentException("attachment object was not allocated"));
        if (!attachment.getObjectKey().equals(objectKey)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "OSS callback object mismatch");
        }
        if (STATUS_UPLOADED.equals(attachment.getStatus())) {
            return toView(attachment);
        }
        if (!STATUS_PENDING.equals(attachment.getStatus())) {
            throw new IllegalStateException("attachment is not pending");
        }
        if (callback.size() > properties.getMaxAttachmentBytes()) {
            objectStorageService.deleteObject(objectKey);
            throw new IllegalArgumentException("attachment is too large");
        }
        attachment.setSizeBytes(callback.size());
        return completeWithinQuota(attachment, true);
    }

    @Scheduled(fixedDelayString = "${specus.object-storage.expiration-scan-interval-ms:3600000}")
    @Transactional
    public void expireOldAttachments() {
        String now = Instant.now().toString();
        while (true) {
            List<TransferAttachment> expired = repository.findTop100ByExpiresAtBeforeAndStatusNotOrderByExpiresAtAsc(
                    now, STATUS_EXPIRED);
            if (expired.isEmpty()) {
                return;
            }
            for (TransferAttachment attachment : expired) {
                if (objectStorageService.isEnabled()) {
                    objectStorageService.deleteObject(attachment.getObjectKey());
                }
                attachment.setStatus(STATUS_EXPIRED);
                attachment.setUpdatedAt(now);
                repository.save(attachment);
            }
            repository.flush();
        }
    }

    private PresignUploadResponse createUpload(String scope,
                                               String tenantId,
                                               String roomId,
                                               String roomTokenHash,
                                               Long publicTransferRoomId,
                                               String ownerUsername,
                                               Long targetClientId,
                                               PresignUploadRequest request) {
        if (!objectStorageService.isEnabled()) {
            throw new IllegalStateException("object storage is not configured");
        }
        String fileName = normalizeFileName(request.fileName());
        String mimeType = normalizeMimeType(request.mimeType());
        long sizeBytes = normalizeSize(request.sizeBytes());
        ensureStorageQuota(tenantId, ownerUsername, sizeBytes, Long.MIN_VALUE);
        String sha256 = normalizeSha256(request.sha256());
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(Math.max(1L, properties.getRetentionHours()) * 3600L);

        for (int attempt = 0; attempt < 8; attempt++) {
            TransferAttachment attachment = new TransferAttachment();
            attachment.setId(newAttachmentId());
            attachment.setTenantId(tenantId);
            attachment.setScope(scope);
            attachment.setRoomId(roomId);
            attachment.setRoomTokenHash(roomTokenHash);
            attachment.setPublicTransferRoomId(publicTransferRoomId);
            attachment.setOwnerUsername(ownerUsername);
            attachment.setTargetClientId(targetClientId);
            attachment.setObjectKey(objectKey(scope, attachment.getId(), fileName, now));
            attachment.setFileName(fileName);
            attachment.setMimeType(mimeType);
            attachment.setSizeBytes(sizeBytes);
            attachment.setSha256(sha256);
            attachment.setStatus(STATUS_PENDING);
            attachment.setCreatedAt(now.toString());
            attachment.setUpdatedAt(now.toString());
            attachment.setExpiresAt(expiresAt.toString());

            objectStorageService.validateObjectKey(attachment.getObjectKey());
            PresignedObjectUrl upload = objectStorageService.presignUpload(
                    attachment.getObjectKey(),
                    mimeType,
                    Duration.ofSeconds(properties.getUploadUrlTtlSeconds())
            );
            attachment.setUploadExpiresAt(upload.expiresAt());
            try {
                repository.saveAndFlush(attachment);
                return new PresignUploadResponse(
                        attachment.getId(),
                        String.valueOf(attachment.getId()),
                        attachment.getObjectKey(),
                        upload.url(),
                        upload.headers(),
                        upload.expiresAt(),
                        toView(attachment)
                );
            } catch (DataIntegrityViolationException e) {
                if (attempt == 7) {
                    throw e;
                }
            }
        }
        throw new IllegalStateException("failed to allocate attachment id");
    }

    private long newAttachmentId() {
        for (int i = 0; i < 8; i++) {
            long candidate = ClientIdGenerator.newId();
            if (!repository.existsById(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("failed to allocate attachment id");
    }

    private TransferAttachmentView completeWithinQuota(TransferAttachment attachment) {
        return completeWithinQuota(attachment, false);
    }

    private TransferAttachmentView completeWithinQuota(TransferAttachment attachment,
                                                        boolean objectVerifiedByCallback) {
        synchronized (quotaLock(attachment.getTenantId(), attachment.getOwnerUsername())) {
            return complete(attachment, objectVerifiedByCallback);
        }
    }

    @Scheduled(fixedDelayString = "${specus.object-storage.expiration-scan-interval-ms:3600000}")
    @Transactional
    public void purgeExpiredDownloadGrants() {
        downloadGrantRepository.deleteByExpiresAtBefore(Instant.now().toString());
    }

    private TransferAttachmentView complete(TransferAttachment attachment,
                                            boolean objectVerifiedByCallback) {
        Instant now = Instant.now();
        if (STATUS_UPLOADED.equals(attachment.getStatus())) {
            return toView(attachment);
        }
        if (!STATUS_PENDING.equals(attachment.getStatus())) {
            throw new IllegalStateException("attachment is not pending");
        }
        if (Instant.parse(attachment.getUploadExpiresAt()).isBefore(now)) {
            throw new IllegalStateException("attachment upload URL is expired");
        }
        if (!objectVerifiedByCallback) {
            verifyUploadedObject(attachment);
        }
        try {
            ensureStorageQuota(attachment.getTenantId(), attachment.getOwnerUsername(),
                    attachment.getSizeBytes(), attachment.getId());
        } catch (RateLimitedException exception) {
            if (objectStorageService.isEnabled()) {
                objectStorageService.deleteObject(attachment.getObjectKey());
            }
            throw exception;
        }
        attachment.setStatus(STATUS_UPLOADED);
        attachment.setUploadedAt(now.toString());
        attachment.setUpdatedAt(now.toString());
        repository.saveAndFlush(attachment);
        return toView(attachment);
    }

    /**
     * 预签名 PUT 不绑定 Content-Length,声明大小(sizeBytes)不可信。complete 阶段 HEAD 对象:
     * 不存在则拒绝(未真正上传);实际大小超限则删对象并拒绝;否则以实际大小为准回写。
     */
    private void verifyUploadedObject(TransferAttachment attachment) {
        if (!objectStorageService.isEnabled()) {
            return;
        }
        ObjectStorageService.ObjectStat stat = objectStorageService.statObject(attachment.getObjectKey());
        if (!stat.exists()) {
            throw new IllegalStateException("attachment object was not uploaded");
        }
        long actualBytes = stat.contentLength();
        if (actualBytes > properties.getMaxAttachmentBytes()) {
            objectStorageService.deleteObject(attachment.getObjectKey());
            throw new IllegalArgumentException("attachment is too large");
        }
        if (actualBytes >= 0) {
            attachment.setSizeBytes(actualBytes);
        }
    }

    private PresignDownloadResponse createDownload(ManagementContext context, TransferAttachment attachment) {
        Instant now = Instant.now();
        if (!STATUS_UPLOADED.equals(attachment.getStatus())) {
            throw new IllegalStateException("attachment is not uploaded");
        }
        if (Instant.parse(attachment.getExpiresAt()).isBefore(now)) {
            throw new IllegalStateException("attachment is expired");
        }
        if (!objectStorageService.isEnabled()) {
            throw new IllegalStateException("object storage is not configured");
        }
        String tenantId = requireAccountText(context.tenant().tenantId(), "tenantId");
        String username = requireAccountText(context.username(), "username");
        synchronized (quotaLock(tenantId, username)) {
            String usageMonth = YearMonth.now(ZoneOffset.UTC).toString();
            long usedBytes = downloadUsageRepository.sumBytesByAccountAndMonth(
                    tenantId, username, usageMonth);
            ensureWithinQuota(usedBytes, attachment.getSizeBytes(),
                    properties.getPerUserMonthlyDownloadQuotaBytes(),
                    "本月 OSS 下载流量额度不足");

            DownloadGrantValue grant = createDownloadGrant(tenantId, username, attachment, now);
            return new PresignDownloadResponse(
                    attachment.getId(),
                    String.valueOf(attachment.getId()),
                    "/api/public/transfer/downloads/" + grant.token(),
                    Map.of(),
                    grant.expiresAt(),
                    toView(attachment)
            );
        }
    }

    private DownloadGrantValue createDownloadGrant(String tenantId, String username,
                                                   TransferAttachment attachment, Instant now) {
        Instant expiresAt = now.plusSeconds(Math.max(1L, properties.getDownloadUrlTtlSeconds()));
        for (int attempt = 0; attempt < 8; attempt++) {
            byte[] tokenBytes = new byte[32];
            secureRandom.nextBytes(tokenBytes);
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
            TransferAttachmentDownloadGrant grant = new TransferAttachmentDownloadGrant();
            grant.setId(ClientIdGenerator.newId());
            grant.setTokenHash(sha256Hex(token));
            grant.setTenantId(tenantId);
            grant.setUsername(username);
            grant.setAttachmentId(attachment.getId());
            grant.setCreatedAt(now.toString());
            grant.setExpiresAt(expiresAt.toString());
            try {
                downloadGrantRepository.saveAndFlush(grant);
                return new DownloadGrantValue(grant.getId(), token, grant.getExpiresAt());
            } catch (DataIntegrityViolationException exception) {
                if (attempt == 7) {
                    throw exception;
                }
            }
        }
        throw new IllegalStateException("failed to allocate download grant");
    }

    private void ensureStorageQuota(String tenantId, String ownerUsername, long requestedBytes,
                                    long excludedAttachmentId) {
        String normalizedTenant = requireAccountText(tenantId, "tenantId");
        String normalizedOwner = requireAccountText(ownerUsername, "ownerUsername");
        long usedBytes = repository.sumActiveStorageBytes(
                normalizedTenant,
                normalizedOwner,
                excludedAttachmentId,
                STATUS_PENDING,
                STATUS_UPLOADED,
                Instant.now().toString()
        );
        ensureWithinQuota(usedBytes, requestedBytes, properties.getPerUserStorageQuotaBytes(),
                "OSS 存储额度不足");
    }

    private void ensureWithinQuota(long usedBytes, long requestedBytes, long limitBytes, String message) {
        long normalizedLimit = limitBytes > 0L ? limitBytes : DEFAULT_PER_USER_QUOTA_BYTES;
        if (requestedBytes < 0L || usedBytes > normalizedLimit - requestedBytes) {
            throw new RateLimitedException(message);
        }
    }

    private void recordDownloadUsage(String tenantId, String username, String usageMonth,
                                     TransferAttachment attachment) {
        for (int attempt = 0; attempt < 8; attempt++) {
            TransferAttachmentDownloadUsage usage = new TransferAttachmentDownloadUsage();
            usage.setId(ClientIdGenerator.newId());
            usage.setTenantId(tenantId);
            usage.setUsername(username);
            usage.setAttachmentId(attachment.getId());
            usage.setSizeBytes(attachment.getSizeBytes());
            usage.setUsageMonth(usageMonth);
            usage.setCreatedAt(Instant.now().toString());
            try {
                downloadUsageRepository.saveAndFlush(usage);
                return;
            } catch (DataIntegrityViolationException exception) {
                if (attempt == 7) {
                    throw exception;
                }
            }
        }
    }

    private void assignOwnerWhenMissing(TransferAttachment attachment, ManagementContext context) {
        if (!StringUtils.hasText(attachment.getTenantId())) {
            attachment.setTenantId(context.tenant().tenantId());
        }
        if (!StringUtils.hasText(attachment.getOwnerUsername())) {
            attachment.setOwnerUsername(context.username());
        }
    }

    private Object quotaLock(String tenantId, String username) {
        int index = Math.floorMod(Objects.hash(tenantId, username), quotaLocks.length);
        return quotaLocks[index];
    }

    private String requireAccountText(String value, String field) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalStateException(field + " is missing from authenticated account");
        }
        return value.trim();
    }

    private void requireAdminClientAccess(ManagementContext context, TransferAttachment attachment) {
        if (!clientAccountService.canAccessClient(context, attachment.getTargetClientId())) {
            throw new IllegalArgumentException("target client is not accessible");
        }
    }

    private void requireMatchingRoomToken(TransferAttachment attachment, String roomToken) {
        String expected = attachment.getRoomTokenHash();
        if (!StringUtils.hasText(expected) || !Objects.equals(expected, roomTokenHash(requireText(roomToken, "roomToken")))) {
            throw new IllegalArgumentException("roomToken is invalid");
        }
    }

    private void requireRoomAccess(TransferAttachment attachment, String roomToken, boolean requireEdit) {
        if (attachment.getPublicTransferRoomId() == null) {
            requireMatchingRoomToken(attachment, roomToken);
            return;
        }
        RoomAccess access = publicTransferRoomService.authenticate(
                attachment.getRoomId(), roomToken, "attachment-access");
        if (access.roomId() != attachment.getPublicTransferRoomId()
                || (requireEdit && !access.role().canEdit())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "房间凭证无效");
        }
    }

    private TransferAttachmentView toView(TransferAttachment attachment) {
        return new TransferAttachmentView(
                attachment.getId(),
                String.valueOf(attachment.getId()),
                attachment.getFileName(),
                attachment.getMimeType(),
                attachment.getSizeBytes(),
                attachment.getSha256(),
                attachment.getStatus(),
                attachment.getExpiresAt()
        );
    }

    private String objectKey(String scope, long attachmentId, String fileName, Instant now) {
        String prefix = StringUtils.hasText(properties.getObjectPrefix()) ? properties.getObjectPrefix().trim() : "";
        while (prefix.startsWith("/")) {
            prefix = prefix.substring(1);
        }
        while (prefix.endsWith("/")) {
            prefix = prefix.substring(0, prefix.length() - 1);
        }
        String scopeSegment = scope.toLowerCase(Locale.ROOT).replace('_', '-');
        String base = prefix.isBlank() ? "" : prefix + "/";
        return base + scopeSegment + "/" + OBJECT_DATE.format(now) + "/" + attachmentId + "/" + fileName;
    }

    private String normalizeFileName(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            throw new IllegalArgumentException("fileName cannot be blank");
        }

        int slash = Math.max(fileName.lastIndexOf('/'), fileName.lastIndexOf('\\'));
        String segment = fileName.substring(slash + 1);
        StringBuilder normalized = new StringBuilder(segment.length());
        boolean previousWasInvalid = false;
        boolean previousWasDot = false;
        for (int offset = 0; offset < segment.length();) {
            int codePoint = segment.codePointAt(offset);
            offset += Character.charCount(codePoint);
            boolean asciiAlphaNumeric = codePoint >= 'A' && codePoint <= 'Z'
                    || codePoint >= 'a' && codePoint <= 'z'
                    || codePoint >= '0' && codePoint <= '9';
            boolean allowed = asciiAlphaNumeric || codePoint == '.' || codePoint == '_' || codePoint == '-';
            if (!allowed) {
                if (!previousWasInvalid) {
                    normalized.append('_');
                }
                previousWasInvalid = true;
                previousWasDot = false;
                continue;
            }
            previousWasInvalid = false;
            if (codePoint == '.') {
                if (!previousWasDot) {
                    normalized.append('.');
                }
                previousWasDot = true;
            } else {
                normalized.appendCodePoint(codePoint);
                previousWasDot = false;
            }
        }

        String result = normalized.toString();
        if (result.isEmpty() || result.equals(".")) {
            return "attachment";
        }
        if (result.length() <= 180) {
            return result;
        }

        int dot = result.lastIndexOf('.');
        if (dot > 0 && dot < result.length() - 1) {
            String extension = result.substring(dot);
            if (extension.length() < 180) {
                return result.substring(0, 180 - extension.length()) + extension;
            }
        }
        return result.substring(0, 180);
    }

    private String normalizeMimeType(String mimeType) {
        if (!StringUtils.hasText(mimeType)) {
            return "application/octet-stream";
        }
        String normalized = mimeType.trim();
        if (normalized.length() > 120 || normalized.contains("\r") || normalized.contains("\n")) {
            throw new IllegalArgumentException("mimeType is invalid");
        }
        return normalized;
    }

    private long normalizeSize(Long sizeBytes) {
        if (sizeBytes == null || sizeBytes <= 0L) {
            throw new IllegalArgumentException("sizeBytes must be positive");
        }
        if (sizeBytes > properties.getMaxAttachmentBytes()) {
            throw new IllegalArgumentException("attachment is too large");
        }
        return sizeBytes;
    }

    private String normalizeSha256(String sha256) {
        if (!StringUtils.hasText(sha256)) {
            return null;
        }
        String normalized = sha256.trim().toLowerCase(Locale.ROOT);
        if (!SHA256_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("sha256 is invalid");
        }
        return normalized;
    }

    private String normalizeRoomId(String roomId) {
        if (!StringUtils.hasText(roomId)) {
            return "default";
        }
        String normalized = roomId.trim();
        if (normalized.length() > 120 || normalized.contains("\r") || normalized.contains("\n")) {
            throw new IllegalArgumentException("roomId is invalid");
        }
        return normalized;
    }

    private String requireText(String value, String field) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(field + " cannot be blank");
        }
        return value.trim();
    }

    private String roomTokenHash(String token) {
        return sha256Hex(token);
    }

    private String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("failed to hash token", e);
        }
    }

    private record DownloadGrantValue(long id, String token, String expiresAt) {
    }

    public record PresignUploadRequest(
            String fileName,
            String mimeType,
            Long sizeBytes,
            String sha256,
            String roomId,
            String roomToken,
            Long targetClientId
    ) {
    }

    public record CompleteAttachmentRequest(String roomToken) {
    }

    public record PresignDownloadRequest(String roomToken) {
    }

    public record PresignUploadResponse(
            long attachmentId,
            String objectId,
            String objectKey,
            String uploadUrl,
            Map<String, String> uploadHeaders,
            String expiresAt,
            TransferAttachmentView attachment
    ) {
    }

    public record PresignDownloadResponse(
            long attachmentId,
            String objectId,
            String downloadUrl,
            Map<String, String> downloadHeaders,
            String expiresAt,
            TransferAttachmentView attachment
    ) {
    }

    public record OssUploadCallback(
            String bucket,
            String object,
            Long size,
            String mimeType,
            String etag
    ) {
    }
}
