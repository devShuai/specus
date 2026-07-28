package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.PublicTransferProperties;
import com.theshuai.specusserver.management.model.PublicTransferDiagramVersion;
import com.theshuai.specusserver.management.model.PublicTransferRoom;
import com.theshuai.specusserver.management.model.PublicTransferRoomAccess;
import com.theshuai.specusserver.management.model.PublicTransferRoomPairingCode;
import com.theshuai.specusserver.management.repository.PublicTransferDiagramVersionRepository;
import com.theshuai.specusserver.management.repository.PublicTransferRoomAccessRepository;
import com.theshuai.specusserver.management.repository.PublicTransferRoomPairingCodeRepository;
import com.theshuai.specusserver.management.repository.PublicTransferRoomRepository;
import com.theshuai.specusserver.security.LocalTokenService;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

@Service
public class PublicTransferRoomService {
    private static final int MAX_SNAPSHOT_BYTES = 3 * 1024 * 1024;
    private static final int MAX_VERSIONS_PER_ROOM = 50;
    private static final int MAX_ACCESS_TOKENS_PER_ROOM = 20;
    private static final long MIN_ACCESS_TOKEN_TTL_SECONDS = 300L;
    private static final long MAX_ACCESS_TOKEN_TTL_SECONDS = 7L * 24 * 60 * 60;
    private static final long PAIRING_ACCESS_TOKEN_TTL_SECONDS = 24L * 60 * 60;
    private static final int MAX_PAIRING_CODE_USES = 5;
    private static final String PAIRING_HMAC_DOMAIN = "public-transfer-pairing:v1:";

    private final PublicTransferRoomRepository roomRepository;
    private final PublicTransferRoomAccessRepository accessRepository;
    private final PublicTransferRoomPairingCodeRepository pairingCodeRepository;
    private final PublicTransferDiagramVersionRepository versionRepository;
    private final PublicTransferProperties properties;
    private final LocalTokenService localTokenService;
    private final SecureRandom secureRandom = new SecureRandom();

    public PublicTransferRoomService(PublicTransferRoomRepository roomRepository,
                                     PublicTransferRoomAccessRepository accessRepository,
                                     PublicTransferRoomPairingCodeRepository pairingCodeRepository,
                                     PublicTransferDiagramVersionRepository versionRepository,
                                     PublicTransferProperties properties,
                                     LocalTokenService localTokenService) {
        this.roomRepository = roomRepository;
        this.accessRepository = accessRepository;
        this.pairingCodeRepository = pairingCodeRepository;
        this.versionRepository = versionRepository;
        this.properties = properties;
        this.localTokenService = localTokenService;
    }

    @Transactional
    public RoomAccess resolve(String roomNameValue, String tokenValue, String peerIdValue) {
        String roomName = requireText(roomNameValue, "roomId", 120);
        String token = requireText(tokenValue, "roomToken", 512);
        String peerId = normalizeText(peerIdValue, "web", 120);
        String tokenHash = sha256(token);

        var ownerRoom = roomRepository.findByRoomNameAndOwnerTokenHash(roomName, tokenHash);
        if (ownerRoom.isPresent()) {
            return new RoomAccess(ownerRoom.get().getId(), Role.OWNER, roomName);
        }
        var invited = accessRepository.findByTokenHash(tokenHash);
        if (invited.isPresent()) {
            return requireUsableInvite(roomName, invited.get());
        }
        if (isInviteToken(token)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "房间凭证无效");
        }

        String now = Instant.now().toString();
        PublicTransferRoom room = new PublicTransferRoom();
        room.setId(newUniqueRoomId());
        room.setRoomName(roomName);
        room.setOwnerTokenHash(tokenHash);
        room.setCreatedByPeerId(peerId);
        room.setCreatedAt(now);
        room.setUpdatedAt(now);
        try {
            roomRepository.saveAndFlush(room);
            return new RoomAccess(room.getId(), Role.OWNER, roomName);
        } catch (DataIntegrityViolationException conflict) {
            return roomRepository.findByRoomNameAndOwnerTokenHash(roomName, tokenHash)
                    .map(existing -> new RoomAccess(existing.getId(), Role.OWNER, roomName))
                    .orElseThrow(() -> conflict);
        }
    }

    @Transactional(readOnly = true)
    public RoomAccess authenticate(String roomNameValue, String tokenValue, String peerIdValue) {
        String roomName = requireText(roomNameValue, "roomId", 120);
        String token = requireText(tokenValue, "roomToken", 512);
        String peerId = normalizeText(peerIdValue, "web", 120);
        String tokenHash = sha256(token);
        var ownerRoom = roomRepository.findByRoomNameAndOwnerTokenHash(roomName, tokenHash);
        if (ownerRoom.isPresent()) {
            return new RoomAccess(ownerRoom.get().getId(), Role.OWNER, roomName);
        }
        var invited = accessRepository.findByTokenHash(tokenHash);
        if (invited.isPresent()) {
            return requireUsableInvite(roomName, invited.get());
        }
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "房间凭证无效");
    }

    @Transactional
    public List<AccessTokenView> listAccessTokens(String roomName, RoomCredential credential) {
        RoomAccess owner = requireRole(roomName, credential, Role.OWNER);
        return accessRepository.findByRoom_IdOrderByCreatedAtDesc(owner.roomId()).stream()
                .map(this::accessTokenView)
                .toList();
    }

    @Transactional
    public CreatedAccessToken createAccessToken(String roomName, CreateAccessTokenRequest request) {
        RoomAccess owner = requireRole(roomName, request.credential(), Role.OWNER);
        Role role = parseInviteRole(request.role());
        PublicTransferRoom room = roomRepository.findById(owner.roomId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "房间不存在"));
        requireAccessTokenCapacity(owner.roomId());
        String now = Instant.now().toString();
        String expiresAt = accessTokenExpiry(request.expiresInSeconds(), Instant.parse(now));
        return issueAccessToken(
                room,
                role,
                normalizeText(request.label(), role == Role.EDITOR ? "编辑者邀请" : "访客邀请", 80),
                now,
                expiresAt
        );
    }

    @Transactional
    public CreatePairingCodeResponse createPairingCode(String roomName, CreatePairingCodeRequest request) {
        RoomAccess owner = requireRole(roomName, request.credential(), Role.OWNER);
        Role role = parseInviteRole(request.role());
        int maxUses = normalizePairingCodeUses(request.maxUses());
        PublicTransferRoom room = roomRepository.findById(owner.roomId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "房间不存在"));

        Instant createdAt = Instant.now();
        long configuredTtl = properties.getPairingCodeTtlSeconds();
        long ttlSeconds = Math.max(60L, Math.min(900L, configuredTtl));
        String plainCode = newUniquePairingCode();
        PublicTransferRoomPairingCode pairingCode = new PublicTransferRoomPairingCode();
        pairingCode.setId(newUniquePairingCodeId());
        pairingCode.setRoom(room);
        pairingCode.setCodeHash(pairingCodeHash(plainCode));
        pairingCode.setRole(role.name());
        pairingCode.setLabel(normalizeText(request.label(), role == Role.EDITOR ? "编辑者配对" : "访客配对", 80));
        pairingCode.setCreatedAt(createdAt.toString());
        pairingCode.setExpiresAt(createdAt.plusSeconds(ttlSeconds).toString());
        pairingCode.setMaxUses(maxUses);
        pairingCode.setUsedCount(0);
        PublicTransferRoomPairingCode saved = pairingCodeRepository.saveAndFlush(pairingCode);
        return new CreatePairingCodeResponse(
                saved.getId(), plainCode, role, saved.getLabel(), saved.getCreatedAt(),
                saved.getExpiresAt(), saved.getMaxUses(), saved.getUsedCount());
    }

    @Transactional
    public RedeemPairingCodeResponse redeemPairingCode(RedeemPairingCodeRequest request) {
        normalizeText(request.peerId(), "web", 120);
        String plainCode = normalizePairingCode(request.code());
        String codeHash = pairingCodeHash(plainCode);
        Instant now = Instant.now();
        if (pairingCodeRepository.consumeUsable(codeHash, now.toString()) != 1) {
            throw invalidPairingCode();
        }
        PublicTransferRoomPairingCode pairingCode = pairingCodeRepository.findByCodeHash(codeHash)
                .orElseThrow(PublicTransferRoomService::invalidPairingCode);
        Role role = parseInviteRole(pairingCode.getRole());
        PublicTransferRoom room = pairingCode.getRoom();
        requireAccessTokenCapacity(room.getId());
        String expiresAt = now.plusSeconds(PAIRING_ACCESS_TOKEN_TTL_SECONDS).toString();
        CreatedAccessToken created = issueAccessToken(
                room,
                role,
                pairingCode.getLabel(),
                now.toString(),
                expiresAt
        );
        return new RedeemPairingCodeResponse(room.getRoomName(), role, created.token(), expiresAt);
    }

    private CreatedAccessToken issueAccessToken(PublicTransferRoom room,
                                                Role role,
                                                String label,
                                                String createdAt,
                                                String expiresAt) {
        for (int attempt = 0; attempt < 4; attempt++) {
            String plainToken = newAccessToken(role);
            PublicTransferRoomAccess access = new PublicTransferRoomAccess();
            access.setId(newUniqueAccessId());
            access.setRoom(room);
            access.setTokenHash(sha256(plainToken));
            access.setRole(role.name());
            access.setLabel(label);
            access.setCreatedAt(createdAt);
            access.setExpiresAt(expiresAt);
            try {
                PublicTransferRoomAccess saved = accessRepository.saveAndFlush(access);
                return new CreatedAccessToken(accessTokenView(saved), plainToken);
            } catch (DataIntegrityViolationException conflict) {
                if (attempt == 3) throw conflict;
            }
        }
        throw new IllegalStateException("无法生成邀请 Token");
    }

    @Transactional
    public AccessTokenView revokeAccessToken(String roomName, long accessId, RoomCredential credential) {
        RoomAccess owner = requireRole(roomName, credential, Role.OWNER);
        PublicTransferRoomAccess access = accessRepository.findByIdAndRoom_Id(accessId, owner.roomId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "邀请 Token 不存在"));
        if (access.getRevokedAt() == null) {
            access.setRevokedAt(Instant.now().toString());
            accessRepository.save(access);
        }
        return accessTokenView(access);
    }

    @Transactional
    public List<DiagramVersionView> listVersions(String roomName, RoomCredential credential) {
        RoomAccess access = resolve(roomName, credential.roomToken(), credential.peerId());
        return versionRepository.findByRoom_IdOrderByCreatedAtDesc(access.roomId()).stream()
                .map(this::versionView)
                .toList();
    }

    @Transactional
    public DiagramVersionView createVersion(String roomName, CreateDiagramVersionRequest request) {
        RoomAccess access = resolve(roomName, request.credential().roomToken(), request.credential().peerId());
        if (!access.role().canEdit()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "访客不能创建流程图版本");
        }
        byte[] snapshot = decodeSnapshot(request.update());
        PublicTransferRoom room = roomRepository.findById(access.roomId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "房间不存在"));
        PublicTransferDiagramVersion version = new PublicTransferDiagramVersion();
        version.setId(newUniqueVersionId());
        version.setRoom(room);
        version.setName(requireText(request.name(), "name", 80));
        version.setAuthorPeerId(normalizeText(request.credential().peerId(), "web", 120));
        version.setSnapshotData(snapshot);
        version.setSizeBytes(snapshot.length);
        version.setCreatedAt(Instant.now().toString());
        PublicTransferDiagramVersion saved = versionRepository.saveAndFlush(version);
        List<PublicTransferDiagramVersion> versions = versionRepository.findByRoom_IdOrderByCreatedAtDesc(access.roomId());
        if (versions.size() > MAX_VERSIONS_PER_ROOM) {
            versionRepository.deleteAll(versions.subList(MAX_VERSIONS_PER_ROOM, versions.size()));
        }
        return versionView(saved);
    }

    @Transactional
    public DiagramVersionDetail getVersion(String roomName, long versionId, RoomCredential credential) {
        RoomAccess access = resolve(roomName, credential.roomToken(), credential.peerId());
        PublicTransferDiagramVersion version = versionRepository.findByIdAndRoom_Id(versionId, access.roomId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "流程图版本不存在"));
        return new DiagramVersionDetail(versionView(version), Base64.getEncoder().encodeToString(version.getSnapshotData()));
    }

    @Transactional
    public void deleteVersion(String roomName, long versionId, RoomCredential credential) {
        RoomAccess owner = requireRole(roomName, credential, Role.OWNER);
        PublicTransferDiagramVersion version = versionRepository.findByIdAndRoom_Id(versionId, owner.roomId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "流程图版本不存在"));
        versionRepository.delete(version);
    }

    private RoomAccess requireRole(String roomName, RoomCredential credential, Role required) {
        RoomAccess access = resolve(roomName, credential.roomToken(), credential.peerId());
        if (access.role() != required) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "需要房主权限");
        }
        return access;
    }

    private RoomAccess requireUsableInvite(String roomName, PublicTransferRoomAccess access) {
        if (!access.getRoom().getRoomName().equals(roomName) || !isUsableAccess(access, Instant.now())) {
            // Keep all known-but-unusable invite states indistinguishable and, critically, prevent
            // resolve() from falling through to legacy owner-room creation.
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "房间凭证无效");
        }
        return new RoomAccess(access.getRoom().getId(), Role.valueOf(access.getRole()), roomName);
    }

    private void requireAccessTokenCapacity(long roomId) {
        Instant now = Instant.now();
        long activeCount = accessRepository.findByRoom_IdOrderByCreatedAtDesc(roomId).stream()
                .filter(access -> isUsableAccess(access, now))
                .count();
        if (activeCount >= MAX_ACCESS_TOKENS_PER_ROOM) {
            throw new IllegalStateException("房间有效邀请 Token 已达到 20 个上限");
        }
    }

    private boolean isUsableAccess(PublicTransferRoomAccess access, Instant now) {
        if (access.getRevokedAt() != null) {
            return false;
        }
        if (!StringUtils.hasText(access.getExpiresAt())) {
            return true;
        }
        try {
            return Instant.parse(access.getExpiresAt()).isAfter(now);
        } catch (RuntimeException malformedTimestamp) {
            return false;
        }
    }

    private String accessTokenExpiry(Long expiresInSeconds, Instant now) {
        if (expiresInSeconds == null) {
            return null;
        }
        if (expiresInSeconds < MIN_ACCESS_TOKEN_TTL_SECONDS || expiresInSeconds > MAX_ACCESS_TOKEN_TTL_SECONDS) {
            throw new IllegalArgumentException("邀请有效期必须在 300 到 604800 秒之间");
        }
        return now.plusSeconds(expiresInSeconds).toString();
    }

    private int normalizePairingCodeUses(Integer value) {
        int normalized = value == null ? 1 : value;
        if (normalized < 1 || normalized > MAX_PAIRING_CODE_USES) {
            throw new IllegalArgumentException("配对码可用次数必须在 1 到 5 之间");
        }
        return normalized;
    }

    private String normalizePairingCode(String value) {
        String code = StringUtils.hasText(value) ? value.trim() : "";
        if (!code.matches("[0-9]{8}")) {
            throw invalidPairingCode();
        }
        return code;
    }

    private String newUniquePairingCode() {
        for (int attempt = 0; attempt < 16; attempt++) {
            String code = String.format(Locale.ROOT, "%08d", secureRandom.nextInt(100_000_000));
            if (!pairingCodeRepository.existsByCodeHash(pairingCodeHash(code))) {
                return code;
            }
        }
        throw new IllegalStateException("无法生成唯一配对码");
    }

    private String pairingCodeHash(String code) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(localTokenService.getSecretKey());
            byte[] digest = mac.doFinal((PAIRING_HMAC_DOMAIN + code).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException("无法计算配对码哈希", exception);
        }
    }

    private static ResponseStatusException invalidPairingCode() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "配对码无效或已过期");
    }

    private byte[] decodeSnapshot(String encoded) {
        if (!StringUtils.hasText(encoded) || encoded.length() > 4 * 1024 * 1024 + 16) {
            throw new IllegalArgumentException("流程图版本数据无效或超过限制");
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("流程图版本数据不是有效的 Base64", exception);
        }
        if (decoded.length == 0 || decoded.length > MAX_SNAPSHOT_BYTES) {
            throw new IllegalArgumentException("流程图版本数据无效或超过 3 MB");
        }
        return decoded;
    }

    private AccessTokenView accessTokenView(PublicTransferRoomAccess access) {
        return new AccessTokenView(
                access.getId(), Role.valueOf(access.getRole()), access.getLabel(), access.getCreatedAt(),
                access.getExpiresAt(), access.getRevokedAt());
    }

    private DiagramVersionView versionView(PublicTransferDiagramVersion version) {
        return new DiagramVersionView(version.getId(), version.getName(), version.getAuthorPeerId(), version.getSizeBytes(), version.getCreatedAt());
    }

    private Role parseInviteRole(String value) {
        try {
            Role role = Role.valueOf(normalizeText(value, "", 16).toUpperCase());
            if (role == Role.OWNER) throw new IllegalArgumentException("不能创建房主邀请 Token");
            return role;
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("邀请角色必须是 EDITOR 或 VIEWER");
        }
    }

    private String newAccessToken(Role role) {
        byte[] random = new byte[32];
        secureRandom.nextBytes(random);
        return "st-" + role.name().toLowerCase() + "-" + Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    }

    private static boolean isInviteToken(String token) {
        return token.startsWith("st-editor-") || token.startsWith("st-viewer-");
    }

    private long newUniqueRoomId() {
        return uniqueId(roomRepository::existsById);
    }

    private long newUniqueAccessId() {
        return uniqueId(accessRepository::existsById);
    }

    private long newUniquePairingCodeId() {
        return uniqueId(pairingCodeRepository::existsById);
    }

    private long newUniqueVersionId() {
        return uniqueId(versionRepository::existsById);
    }

    private long uniqueId(java.util.function.LongPredicate exists) {
        for (int attempt = 0; attempt < 8; attempt++) {
            long id = ClientIdGenerator.newId();
            if (!exists.test(id)) return id;
        }
        throw new IllegalStateException("无法生成唯一 ID");
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("无法计算房间 Token 哈希", exception);
        }
    }

    private static String requireText(String value, String field, int maxLength) {
        if (!StringUtils.hasText(value)) throw new IllegalArgumentException(field + " 不能为空");
        return normalizeText(value, "", maxLength);
    }

    private static String normalizeText(String value, String fallback, int maxLength) {
        String normalized = StringUtils.hasText(value) ? value.trim() : fallback;
        if (normalized.length() > maxLength) throw new IllegalArgumentException("字段长度不能超过 " + maxLength);
        if (normalized.indexOf('\r') >= 0 || normalized.indexOf('\n') >= 0) throw new IllegalArgumentException("字段不能包含换行");
        return normalized;
    }

    public enum Role {
        OWNER,
        EDITOR,
        VIEWER;

        public boolean canEdit() {
            return this == OWNER || this == EDITOR;
        }
    }

    public record RoomAccess(long roomId, Role role, String roomName) {}

    public record RoomCredential(String roomId, String roomToken, String peerId) {}

    public record CreateAccessTokenRequest(String roomId,
                                           String roomToken,
                                           String peerId,
                                           String role,
                                           String label,
                                           Long expiresInSeconds) {
        RoomCredential credential() {
            return new RoomCredential(roomId, roomToken, peerId);
        }
    }

    public record AccessTokenView(long id,
                                  Role role,
                                  String label,
                                  String createdAt,
                                  String expiresAt,
                                  String revokedAt) {}

    public record CreatedAccessToken(AccessTokenView access, String token) {}

    public record CreatePairingCodeRequest(String roomId,
                                           String roomToken,
                                           String peerId,
                                           String role,
                                           String label,
                                           Integer maxUses) {
        RoomCredential credential() {
            return new RoomCredential(roomId, roomToken, peerId);
        }
    }

    public record CreatePairingCodeResponse(long id,
                                            String code,
                                            Role role,
                                            String label,
                                            String createdAt,
                                            String expiresAt,
                                            int maxUses,
                                            int usedCount) {}

    public record RedeemPairingCodeRequest(String code, String peerId) {}

    public record RedeemPairingCodeResponse(String roomId,
                                            Role role,
                                            String roomToken,
                                            String expiresAt) {}

    public record CreateDiagramVersionRequest(String roomId, String roomToken, String peerId, String name, String update) {
        RoomCredential credential() {
            return new RoomCredential(roomId, roomToken, peerId);
        }
    }

    public record DiagramVersionView(long id, String name, String authorPeerId, long sizeBytes, String createdAt) {}

    public record DiagramVersionDetail(DiagramVersionView version, String update) {}
}
