package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.PublicTransferDiagramVersion;
import com.theshuai.tunnelserver.management.model.PublicTransferRoom;
import com.theshuai.tunnelserver.management.model.PublicTransferRoomAccess;
import com.theshuai.tunnelserver.management.repository.PublicTransferDiagramVersionRepository;
import com.theshuai.tunnelserver.management.repository.PublicTransferRoomAccessRepository;
import com.theshuai.tunnelserver.management.repository.PublicTransferRoomRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

@Service
public class PublicTransferRoomService {
    private static final int MAX_SNAPSHOT_BYTES = 3 * 1024 * 1024;
    private static final int MAX_VERSIONS_PER_ROOM = 50;
    private static final int MAX_ACCESS_TOKENS_PER_ROOM = 20;

    private final PublicTransferRoomRepository roomRepository;
    private final PublicTransferRoomAccessRepository accessRepository;
    private final PublicTransferDiagramVersionRepository versionRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    public PublicTransferRoomService(PublicTransferRoomRepository roomRepository,
                                     PublicTransferRoomAccessRepository accessRepository,
                                     PublicTransferDiagramVersionRepository versionRepository) {
        this.roomRepository = roomRepository;
        this.accessRepository = accessRepository;
        this.versionRepository = versionRepository;
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
        var invited = accessRepository.findByTokenHashAndRevokedAtIsNull(tokenHash);
        if (invited.isPresent()) {
            PublicTransferRoomAccess access = invited.get();
            if (!access.getRoom().getRoomName().equals(roomName)) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "邀请 Token 不属于当前房间");
            }
            return new RoomAccess(access.getRoom().getId(), Role.valueOf(access.getRole()), roomName);
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
        var invited = accessRepository.findByTokenHashAndRevokedAtIsNull(tokenHash);
        if (invited.isPresent() && invited.get().getRoom().getRoomName().equals(roomName)) {
            PublicTransferRoomAccess access = invited.get();
            return new RoomAccess(access.getRoom().getId(), Role.valueOf(access.getRole()), roomName);
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
        List<PublicTransferRoomAccess> existing = accessRepository.findByRoom_IdOrderByCreatedAtDesc(owner.roomId());
        long activeCount = existing.stream().filter(item -> item.getRevokedAt() == null).count();
        if (activeCount >= MAX_ACCESS_TOKENS_PER_ROOM) {
            throw new IllegalStateException("房间有效邀请 Token 已达到 20 个上限");
        }
        PublicTransferRoom room = roomRepository.findById(owner.roomId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "房间不存在"));
        for (int attempt = 0; attempt < 4; attempt++) {
            String plainToken = newAccessToken(role);
            String now = Instant.now().toString();
            PublicTransferRoomAccess access = new PublicTransferRoomAccess();
            access.setId(newUniqueAccessId());
            access.setRoom(room);
            access.setTokenHash(sha256(plainToken));
            access.setRole(role.name());
            access.setLabel(normalizeText(request.label(), role == Role.EDITOR ? "编辑者邀请" : "访客邀请", 80));
            access.setCreatedAt(now);
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
        return new AccessTokenView(access.getId(), Role.valueOf(access.getRole()), access.getLabel(), access.getCreatedAt(), access.getRevokedAt());
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

    private long newUniqueRoomId() {
        return uniqueId(roomRepository::existsById);
    }

    private long newUniqueAccessId() {
        return uniqueId(accessRepository::existsById);
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

    public record CreateAccessTokenRequest(String roomId, String roomToken, String peerId, String role, String label) {
        RoomCredential credential() {
            return new RoomCredential(roomId, roomToken, peerId);
        }
    }

    public record AccessTokenView(long id, Role role, String label, String createdAt, String revokedAt) {}

    public record CreatedAccessToken(AccessTokenView access, String token) {}

    public record CreateDiagramVersionRequest(String roomId, String roomToken, String peerId, String name, String update) {
        RoomCredential credential() {
            return new RoomCredential(roomId, roomToken, peerId);
        }
    }

    public record DiagramVersionView(long id, String name, String authorPeerId, long sizeBytes, String createdAt) {}

    public record DiagramVersionDetail(DiagramVersionView version, String update) {}
}
