package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.UserDiagramDocument;
import com.theshuai.tunnelserver.management.repository.UserDiagramDocumentRepository;
import com.theshuai.tunnelserver.management.repository.UserDiagramDocumentRepository.UserDiagramDocumentSummary;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import org.springframework.http.HttpStatus;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Base64;
import java.util.List;

@Service
public class UserDiagramDocumentService {
    private static final int MAX_DOCUMENTS_PER_USER = 100;
    private static final int MAX_SNAPSHOT_BYTES = 3 * 1024 * 1024;

    private final UserDiagramDocumentRepository repository;

    public UserDiagramDocumentService(UserDiagramDocumentRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public List<DiagramDocumentView> list(ManagementContext context) {
        Owner owner = owner(context);
        return repository.findSummariesByOwner(owner.tenantId(), owner.username()).stream()
                .map(this::view)
                .toList();
    }

    @Transactional(readOnly = true)
    public DiagramDocumentDetail get(ManagementContext context, long id) {
        UserDiagramDocument document = requireOwned(context, id);
        return new DiagramDocumentDetail(view(document), Base64.getEncoder().encodeToString(document.getSnapshotData()));
    }

    @Transactional
    public DiagramDocumentView create(ManagementContext context, DiagramDocumentMutation request) {
        Owner owner = owner(context);
        if (repository.countByTenantIdAndOwnerUsername(owner.tenantId(), owner.username()) >= MAX_DOCUMENTS_PER_USER) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "云端流程图数量已达到 100 个上限");
        }
        byte[] snapshot = decodeSnapshot(request.update());
        String now = Instant.now().toString();
        UserDiagramDocument document = new UserDiagramDocument();
        document.setId(newUniqueId());
        document.setTenantId(owner.tenantId());
        document.setOwnerUsername(owner.username());
        document.setName(requireText(request.name(), "name", 120));
        document.setSnapshotData(snapshot);
        document.setSizeBytes(snapshot.length);
        document.setCreatedAt(now);
        document.setUpdatedAt(now);
        return view(repository.saveAndFlush(document));
    }

    @Transactional
    public DiagramDocumentView update(ManagementContext context, long id, DiagramDocumentMutation request) {
        UserDiagramDocument document = requireOwned(context, id);
        if (request.revision() == null || request.revision() != document.getRevision()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "云端文件已被其他会话更新，请重新打开后再保存");
        }
        byte[] snapshot = decodeSnapshot(request.update());
        document.setName(requireText(request.name(), "name", 120));
        document.setSnapshotData(snapshot);
        document.setSizeBytes(snapshot.length);
        document.setUpdatedAt(Instant.now().toString());
        try {
            return view(repository.saveAndFlush(document));
        } catch (ObjectOptimisticLockingFailureException conflict) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "云端文件已被其他会话更新，请重新打开后再保存", conflict);
        }
    }

    @Transactional
    public void delete(ManagementContext context, long id) {
        repository.delete(requireOwned(context, id));
    }

    private UserDiagramDocument requireOwned(ManagementContext context, long id) {
        Owner owner = owner(context);
        return repository.findByIdAndTenantIdAndOwnerUsername(id, owner.tenantId(), owner.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "云端流程图不存在"));
    }

    private Owner owner(ManagementContext context) {
        if (context == null || context.tenant() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "需要登录后才能访问云端流程图");
        }
        return new Owner(
                requireText(context.tenant().tenantId(), "tenantId", 80),
                requireText(context.username(), "username", 160)
        );
    }

    private byte[] decodeSnapshot(String encoded) {
        if (!StringUtils.hasText(encoded) || encoded.length() > 4 * 1024 * 1024 + 16) {
            throw new IllegalArgumentException("流程图数据无效或超过限制");
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("流程图数据不是有效的 Base64", exception);
        }
        if (decoded.length == 0 || decoded.length > MAX_SNAPSHOT_BYTES) {
            throw new IllegalArgumentException("流程图数据无效或超过 3 MB");
        }
        return decoded;
    }

    private long newUniqueId() {
        for (int attempt = 0; attempt < 8; attempt++) {
            long id = ClientIdGenerator.newId();
            if (!repository.existsById(id)) return id;
        }
        throw new IllegalStateException("无法生成云端流程图 ID");
    }

    private DiagramDocumentView view(UserDiagramDocument document) {
        return new DiagramDocumentView(
                document.getId(),
                document.getName(),
                document.getSizeBytes(),
                document.getRevision(),
                document.getCreatedAt(),
                document.getUpdatedAt()
        );
    }

    private DiagramDocumentView view(UserDiagramDocumentSummary document) {
        return new DiagramDocumentView(
                document.getId(),
                document.getName(),
                document.getSizeBytes(),
                document.getRevision(),
                document.getCreatedAt(),
                document.getUpdatedAt()
        );
    }

    private static String requireText(String value, String field, int maxLength) {
        if (!StringUtils.hasText(value)) throw new IllegalArgumentException(field + " 不能为空");
        String normalized = value.trim();
        if (normalized.length() > maxLength) throw new IllegalArgumentException("字段长度不能超过 " + maxLength);
        if (normalized.indexOf('\r') >= 0 || normalized.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("字段不能包含换行");
        }
        return normalized;
    }

    private record Owner(String tenantId, String username) {}

    public record DiagramDocumentMutation(String name, String update, Long revision) {}

    public record DiagramDocumentView(long id,
                                      String name,
                                      long sizeBytes,
                                      long revision,
                                      String createdAt,
                                      String updatedAt) {}

    public record DiagramDocumentDetail(DiagramDocumentView document, String update) {}
}
