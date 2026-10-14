package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementWriteAuthority;
import com.theshuai.specusserver.management.tenant.TenantContext;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import static com.theshuai.specusserver.management.service.ClientOwnerTransferPlan.*;

/** Database-only transfer core. Deliberately NOT wired to POST until runtime/reference writers,
 * selective revocation and cross-instance publication satisfy the shared contract. An audit row
 * proves only database commit, never runtime notification/delivery. No precommit cache effects. */
@Service
public class ClientOwnerTransferWriter {
    private final ManagementWriteAuthority authority;
    private final ClientOwnerTransferRows rows;
    private final AuthProperties auth;
    @PersistenceContext private EntityManager entities;
    private static final ObjectMapper JSON = new ObjectMapper();

    public ClientOwnerTransferWriter(ManagementWriteAuthority authority, ClientOwnerTransferRows rows, AuthProperties auth) {
        this.authority = authority; this.rows = rows; this.auth = auth;
    }

    @Transactional
    public Outcome transferClient(ManagementContext resolved, String id, JsonNode request) {
        return transfer(resolved, PathScope.SINGLE, id, request);
    }
    @Transactional
    public Outcome transferCredential(ManagementContext resolved, String id, JsonNode request) {
        return transfer(resolved, PathScope.CREDENTIAL_GROUP, id, request);
    }

    private Outcome transfer(ManagementContext resolved, PathScope scope, String textId, JsonNode request) {
        String requestedTarget = request != null && request.isObject() && request.path("targetUsername").isTextual()
                ? request.path("targetUsername").textValue() : null;
        // Actor AND target key order precedes every resource lock; target availability is checked
        // only after path/range/revision errors. Holding the target row serializes disable/delete.
        var actors = authority.currentAndTarget(resolved, requestedTarget);
        ManagementContext actor = actors.actor();
        long id = ClientOwnerTransferService.parseId(actor, textId);
        if (request == null || !request.isObject()) throw new ClientOwnerTransferException(400, "INVALID_TRANSFER_REQUEST");
        Snapshot current = rows.lock(actor.tenant().tenantId(), scope, id);
        Prepared prepared = ClientOwnerTransferPlan.prepare(actor, scope, id, request, current);
        String normalized = prepared.requestedTargetUsername().toLowerCase(Locale.ROOT);
        String target;
        if (normalized.equals(auth.getUsername().toLowerCase(Locale.ROOT))
                && actor.tenant().tenantId().equals(TenantContext.normalize(auth.getTenantId()))
                && auth.isPasswordLoginEnabled() && StringUtils.hasText(auth.getPassword())) target = auth.getUsername();
        else target = actors.target().filter(user -> user.isEnabled() && normalized.equals(user.getLoginNameNormalized()))
                .map(user -> user.getLoginName()).orElseThrow(() -> new ClientOwnerTransferException(400, "INVALID_TARGET_OWNER"));
        var preview = prepared.preview();
        boolean changed = current.clients().stream().anyMatch(row -> !Objects.equals(target, row.ownerUsername()))
                || current.credentials().stream().anyMatch(row -> !Objects.equals(target, row.ownerUsername()))
                || current.peers().stream().anyMatch(row -> !Objects.equals(target, row.ownerUsername()));
        List<Long> ids = preview.affectedClients().stream().map(client -> client.id()).toList();
        Result result = new Result(scope.wireName, target, preview.credentialId(), ids, changed, true);
        if (!changed) return new Outcome(result, null);
        String now = Instant.now().toString(), tenant = actor.tenant().tenantId();
        for (ClientRow client : current.clients()) update("specus_client_account", client.id(), tenant, target, now);
        for (CredentialRow credential : current.credentials()) update("specus_client_credential", credential.id(), tenant, target, now);
        for (PeerRow peer : current.peers()) update("peer_mesh_device", peer.id(), tenant, target, now);
        long auditId = ClientIdGenerator.newId();
        String details;
        try {
            details = JSON.writeValueAsString(Map.of("clients", current.clients(), "credentials", current.credentials(),
                    "peerDevices", current.peers(), "affectedClientIds", ids));
        } catch (JsonProcessingException failure) { throw new IllegalStateException("ownership audit serialization failed", failure); }
        entities.createNativeQuery("""
                insert into client_owner_transfer_audit(id,tenant_id,occurred_at,actor,scope,path_id,target_username,credential_id,detail_json)
                values (?1,?2,?3,?4,?5,?6,?7,?8,?9)
                """).setParameter(1, auditId).setParameter(2, tenant).setParameter(3, now).setParameter(4, actor.username())
                .setParameter(5, scope.wireName).setParameter(6, id).setParameter(7, target)
                .setParameter(8, preview.credentialId()).setParameter(9, details).executeUpdate();
        return new Outcome(result, auditId);
    }

    private void update(String table, long id, String tenant, String target, String now) {
        // Identifiers are internal constants. Preserve all keys, flags, limits and references.
        entities.createNativeQuery("update " + table + " set owner_username=?1,updated_at=?2 where id=?3 and tenant_id=?4")
                .setParameter(1, target).setParameter(2, now).setParameter(3, id).setParameter(4, tenant).executeUpdate();
        // MySQL's useAffectedRows may return zero for a valid already-equal row. Verify the
        // current postcondition instead of trusting either a changed-row count or an old RR read.
        String lock = entities.unwrap(Session.class).doReturningWork(connection ->
                connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
        List<?> written = entities.createNativeQuery("select tenant_id,owner_username from " + table + " where id=?1 and tenant_id=?2" + lock)
                .setParameter(1, id).setParameter(2, tenant).getResultList();
        if (written.size() != 1 || !tenant.equals(((Object[]) written.getFirst())[0])
                || !target.equals(((Object[]) written.getFirst())[1])) throw new IllegalStateException("ownership write postcondition failed");
    }
    public record Result(String scope, String targetUsername, Long credentialId, List<Long> affectedClientIds,
                         boolean changed, boolean accessRetained) { public Result { affectedClientIds = List.copyOf(affectedClientIds); } }
    /** Internal orchestration result, not the public response. auditId is null for a no-op. */
    public record Outcome(Result response, Long auditId) {}
}
