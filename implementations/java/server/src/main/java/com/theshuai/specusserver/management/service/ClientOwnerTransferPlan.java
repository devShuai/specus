package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.specusserver.management.model.ClientOwnerTransferPreview;
import com.theshuai.specusserver.management.model.ClientOwnerTransferPreview.AffectedClient;
import com.theshuai.specusserver.management.security.ManagementContext;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Side-effect-free range/revision validation for the #237 ownership contract.
 * Not an authorization token, database lock, transfer operation, or published API.
 * The future writer must load a complete snapshot inside its database coordination boundary,
 * validate the current target there, and commit ownership and audit atomically.
 */
final class ClientOwnerTransferPlan {
    private static final long MAX_SAFE_ID = 9_007_199_254_740_991L;

    enum PathScope {
        SINGLE("single"), CREDENTIAL_GROUP("credential-group");
        final String wireName;
        PathScope(String wireName) { this.wireName = wireName; }
    }

    record ClientRow(long id, String tenantId, String clientName, String ownerUsername, boolean enabled) {}
    record CredentialRow(long id, String tenantId, String ownerUsername, boolean enabled) {}
    record IdentityRow(long id, String tenantId, long credentialId, long clientId) {}
    record PeerRow(long id, String tenantId, long clientId, String clientName,
                   String ownerUsername, boolean enabled) {}

    /** Must include all edges touching the selected credential or clients, even foreign edges. */
    record Snapshot(List<ClientRow> clients, List<CredentialRow> credentials,
                    List<IdentityRow> identities, List<PeerRow> peers) {
        Snapshot {
            clients = List.copyOf(clients);
            credentials = List.copyOf(credentials);
            identities = List.copyOf(identities);
            peers = List.copyOf(peers);
        }
    }

    record Prepared(ClientOwnerTransferPreview preview, String requestedTargetUsername) {}

    static ClientOwnerTransferPreview preview(ManagementContext context, PathScope scope, long pathId, Snapshot snapshot) {
        authorizeAndValidateId(context, pathId);
        requireResource(context, scope, pathId, snapshot);
        return build(context.tenant().tenantId(), scope, pathId, snapshot);
    }

    /** Only validates through revision checking (steps 1–8); never resolves a target or writes. */
    static Prepared prepare(ManagementContext context, PathScope scope, long pathId,
                            JsonNode request, Snapshot current) {
        authorizeAndValidateId(context, pathId);
        if (request == null || !request.isObject()) throw invalid();
        requireResource(context, scope, pathId, current);
        JsonNode requestedScope = request.get("scope");
        if (requestedScope == null || !requestedScope.isTextual()
                || !scope.wireName.equals(requestedScope.textValue())) throw invalid();
        for (String field : List.of("targetUsername", "expectedRevision")) {
            JsonNode value = request.get(field);
            if (value != null && !value.isTextual()) throw invalid();
        }
        ClientOwnerTransferPreview preview = build(context.tenant().tenantId(), scope, pathId, current);
        if (!preview.canTransfer()) throw new ClientOwnerTransferException(409, "CREDENTIAL_SHARED");
        String target = requiredText(request, "targetUsername");
        String revision = requiredText(request, "expectedRevision");
        // Revisions are opaque: don't normalize them (unlike the requested target lookup text).
        if (!preview.revision().equals(revision)) throw new ClientOwnerTransferException(409, "TRANSFER_PREVIEW_CHANGED");
        return new Prepared(preview, target.trim());
    }

    static void authorizeAndValidateId(ManagementContext context, long id) {
        Objects.requireNonNull(context, "management identity must already be resolved");
        if (!context.isAdmin()) throw new ClientOwnerTransferException(403, "FORBIDDEN");
        if (id <= 0 || id > MAX_SAFE_ID) throw invalid();
    }

    private static void requireResource(ManagementContext context, PathScope scope, long id, Snapshot data) {
        String tenant = context.tenant().tenantId();
        boolean exists = scope == PathScope.SINGLE
                ? data.clients().stream().anyMatch(c -> c.id() == id && tenant.equals(c.tenantId()))
                : data.credentials().stream().anyMatch(c -> c.id() == id && tenant.equals(c.tenantId()));
        if (!exists) throw new ClientOwnerTransferException(404, "RESOURCE_NOT_FOUND");
    }

    private static ClientOwnerTransferPreview build(String tenant, PathScope scope, long pathId, Snapshot data) {
        Long credentialId = scope == PathScope.CREDENTIAL_GROUP ? pathId : null;
        if (scope == PathScope.SINGLE) {
            List<IdentityRow> direct = data.identities().stream().filter(i -> i.clientId() == pathId).toList();
            for (IdentityRow identity : direct) {
                if (!tenant.equals(identity.tenantId())) throw inconsistent();
                if (credentialId != null && credentialId != identity.credentialId()) throw inconsistent();
                credentialId = identity.credentialId();
            }
        }

        CredentialRow credential = null;
        List<IdentityRow> identities = List.of();
        TreeSet<Long> clientIds = new TreeSet<>();
        if (credentialId != null) {
            long id = credentialId;
            List<CredentialRow> found = data.credentials().stream().filter(c -> c.id() == id).toList();
            if (id <= 0 || id > MAX_SAFE_ID || found.size() != 1
                    || !tenant.equals(found.getFirst().tenantId())) throw inconsistent();
            credential = found.getFirst();
            identities = data.identities().stream().filter(i -> i.credentialId() == id)
                    .sorted(Comparator.comparingLong(IdentityRow::id)).toList();
            TreeSet<Long> identityIds = new TreeSet<>();
            for (IdentityRow identity : identities) {
                if (!tenant.equals(identity.tenantId()) || !identityIds.add(identity.id())) throw inconsistent();
                clientIds.add(identity.clientId());
            }
        } else {
            clientIds.add(pathId);
        }

        Map<Long, List<ClientRow>> accountsById = data.clients().stream().collect(Collectors.groupingBy(ClientRow::id));
        List<ClientRow> clients = clientIds.stream().map(id -> {
            List<ClientRow> found = accountsById.getOrDefault(id, List.of());
            if (id <= 0 || id > MAX_SAFE_ID || found.size() != 1
                    || !tenant.equals(found.getFirst().tenantId())) throw inconsistent();
            return found.getFirst();
        }).toList();
        // Validate the whole group's reverse edges, not just the initially requested client.
        for (IdentityRow identity : data.identities()) {
            if (clientIds.contains(identity.clientId())
                    && (!tenant.equals(identity.tenantId()) || credentialId == null
                        || credentialId != identity.credentialId())) throw inconsistent();
        }
        List<PeerRow> peers = data.peers().stream()
                .filter(p -> tenant.equals(p.tenantId()) && clientIds.contains(p.clientId()))
                .sorted(Comparator.comparingLong(PeerRow::id)).toList();
        TreeSet<Long> peerClientIds = new TreeSet<>();
        TreeSet<Long> peerIds = new TreeSet<>();
        for (PeerRow peer : peers) {
            if (!peerClientIds.add(peer.clientId()) || !peerIds.add(peer.id())) throw inconsistent();
        }

        boolean shared = scope == PathScope.SINGLE && clientIds.size() > 1;
        List<AffectedClient> affected = clients.stream().map(c ->
                new AffectedClient(c.id(), c.clientName(), c.ownerUsername(), c.enabled())).toList();
        return new ClientOwnerTransferPreview(scope.wireName, scope == PathScope.SINGLE ? pathId : null,
                credentialId, credential == null ? null : credential.ownerUsername(),
                credential == null ? null : credential.enabled(), affected, affected.size(),
                !shared, shared ? "CREDENTIAL_SHARED" : null,
                shared ? null : revision(tenant, scope, pathId, credential, clients, identities, peers), true);
    }

    private static String revision(String tenant, PathScope scope, long pathId, CredentialRow credential,
                                    List<ClientRow> clients, List<IdentityRow> identities, List<PeerRow> peers) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream out = new DataOutputStream(bytes)) {
                text(out, "specus-owner-transfer-java-v1");
                text(out, tenant);
                text(out, scope.wireName);
                out.writeLong(pathId);
                out.writeBoolean(credential != null);
                if (credential != null) {
                    out.writeLong(credential.id());
                    text(out, credential.ownerUsername());
                    out.writeBoolean(credential.enabled());
                }
                out.writeInt(clients.size());
                for (ClientRow client : clients) {
                    out.writeLong(client.id());
                    text(out, client.clientName());
                    text(out, client.ownerUsername());
                    out.writeBoolean(client.enabled());
                }
                out.writeInt(identities.size());
                for (IdentityRow identity : identities) {
                    out.writeLong(identity.id());
                    out.writeLong(identity.credentialId());
                    out.writeLong(identity.clientId());
                }
                out.writeInt(peers.size());
                for (PeerRow peer : peers) {
                    out.writeLong(peer.id());
                    out.writeLong(peer.clientId());
                    text(out, peer.clientName());
                    text(out, peer.ownerUsername());
                    out.writeBoolean(peer.enabled());
                }
            }
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()));
        } catch (IOException | NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("could not encode ownership preview", impossible);
        }
    }

    private static void text(DataOutputStream out, String value) throws IOException {
        if (value == null) { out.writeInt(-1); return; }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static String requiredText(JsonNode request, String field) {
        JsonNode value = request.get(field);
        if (value == null || value.textValue().isBlank()) throw invalid();
        return value.textValue();
    }
    private static ClientOwnerTransferException invalid() { return new ClientOwnerTransferException(400, "INVALID_TRANSFER_REQUEST"); }
    private static ClientOwnerTransferException inconsistent() { return new ClientOwnerTransferException(409, "INCONSISTENT_CREDENTIAL_GROUP"); }
}
