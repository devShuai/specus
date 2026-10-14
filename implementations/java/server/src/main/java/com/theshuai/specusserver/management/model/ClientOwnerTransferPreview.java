package com.theshuai.specusserver.management.model;

import java.util.List;

/** Public management preview; deliberately contains no access credential or session material. */
public record ClientOwnerTransferPreview(
        String scope, Long clientId, Long credentialId, String credentialOwnerUsername,
        Boolean credentialEnabled, List<AffectedClient> affectedClients, int affectedClientCount,
        boolean canTransfer, String conflictCode, String revision, boolean accessRetained
) {
    public ClientOwnerTransferPreview { affectedClients = List.copyOf(affectedClients); }

    public record AffectedClient(long id, String clientName, String ownerUsername, boolean enabled) {}
}
