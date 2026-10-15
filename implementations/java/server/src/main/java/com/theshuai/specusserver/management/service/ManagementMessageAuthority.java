package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementWriteAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import java.util.function.Consumer;

/** Management identity first, then credential/client locks, held through network acceptance.
 * This is separate from the queue producer: its snapshot must not be an old outer read view. */
@Service
public class ManagementMessageAuthority {
    private final ManagementWriteAuthority actors;
    private final ClientAccountRepository clients;
    public ManagementMessageAuthority(ManagementWriteAuthority actors, ClientAccountRepository clients) {
        this.actors = actors; this.clients = clients;
    }
    public static final class Denied extends RuntimeException {
        private final String reason;
        public Denied(String reason) { super(reason); this.reason = reason; }
        public String reason() { return reason; }
    }
    @Transactional
    public void publish(ManagementContext identity, ClientAccount reference, Consumer<ClientAccount> publisher) {
        ManagementContext actor;
        try { actor = actors.current(identity); }
        catch (ResponseStatusException revoked) { throw new Denied("identity-revoked"); }
        if (actor.isAdmin() != identity.isAdmin()) throw new Denied("identity-revoked");
        ClientAccount current = clients.lockCurrent(reference.getId(), actor.tenant().tenantId())
                .filter(ClientAccount::isEnabled)
                .filter(account -> account.getClientName().equals(reference.getClientName()))
                .filter(account -> actor.isAdmin() || actor.username().equals(account.getOwnerUsername()))
                .orElseThrow(() -> new Denied("target-not-found"));
        publisher.accept(current);
    }
}
