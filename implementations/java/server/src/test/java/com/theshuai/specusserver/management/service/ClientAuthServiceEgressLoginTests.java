package com.theshuai.specusserver.management.service;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.config.ClientAuthProperties;
import com.theshuai.specusserver.config.NettyServerProperties;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.ClientCredential;
import com.theshuai.specusserver.management.model.ClientIdentity;
import com.theshuai.specusserver.management.model.ClientSession;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.management.repository.ClientIdentityRepository;
import com.theshuai.specusserver.management.repository.ClientSessionRepository;
import com.theshuai.specusserver.management.repository.ConnectionRecordRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.security.TlsProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.PlatformTransactionManager;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * What a login's {@code clientEgressCapabilities} leaves on the session. The egress-catalog reads
 * {@code domainTargetCapable} back from there, so a claim stored wrongly here is advertised to every
 * consumer of that egress.
 */
class ClientAuthServiceEgressLoginTests {
    private static final String TENANT = "t1";
    private static final String API_KEY = "egress-key";
    private static final String SECRET = "egress-secret";

    private final ClientCredentialRepository credentialRepository = mock(ClientCredentialRepository.class);
    private final ClientIdentityRepository identityRepository = mock(ClientIdentityRepository.class);
    private final ClientSessionRepository sessionRepository = mock(ClientSessionRepository.class);
    private final ClientAccountRepository clientAccountRepository = mock(ClientAccountRepository.class);
    private final ClientAuthNonceService nonceService = mock(ClientAuthNonceService.class);

    private final ClientAuthService service = new ClientAuthService(
            credentialRepository,
            identityRepository,
            sessionRepository,
            clientAccountRepository,
            mock(ConnectionRecordRepository.class),
            mock(SpecusMappingRepository.class),
            mock(HttpRouteMappingRepository.class),
            mock(PeerMeshService.class),
            nonceService,
            new ClientAuthProperties(),
            new NettyServerProperties(),
            new TlsProperties(),
            mock(PlatformTransactionManager.class),
            "");

    @BeforeEach
    void knownCredentialAndDevice() {
        ClientCredential credential = new ClientCredential();
        credential.setId(11L);
        credential.setTenantId(TENANT);
        credential.setApiKey(API_KEY);
        credential.setSecretHash(PasswordService.hashToken(SECRET));
        when(credentialRepository.findByApiKey(API_KEY)).thenReturn(Optional.of(credential));
        when(nonceService.consume(anyString(), anyString())).thenReturn(true);

        ClientIdentity identity = new ClientIdentity();
        identity.setId(12L);
        identity.setTenantId(TENANT);
        identity.setCredentialId(11L);
        identity.setClientId(2L);
        when(identityRepository.findByCredentialIdAndMachineFingerprintAndOsUser(any(), any(), any()))
                .thenReturn(Optional.of(identity));
        when(identityRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ClientAccount account = new ClientAccount();
        account.setId(2L);
        account.setTenantId(TENANT);
        account.setClientName("office-gateway");
        account.setEnabled(true);
        when(clientAccountRepository.findByIdAndTenantId(2L, TENANT)).thenReturn(Optional.of(account));
    }

    @Test
    void anEgressThatDeclaresDomainTargetsIsStoredAsSuch() {
        ClientSession session = loginWith("""
                {"version": 1, "egressCapable": true, "consumerCapable": true, "domainTargetCapable": true}
                """);

        assertThat(session.getClientEgressVersion()).isEqualTo(1);
        assertThat(session.isClientEgressDomainTargets()).isTrue();
    }

    @Test
    void anEgressThatDoesNotDeclareDomainTargetsIsStoredWithout() {
        assertThat(loginWith("""
                {"version": 1, "egressCapable": true, "domainTargetCapable": false}
                """).isClientEgressDomainTargets()).isFalse();
        // Absent is the same as false: older clients never sent the field.
        assertThat(loginWith("""
                {"version": 1, "egressCapable": true}
                """).isClientEgressDomainTargets()).isFalse();
    }

    /**
     * A client that does not take part in egress gets no egress messages at all, so a stray
     * domain-target flag from it must not be kept for the catalog to pick up.
     */
    @Test
    void aDomainTargetClaimWithoutAnEgressVersionIsNotKept() {
        ClientSession session = loginWith("""
                {"version": 0, "domainTargetCapable": true}
                """);

        assertThat(session.getClientEgressVersion()).isZero();
        assertThat(session.isClientEgressDomainTargets()).isFalse();
    }

    /** An explicit null reads like an absent object instead of failing the login. */
    @Test
    void aNullEgressCapabilityObjectLogsInWithoutEgress() {
        ClientSession session = loginWith("null");

        assertThat(session.getClientEgressVersion()).isZero();
        assertThat(session.isClientEgressDomainTargets()).isFalse();
    }

    private ClientSession loginWith(String egressCapabilitiesJson) {
        ClientEnvironmentInfo environment = JsonUtil.stringToObject("""
                {
                  "machineFingerprint": "fp-office",
                  "osUser": "ops",
                  "hostname": "office",
                  "clientEgressCapabilities": %s
                }
                """.formatted(egressCapabilitiesJson), ClientEnvironmentInfo.class);
        assertThat(environment).isNotNull();

        ClientAuthLoginRequest request = new ClientAuthLoginRequest();
        request.setApiKey(API_KEY);
        request.setTimestamp(Long.toString(System.currentTimeMillis()));
        request.setNonce(UUID.randomUUID().toString());
        request.setEnvironment(environment);
        request.setSignature(ClientAuthSigner.signApiKey(
                API_KEY, request.getTimestamp(), request.getNonce(), environment, SECRET));

        service.login(request, "127.0.0.1");

        ArgumentCaptor<ClientSession> saved = ArgumentCaptor.forClass(ClientSession.class);
        verify(sessionRepository, atLeastOnce()).save(saved.capture());
        return saved.getValue();
    }
}
