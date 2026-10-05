package com.theshuai.specusserver.management.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.PeerMeshEgressPolicy;
import com.theshuai.specusserver.management.model.PeerMeshEgressSwitch;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientSessionRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.specusserver.management.repository.PeerMeshEgressActivityRepository;
import com.theshuai.specusserver.management.repository.PeerMeshEgressPolicyRepository;
import com.theshuai.specusserver.management.repository.PeerMeshEgressSwitchRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.PeerEgressService;
import com.theshuai.specusserver.management.service.PeerMeshService;
import com.theshuai.specusserver.management.service.PeerSignalService;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

/**
 * The egress management API as a client sees it: request binding, the service and the status
 * mapping of {@link GlobalExceptionHandler} together, per {@code protocol/spec/peer-egress.md}.
 *
 * <p>Driven over HTTP rather than against the service alone because what the shared vector pins is
 * the request body, including lists a client leaves out.
 */
class PeerEgressResourceTests {
    private static final String TENANT = "t1";
    private static final String BASE = "/api/admin/peer-mesh/egress";
    private static final long EGRESS_ID = 2L;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String DOMAIN_POLICY_VECTOR = "peer-egress-domain-policy-v1.json";

    private final PeerMeshEgressPolicyRepository policyRepository = mock(PeerMeshEgressPolicyRepository.class);
    private final PeerMeshEgressSwitchRepository switchRepository = mock(PeerMeshEgressSwitchRepository.class);
    private final ClientAccountRepository clientAccountRepository = mock(ClientAccountRepository.class);
    private final PeerMeshService peerMeshService = mock(PeerMeshService.class);
    private final PeerSignalService peerSignalService = mock(PeerSignalService.class);
    private final ManagementContextResolver contextResolver = mock(ManagementContextResolver.class);

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        PeerEgressService service = new PeerEgressService(
                policyRepository, mock(PeerMeshEgressActivityRepository.class), switchRepository,
                mock(PeerMeshDeviceRepository.class), clientAccountRepository,
                mock(ClientSessionRepository.class), peerMeshService);
        mvc = standaloneSetup(new PeerEgressResource(service, peerSignalService, contextResolver))
                .setControllerAdvice(new GlobalExceptionHandler())
                .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver())
                .build();

        actAs(true);
        ClientAccount egress = new ClientAccount();
        egress.setId(EGRESS_ID);
        egress.setTenantId(TENANT);
        egress.setClientName("office-gateway");
        egress.setOwnerUsername("admin");
        when(clientAccountRepository.findByIdAndTenantId(EGRESS_ID, TENANT)).thenReturn(Optional.of(egress));
        when(policyRepository.save(any(PeerMeshEgressPolicy.class))).thenAnswer(call -> call.getArgument(0));
        when(peerMeshService.isEnabled()).thenReturn(true);
    }

    /** Every accepted case stores, and answers with, exactly the vector's {@code stored} rules. */
    @Test
    void acceptCasesOfTheManagementVectorAreStoredNormalised() throws Exception {
        JsonNode cases = readVector().path("accept");
        assertThat(cases.size()).as("accept cases").isPositive();
        ArgumentCaptor<PeerMeshEgressPolicy> saved = ArgumentCaptor.forClass(PeerMeshEgressPolicy.class);
        for (JsonNode node : cases) {
            String name = node.path("name").asText();
            clearInvocations(policyRepository, peerSignalService);

            MvcResult result = mvc.perform(json(post(BASE + "/policies"), policyBody(node)))
                    .andReturn();

            assertThat(result.getResponse().getStatus()).as(name).isEqualTo(200);
            JsonNode returned = JSON.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
            assertThat(returned.path("destinationRules")).as(name + " response").isEqualTo(node.path("stored"));
            verify(policyRepository).save(saved.capture());
            assertThat(JSON.readTree(saved.getValue().getDestinationRules()))
                    .as(name + " persisted").isEqualTo(node.path("stored"));
            verify(peerSignalService).pushTenantEgress(TENANT);
        }
    }

    /** A refused list is refused whole: 400 in the usual error body, nothing saved or pushed. */
    @Test
    void rejectCasesOfTheManagementVectorAreRefusedWithoutSaving() throws Exception {
        JsonNode cases = readVector().path("reject");
        assertThat(cases.size()).as("reject cases").isPositive();
        for (JsonNode node : cases) {
            String name = node.path("name").asText();

            MvcResult result = mvc.perform(json(post(BASE + "/policies"), policyBody(node)))
                    .andReturn();

            assertThat(result.getResponse().getStatus()).as(name).isEqualTo(400);
            JsonNode body = JSON.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
            assertThat(body.path("error").asText()).as(name + " error").isNotBlank();
        }
        verify(policyRepository, never()).save(any());
        verify(peerSignalService, never()).pushTenantEgress(any());
    }

    /**
     * Every accepted case of the domain-policy vector stores, byte for byte (the size limit is
     * counted on that form), and answers with exactly the vector's {@code stored} rules.
     */
    @Test
    void acceptCasesOfTheDomainPolicyVectorAreStoredNormalised() throws Exception {
        JsonNode vector = readVector(DOMAIN_POLICY_VECTOR);
        assertThat(vector.path("limits").path("rules").asInt()).isEqualTo(PeerMeshEgressPolicy.MAX_DOMAIN_RULES);
        assertThat(vector.path("limits").path("portRangesPerRule").asInt())
                .isEqualTo(PeerMeshEgressPolicy.MAX_PORT_RANGES_PER_RULE);
        assertThat(vector.path("limits").path("storedJsonBytes").asInt())
                .isEqualTo(PeerMeshEgressPolicy.MAX_DOMAIN_RULES_BYTES);
        JsonNode cases = vector.path("management").path("accept");
        assertThat(cases.size()).as("accept cases").isPositive();
        ArgumentCaptor<PeerMeshEgressPolicy> saved = ArgumentCaptor.forClass(PeerMeshEgressPolicy.class);
        for (JsonNode node : cases) {
            String name = node.path("name").asText();
            clearInvocations(policyRepository, peerSignalService);

            MvcResult result = mvc.perform(json(post(BASE + "/policies"), domainPolicyBody(node)))
                    .andReturn();

            assertThat(result.getResponse().getStatus()).as(name).isEqualTo(200);
            JsonNode returned = JSON.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
            assertThat(returned.path("domainRules")).as(name + " response").isEqualTo(node.path("stored"));
            verify(policyRepository).save(saved.capture());
            assertThat(saved.getValue().getDomainRules())
                    .as(name + " persisted").isEqualTo(JSON.writeValueAsString(node.path("stored")));
            assertThat(saved.getValue().getDestinationRules()).as(name + " destination rules").isEqualTo("[]");
            verify(peerSignalService).pushTenantEgress(TENANT);
        }
    }

    /** A refused domain rule list is refused whole: 400, nothing saved or pushed. */
    @Test
    void rejectCasesOfTheDomainPolicyVectorAreRefusedWithoutSaving() throws Exception {
        JsonNode cases = readVector(DOMAIN_POLICY_VECTOR).path("management").path("reject");
        assertThat(cases.size()).as("reject cases").isPositive();
        for (JsonNode node : cases) {
            String name = node.path("name").asText();

            MvcResult result = mvc.perform(json(post(BASE + "/policies"), domainPolicyBody(node)))
                    .andReturn();

            assertThat(result.getResponse().getStatus()).as(name).isEqualTo(400);
            JsonNode body = JSON.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
            assertThat(body.path("error").asText()).as(name + " error").isNotBlank();
        }
        verify(policyRepository, never()).save(any());
        verify(peerSignalService, never()).pushTenantEgress(any());
    }

    /**
     * Omitted fields keep their stored value, domain rules included; a policy created without them
     * stores an empty list.
     */
    @Test
    void domainRulesAreKeptWhenOmittedAndEmptyOnANewPolicy() throws Exception {
        ArgumentCaptor<PeerMeshEgressPolicy> saved = ArgumentCaptor.forClass(PeerMeshEgressPolicy.class);
        mvc.perform(json(post(BASE + "/policies"), "{\"egressClientId\":2}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.domainRules").isArray())
                .andExpect(jsonPath("$.domainRules").isEmpty());
        verify(policyRepository).save(saved.capture());
        assertThat(saved.getValue().getDomainRules()).isEqualTo("[]");

        PeerMeshEgressPolicy existing = saved.getValue();
        existing.setDomainRules("[{\"match\":\"example.com\",\"protocols\":[\"tcp\"],\"portRanges\":[[443,443]]}]");
        when(policyRepository.findByTenantIdAndEgressClientId(TENANT, EGRESS_ID)).thenReturn(Optional.of(existing));
        clearInvocations(policyRepository);

        mvc.perform(json(post(BASE + "/policies"), "{\"egressClientId\":2,\"scope\":\"LAN\",\"domainRules\":null}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.domainRules[0].match").value("example.com"));
        verify(policyRepository).save(saved.capture());
        assertThat(saved.getValue().getDomainRules())
                .isEqualTo("[{\"match\":\"example.com\",\"protocols\":[\"tcp\"],\"portRanges\":[[443,443]]}]");
        assertThat(saved.getValue().getScope()).isEqualTo("LAN");
    }

    /**
     * A switch request without {@code enabled} used to be read as off, so a malformed request could
     * stop egress for the whole tenant.
     */
    @Test
    void aSwitchRequestWithoutEnabledIsRefused() throws Exception {
        mvc.perform(json(put(BASE + "/switch"), "{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("enabled is required"));
        mvc.perform(json(put(BASE + "/switch"), "{\"enabled\":null}"))
                .andExpect(status().isBadRequest());
        verify(switchRepository, never()).save(any());
        verify(peerSignalService, never()).pushTenantEgress(any());

        // An explicit false is still how the tenant is switched off.
        mvc.perform(json(put(BASE + "/switch"), "{\"enabled\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.configuredEnabled").value(false));
        verify(switchRepository).save(any(PeerMeshEgressSwitch.class));
    }

    @Test
    void enablingWhilePeerMeshIsOffIsABadRequest() throws Exception {
        when(peerMeshService.isEnabled()).thenReturn(false);

        mvc.perform(json(put(BASE + "/switch"), "{\"enabled\":true}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").isNotEmpty());
        verify(switchRepository, never()).save(any());
    }

    @Test
    void aBodyThatCannotBeParsedIsABadRequest() throws Exception {
        mvc.perform(json(put(BASE + "/switch"), "{\"enabled\":"))
                .andExpect(status().isBadRequest());
        mvc.perform(json(post(BASE + "/policies"),
                        "{\"egressClientId\":2,\"destinationRules\":[{\"cidr\":\"10.0.0.0/8\",\"portRanges\":\"443\"}]}"))
                .andExpect(status().isBadRequest());
        verify(switchRepository, never()).save(any());
        verify(policyRepository, never()).save(any());
    }

    @Test
    void mutationsByANonAdminAreForbidden() throws Exception {
        actAs(false);

        mvc.perform(json(put(BASE + "/switch"), "{\"enabled\":false}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").isNotEmpty());
        mvc.perform(json(post(BASE + "/policies"), "{\"egressClientId\":2,\"enabled\":true}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").isNotEmpty());
        mvc.perform(delete(BASE + "/policies/10"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").isNotEmpty());
        verify(switchRepository, never()).save(any());
        verify(policyRepository, never()).save(any());
        verify(policyRepository, never()).delete(any());
        verify(peerSignalService, never()).pushTenantEgress(any());
    }

    @Test
    void anUnknownEgressClientIsNotFound() throws Exception {
        mvc.perform(json(post(BASE + "/policies"), "{\"egressClientId\":999,\"enabled\":true}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("client not found: 999"));
        verify(policyRepository, never()).save(any());
    }

    @Test
    void deletingAnUnknownPolicyIsNotFound() throws Exception {
        mvc.perform(delete(BASE + "/policies/12345"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("egress policy not found: 12345"));
        verify(policyRepository, never()).delete(any());
        verify(peerSignalService, never()).pushTenantEgress(any());
    }

    /**
     * Beyond the vector, which is written in JSON integers: bound as integers, the request reader
     * would turn each of these into port 443 (or 100) and store a range nobody wrote.
     */
    @Test
    void portBoundsThatAreNotJsonIntegersAreRefused() throws Exception {
        for (String pair : new String[]{"[443.5,443]", "[443.0,443]", "[1e2,443]", "[\"443\",443]", "[true,1]",
                "[null,443]", "[443,443,443]", "[4294967296,4294967296]"}) {
            String body = "{\"egressClientId\":2,\"destinationRules\":[{\"cidr\":\"10.0.0.0/8\","
                    + "\"protocols\":[\"tcp\"],\"portRanges\":[" + pair + "]}]}";
            mvc.perform(json(post(BASE + "/policies"), body))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").isNotEmpty());
        }
        verify(policyRepository, never()).save(any());
    }

    private void actAs(boolean admin) {
        when(contextResolver.resolve(any())).thenReturn(
                new ManagementContext(new TenantContext(TENANT), admin ? "admin" : "member", admin));
    }

    private static String policyBody(JsonNode vectorCase) {
        ObjectNode body = JSON.createObjectNode();
        body.put("egressClientId", EGRESS_ID);
        body.set("destinationRules", vectorCase.path("destinationRules"));
        return body.toString();
    }

    private static String domainPolicyBody(JsonNode vectorCase) {
        ObjectNode body = JSON.createObjectNode();
        body.put("egressClientId", EGRESS_ID);
        body.set("domainRules", vectorCase.path("domainRules"));
        return body.toString();
    }

    private static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder request, String body) {
        return request.contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static JsonNode readVector() throws IOException {
        return readVector("peer-egress-management-v1.json");
    }

    private static JsonNode readVector(String name) throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/" + name);
            if (Files.isRegularFile(candidate)) {
                return JSON.readTree(Files.readString(candidate));
            }
        }
        throw new IllegalStateException("cannot locate " + name);
    }
}
