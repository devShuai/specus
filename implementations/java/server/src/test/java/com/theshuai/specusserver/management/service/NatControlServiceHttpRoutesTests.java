package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** NAT_CONTROL always carries the full HTTP route list, so a client drops routes that were deleted. */
class NatControlServiceHttpRoutesTests {
    private final SpecusMappingRepository specusMappingRepository = mock(SpecusMappingRepository.class);
    private final HttpRouteMappingRepository httpRouteMappingRepository = mock(HttpRouteMappingRepository.class);
    private final NatControlService service = new NatControlService(
            specusMappingRepository, httpRouteMappingRepository, mock(ClientAccountRepository.class),
            mock(WorkbenchReferences.class), 7010, "");

    private final ClientAccount account = new ClientAccount();
    private final EmbeddedChannel control = new EmbeddedChannel();

    @BeforeEach
    void setUp() {
        account.setId(42L);
        account.setTenantId("tenant-a");
        account.setClientName("nat-control-" + UUID.randomUUID());
        when(specusMappingRepository.findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc("tenant-a", 42L))
                .thenReturn(List.of());
        SessionUtil.bindControlSession(new Session(account.getClientName()), control);
    }

    @AfterEach
    void tearDown() {
        control.finishAndReleaseAll();
    }

    @Test
    void deletingTheLastRoutePushesAnExplicitEmptyList() throws Exception {
        HttpRouteMapping route = new HttpRouteMapping();
        route.setRoute("web");
        route.setTargetBaseUrl("http://127.0.0.1:8080");
        when(httpRouteMappingRepository.findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc("tenant-a", 42L))
                .thenReturn(List.of(route));
        service.pushSnapshotIfOnline(account);
        JsonNode withRoute = lastPushedHttpRoutes();
        assertThat(withRoute).hasSize(1);
        assertThat(withRoute.get(0).get("route").asText()).isEqualTo("web");

        // The route was deleted, so the client has no route row left at all.
        when(httpRouteMappingRepository.findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc("tenant-a", 42L))
                .thenReturn(List.of());
        service.pushSnapshotIfOnline(account);

        JsonNode afterDelete = lastPushedHttpRoutes();
        assertThat(afterDelete).isNotNull();
        assertThat(afterDelete.isArray()).isTrue();
        assertThat(afterDelete).isEmpty();
    }

    /** The httpSpecusConfigList of the last NAT_CONTROL written since the previous call, or null. */
    private JsonNode lastPushedHttpRoutes() throws Exception {
        JsonNode last = null;
        Object outbound;
        while ((outbound = control.readOutbound()) != null) {
            MessageResponsePacket packet = (MessageResponsePacket) outbound;
            assertThat(packet.getMessageType()).isEqualTo(MessageType.NAT_CONTROL);
            last = new ObjectMapper().readTree(packet.getMessage());
        }
        assertThat(last).as("a NAT_CONTROL push").isNotNull();
        return last.get("httpSpecusConfigList");
    }
}
