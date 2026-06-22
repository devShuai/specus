package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchange;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.repository.HttpTrafficExchangeRepository;
import com.theshuai.tunnelserver.management.repository.TcpTrafficFrameRepository;
import com.theshuai.tunnelserver.management.repository.TunnelMappingRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.StreamSupport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TrafficInspectionServiceTests {

    @Test
    void httpBodiesAreStoredWithoutPreviewTruncation() {
        ClientAccountService clientAccountService = mock(ClientAccountService.class);
        TunnelMappingRepository tunnelMappingRepository = mock(TunnelMappingRepository.class);
        HttpRouteMappingRepository httpRouteMappingRepository = mock(HttpRouteMappingRepository.class);
        HttpTrafficExchangeRepository httpTrafficExchangeRepository = mock(HttpTrafficExchangeRepository.class);
        TcpTrafficFrameRepository tcpTrafficFrameRepository = mock(TcpTrafficFrameRepository.class);

        ClientAccount account = new ClientAccount();
        account.setId(7L);
        account.setTenantId("tenant-a");
        account.setClientName("Demo");
        when(clientAccountService.findClientByName("Demo")).thenReturn(Optional.of(account));
        when(httpRouteMappingRepository.findByTenantIdAndClientIdAndRoute(eq("tenant-a"), eq(7L), eq("api")))
                .thenReturn(Optional.empty());

        TrafficInspectionService service = new TrafficInspectionService(
                clientAccountService,
                tunnelMappingRepository,
                httpRouteMappingRepository,
                httpTrafficExchangeRepository,
                tcpTrafficFrameRepository,
                true,
                8,
                8192,
                10,
                10
        );
        String requestBody = "0123456789abcdefghijklmnopqrstuvwxyz";
        String responseBody = "response-body-with-more-than-eight-bytes";

        service.recordHttpExchange(
                "Demo",
                "api",
                "POST",
                "/orders",
                null,
                List.of("Content-Type: text/plain"),
                requestBody.getBytes(StandardCharsets.UTF_8),
                200,
                List.of("Content-Type: text/plain"),
                responseBody.getBytes(StandardCharsets.UTF_8),
                System.currentTimeMillis(),
                "127.0.0.1:60000",
                null
        );
        service.flush();

        @SuppressWarnings({"rawtypes", "unchecked"})
        ArgumentCaptor<Iterable<HttpTrafficExchange>> captor = ArgumentCaptor.forClass((Class) Iterable.class);
        verify(httpTrafficExchangeRepository).saveAll(captor.capture());
        List<HttpTrafficExchange> saved = StreamSupport.stream(captor.getValue().spliterator(), false).toList();

        assertThat(saved).hasSize(1);
        HttpTrafficExchange exchange = saved.get(0);
        assertThat(exchange.getRequestPreviewText()).isEqualTo(requestBody);
        assertThat(exchange.isRequestTruncated()).isFalse();
        assertThat(exchange.getResponsePreviewText()).isEqualTo(responseBody);
        assertThat(exchange.isResponseTruncated()).isFalse();
    }

    @Test
    void binaryHttpBodyIsStoredAsDataUrl() {
        ClientAccountService clientAccountService = mock(ClientAccountService.class);
        TunnelMappingRepository tunnelMappingRepository = mock(TunnelMappingRepository.class);
        HttpRouteMappingRepository httpRouteMappingRepository = mock(HttpRouteMappingRepository.class);
        HttpTrafficExchangeRepository httpTrafficExchangeRepository = mock(HttpTrafficExchangeRepository.class);
        TcpTrafficFrameRepository tcpTrafficFrameRepository = mock(TcpTrafficFrameRepository.class);

        ClientAccount account = new ClientAccount();
        account.setId(7L);
        account.setTenantId("tenant-a");
        account.setClientName("Demo");
        when(clientAccountService.findClientByName("Demo")).thenReturn(Optional.of(account));
        when(httpRouteMappingRepository.findByTenantIdAndClientIdAndRoute(eq("tenant-a"), eq(7L), eq("api")))
                .thenReturn(Optional.empty());

        TrafficInspectionService service = new TrafficInspectionService(
                clientAccountService,
                tunnelMappingRepository,
                httpRouteMappingRepository,
                httpTrafficExchangeRepository,
                tcpTrafficFrameRepository,
                true,
                8,
                8192,
                10,
                10
        );
        byte[] pngBytes = new byte[] {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};

        service.recordHttpExchange(
                "Demo",
                "api",
                "GET",
                "/image.png",
                null,
                List.of(),
                new byte[0],
                200,
                List.of("Content-Type: image/png;charset=UTF-8"),
                pngBytes,
                System.currentTimeMillis(),
                "127.0.0.1:60000",
                null
        );
        service.flush();

        @SuppressWarnings({"rawtypes", "unchecked"})
        ArgumentCaptor<Iterable<HttpTrafficExchange>> captor = ArgumentCaptor.forClass((Class) Iterable.class);
        verify(httpTrafficExchangeRepository).saveAll(captor.capture());
        List<HttpTrafficExchange> saved = StreamSupport.stream(captor.getValue().spliterator(), false).toList();

        assertThat(saved).hasSize(1);
        HttpTrafficExchange exchange = saved.get(0);
        assertThat(exchange.getResponsePreviewText())
                .isEqualTo("data:image/png;base64," + Base64.getEncoder().encodeToString(pngBytes));
        assertThat(exchange.isResponseTruncated()).isFalse();
    }
}
