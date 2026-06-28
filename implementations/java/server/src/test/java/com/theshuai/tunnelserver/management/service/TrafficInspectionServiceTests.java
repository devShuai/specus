package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchange;
import com.theshuai.tunnelserver.management.model.TcpTrafficFrame;
import com.theshuai.tunnelserver.management.model.TunnelMapping;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.repository.TunnelMappingRepository;
import com.theshuai.tunnelserver.management.storage.HttpTrafficExchangeStore;
import com.theshuai.tunnelserver.management.storage.TcpTrafficFrameStore;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class TrafficInspectionServiceTests {

    @Test
    void httpBodiesAreStoredWithoutPreviewTruncation() {
        ClientAccountService clientAccountService = mock(ClientAccountService.class);
        TunnelMappingRepository tunnelMappingRepository = mock(TunnelMappingRepository.class);
        HttpRouteMappingRepository httpRouteMappingRepository = mock(HttpRouteMappingRepository.class);
        HttpTrafficExchangeStore httpTrafficExchangeStore = mock(HttpTrafficExchangeStore.class);
        TcpTrafficFrameStore tcpTrafficFrameStore = mock(TcpTrafficFrameStore.class);

        ClientAccount account = new ClientAccount();
        account.setId(7L);
        account.setTenantId("tenant-a");
        account.setClientName("Demo");
        when(clientAccountService.findClientByName("Demo")).thenReturn(Optional.of(account));
        when(httpRouteMappingRepository.findByTenantIdAndClientIdAndRoute(eq("tenant-a"), eq(7L), eq("api")))
                .thenReturn(Optional.of(httpRouteMapping()));

        TrafficInspectionService service = new TrafficInspectionService(
                clientAccountService,
                tunnelMappingRepository,
                httpRouteMappingRepository,
                httpTrafficExchangeStore,
                tcpTrafficFrameStore,
                true,
                8,
                8192,
                1048576,
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
        ArgumentCaptor<List<HttpTrafficExchange>> captor = ArgumentCaptor.forClass((Class) List.class);
        verify(httpTrafficExchangeStore).saveAll(captor.capture());
        List<HttpTrafficExchange> saved = captor.getValue();

        assertThat(saved).hasSize(1);
        HttpTrafficExchange exchange = saved.get(0);
        assertThat(exchange.getRequestPreviewText()).isEqualTo(requestBody);
        assertThat(exchange.isRequestTruncated()).isFalse();
        assertThat(exchange.getResponsePreviewText()).isEqualTo(responseBody);
        assertThat(exchange.isResponseTruncated()).isFalse();
    }

    @Test
    void httpDetailCaptureIsDisabledByDefaultForChannel() {
        ClientAccountService clientAccountService = mock(ClientAccountService.class);
        TunnelMappingRepository tunnelMappingRepository = mock(TunnelMappingRepository.class);
        HttpRouteMappingRepository httpRouteMappingRepository = mock(HttpRouteMappingRepository.class);
        HttpTrafficExchangeStore httpTrafficExchangeStore = mock(HttpTrafficExchangeStore.class);
        TcpTrafficFrameStore tcpTrafficFrameStore = mock(TcpTrafficFrameStore.class);

        ClientAccount account = new ClientAccount();
        account.setId(7L);
        account.setTenantId("tenant-a");
        account.setClientName("Demo");
        HttpRouteMapping mapping = httpRouteMapping();
        mapping.setDetailCaptureEnabled(false);
        when(clientAccountService.findClientByName("Demo")).thenReturn(Optional.of(account));
        when(httpRouteMappingRepository.findByTenantIdAndClientIdAndRoute(eq("tenant-a"), eq(7L), eq("api")))
                .thenReturn(Optional.of(mapping));

        TrafficInspectionService service = new TrafficInspectionService(
                clientAccountService,
                tunnelMappingRepository,
                httpRouteMappingRepository,
                httpTrafficExchangeStore,
                tcpTrafficFrameStore,
                true,
                8,
                8192,
                1048576,
                10,
                10
        );

        service.recordHttpExchange(
                "Demo",
                "api",
                "GET",
                "/health",
                null,
                List.of(),
                new byte[0],
                200,
                List.of(),
                new byte[0],
                System.currentTimeMillis(),
                "127.0.0.1:60000",
                null
        );
        service.flush();

        verifyNoInteractions(httpTrafficExchangeStore);
    }

    @Test
    void gzipHttpBodyIsDecodedBeforeStored() throws IOException {
        ClientAccountService clientAccountService = mock(ClientAccountService.class);
        TunnelMappingRepository tunnelMappingRepository = mock(TunnelMappingRepository.class);
        HttpRouteMappingRepository httpRouteMappingRepository = mock(HttpRouteMappingRepository.class);
        HttpTrafficExchangeStore httpTrafficExchangeStore = mock(HttpTrafficExchangeStore.class);
        TcpTrafficFrameStore tcpTrafficFrameStore = mock(TcpTrafficFrameStore.class);

        ClientAccount account = new ClientAccount();
        account.setId(7L);
        account.setTenantId("tenant-a");
        account.setClientName("Demo");
        when(clientAccountService.findClientByName("Demo")).thenReturn(Optional.of(account));
        when(httpRouteMappingRepository.findByTenantIdAndClientIdAndRoute(eq("tenant-a"), eq(7L), eq("api")))
                .thenReturn(Optional.of(httpRouteMapping()));

        TrafficInspectionService service = new TrafficInspectionService(
                clientAccountService,
                tunnelMappingRepository,
                httpRouteMappingRepository,
                httpTrafficExchangeStore,
                tcpTrafficFrameStore,
                true,
                8,
                8192,
                1048576,
                10,
                10
        );
        String responseBody = "{\"ok\":true,\"message\":\"gzip response\"}";
        byte[] gzipBytes = gzip(responseBody.getBytes(StandardCharsets.UTF_8));

        service.recordHttpExchange(
                "Demo",
                "api",
                "GET",
                "/gzip",
                null,
                List.of(),
                new byte[0],
                200,
                List.of("Content-Type: application/json", "Content-Encoding: gzip"),
                gzipBytes,
                System.currentTimeMillis(),
                "127.0.0.1:60000",
                null
        );
        service.flush();

        @SuppressWarnings({"rawtypes", "unchecked"})
        ArgumentCaptor<List<HttpTrafficExchange>> captor = ArgumentCaptor.forClass((Class) List.class);
        verify(httpTrafficExchangeStore).saveAll(captor.capture());
        List<HttpTrafficExchange> saved = captor.getValue();

        assertThat(saved).hasSize(1);
        HttpTrafficExchange exchange = saved.get(0);
        assertThat(exchange.getResponseBytes()).isEqualTo(gzipBytes.length);
        assertThat(exchange.getResponseBodyType()).isEqualTo("json");
        assertThat(exchange.getResponseHeaders()).contains("Content-Encoding: gzip");
        assertThat(exchange.getResponsePreviewText()).isEqualTo(responseBody);
        assertThat(exchange.isResponseTruncated()).isFalse();
    }

    @Test
    void binaryHttpBodyIsStoredAsDataUrl() {
        ClientAccountService clientAccountService = mock(ClientAccountService.class);
        TunnelMappingRepository tunnelMappingRepository = mock(TunnelMappingRepository.class);
        HttpRouteMappingRepository httpRouteMappingRepository = mock(HttpRouteMappingRepository.class);
        HttpTrafficExchangeStore httpTrafficExchangeStore = mock(HttpTrafficExchangeStore.class);
        TcpTrafficFrameStore tcpTrafficFrameStore = mock(TcpTrafficFrameStore.class);

        ClientAccount account = new ClientAccount();
        account.setId(7L);
        account.setTenantId("tenant-a");
        account.setClientName("Demo");
        when(clientAccountService.findClientByName("Demo")).thenReturn(Optional.of(account));
        when(httpRouteMappingRepository.findByTenantIdAndClientIdAndRoute(eq("tenant-a"), eq(7L), eq("api")))
                .thenReturn(Optional.of(httpRouteMapping()));

        TrafficInspectionService service = new TrafficInspectionService(
                clientAccountService,
                tunnelMappingRepository,
                httpRouteMappingRepository,
                httpTrafficExchangeStore,
                tcpTrafficFrameStore,
                true,
                8,
                8192,
                1048576,
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
        ArgumentCaptor<List<HttpTrafficExchange>> captor = ArgumentCaptor.forClass((Class) List.class);
        verify(httpTrafficExchangeStore).saveAll(captor.capture());
        List<HttpTrafficExchange> saved = captor.getValue();

        assertThat(saved).hasSize(1);
        HttpTrafficExchange exchange = saved.get(0);
        assertThat(exchange.getResponseBodyType()).isEqualTo("image");
        assertThat(exchange.getResponsePreviewText())
                .isEqualTo("data:image/png;base64," + Base64.getEncoder().encodeToString(pngBytes));
        assertThat(exchange.isResponseTruncated()).isFalse();
    }

    @Test
    void tcpPayloadIsStoredInFullWithShortPreviewOnly() {
        ClientAccountService clientAccountService = mock(ClientAccountService.class);
        TunnelMappingRepository tunnelMappingRepository = mock(TunnelMappingRepository.class);
        HttpRouteMappingRepository httpRouteMappingRepository = mock(HttpRouteMappingRepository.class);
        HttpTrafficExchangeStore httpTrafficExchangeStore = mock(HttpTrafficExchangeStore.class);
        TcpTrafficFrameStore tcpTrafficFrameStore = mock(TcpTrafficFrameStore.class);

        ClientAccount account = new ClientAccount();
        account.setId(7L);
        account.setTenantId("tenant-a");
        account.setClientName("Demo");
        when(clientAccountService.findClientByName("Demo")).thenReturn(Optional.of(account));
        when(tunnelMappingRepository.findByListenPort(8080)).thenReturn(Optional.of(tunnelMapping()));

        TrafficInspectionService service = new TrafficInspectionService(
                clientAccountService,
                tunnelMappingRepository,
                httpRouteMappingRepository,
                httpTrafficExchangeStore,
                tcpTrafficFrameStore,
                true,
                4,
                8192,
                1048576,
                10,
                10
        );
        byte[] payload = "hello-tcp-payload".getBytes(StandardCharsets.UTF_8);

        service.recordTcpFrame("Demo", 8080, "channel-1", "PUBLIC_TO_CLIENT",
                "127.0.0.1", 60000, "127.0.0.1", 8080, payload);
        service.flush();

        @SuppressWarnings({"rawtypes", "unchecked"})
        ArgumentCaptor<List<TcpTrafficFrame>> captor = ArgumentCaptor.forClass((Class) List.class);
        verify(tcpTrafficFrameStore).saveAll(captor.capture());
        List<TcpTrafficFrame> saved = captor.getValue();

        assertThat(saved).hasSize(1);
        TcpTrafficFrame frame = saved.get(0);
        assertThat(frame.getPayloadBytes()).isEqualTo(payload.length);
        assertThat(frame.getSourceAddress()).isEqualTo("127.0.0.1");
        assertThat(frame.getSourcePort()).isEqualTo(60000);
        assertThat(frame.getDestinationAddress()).isEqualTo("127.0.0.1");
        assertThat(frame.getDestinationPort()).isEqualTo(8080);
        assertThat(frame.getStreamOffset()).isZero();
        assertThat(frame.getStreamEndOffset()).isEqualTo(payload.length);
        assertThat(frame.getFrameIndex()).isZero();
        assertThat(frame.getPayloadData()).containsExactly(payload);
        assertThat(frame.getPayloadPreviewText()).isEqualTo("hell");
        assertThat(frame.isTruncated()).isFalse();
    }

    private static byte[] gzip(byte[] data) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(output)) {
            gzip.write(data);
        }
        return output.toByteArray();
    }

    private static HttpRouteMapping httpRouteMapping() {
        HttpRouteMapping mapping = new HttpRouteMapping();
        mapping.setId(99L);
        mapping.setTenantId("tenant-a");
        mapping.setClientId(7L);
        mapping.setClientName("Demo");
        mapping.setRoute("api");
        mapping.setTargetBaseUrl("http://127.0.0.1:8080");
        mapping.setEnabled(true);
        mapping.setDetailCaptureEnabled(true);
        return mapping;
    }

    private static TunnelMapping tunnelMapping() {
        TunnelMapping mapping = new TunnelMapping();
        mapping.setId(100L);
        mapping.setTenantId("tenant-a");
        mapping.setClientId(7L);
        mapping.setClientName("Demo");
        mapping.setListenPort(8080);
        mapping.setTargetAddress("127.0.0.1");
        mapping.setTargetPort(80);
        mapping.setEnabled(true);
        mapping.setDetailCaptureEnabled(true);
        return mapping;
    }
}
