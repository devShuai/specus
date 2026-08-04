package com.theshuai.specusserver.http;

import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.management.service.HttpMediaCaptureService;
import com.theshuai.specusserver.management.service.TrafficInspectionService;
import com.theshuai.specusserver.management.service.TrafficUsageService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HttpSpecusControllerAuthenticationTests {
    private final TrafficUsageService trafficUsageService = mock(TrafficUsageService.class);
    private final TrafficInspectionService trafficInspectionService = mock(TrafficInspectionService.class);
    private final HttpMediaCaptureService mediaCaptureService = mock(HttpMediaCaptureService.class);
    private final ResponseRewriter responseRewriter = mock(ResponseRewriter.class);
    private final ClientAccountService clientAccountService = mock(ClientAccountService.class);
    private final HttpRouteMappingRepository routeRepository = mock(HttpRouteMappingRepository.class);
    private final HttpRouteAuthenticationService authenticationService = mock(HttpRouteAuthenticationService.class);
    private final HttpSpecusController controller = new HttpSpecusController(
            trafficUsageService,
            trafficInspectionService,
            mediaCaptureService,
            responseRewriter,
            clientAccountService,
            routeRepository,
            authenticationService,
            1_000,
            1_024,
            0);

    @Test
    void missingCredentialsReturnBasicChallengeBeforeOpeningTunnel() throws Exception {
        String clientName = "auth-test-" + UUID.randomUUID();
        when(authenticationService.authorize(clientName, "private", "Basic invalid"))
                .thenReturn(new HttpRouteAuthenticationService.Decision(
                        HttpRouteAuthenticationService.Outcome.UNAUTHORIZED));
        MockHttpServletRequest request = request(clientName);
        request.addHeader(HttpHeaders.AUTHORIZATION, "Basic invalid");
        MockHttpServletResponse response = new MockHttpServletResponse();

        controller.forward(clientName, "private", request, response);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo(HttpRouteAuthenticationService.BASIC_CHALLENGE);
        assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
        assertThat(response.getContentAsString(StandardCharsets.UTF_8)).isEqualTo("需要 HTTP Basic 认证");
        assertThat(capturedRequestHeaders(clientName, 401)).isEmpty();
    }

    @Test
    void authenticationLookupFailureReturnsNonCacheableServiceUnavailable() throws Exception {
        String clientName = "auth-test-" + UUID.randomUUID();
        when(authenticationService.authorize(clientName, "private", null))
                .thenReturn(new HttpRouteAuthenticationService.Decision(
                        HttpRouteAuthenticationService.Outcome.UNAVAILABLE));
        MockHttpServletResponse response = new MockHttpServletResponse();

        controller.forward(clientName, "private", request(clientName), response);

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
        assertThat(response.getContentAsString(StandardCharsets.UTF_8)).isEqualTo("HTTP 路由认证暂不可用");
        assertThat(capturedRequestHeaders(clientName, 503)).isEmpty();
    }

    @Test
    void authenticatedRouteDoesNotForwardOrCaptureConsumedAuthorization() throws Exception {
        String clientName = "auth-test-" + UUID.randomUUID();
        when(authenticationService.authorize(clientName, "private", "Basic valid"))
                .thenReturn(new HttpRouteAuthenticationService.Decision(
                        HttpRouteAuthenticationService.Outcome.AUTHENTICATED));
        when(trafficInspectionService.shouldCaptureHttpExchange(clientName, "private")).thenReturn(true);
        MockHttpServletRequest request = request(clientName);
        request.addHeader(HttpHeaders.AUTHORIZATION, "Basic valid");
        request.addHeader("X-Test", "kept");
        MockHttpServletResponse response = new MockHttpServletResponse();

        controller.forward(clientName, "private", request, response);

        assertThat(response.getStatus()).isEqualTo(502);
        assertThat(capturedRequestHeaders(clientName, 502))
                .contains("X-Test:kept")
                .noneMatch(header -> header.regionMatches(true, 0, "Authorization:", 0, 14));
    }

    @Test
    void protectedRouteStripsAuthorizationTrailerWhilePublicRoutePreservesIt() {
        Map<String, String> trailers = new LinkedHashMap<>();
        trailers.put("X-Checksum", "kept");
        trailers.put("aUtHoRiZaTiOn", "Basic consumed");

        assertThat(HttpSpecusController.flattenTrailers(trailers, true))
                .containsExactly("X-Checksum:kept");
        assertThat(HttpSpecusController.flattenTrailers(trailers, false))
                .containsExactly("X-Checksum:kept", "aUtHoRiZaTiOn:Basic consumed");
    }

    @SuppressWarnings("unchecked")
    private List<String> capturedRequestHeaders(String clientName, int status) {
        ArgumentCaptor<List<String>> headers = ArgumentCaptor.forClass(List.class);
        verify(trafficInspectionService).recordHttpExchange(
                eq(clientName), eq("private"), eq("GET"), eq("/"), eq(null), headers.capture(),
                any(byte[].class), eq(0L), eq(status), any(), any(byte[].class), eq(0L),
                anyLong(), any(), any());
        return headers.getValue();
    }

    private MockHttpServletRequest request(String clientName) {
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET", "/http/" + clientName + "/private/");
        request.setRemoteAddr("203.0.113.10");
        request.setRemotePort(45678);
        return request;
    }
}
