package com.theshuai.specusserver.http;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.socket.WebSocketHandler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class WebSocketSpecusHandshakeInterceptorAuthenticationTests {
    private final HttpRouteAuthenticationService authenticationService = mock(HttpRouteAuthenticationService.class);
    private final WebSocketSpecusHandshakeInterceptor interceptor =
            new WebSocketSpecusHandshakeInterceptor(authenticationService);
    private final WebSocketHandler handler = mock(WebSocketHandler.class);

    @Test
    void protectedHandshakeRejectsMissingCredentialsWithBasicChallenge() {
        when(authenticationService.authorize("client-a", "private", null))
                .thenReturn(new HttpRouteAuthenticationService.Decision(
                        HttpRouteAuthenticationService.Outcome.UNAUTHORIZED));
        MockHttpServletRequest servletRequest = request();
        ServerHttpResponse response = mock(ServerHttpResponse.class);
        HttpHeaders responseHeaders = new HttpHeaders();
        when(response.getHeaders()).thenReturn(responseHeaders);

        boolean accepted = interceptor.beforeHandshake(
                new ServletServerHttpRequest(servletRequest), response, handler, new HashMap<>());

        assertThat(accepted).isFalse();
        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
        assertThat(responseHeaders.getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo(HttpRouteAuthenticationService.BASIC_CHALLENGE);
        assertThat(responseHeaders.getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
    }

    @Test
    void authenticationLookupFailureRejectsHandshakeWithoutCaching() {
        when(authenticationService.authorize("client-a", "private", null))
                .thenReturn(new HttpRouteAuthenticationService.Decision(
                        HttpRouteAuthenticationService.Outcome.UNAVAILABLE));
        ServerHttpResponse response = mock(ServerHttpResponse.class);
        HttpHeaders responseHeaders = new HttpHeaders();
        when(response.getHeaders()).thenReturn(responseHeaders);

        boolean accepted = interceptor.beforeHandshake(
                new ServletServerHttpRequest(request()), response, handler, new HashMap<>());

        assertThat(accepted).isFalse();
        verify(response).setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(responseHeaders.getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
    }

    @Test
    void disabledRouteRejectsHandshakeWithoutCaching() {
        when(authenticationService.authorize("client-a", "private", null))
                .thenReturn(new HttpRouteAuthenticationService.Decision(
                        HttpRouteAuthenticationService.Outcome.NOT_FOUND));
        ServerHttpResponse response = mock(ServerHttpResponse.class);
        HttpHeaders responseHeaders = new HttpHeaders();
        when(response.getHeaders()).thenReturn(responseHeaders);

        boolean accepted = interceptor.beforeHandshake(
                new ServletServerHttpRequest(request()), response, handler, new HashMap<>());

        assertThat(accepted).isFalse();
        verify(response).setStatusCode(HttpStatus.NOT_FOUND);
        assertThat(responseHeaders.getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
    }

    @Test
    void encodedIdentitySegmentsAreDecodedButRelativePathStaysRaw() {
        when(authenticationService.authorize("Demo client", "private route", null))
                .thenReturn(new HttpRouteAuthenticationService.Decision(
                        HttpRouteAuthenticationService.Outcome.PUBLIC));
        MockHttpServletRequest servletRequest = new MockHttpServletRequest(
                "GET", "/http/Demo%20client/private%20route/socket%2Fraw");
        Map<String, Object> attributes = new HashMap<>();

        boolean accepted = interceptor.beforeHandshake(
                new ServletServerHttpRequest(servletRequest), mock(ServerHttpResponse.class),
                handler, attributes);

        assertThat(accepted).isTrue();
        verify(authenticationService).authorize("Demo client", "private route", null);
        assertThat(attributes.get(WebSocketSpecusHandler.ATTR_CLIENT_NAME)).isEqualTo("Demo client");
        assertThat(attributes.get(WebSocketSpecusHandler.ATTR_ROUTE)).isEqualTo("private route");
        assertThat(attributes.get(WebSocketSpecusHandler.ATTR_RELATIVE_PATH)).isEqualTo("/socket%2Fraw");
    }

    @Test
    @SuppressWarnings("unchecked")
    void protectedHandshakeConsumesAuthorizationBeforeForwardingMetadata() {
        when(authenticationService.authorize("client-a", "private", "Basic valid"))
                .thenReturn(new HttpRouteAuthenticationService.Decision(
                        HttpRouteAuthenticationService.Outcome.AUTHENTICATED));
        MockHttpServletRequest servletRequest = request();
        servletRequest.addHeader(HttpHeaders.AUTHORIZATION, "Basic valid");
        servletRequest.addHeader("X-Test", "kept");
        ServerHttpResponse response = mock(ServerHttpResponse.class);
        Map<String, Object> attributes = new HashMap<>();

        boolean accepted = interceptor.beforeHandshake(
                new ServletServerHttpRequest(servletRequest), response, handler, attributes);

        assertThat(accepted).isTrue();
        List<String> headers = (List<String>) attributes.get(WebSocketSpecusHandler.ATTR_HEADERS);
        assertThat(headers)
                .contains("X-Test:kept")
                .noneMatch(header -> header.regionMatches(true, 0, "Authorization:", 0, 14));
    }

    private MockHttpServletRequest request() {
        return new MockHttpServletRequest("GET", "/http/client-a/private/socket");
    }
}
