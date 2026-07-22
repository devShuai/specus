package com.theshuai.tunnelserver.http;

import com.theshuai.tunnelserver.management.service.TrafficInspectionService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class HttpTunnelBodyLimitFilterTests {

    private final TrafficInspectionService trafficInspectionService = mock(TrafficInspectionService.class);
    private final HttpTunnelBodyLimitFilter filter = new HttpTunnelBodyLimitFilter(10, trafficInspectionService);

    @Test
    void recordsExchangeWhenContentLengthExceedsLimit() throws Exception {
        byte[] content = "0123456789abcdefghij".getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/http/alice/web/api/data");
        request.setQueryString("a=1");
        request.setContent(content);
        request.addHeader("X-Test", "foo");
        request.setRemoteAddr("203.0.113.7");
        request.setRemotePort(54321);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentAsString()).isEqualTo("HTTP 请求体超过限制");
        assertThat(chain.getRequest()).isNull();

        ArgumentCaptor<byte[]> requestBody = ArgumentCaptor.forClass(byte[].class);
        ArgumentCaptor<byte[]> responseBody = ArgumentCaptor.forClass(byte[].class);
        verify(trafficInspectionService).recordHttpExchange(
                eq("alice"), eq("web"), eq("POST"), eq("/api/data"), eq("a=1"),
                argThat(headers -> headers.contains("X-Test:foo")
                        && headers.stream().noneMatch(header -> header.startsWith("Content-Length"))),
                requestBody.capture(), eq(413),
                eq(List.of("Content-Type:text/plain;charset=UTF-8")), responseBody.capture(),
                anyLong(), eq("203.0.113.7:54321"), eq("HTTP 请求体超过限制"));
        assertThat(requestBody.getValue()).isEqualTo(Arrays.copyOf(content, 11));
        assertThat(responseBody.getValue()).isEqualTo("HTTP 请求体超过限制".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void passesThroughWhenContentLengthWithinLimit() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/http/alice/web/api/data");
        request.setContent("small".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        verifyNoInteractions(trafficInspectionService);
    }

    @Test
    void ignoresNonHttpTunnelRequests() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/other");
        request.setContent("0123456789abcdefghij".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        verifyNoInteractions(trafficInspectionService);
    }
}
