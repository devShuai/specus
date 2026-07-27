package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.HttpMediaCapture;
import com.theshuai.tunnelserver.management.service.HttpMediaCaptureService;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackService;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackTicketService;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackTicketService.ResolvedTicket;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PublicHttpMediaPlaybackResourceTests {

    @Test
    void returnsTheSelectedCachedBlockForAnInitialRequestWithoutRange() throws Exception {
        HttpMediaPlaybackTicketService ticketService =
                mock(HttpMediaPlaybackTicketService.class);
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService playbackService = mock(HttpMediaPlaybackService.class);
        PublicHttpMediaPlaybackResource resource = new PublicHttpMediaPlaybackResource(
                ticketService, captureService, playbackService);
        HttpMediaCapture capture = new HttpMediaCapture();
        capture.setId(23L);
        capture.setClientName("client-a");
        capture.setRoute("jellyfin");
        capture.setSourceUrl("/Videos/movie/stream.mp4");
        when(ticketService.resolve("ticket")).thenReturn(
                new ResolvedTicket(
                        "ticket", capture, Instant.now().plusSeconds(60), false));
        when(playbackService.plan(capture, null)).thenReturn(
                new HttpMediaPlaybackService.PlaybackPlan(
                        capture,
                        "video/mp4",
                        null,
                        "etag",
                        300,
                        100,
                        149,
                        true,
                        List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/play");
        MockHttpServletResponse response = new MockHttpServletResponse();

        resource.play("ticket", request, response);

        assertThat(response.getStatus()).isEqualTo(206);
        assertThat(response.getHeader(HttpHeaders.CONTENT_RANGE))
                .isEqualTo("bytes 100-149/300");
        assertThat(response.getContentLengthLong()).isEqualTo(50);
    }

    @Test
    void returnsRangeMissWithoutFallingBackToOriginalTunnelRoute() throws Exception {
        HttpMediaPlaybackTicketService ticketService =
                mock(HttpMediaPlaybackTicketService.class);
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService playbackService = mock(HttpMediaPlaybackService.class);
        PublicHttpMediaPlaybackResource resource = new PublicHttpMediaPlaybackResource(
                ticketService, captureService, playbackService);
        HttpMediaCapture capture = new HttpMediaCapture();
        capture.setId(23L);
        capture.setClientName("client-a");
        capture.setRoute("jellyfin");
        capture.setSourceUrl("/Videos/movie/stream.mp4?ApiKey=secret");
        when(ticketService.resolve("ticket")).thenReturn(
                new ResolvedTicket(
                        "ticket", capture, Instant.now().plusSeconds(60), false));
        when(playbackService.plan(capture, "bytes=16777216-25165823"))
                .thenThrow(new HttpMediaPlaybackService.MediaRangeException(
                        "采集数据存在空洞，缺少字节 16777216", 3_197_229_691L));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/play");
        request.addHeader(HttpHeaders.RANGE, "bytes=16777216-25165823");
        MockHttpServletResponse response = new MockHttpServletResponse();

        resource.play("ticket", request, response);

        assertThat(response.getStatus()).isEqualTo(416);
        assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
        assertThat(response.getHeader(HttpHeaders.CONTENT_RANGE))
                .isEqualTo("bytes */3197229691");
        assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL))
                .isEqualTo("private, no-store");
        assertThat(response.getContentAsString()).contains("缺少字节 16777216");
    }

    @Test
    void redirectsMissingRangeWhenOptionalBackfillIsEnabled() throws Exception {
        HttpMediaPlaybackTicketService ticketService =
                mock(HttpMediaPlaybackTicketService.class);
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService playbackService = mock(HttpMediaPlaybackService.class);
        PublicHttpMediaPlaybackResource resource = new PublicHttpMediaPlaybackResource(
                ticketService, captureService, playbackService);
        HttpMediaCapture capture = new HttpMediaCapture();
        capture.setId(23L);
        capture.setClientName("client-a");
        capture.setRoute("jellyfin");
        capture.setSourceUrl("/Videos/movie/stream.mp4?ApiKey=secret");
        when(ticketService.resolve("ticket")).thenReturn(
                new ResolvedTicket(
                        "ticket", capture, Instant.now().plusSeconds(60), true));
        when(playbackService.plan(capture, "bytes=16777216-25165823"))
                .thenThrow(new HttpMediaPlaybackService.MediaRangeException(
                        "请求位置尚未缓存，缺少字节 16777216", 3_197_229_691L));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/play");
        request.addHeader(HttpHeaders.RANGE, "bytes=16777216-25165823");
        MockHttpServletResponse response = new MockHttpServletResponse();

        resource.play("ticket", request, response);

        assertThat(response.getStatus()).isEqualTo(307);
        assertThat(response.getHeader(HttpHeaders.LOCATION))
                .isEqualTo("/http/client-a/jellyfin/Videos/movie/stream.mp4?ApiKey=secret");
        assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL))
                .isEqualTo("private, no-store");
    }

    @Test
    void returnsNotFoundForUncapturedManifestAsset() throws Exception {
        HttpMediaPlaybackTicketService ticketService =
                mock(HttpMediaPlaybackTicketService.class);
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService playbackService = mock(HttpMediaPlaybackService.class);
        PublicHttpMediaPlaybackResource resource = new PublicHttpMediaPlaybackResource(
                ticketService, captureService, playbackService);
        HttpMediaCapture manifest = new HttpMediaCapture();
        manifest.setId(7L);
        manifest.setClientName("client-a");
        manifest.setRoute("jellyfin");
        when(ticketService.resolve("ticket")).thenReturn(
                new ResolvedTicket(
                        "ticket", manifest, Instant.now().plusSeconds(60), false));
        when(captureService.latestForSource(manifest, "/hls/segment-8.ts"))
                .thenThrow(new IllegalArgumentException("尚未采集"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/asset");
        MockHttpServletResponse response = new MockHttpServletResponse();

        resource.asset("ticket", "/hls/segment-8.ts", request, response);

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
        assertThat(response.getContentAsString()).contains("尚未缓存");
    }

    @Test
    void redirectsUncapturedManifestAssetWhenOptionalBackfillIsEnabled() throws Exception {
        HttpMediaPlaybackTicketService ticketService =
                mock(HttpMediaPlaybackTicketService.class);
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService playbackService = mock(HttpMediaPlaybackService.class);
        PublicHttpMediaPlaybackResource resource = new PublicHttpMediaPlaybackResource(
                ticketService, captureService, playbackService);
        HttpMediaCapture manifest = new HttpMediaCapture();
        manifest.setId(7L);
        manifest.setClientName("client-a");
        manifest.setRoute("jellyfin");
        when(ticketService.resolve("ticket")).thenReturn(
                new ResolvedTicket(
                        "ticket", manifest, Instant.now().plusSeconds(60), true));
        when(captureService.latestForSource(manifest, "/hls/segment-8.ts"))
                .thenThrow(new IllegalArgumentException("尚未采集"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/asset");
        MockHttpServletResponse response = new MockHttpServletResponse();

        resource.asset("ticket", "/hls/segment-8.ts", request, response);

        assertThat(response.getStatus()).isEqualTo(307);
        assertThat(response.getHeader(HttpHeaders.LOCATION))
                .isEqualTo("/http/client-a/jellyfin/hls/segment-8.ts");
    }
}
