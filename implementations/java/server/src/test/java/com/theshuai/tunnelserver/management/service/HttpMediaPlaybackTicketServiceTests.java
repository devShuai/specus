package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.config.MediaCaptureProperties;
import com.theshuai.tunnelserver.management.model.HttpMediaCapture;
import com.theshuai.tunnelserver.management.repository.HttpMediaCaptureRepository;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HttpMediaPlaybackTicketServiceTests {

    @Test
    void allowsSparseProgressiveCaptureToUseCachedRangePlayback() {
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService playbackService = mock(HttpMediaPlaybackService.class);
        HttpMediaPlaybackTicketService ticketService = new HttpMediaPlaybackTicketService(
                captureService,
                playbackService,
                mock(HttpMediaCaptureRepository.class),
                mock(MediaCaptureProperties.class));
        ManagementContext context = mock(ManagementContext.class);
        HttpMediaCapture capture = new HttpMediaCapture();
        capture.setId(42L);
        capture.setTenantId("tenant-a");
        capture.setState(HttpMediaCaptureService.STATE_COMPLETE);
        capture.setMediaKind(HttpMediaManifestSupport.PROGRESSIVE);
        capture.setCapturedBytes(512);
        when(captureService.requireAccessible(context, 42L)).thenReturn(capture);
        when(playbackService.availability(capture)).thenReturn(
                new HttpMediaPlaybackService.PlaybackAvailability(
                        false, 1024, "采集数据不完整，缺少字节 512"));
        HttpMediaPlaybackTicketService.PlaybackTicketView ticket =
                ticketService.create(context, 42L);

        assertThat(ticket.playUrl()).startsWith("/api/public/media-playback/");
        assertThat(ticket.playUrl()).endsWith("/play");
        assertThat(ticket.backfillMissing()).isFalse();
    }

    @Test
    void recordsOptionalBackfillInPlaybackTicket() {
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService playbackService = mock(HttpMediaPlaybackService.class);
        HttpMediaCaptureRepository captureRepository = mock(HttpMediaCaptureRepository.class);
        HttpMediaPlaybackTicketService ticketService = new HttpMediaPlaybackTicketService(
                captureService,
                playbackService,
                captureRepository,
                mock(MediaCaptureProperties.class));
        ManagementContext context = mock(ManagementContext.class);
        HttpMediaCapture capture = new HttpMediaCapture();
        capture.setId(43L);
        capture.setTenantId("tenant-a");
        capture.setState(HttpMediaCaptureService.STATE_COMPLETE);
        capture.setMediaKind(HttpMediaManifestSupport.PROGRESSIVE);
        capture.setCapturedBytes(512);
        when(captureService.requireAccessible(context, 43L)).thenReturn(capture);
        when(playbackService.availability(capture)).thenReturn(
                new HttpMediaPlaybackService.PlaybackAvailability(
                        false, 1024, "采集数据不完整，缺少字节 512"));
        when(captureRepository.findByIdAndTenantId(43L, "tenant-a"))
                .thenReturn(Optional.of(capture));

        HttpMediaPlaybackTicketService.PlaybackTicketView ticket =
                ticketService.create(context, 43L, true);

        assertThat(ticket.backfillMissing()).isTrue();
        assertThat(ticketService.resolve(ticket.ticket()).backfillMissing()).isTrue();
    }
}
