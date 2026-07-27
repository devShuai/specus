package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.HttpMediaCapture;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackService.MediaRangeException;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackService.PlaybackAvailability;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackService.PlaybackPlan;
import com.theshuai.tunnelserver.management.storage.media.RustFsMediaStorage;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HttpMediaPlaybackServiceTests {

    @Test
    void assemblesOneRangeAcrossMultipleRustFsObjects() {
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService service = new HttpMediaPlaybackService(
                captureService, mock(RustFsMediaStorage.class));
        HttpMediaCapture first = capture(1, 0, 99, 200, "part-a");
        HttpMediaCapture second = capture(2, 100, 199, 200, "part-b");
        when(captureService.completeResourceCaptures(second)).thenReturn(List.of(second, first));

        PlaybackPlan plan = service.plan(second, "bytes=50-149");

        assertThat(plan.partial()).isTrue();
        assertThat(plan.totalBytes()).isEqualTo(200);
        assertThat(plan.contentLength()).isEqualTo(100);
        assertThat(plan.slices()).hasSize(2);
        assertThat(plan.slices().get(0).capture().getObjectKey()).isEqualTo("part-a");
        assertThat(plan.slices().get(0).objectStart()).isEqualTo(50);
        assertThat(plan.slices().get(0).objectEnd()).isEqualTo(99);
        assertThat(plan.slices().get(1).capture().getObjectKey()).isEqualTo("part-b");
        assertThat(plan.slices().get(1).objectStart()).isZero();
        assertThat(plan.slices().get(1).objectEnd()).isEqualTo(49);
    }

    @Test
    void clipsPlaybackAtFirstUncachedByte() {
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService service = new HttpMediaPlaybackService(
                captureService, mock(RustFsMediaStorage.class));
        HttpMediaCapture first = capture(1, 0, 49, 200, "part-a");
        HttpMediaCapture second = capture(2, 100, 199, 200, "part-b");
        when(captureService.completeResourceCaptures(second)).thenReturn(List.of(second, first));

        PlaybackPlan plan = service.plan(second, "bytes=0-149");

        assertThat(plan.start()).isZero();
        assertThat(plan.end()).isEqualTo(49);
        assertThat(plan.contentLength()).isEqualTo(50);
        assertThat(plan.partial()).isTrue();
        assertThat(plan.slices()).hasSize(1);
        assertThat(plan.slices().getFirst().capture().getObjectKey()).isEqualTo("part-a");
    }

    @Test
    void rejectsRangeThatStartsInsideUncachedHole() {
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService service = new HttpMediaPlaybackService(
                captureService, mock(RustFsMediaStorage.class));
        HttpMediaCapture first = capture(1, 0, 49, 200, "part-a");
        HttpMediaCapture second = capture(2, 100, 199, 200, "part-b");
        when(captureService.completeResourceCaptures(second)).thenReturn(List.of(second, first));

        assertThatThrownBy(() -> service.plan(second, "bytes=50-99"))
                .isInstanceOf(MediaRangeException.class)
                .hasMessageContaining("尚未缓存")
                .hasMessageContaining("50");
    }

    @Test
    void usesTheSelectedCachedBlockForARequestWithoutRange() {
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService service = new HttpMediaPlaybackService(
                captureService, mock(RustFsMediaStorage.class));
        HttpMediaCapture first = capture(1, 0, 49, 200, "part-a");
        HttpMediaCapture second = capture(2, 100, 149, 200, "part-b");
        when(captureService.completeResourceCaptures(second)).thenReturn(List.of(second, first));

        PlaybackPlan plan = service.plan(second, null);

        assertThat(plan.partial()).isTrue();
        assertThat(plan.start()).isEqualTo(100);
        assertThat(plan.end()).isEqualTo(149);
        assertThat(plan.totalBytes()).isEqualTo(200);
        assertThat(plan.slices()).hasSize(1);
        assertThat(plan.slices().getFirst().capture()).isSameAs(second);
    }

    @Test
    void mergesAllCachedBlocksForOfflinePlayback() {
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService service = new HttpMediaPlaybackService(
                captureService, mock(RustFsMediaStorage.class));
        HttpMediaCapture first = capture(1, 0, 49, 300, "part-a");
        HttpMediaCapture adjacent = capture(2, 50, 99, 300, "part-b");
        HttpMediaCapture later = capture(3, 200, 249, 300, "part-c");
        when(captureService.completeResourceCaptures(later))
                .thenReturn(List.of(later, adjacent, first));

        HttpMediaPlaybackService.PlaybackCacheLayout layout =
                service.cacheLayout(later);

        assertThat(layout.totalBytes()).isEqualTo(300);
        assertThat(layout.cachedRanges()).containsExactly(
                new HttpMediaPlaybackService.PlaybackByteRange(0, 99),
                new HttpMediaPlaybackService.PlaybackByteRange(200, 249));
    }

    @Test
    void reportsSparseCaptureAsUnavailableBeforeTicketCreation() {
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService service = new HttpMediaPlaybackService(
                captureService, mock(RustFsMediaStorage.class));
        HttpMediaCapture first = capture(1, 0, 49, 200, "part-a");
        HttpMediaCapture second = capture(2, 100, 199, 200, "part-b");
        when(captureService.completeResourceCaptures(second)).thenReturn(List.of(second, first));

        PlaybackAvailability availability = service.availability(second);

        assertThat(availability.playable()).isFalse();
        assertThat(availability.totalBytes()).isEqualTo(200);
        assertThat(availability.reason()).contains("缺少字节 50");
    }

    @Test
    void reportsAdjacentRangeCapturesAsPlayable() {
        HttpMediaCapture first = capture(1, 0, 99, 200, "part-a");
        HttpMediaCapture second = capture(2, 100, 199, 200, "part-b");

        PlaybackAvailability availability =
                HttpMediaPlaybackService.evaluateCoverage(List.of(second, first));

        assertThat(availability.playable()).isTrue();
        assertThat(availability.totalBytes()).isEqualTo(200);
        assertThat(availability.reason()).isNull();
    }

    @Test
    void supportsSuffixRangesAndPreservesContentEncoding() {
        HttpMediaCaptureService captureService = mock(HttpMediaCaptureService.class);
        HttpMediaPlaybackService service = new HttpMediaPlaybackService(
                captureService, mock(RustFsMediaStorage.class));
        HttpMediaCapture complete = capture(1, 0, 999, 1000, "complete");
        complete.setContentEncoding("gzip");
        when(captureService.completeResourceCaptures(complete)).thenReturn(List.of(complete));

        PlaybackPlan plan = service.plan(complete, "bytes=-128");

        assertThat(plan.start()).isEqualTo(872);
        assertThat(plan.end()).isEqualTo(999);
        assertThat(plan.contentEncoding()).isEqualTo("gzip");
    }

    private static HttpMediaCapture capture(long id,
                                            long start,
                                            long end,
                                            long total,
                                            String objectKey) {
        HttpMediaCapture capture = new HttpMediaCapture();
        capture.setId(id);
        capture.setState(HttpMediaCaptureService.STATE_COMPLETE);
        capture.setContentType("video/mp4");
        capture.setContentRangeStart(start);
        capture.setContentRangeEnd(end);
        capture.setTotalBytes(total);
        capture.setCapturedBytes(end - start + 1);
        capture.setObjectKey(objectKey);
        return capture;
    }
}
