package com.theshuai.specusserver.management.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HttpMediaManifestSupportTests {

    @Test
    void classifiesRangeAndOpaqueMediaResponsesOnEnabledMediaRoutes() {
        assertThat(HttpMediaManifestSupport.classify(
                "/stream?id=42", "video/mp4", 206, "bytes 0-99/1000"))
                .isEqualTo(HttpMediaManifestSupport.PROGRESSIVE);
        assertThat(HttpMediaManifestSupport.classify(
                "/segment?id=42", "application/octet-stream", 200, null))
                .isEqualTo(HttpMediaManifestSupport.MEDIA_SEGMENT);
        assertThat(HttpMediaManifestSupport.classify(
                "/keys/session.key", "application/binary", 200, null))
                .isEqualTo(HttpMediaManifestSupport.MEDIA_SEGMENT);
    }

    @Test
    void parsesAndRewritesHlsReferences() {
        String manifest = """
                #EXTM3U
                #EXT-X-MEDIA-SEQUENCE:12
                #EXT-X-MAP:URI="init.mp4"
                #EXT-X-KEY:METHOD=AES-128,URI="secret.key"
                #EXTINF:4,
                part-12.m4s
                """;

        HttpMediaManifestSupport.ParsedManifest parsed = HttpMediaManifestSupport.parse(
                HttpMediaManifestSupport.HLS_MANIFEST, "/media/live/index.m3u8", manifest);

        assertThat(parsed.live()).isTrue();
        assertThat(parsed.references())
                .extracting(HttpMediaManifestSupport.ManifestReference::relationType)
                .containsExactly("INITIALIZATION", "KEY", "SEGMENT");
        assertThat(parsed.references().get(2).sequence()).isEqualTo(12L);
        assertThat(parsed.references().get(2).resolvedSourceUrl()).isEqualTo("/media/live/part-12.m4s");

        String rewritten = HttpMediaManifestSupport.rewrite(
                HttpMediaManifestSupport.HLS_MANIFEST,
                "/media/live/index.m3u8",
                manifest,
                "/api/public/media-playback/ticket/asset");
        assertThat(rewritten)
                .contains("url=%2Fmedia%2Flive%2Finit.mp4")
                .contains("url=%2Fmedia%2Flive%2Fsecret.key")
                .contains("url=%2Fmedia%2Flive%2Fpart-12.m4s");
    }

    @Test
    void keepsDashTemplateTokensAvailableForThePlayer() {
        String manifest = """
                <MPD type="dynamic">
                  <Period><AdaptationSet>
                    <SegmentTemplate initialization="init-$RepresentationID$.mp4"
                                     media="chunk-$Number$.m4s"/>
                  </AdaptationSet></Period>
                </MPD>
                """;

        String rewritten = HttpMediaManifestSupport.rewrite(
                HttpMediaManifestSupport.DASH_MANIFEST,
                "/dash/manifest.mpd",
                manifest,
                "/api/public/media-playback/ticket/asset");

        assertThat(rewritten)
                .contains("$RepresentationID$")
                .contains("$Number$")
                .contains("url=%2Fdash%2Fchunk-$Number$.m4s");
    }

    @Test
    void rejectsInvalidContentRanges() {
        assertThat(HttpMediaManifestSupport.parseContentRange("bytes 10-19/20"))
                .isEqualTo(new HttpMediaManifestSupport.ContentRange(10, 19, 20L));
        assertThat(HttpMediaManifestSupport.parseContentRange("bytes 20-10/30")).isNull();
        assertThat(HttpMediaManifestSupport.parseContentRange("bytes 0-30/30")).isNull();
    }
}
