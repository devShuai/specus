using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class HttpMediaManifestSupportTests
{
    [Fact]
    public void ClassifiesRangeOpaqueAndManifestResponsesLikeJava()
    {
        Assert.Equal(HttpMediaManifestSupport.Progressive,
            HttpMediaManifestSupport.Classify("/stream?id=42", "video/mp4", 206,
                "bytes 0-99/1000"));
        Assert.Equal(HttpMediaManifestSupport.MediaSegment,
            HttpMediaManifestSupport.Classify("/segment?id=42", "application/octet-stream", 200,
                null));
        Assert.Equal(HttpMediaManifestSupport.MediaSegment,
            HttpMediaManifestSupport.Classify("/keys/session.key", "application/binary", 200,
                null));
        Assert.Equal(HttpMediaManifestSupport.HlsManifest,
            HttpMediaManifestSupport.Classify("/index.m3u8", "text/plain", 200, null));
    }

    [Fact]
    public void ParsesAndRewritesHlsReferences()
    {
        const string manifest = """
            #EXTM3U
            #EXT-X-MEDIA-SEQUENCE:12
            #EXT-X-MAP:URI="init.mp4"
            #EXT-X-KEY:METHOD=AES-128,URI="secret.key"
            #EXTINF:4,
            part-12.m4s
            """;

        var parsed = HttpMediaManifestSupport.Parse(HttpMediaManifestSupport.HlsManifest,
            "/media/live/index.m3u8", manifest);

        Assert.True(parsed.Live);
        Assert.Equal(["INITIALIZATION", "KEY", "SEGMENT"],
            parsed.References.Select(reference => reference.RelationType));
        Assert.Equal(12, parsed.References[2].Sequence);
        Assert.Equal("/media/live/part-12.m4s", parsed.References[2].ResolvedSourceUrl);
        var rewritten = HttpMediaManifestSupport.Rewrite(HttpMediaManifestSupport.HlsManifest,
            "/media/live/index.m3u8", manifest,
            "/api/public/media-playback/ticket/asset");
        Assert.Contains("url=%2Fmedia%2Flive%2Finit.mp4", rewritten,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains("url=%2Fmedia%2Flive%2Fsecret.key", rewritten,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains("url=%2Fmedia%2Flive%2Fpart-12.m4s", rewritten,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DashRewritePreservesPlayerTemplateTokens()
    {
        const string manifest = """
            <MPD type="dynamic">
              <Period><AdaptationSet>
                <SegmentTemplate initialization="init-$RepresentationID$.mp4"
                                 media="chunk-$Number$.m4s"/>
              </AdaptationSet></Period>
            </MPD>
            """;

        var rewritten = HttpMediaManifestSupport.Rewrite(HttpMediaManifestSupport.DashManifest,
            "/dash/manifest.mpd", manifest,
            "/api/public/media-playback/ticket/asset");

        Assert.Contains("$RepresentationID$", rewritten, StringComparison.Ordinal);
        Assert.Contains("$Number$", rewritten, StringComparison.Ordinal);
        Assert.Contains("url=%2Fdash%2Fchunk-$Number$.m4s", rewritten,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RejectsInvalidContentRanges()
    {
        Assert.Equal(new HttpMediaManifestSupport.ContentRange(10, 19, 20),
            HttpMediaManifestSupport.ParseContentRange("bytes 10-19/20"));
        Assert.Null(HttpMediaManifestSupport.ParseContentRange("bytes 20-10/30"));
        Assert.Null(HttpMediaManifestSupport.ParseContentRange("bytes 0-30/30"));
    }
}
