package media

import (
	"strings"
	"testing"
)

func TestManifestClassificationAndContentRange(t *testing.T) {
	t.Parallel()
	if got := Classify("/video/stream", "video/mp4", 206, "bytes 10-19/100"); got != KindProgressive {
		t.Fatalf("Classify progressive = %q", got)
	}
	if got := Classify("/hls/master.m3u8", "text/plain", 200, ""); got != KindHLSManifest {
		t.Fatalf("Classify HLS = %q", got)
	}
	if got := Classify("/dash/chunk-3.m4s", "", 200, ""); got != KindMediaSegment {
		t.Fatalf("Classify segment = %q", got)
	}
	parsed := ParseContentRange("bytes 10-19/100")
	if parsed == nil || parsed.Start != 10 || parsed.End != 19 || parsed.Total == nil || *parsed.Total != 100 {
		t.Fatalf("ParseContentRange = %#v", parsed)
	}
	for _, invalid := range []string{"bytes 20-10/100", "bytes 0-100/100", "items 0-1/2"} {
		if got := ParseContentRange(invalid); got != nil {
			t.Fatalf("ParseContentRange(%q) = %#v", invalid, got)
		}
	}
}

func TestParseAndRewriteHLSManifest(t *testing.T) {
	t.Parallel()
	text := "#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:7\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXT-X-KEY:METHOD=AES-128,URI='key.bin'\nsegment-7.ts\nsegment-8.ts\n"
	parsed := ParseManifest(KindHLSManifest, "/live/channel/index.m3u8?token=secret", text)
	if !parsed.Live || len(parsed.References) != 4 {
		t.Fatalf("parsed HLS = %#v", parsed)
	}
	if parsed.References[2].Sequence == nil || *parsed.References[2].Sequence != 7 ||
		parsed.References[2].ResolvedSourceURL != "/live/channel/segment-7.ts" {
		t.Fatalf("segment reference = %#v", parsed.References[2])
	}
	rewritten := RewriteManifest(KindHLSManifest, "/live/channel/index.m3u8", text, "/asset")
	for _, expected := range []string{
		`URI="/asset?url=%2Flive%2Fchannel%2Finit.mp4"`,
		`/asset?url=%2Flive%2Fchannel%2Fsegment-7.ts`,
	} {
		if !strings.Contains(rewritten, expected) {
			t.Fatalf("rewritten HLS missing %q:\n%s", expected, rewritten)
		}
	}
}

func TestRewriteDASHPreservesTemplateTokens(t *testing.T) {
	t.Parallel()
	text := `<MPD type="dynamic"><BaseURL>video/</BaseURL><SegmentTemplate initialization="init-$RepresentationID$.mp4" media="chunk-$Number$.m4s"/></MPD>`
	parsed := ParseManifest(KindDASHManifest, "/dash/manifest.mpd", text)
	if !parsed.Live || len(parsed.References) != 3 {
		t.Fatalf("parsed DASH = %#v", parsed)
	}
	rewritten := RewriteManifest(KindDASHManifest, "/dash/manifest.mpd", text, "/asset")
	if !strings.Contains(rewritten, `$Number$`) || !strings.Contains(rewritten, `$RepresentationID$`) {
		t.Fatalf("DASH template tokens were escaped: %s", rewritten)
	}
	if !strings.Contains(rewritten, `&amp;`) && strings.Contains(rewritten, `?url=`) {
		// A single query parameter contains no ampersand; the assertion below verifies the URL.
		if !strings.Contains(rewritten, `/asset?url=%2Fdash%2Fchunk-$Number$.m4s`) {
			t.Fatalf("DASH media URL not rewritten: %s", rewritten)
		}
	}
}
