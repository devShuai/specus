package directhttp

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
)

// gzipOf compresses the payload the way an upstream would.
func gzipOf(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("compress: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close compressor: %v", err)
	}
	return buffer.Bytes()
}

func TestOrdinaryBodiesDecompressUnchanged(t *testing.T) {
	payload := []byte(strings.Repeat("the quick brown fox. ", 2000))
	compressed := gzipOf(t, payload)

	decoded, ok := decompressIfNeeded(compressed, []string{"content-encoding: gzip"})
	if !ok {
		t.Fatal("a normal body must decompress")
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded %d bytes, want the original %d", len(decoded), len(payload))
	}
}

// A few kilobytes of crafted gzip expands to gigabytes. Reading to EOF would end the process.
func TestDecompressionBombIsRefused(t *testing.T) {
	// Highly repetitive input compresses far past the ratio cap.
	bomb := gzipOf(t, bytes.Repeat([]byte{0}, 32<<20))
	if len(bomb) >= 32<<20 {
		t.Fatalf("test input did not compress: %d bytes", len(bomb))
	}

	if _, ok := decompressIfNeeded(bomb, []string{"content-encoding: gzip"}); ok {
		t.Fatalf("a %d-byte input expanding to 32 MiB must be refused", len(bomb))
	}

	reader, err := gzip.NewReader(bytes.NewReader(bomb))
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()
	if _, err := readDecompressedLimited(reader, len(bomb)); !errors.Is(err, errDecompressionLimit) {
		t.Fatalf("err = %v, want errDecompressionLimit", err)
	}
}

func TestDecompressionLimitCombinesTheAbsoluteAndRatioCaps(t *testing.T) {
	// Tiny inputs get the flat allowance, so framing overhead cannot make the ratio meaningless.
	if got := decompressionLimitFor(0); got != minRatioAllowanceBytes {
		t.Fatalf("limit(0) = %d, want the flat allowance %d", got, minRatioAllowanceBytes)
	}
	if got := decompressionLimitFor(-1); got != minRatioAllowanceBytes {
		t.Fatalf("limit(-1) = %d, want the flat allowance", got)
	}

	// In the middle the ratio binds: 256 KiB * 100 is still under the absolute cap.
	if got := decompressionLimitFor(256 << 10); got != (256<<10)*maxDecompressionRatio {
		t.Fatalf("limit(256KiB) = %d, want the ratio allowance %d",
			got, (256<<10)*maxDecompressionRatio)
	}
	// Once the ratio allowance passes the absolute cap, the cap is what binds.
	if got := decompressionLimitFor(1 << 20); got != maxDecompressedBytes {
		t.Fatalf("limit(1MiB) = %d, want the absolute cap %d", got, maxDecompressedBytes)
	}

	// Past that the absolute cap binds, and a size large enough to overflow the multiplication
	// must still land on the cap rather than wrapping to something small.
	if got := decompressionLimitFor(1 << 30); got != maxDecompressedBytes {
		t.Fatalf("limit(1GiB) = %d, want the absolute cap %d", got, maxDecompressedBytes)
	}
	if got := decompressionLimitFor(1 << 62); got != maxDecompressedBytes {
		t.Fatalf("limit(huge) = %d, want the absolute cap, not a wrapped value", got)
	}
}

// A body that exactly fills its allowance is legitimate and must not be rejected.
func TestBodyAtExactlyTheLimitIsAccepted(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), minRatioAllowanceBytes)
	compressed := gzipOf(t, payload)
	limit := decompressionLimitFor(len(compressed))
	if limit < len(payload) {
		t.Skipf("allowance %d is below the payload %d for this input", limit, len(payload))
	}

	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()
	decoded, err := readDecompressedLimited(reader, len(compressed))
	if err != nil {
		t.Fatalf("a body within the allowance must be accepted: %v", err)
	}
	if len(decoded) != len(payload) {
		t.Fatalf("decoded %d bytes, want %d", len(decoded), len(payload))
	}
}

func TestUncompressedBodiesBypassTheLimit(t *testing.T) {
	payload := bytes.Repeat([]byte("y"), 4096)
	for _, encoding := range []string{"", "identity", "br"} {
		decoded, ok := decompressIfNeeded(payload, []string{"content-encoding: " + encoding})
		if !ok || !bytes.Equal(decoded, payload) {
			t.Fatalf("encoding %q: body must pass through untouched", encoding)
		}
	}
}
