package directhttp

import (
	"errors"
	"fmt"
	"io"
)

// Decompression is the one place where a small input can cost unbounded memory. A few kilobytes of
// crafted gzip expands to gigabytes, so reading a decompressor to EOF hands any upstream — or any
// peer able to influence one — a way to end the process.
//
// Two limits, because either alone leaves a gap. The absolute cap bounds what a single body can
// cost. The ratio cap catches a bomb that stays under the absolute cap but is still wildly
// disproportionate to its input, which is the signature of a bomb rather than of real content.
const (
	// maxDecompressedBytes matches the largest response body the proxy will carry anyway, so no
	// legitimate payload is lost to it.
	maxDecompressedBytes = 64 << 20
	// maxDecompressionRatio is generous next to real text, which rarely exceeds 20:1.
	maxDecompressionRatio = 100
	// minRatioAllowanceBytes keeps the ratio from rejecting tiny inputs, where a few bytes of
	// framing overhead make the ratio meaningless.
	minRatioAllowanceBytes = 64 << 10
)

// errDecompressionLimit reports a body that exceeded either limit.
var errDecompressionLimit = errors.New("decompressed body exceeded its limit")

// readDecompressedLimited reads the decompressor, refusing anything past the byte or ratio cap.
//
// compressedSize is the size of the input the decompressor was handed, and is what makes the ratio
// check possible.
func readDecompressedLimited(reader io.Reader, compressedSize int) ([]byte, error) {
	limit := decompressionLimitFor(compressedSize)
	// One byte past the limit is enough to tell "at the limit" from "over it", so a body that
	// exactly fills the cap is still accepted.
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(decoded) > limit {
		return nil, fmt.Errorf("%w: %d bytes from %d compressed", errDecompressionLimit,
			len(decoded), compressedSize)
	}
	return decoded, nil
}

// decompressionLimitFor returns the smaller of the absolute cap and the ratio allowance.
func decompressionLimitFor(compressedSize int) int {
	if compressedSize < 0 {
		compressedSize = 0
	}
	allowance := minRatioAllowanceBytes
	if compressedSize > 0 {
		scaled := compressedSize * maxDecompressionRatio
		// Guard the multiplication: a huge compressed size would otherwise wrap and produce a
		// limit far below the absolute cap.
		if scaled/maxDecompressionRatio != compressedSize || scaled > maxDecompressedBytes {
			scaled = maxDecompressedBytes
		}
		if scaled > allowance {
			allowance = scaled
		}
	}
	if allowance > maxDecompressedBytes {
		return maxDecompressedBytes
	}
	return allowance
}
