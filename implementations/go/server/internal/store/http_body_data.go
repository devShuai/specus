package store

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// httpBodyCapture is what Java's TrafficInspectionService.captureHttpBody keeps of one HTTP body:
// the bytes as they were received, the first capture-preview-bytes of them as hex, and the text a
// body search looks at (decoded, at most capture-preview-bytes characters, empty for binary).
type httpBodyCapture struct {
	previewHex string
	bodyData   []byte
	searchText string
}

func captureHTTPBody(data []byte, contentType, contentEncoding string, options TrafficDetailOptions) httpBodyCapture {
	if len(data) == 0 {
		return httpBodyCapture{}
	}
	limit := previewBytes(options)
	previewHex, _, _ := tcpPreview(data, limit)
	decoded, _ := decodeBody(data, contentEncoding, decodeMaxBytes(options))
	searchText := ""
	if isTextBody(contentType) || looksLikeText(decoded) {
		searchText = capUTF16(sanitizeText(string(decoded)), limit)
	}
	return httpBodyCapture{previewHex: previewHex, bodyData: data, searchText: searchText}
}

// capUTF16 is Java's String cap: at most max UTF-16 code units, without splitting a surrogate pair.
func capUTF16(text string, max int) string {
	if max <= 0 {
		return ""
	}
	units := 0
	for i, r := range text {
		width := 1
		if r >= 0x10000 {
			width = 2
		}
		if units+width > max {
			return text[:i]
		}
		units += width
	}
	return text
}

// showHTTPBodies puts the stored bodies of one exchange into the preview text its detail returns,
// as Java's detail views do with HttpBodyDataCodec. An exchange recorded without bodies keeps the
// preview text it has.
func showHTTPBodies(item *HTTPTrafficExchange) {
	item.RequestPreviewText = httpBodyDisplayText(item.RequestBodyData, stringOrEmpty(item.RequestContentType),
		item.RequestHeaders, item.RequestPreviewText)
	item.ResponsePreviewText = httpBodyDisplayText(item.ResponseBodyData, stringOrEmpty(item.ResponseContentType),
		item.ResponseHeaders, item.ResponsePreviewText)
}

// httpBodyDisplayText is Java's HttpBodyDataCodec.toDisplayText. A body with a Content-Encoding is
// decoded first; one that cannot be is shown as its own bytes, as application/octet-stream. Text is
// shown whole with its control characters replaced, anything else as a data: URL of its type.
func httpBodyDisplayText(body []byte, contentType, headers, fallback string) string {
	if len(body) == 0 {
		return fallback
	}
	encoding := storedHeaderValue(headers, "content-encoding")
	if hasContentEncoding(encoding) {
		decoded, ok := decodeStoredBody(body, encoding)
		if !ok {
			return bodyDataURL("application/octet-stream", body)
		}
		body = decoded
	}
	if !isTextBody(contentType) && !looksLikeText(body) {
		return bodyDataURL(contentMediaType(contentType), body)
	}
	return sanitizeText(string(body))
}

func bodyDataURL(mediaType string, body []byte) string {
	return "data:" + mediaType + ";base64," + base64.StdEncoding.EncodeToString(body)
}

// storedHeaderValue reads a header from the stored header lines (joinHeaders).
func storedHeaderValue(headers, name string) string {
	for _, line := range strings.Split(headers, "\n") {
		if idx := strings.IndexByte(line, ':'); idx > 0 && strings.EqualFold(strings.TrimSpace(line[:idx]), name) {
			return strings.TrimSpace(line[idx+1:])
		}
	}
	return ""
}

func hasContentEncoding(contentEncoding string) bool {
	for _, token := range strings.Split(contentEncoding, ",") {
		if token = strings.ToLower(strings.TrimSpace(token)); token != "" && token != "identity" {
			return true
		}
	}
	return false
}

// decodeStoredBody undoes every coding of a stored body, last applied first. Unlike the capture
// preview it never shows part of a body: an unknown coding, a corrupt stream or an expansion past
// the decompression limit fails the whole decode.
func decodeStoredBody(body []byte, contentEncoding string) ([]byte, bool) {
	tokens := strings.Split(contentEncoding, ",")
	current := body
	for i := len(tokens) - 1; i >= 0; i-- {
		token := strings.ToLower(strings.TrimSpace(tokens[i]))
		var next []byte
		var err error
		switch token {
		case "", "identity":
			continue
		case "gzip", "x-gzip":
			var reader *gzip.Reader
			if reader, err = gzip.NewReader(bytes.NewReader(current)); err == nil {
				next, err = readStoredBodyLimited(reader, len(current))
			}
		case "deflate", "x-deflate":
			// zlib-wrapped as the standard says, else raw deflate as some servers send it.
			var reader io.ReadCloser
			if reader, err = zlib.NewReader(bytes.NewReader(current)); err == nil {
				next, err = readStoredBodyLimited(reader, len(current))
			}
			if err != nil {
				next, err = readStoredBodyLimited(flate.NewReader(bytes.NewReader(current)), len(current))
			}
		case "br":
			next, err = readStoredBodyLimited(brotli.NewReader(bytes.NewReader(current)), len(current))
		default:
			return nil, false
		}
		if err != nil {
			return nil, false
		}
		current = next
	}
	return current, true
}

// The decompression limits of Java's DecompressionLimits (and of directhttp): at most 64 MiB, and
// at most 100 times the compressed size with 64 KiB allowed for any input.
const (
	storedBodyMaxDecodedBytes   = 64 << 20
	storedBodyMaxRatio          = 100
	storedBodyMinRatioAllowance = 64 << 10
)

var errStoredBodyLimit = errors.New("decoded body exceeded its limit")

func readStoredBodyLimited(reader io.Reader, compressedSize int) ([]byte, error) {
	limit := storedBodyMinRatioAllowance
	if compressedSize > storedBodyMaxDecodedBytes/storedBodyMaxRatio {
		limit = storedBodyMaxDecodedBytes
	} else if scaled := compressedSize * storedBodyMaxRatio; scaled > limit {
		limit = scaled
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(decoded) > limit {
		return nil, errStoredBodyLimit
	}
	return decoded, nil
}

func stringOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// nullableBytes stores no body as NULL; the detail reads NULL and empty alike as no body.
func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
