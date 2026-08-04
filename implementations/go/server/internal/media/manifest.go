package media

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
)

const (
	KindHLSManifest  = "HLS_MANIFEST"
	KindDASHManifest = "DASH_MANIFEST"
	KindProgressive  = "PROGRESSIVE"
	KindMediaSegment = "MEDIA_SEGMENT"
)

var (
	hlsURIAttribute  = regexp.MustCompile(`URI=("([^"]+)"|'([^']+)')`)
	dashURIAttribute = regexp.MustCompile(`(?i)(media|initialization|sourceURL|href)\s*=\s*("([^"]+)"|'([^']+)')`)
	dashBaseURL      = regexp.MustCompile(`(?is)<BaseURL(\s[^>]*)?>([^<]+)</BaseURL>`)
	contentRangeRE   = regexp.MustCompile(`(?i)^bytes\s+(\d+)-(\d+)/(\d+|\*)$`)
	trailingNumberRE = regexp.MustCompile(`(\d+)$`)
)

type ContentRange struct {
	Start int64
	End   int64
	Total *int64
}

type ManifestReference struct {
	RelationType      string
	Sequence          *int64
	OriginalURI       string
	ResolvedSourceURL string
}

type ParsedManifest struct {
	Live       bool
	References []ManifestReference
}

func Classify(sourceURL, contentType string, statusCode int, contentRange string) string {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	path := strings.ToLower(pathOnly(sourceURL))
	switch {
	case mediaType == "application/vnd.apple.mpegurl", mediaType == "application/x-mpegurl",
		mediaType == "audio/mpegurl", strings.HasSuffix(path, ".m3u8"):
		return KindHLSManifest
	case mediaType == "application/dash+xml", strings.HasSuffix(path, ".mpd"):
		return KindDASHManifest
	case isSegmentPath(path), mediaType == "video/mp2t", mediaType == "application/octet-stream":
		return KindMediaSegment
	case strings.HasPrefix(mediaType, "video/"), strings.HasPrefix(mediaType, "audio/"),
		isProgressivePath(path), statusCode == httpStatusPartialContent && strings.TrimSpace(contentRange) != "":
		return KindProgressive
	default:
		return ""
	}
}

const httpStatusPartialContent = 206

func ParseContentRange(value string) *ContentRange {
	match := contentRangeRE.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return nil
	}
	start, startErr := strconv.ParseInt(match[1], 10, 64)
	end, endErr := strconv.ParseInt(match[2], 10, 64)
	if startErr != nil || endErr != nil || end < start {
		return nil
	}
	var total *int64
	if match[3] != "*" {
		parsed, err := strconv.ParseInt(match[3], 10, 64)
		if err != nil || parsed <= end {
			return nil
		}
		total = &parsed
	}
	return &ContentRange{Start: start, End: end, Total: total}
}

func InferSequence(sourceURL string) *int64 {
	path := pathOnly(sourceURL)
	if dot := strings.LastIndexByte(path, '.'); dot >= 0 {
		path = path[:dot]
	}
	match := trailingNumberRE.FindString(path)
	if match == "" {
		return nil
	}
	value, err := strconv.ParseInt(match, 10, 64)
	if err != nil {
		return nil
	}
	return &value
}

func IsInitializationSegment(sourceURL string) bool {
	path := strings.ToLower(pathOnly(sourceURL))
	if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
		path = path[slash+1:]
	}
	return strings.HasPrefix(path, "init.") || strings.HasPrefix(path, "init-") ||
		strings.Contains(path, "initialization")
}

func NormalizeSourceURL(value string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "/"
	}
	if parsed, err := url.Parse(normalized); err == nil && parsed.IsAbs() {
		normalized = parsed.EscapedPath()
		if normalized == "" {
			normalized = "/"
		}
		if parsed.RawQuery != "" {
			normalized += "?" + parsed.RawQuery
		}
	}
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}
	if len(normalized) > 3072 {
		normalized = normalized[:3072]
	}
	return normalized
}

func ResolveSourceURL(baseSourceURL, reference string) string {
	if strings.TrimSpace(reference) == "" || strings.HasPrefix(reference, "data:") {
		return reference
	}
	base, baseErr := url.Parse("https://capture.invalid" + NormalizeSourceURL(baseSourceURL))
	ref, refErr := url.Parse(strings.TrimSpace(reference))
	if baseErr == nil && refErr == nil {
		resolved := base.ResolveReference(ref)
		path := resolved.EscapedPath()
		if path == "" {
			path = "/"
		}
		if resolved.RawQuery != "" {
			path += "?" + resolved.RawQuery
		}
		return NormalizeSourceURL(path)
	}
	return NormalizeSourceURL(reference)
}

func ParseManifest(kind, sourceURL, text string) ParsedManifest {
	switch kind {
	case KindHLSManifest:
		return parseHLS(sourceURL, text)
	case KindDASHManifest:
		return parseDASH(sourceURL, text)
	default:
		return ParsedManifest{}
	}
}

func RewriteManifest(kind, sourceURL, text, assetBasePath string) string {
	switch kind {
	case KindHLSManifest:
		return rewriteHLS(sourceURL, text, assetBasePath)
	case KindDASHManifest:
		return rewriteDASH(sourceURL, text, assetBasePath)
	default:
		return text
	}
}

func parseHLS(sourceURL, text string) ParsedManifest {
	result := ParsedManifest{}
	mediaSequence := int64(0)
	endList := false
	hasMediaSegment := false
	for _, line := range splitManifestLines(text) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#EXT-X-MEDIA-SEQUENCE:") {
			if parsed, err := strconv.ParseInt(strings.TrimSpace(strings.SplitN(trimmed, ":", 2)[1]), 10, 64); err == nil {
				mediaSequence = parsed
			} else {
				mediaSequence = 0
			}
		} else if trimmed == "#EXT-X-ENDLIST" {
			endList = true
		}
		for _, match := range hlsURIAttribute.FindAllStringSubmatch(line, -1) {
			uri := firstNonEmpty(match[2], match[3])
			relation := "ASSET"
			if strings.HasPrefix(trimmed, "#EXT-X-MAP") {
				relation = "INITIALIZATION"
			} else if strings.HasPrefix(trimmed, "#EXT-X-KEY") {
				relation = "KEY"
			}
			result.References = append(result.References, ManifestReference{
				RelationType: relation, OriginalURI: uri, ResolvedSourceURL: ResolveSourceURL(sourceURL, uri),
			})
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			relation := "SEGMENT"
			if strings.HasSuffix(strings.ToLower(pathOnly(trimmed)), ".m3u8") {
				relation = "PLAYLIST"
			}
			var sequence *int64
			if relation == "SEGMENT" {
				value := mediaSequence
				sequence = &value
				mediaSequence++
				hasMediaSegment = true
			}
			result.References = append(result.References, ManifestReference{
				RelationType: relation, Sequence: sequence, OriginalURI: trimmed,
				ResolvedSourceURL: ResolveSourceURL(sourceURL, trimmed),
			})
		}
	}
	result.Live = hasMediaSegment && !endList
	return result
}

func parseDASH(sourceURL, text string) ParsedManifest {
	result := ParsedManifest{}
	sequence := int64(0)
	for _, match := range dashURIAttribute.FindAllStringSubmatch(text, -1) {
		name := strings.ToLower(match[1])
		uri := firstNonEmpty(match[3], match[4])
		relation := "SEGMENT"
		var index *int64
		if name == "initialization" || name == "sourceurl" {
			relation = "INITIALIZATION"
		} else {
			value := sequence
			index = &value
			sequence++
		}
		result.References = append(result.References, ManifestReference{
			RelationType: relation, Sequence: index, OriginalURI: uri,
			ResolvedSourceURL: ResolveSourceURL(sourceURL, uri),
		})
	}
	for _, match := range dashBaseURL.FindAllStringSubmatch(text, -1) {
		uri := strings.TrimSpace(match[2])
		if uri != "" {
			result.References = append(result.References, ManifestReference{
				RelationType: "BASE", OriginalURI: uri, ResolvedSourceURL: ResolveSourceURL(sourceURL, uri),
			})
		}
	}
	dynamic := regexp.MustCompile(`(?i)<MPD\b[^>]*\btype\s*=\s*["']dynamic["']`)
	result.Live = dynamic.MatchString(text)
	return result
}

func rewriteHLS(sourceURL, text, assetBasePath string) string {
	lines := splitManifestLines(text)
	for index, line := range lines {
		line = replaceRegexpSubmatches(hlsURIAttribute, line, func(groups []string) string {
			original := firstNonEmpty(groups[2], groups[3])
			return `URI="` + assetURL(assetBasePath, ResolveSourceURL(sourceURL, original)) + `"`
		})
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			line = assetURL(assetBasePath, ResolveSourceURL(sourceURL, trimmed))
		}
		lines[index] = line
	}
	return strings.Join(lines, "\n")
}

func rewriteDASH(sourceURL, text, assetBasePath string) string {
	rewritten := replaceRegexpSubmatches(dashURIAttribute, text, func(groups []string) string {
		original := firstNonEmpty(groups[3], groups[4])
		return groups[1] + `="` + xmlEscape(assetURL(assetBasePath, ResolveSourceURL(sourceURL, original))) + `"`
	})
	return replaceRegexpSubmatches(dashBaseURL, rewritten, func(groups []string) string {
		return "<BaseURL" + groups[1] + ">" +
			xmlEscape(assetURL(assetBasePath, ResolveSourceURL(sourceURL, strings.TrimSpace(groups[2])))) +
			"</BaseURL>"
	})
}

func replaceRegexpSubmatches(expression *regexp.Regexp, input string,
	replace func([]string) string) string {
	indexes := expression.FindAllStringSubmatchIndex(input, -1)
	if len(indexes) == 0 {
		return input
	}
	var output strings.Builder
	cursor := 0
	for _, positions := range indexes {
		output.WriteString(input[cursor:positions[0]])
		groups := make([]string, len(positions)/2)
		for index := range groups {
			start, end := positions[index*2], positions[index*2+1]
			if start >= 0 {
				groups[index] = input[start:end]
			}
		}
		output.WriteString(replace(groups))
		cursor = positions[1]
	}
	output.WriteString(input[cursor:])
	return output.String()
}

func assetURL(basePath, resolved string) string {
	encoded := strings.ReplaceAll(url.QueryEscape(resolved), "+", "%20")
	encoded = strings.ReplaceAll(encoded, "%24", "$")
	return basePath + "?url=" + encoded
}

func DecodeManifestBody(data []byte, contentEncoding string, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		maxBytes = 16 * 1024 * 1024
	}
	current := append([]byte(nil), data...)
	tokens := strings.Split(contentEncoding, ",")
	for index := len(tokens) - 1; index >= 0; index-- {
		token := strings.ToLower(strings.TrimSpace(tokens[index]))
		var reader io.ReadCloser
		switch token {
		case "", "identity":
			continue
		case "gzip", "x-gzip":
			decoded, err := gzip.NewReader(bytes.NewReader(current))
			if err != nil {
				return "", err
			}
			reader = decoded
		case "deflate", "x-deflate":
			decoded, err := zlib.NewReader(bytes.NewReader(current))
			if err == nil {
				reader = decoded
			} else {
				reader = flate.NewReader(bytes.NewReader(current))
			}
		case "br":
			reader = io.NopCloser(brotli.NewReader(bytes.NewReader(current)))
		default:
			return "", fmt.Errorf("unsupported manifest content encoding %q", tokens[index])
		}
		decoded, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
		closeErr := reader.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
		if int64(len(decoded)) > maxBytes {
			return "", fmt.Errorf("decoded manifest exceeds %d bytes", maxBytes)
		}
		current = decoded
	}
	if int64(len(current)) > maxBytes {
		return "", fmt.Errorf("decoded manifest exceeds %d bytes", maxBytes)
	}
	return string(current), nil
}

func splitManifestLines(text string) []string {
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	return strings.Split(normalized, "\n")
}

func pathOnly(sourceURL string) string {
	if index := strings.IndexByte(sourceURL, '?'); index >= 0 {
		return sourceURL[:index]
	}
	return sourceURL
}

func isProgressivePath(path string) bool {
	for _, suffix := range []string{".mp4", ".webm", ".mkv", ".mov", ".m4v", ".mp3", ".m4a", ".ogg", ".opus", ".wav", ".flac"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func isSegmentPath(path string) bool {
	for _, suffix := range []string{".ts", ".m4s", ".cmfv", ".cmfa", ".aac", ".vtt", ".key"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func firstNonEmpty(first, second string) string {
	if first != "" {
		return first
	}
	return second
}

func xmlEscape(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "&", "&amp;"), `"`, "&quot;")
}
