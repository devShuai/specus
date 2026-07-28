package directhttp

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/url"
	"regexp"
	"strings"
)

var rewritableContentTypes = map[string]struct{}{
	"text/html":                {},
	"text/css":                 {},
	"text/javascript":          {},
	"application/javascript":   {},
	"application/x-javascript": {},
	"application/ecmascript":   {},
	"text/ecmascript":          {},
}

var (
	htmlPathDoublePattern = regexp.MustCompile(`(?i)(href|src|action|data-href|data-src|poster|background|formaction|cite|longdesc|usemap)(\s*=\s*)"(/[^"]*)"`)
	htmlPathSinglePattern = regexp.MustCompile(`(?i)(href|src|action|data-href|data-src|poster|background|formaction|cite|longdesc|usemap)(\s*=\s*)'(/[^']*)'`)
	htmlSrcsetDouble      = regexp.MustCompile(`(?i)(srcset)(\s*=\s*)"([^"]*)"`)
	htmlSrcsetSingle      = regexp.MustCompile(`(?i)(srcset)(\s*=\s*)'([^']*)'`)
	cssURLPattern         = regexp.MustCompile(`(?i)url\(\s*(['"]?)(/[^'")\s]+)['"]?\s*\)`)
	cssImportPattern      = regexp.MustCompile(`(?i)(@import\s+)(['"])(/[^'"]*)['"]`)
	headTagPattern        = regexp.MustCompile(`(?i)<head\b[^>]*>`)
	htmlTagPattern        = regexp.MustCompile(`(?i)<html\b[^>]*>`)
)

type responseRewriter struct {
	maxBodyBytes int
}

func newResponseRewriter(maxBodyBytes int) responseRewriter {
	if maxBodyBytes < 0 {
		maxBodyBytes = 0
	}
	return responseRewriter{maxBodyBytes: maxBodyBytes}
}

func (rw responseRewriter) rewrite(body []byte, clientName, route string, headers []string) ([]byte, bool) {
	if len(body) == 0 || rw.maxBodyBytes == 0 || len(body) > rw.maxBodyBytes {
		return nil, false
	}
	contentType := contentType(headers)
	if _, ok := rewritableContentTypes[contentType]; !ok {
		return nil, false
	}
	plain, ok := decompressIfNeeded(body, headers)
	if !ok {
		return nil, false
	}
	prefix := "/http/" + url.PathEscape(clientName) + "/" + url.PathEscape(route)
	text := string(plain)
	rewritten := text
	if contentType == "text/html" {
		rewritten = rewriteQuotedPaths(rewritten, prefix, htmlPathDoublePattern, '"')
		rewritten = rewriteQuotedPaths(rewritten, prefix, htmlPathSinglePattern, '\'')
		rewritten = rewriteSrcset(rewritten, prefix, htmlSrcsetDouble, '"')
		rewritten = rewriteSrcset(rewritten, prefix, htmlSrcsetSingle, '\'')
		rewritten = injectRuntimePolyfill(rewritten, prefix)
	}
	if contentType == "text/css" {
		rewritten = rewriteCSSURLs(rewritten, prefix)
		rewritten = rewriteCSSImports(rewritten, prefix)
	}
	if rewritten == text {
		return nil, false
	}
	return []byte(rewritten), true
}

func rewriteQuotedPaths(input, prefix string, pattern *regexp.Regexp, quote byte) string {
	matches := pattern.FindAllStringSubmatchIndex(input, -1)
	if len(matches) == 0 {
		return input
	}
	var out strings.Builder
	out.Grow(len(input) + 128)
	last := 0
	for _, m := range matches {
		path := input[m[6]:m[7]]
		if !shouldRewritePath(path, prefix) {
			continue
		}
		out.WriteString(input[last:m[0]])
		out.WriteString(input[m[2]:m[3]])
		out.WriteString(input[m[4]:m[5]])
		out.WriteByte(quote)
		out.WriteString(prefix)
		out.WriteString(path)
		out.WriteByte(quote)
		last = m[1]
	}
	if last == 0 {
		return input
	}
	out.WriteString(input[last:])
	return out.String()
}

func rewriteSrcset(input, prefix string, pattern *regexp.Regexp, quote byte) string {
	matches := pattern.FindAllStringSubmatchIndex(input, -1)
	if len(matches) == 0 {
		return input
	}
	var out strings.Builder
	out.Grow(len(input) + 128)
	last := 0
	for _, m := range matches {
		value := input[m[6]:m[7]]
		rewritten := rewriteSrcsetValue(value, prefix)
		if rewritten == value {
			continue
		}
		out.WriteString(input[last:m[0]])
		out.WriteString(input[m[2]:m[3]])
		out.WriteString(input[m[4]:m[5]])
		out.WriteByte(quote)
		out.WriteString(rewritten)
		out.WriteByte(quote)
		last = m[1]
	}
	if last == 0 {
		return input
	}
	out.WriteString(input[last:])
	return out.String()
}

func rewriteSrcsetValue(value, prefix string) string {
	parts := strings.Split(value, ",")
	changed := false
	for i, part := range parts {
		left := len(part) - len(strings.TrimLeft(part, " \t\r\n"))
		if left < len(part) {
			tokenEnd := left
			for tokenEnd < len(part) && !isSpace(part[tokenEnd]) {
				tokenEnd++
			}
			token := part[left:tokenEnd]
			if shouldRewritePath(token, prefix) {
				parts[i] = part[:left] + prefix + part[left:]
				changed = true
			}
		}
	}
	if !changed {
		return value
	}
	return strings.Join(parts, ",")
}

func rewriteCSSURLs(input, prefix string) string {
	matches := cssURLPattern.FindAllStringSubmatchIndex(input, -1)
	if len(matches) == 0 {
		return input
	}
	var out strings.Builder
	out.Grow(len(input) + 128)
	last := 0
	for _, m := range matches {
		path := input[m[4]:m[5]]
		if !shouldRewritePath(path, prefix) {
			continue
		}
		quote := input[m[2]:m[3]]
		out.WriteString(input[last:m[0]])
		out.WriteString("url(")
		out.WriteString(quote)
		out.WriteString(prefix)
		out.WriteString(path)
		out.WriteString(quote)
		out.WriteString(")")
		last = m[1]
	}
	if last == 0 {
		return input
	}
	out.WriteString(input[last:])
	return out.String()
}

func rewriteCSSImports(input, prefix string) string {
	matches := cssImportPattern.FindAllStringSubmatchIndex(input, -1)
	if len(matches) == 0 {
		return input
	}
	var out strings.Builder
	out.Grow(len(input) + 128)
	last := 0
	for _, m := range matches {
		path := input[m[6]:m[7]]
		if !shouldRewritePath(path, prefix) {
			continue
		}
		quote := input[m[4]:m[5]]
		out.WriteString(input[last:m[0]])
		out.WriteString(input[m[2]:m[3]])
		out.WriteString(quote)
		out.WriteString(prefix)
		out.WriteString(path)
		out.WriteString(quote)
		last = m[1]
	}
	if last == 0 {
		return input
	}
	out.WriteString(input[last:])
	return out.String()
}

func shouldRewritePath(path, prefix string) bool {
	return strings.HasPrefix(path, "/") &&
		!strings.HasPrefix(path, "//") &&
		path != prefix &&
		!strings.HasPrefix(path, prefix+"/")
}

func injectRuntimePolyfill(html, prefix string) string {
	script := buildPolyfillScript(prefix)
	if loc := headTagPattern.FindStringIndex(html); loc != nil {
		return html[:loc[1]] + script + html[loc[1]:]
	}
	if loc := htmlTagPattern.FindStringIndex(html); loc != nil {
		return html[:loc[1]] + script + html[loc[1]:]
	}
	return script + html
}

func buildPolyfillScript(prefix string) string {
	escaped := strings.ReplaceAll(strings.ReplaceAll(prefix, `\`, `\\`), `'`, `\'`)
	return "<script>(function(){try{" +
		"var P='" + escaped + "';" +
		"function need(u){if(typeof u!=='string')return false;if(u.length===0||u.charAt(0)!=='/')return false;if(u.length>1&&u.charAt(1)==='/')return false;if(u.indexOf(P+'/')===0||u===P)return false;return true;}" +
		"function fix(u){return need(u)?P+u:u;}" +
		"if(typeof fetch==='function'){var of=fetch;window.fetch=function(i,n){try{if(typeof i==='string')i=fix(i);else if(i&&typeof i.url==='string'&&need(i.url))i=new Request(fix(i.url),i);}catch(e){}return of.call(this,i,n);};}" +
		"if(typeof XMLHttpRequest!=='undefined'){var oo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){try{u=fix(u);}catch(e){}arguments[1]=u;return oo.apply(this,arguments);};}" +
		"function wrapHistory(name){var orig=history[name];if(typeof orig==='function'){history[name]=function(s,t,u){try{if(typeof u==='string')u=fix(u);}catch(e){}return orig.call(this,s,t,u);};}}" +
		"if(typeof history!=='undefined'){wrapHistory('pushState');wrapHistory('replaceState');}" +
		"if(typeof Element!=='undefined'){var osa=Element.prototype.setAttribute;var A={src:1,href:1,action:1,formaction:1,poster:1,background:1,'data-src':1,'data-href':1};Element.prototype.setAttribute=function(n,v){try{if(n&&A[String(n).toLowerCase()]&&typeof v==='string')v=fix(v);}catch(e){}return osa.call(this,n,v);};}" +
		"if(typeof EventSource==='function'){var OE=EventSource;window.EventSource=function(u,c){return new OE(fix(u),c);};window.EventSource.prototype=OE.prototype;}" +
		"if(typeof WebSocket==='function'){var OW=WebSocket;window.WebSocket=function(u,p){try{if(typeof u==='string'&&u.indexOf('ws://')!==0&&u.indexOf('wss://')!==0&&need(u))u=fix(u);}catch(e){}return p===undefined?new OW(u):new OW(u,p);};window.WebSocket.prototype=OW.prototype;}" +
		"}catch(e){console&&console.warn&&console.warn('specus polyfill failed',e);}})();</script>"
}

func contentType(headers []string) string {
	raw := headerValue(headers, "content-type")
	if raw == "" {
		return ""
	}
	if i := strings.IndexByte(raw, ';'); i >= 0 {
		raw = raw[:i]
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func headerValue(headers []string, name string) string {
	for _, header := range headers {
		separator := strings.IndexByte(header, ':')
		if separator <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(header[:separator]), name) {
			return strings.TrimSpace(header[separator+1:])
		}
	}
	return ""
}

func decompressIfNeeded(body []byte, headers []string) ([]byte, bool) {
	switch strings.ToLower(headerValue(headers, "content-encoding")) {
	case "", "identity":
		return body, true
	case "gzip", "x-gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		defer reader.Close()
		plain, err := io.ReadAll(reader)
		return plain, err == nil
	case "deflate":
		if plain, ok := readZlib(body); ok {
			return plain, true
		}
		reader := flate.NewReader(bytes.NewReader(body))
		defer reader.Close()
		plain, err := io.ReadAll(reader)
		return plain, err == nil
	default:
		return body, true
	}
}

func readZlib(body []byte) ([]byte, bool) {
	reader, err := zlib.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, false
	}
	defer reader.Close()
	plain, err := io.ReadAll(reader)
	return plain, err == nil
}

func isSpace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'
}
