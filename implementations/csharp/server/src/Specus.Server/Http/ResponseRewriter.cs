using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Specus.Server.Http;

internal static partial class ResponseRewriter
{
    private static readonly HashSet<string> RewritableContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "text/html",
        "text/css",
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript",
    };

    public static bool TryRewrite(byte[] body, string clientName, string route, IReadOnlyList<string>? headers,
        int maxBodyBytes, out byte[] rewritten)
    {
        rewritten = Array.Empty<byte>();
        if (body.Length == 0 || maxBodyBytes <= 0 || body.Length > maxBodyBytes)
        {
            return false;
        }

        var contentType = ContentType(headers);
        if (contentType is null || !RewritableContentTypes.Contains(contentType))
        {
            return false;
        }

        var plain = DecompressIfNeeded(body, headers);
        if (plain is null)
        {
            return false;
        }

        var prefix = $"/http/{Uri.EscapeDataString(clientName)}/{Uri.EscapeDataString(route)}";
        var text = Encoding.UTF8.GetString(plain);
        var next = text;
        if (contentType.Equals("text/html", StringComparison.OrdinalIgnoreCase))
        {
            next = RewriteHtmlAttributeDouble().Replace(next, m => RewriteQuotedPath(m, prefix, '"'));
            next = RewriteHtmlAttributeSingle().Replace(next, m => RewriteQuotedPath(m, prefix, '\''));
            next = RewriteSrcsetDouble().Replace(next, m => RewriteSrcset(m, prefix, '"'));
            next = RewriteSrcsetSingle().Replace(next, m => RewriteSrcset(m, prefix, '\''));
            next = InjectRuntimePolyfill(next, prefix);
        }
        if (contentType.Equals("text/css", StringComparison.OrdinalIgnoreCase))
        {
            next = RewriteCssUrl().Replace(next, m => RewriteCssUrlMatch(m, prefix));
            next = RewriteCssImport().Replace(next, m => RewriteCssImportMatch(m, prefix));
        }

        if (next == text)
        {
            return false;
        }

        rewritten = Encoding.UTF8.GetBytes(next);
        return true;
    }

    private static string RewriteQuotedPath(Match match, string prefix, char quote)
    {
        var path = match.Groups[3].Value;
        if (!ShouldRewritePath(path, prefix))
        {
            return match.Value;
        }
        return $"{match.Groups[1].Value}{match.Groups[2].Value}{quote}{prefix}{path}{quote}";
    }

    private static string RewriteSrcset(Match match, string prefix, char quote)
    {
        var value = match.Groups[3].Value;
        var candidates = value.Split(',');
        var changed = false;
        for (var i = 0; i < candidates.Length; i++)
        {
            var candidate = candidates[i];
            var start = 0;
            while (start < candidate.Length && char.IsWhiteSpace(candidate[start]))
            {
                start++;
            }

            var tokenEnd = start;
            while (tokenEnd < candidate.Length && !char.IsWhiteSpace(candidate[tokenEnd]))
            {
                tokenEnd++;
            }

            if (tokenEnd > start && ShouldRewritePath(candidate[start..tokenEnd], prefix))
            {
                candidates[i] = candidate[..start] + prefix + candidate[start..];
                changed = true;
            }
        }

        return changed
            ? $"{match.Groups[1].Value}{match.Groups[2].Value}{quote}{string.Join(',', candidates)}{quote}"
            : match.Value;
    }

    private static string RewriteCssUrlMatch(Match match, string prefix)
    {
        var path = match.Groups[2].Value;
        if (!ShouldRewritePath(path, prefix))
        {
            return match.Value;
        }
        var quote = match.Groups[1].Value;
        return $"url({quote}{prefix}{path}{quote})";
    }

    private static string RewriteCssImportMatch(Match match, string prefix)
    {
        var path = match.Groups[3].Value;
        if (!ShouldRewritePath(path, prefix))
        {
            return match.Value;
        }
        var quote = match.Groups[2].Value;
        return $"{match.Groups[1].Value}{quote}{prefix}{path}{quote}";
    }

    private static bool ShouldRewritePath(string path, string prefix) =>
        path.StartsWith("/", StringComparison.Ordinal)
        && !path.StartsWith("//", StringComparison.Ordinal)
        && !path.Equals(prefix, StringComparison.Ordinal)
        && !path.StartsWith(prefix + "/", StringComparison.Ordinal);

    private static string InjectRuntimePolyfill(string html, string prefix)
    {
        var script = BuildPolyfillScript(prefix);
        var head = HeadTag().Match(html);
        if (head.Success)
        {
            return html.Insert(head.Index + head.Length, script);
        }
        var htmlTag = HtmlTag().Match(html);
        return htmlTag.Success ? html.Insert(htmlTag.Index + htmlTag.Length, script) : script + html;
    }

    private static string BuildPolyfillScript(string prefix)
    {
        var escaped = prefix.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("'", "\\'", StringComparison.Ordinal);
        return "<script>(function(){try{"
               + $"var P='{escaped}';"
               + "function hrefOf(u){if(typeof u==='string')return u;if(u&&typeof u.href==='string')return u.href;if(u&&typeof u.url==='string')return u.url;return '';}"
               + "function locParts(){if(typeof location==='undefined')return null;return {http:location.origin,ws:(location.protocol==='https:'?'wss://':'ws://')+location.host};}"
               + "function need(u){if(typeof u!=='string'||!u)return false;var path=u,loc=locParts(),base=null;if(u.charAt(0)!=='/'){if(!loc)return false;if(u.indexOf(loc.http)===0)base=loc.http;else if(u.indexOf(loc.ws)===0)base=loc.ws;else return false;path=u.slice(base.length);if(!path||path.charAt(0)!=='/')return false;}if(path.length>1&&path.charAt(1)==='/')return false;if(path.indexOf(P+'/')===0||path===P||path.indexOf(P+'?')===0||path.indexOf(P+'#')===0)return false;return true;}"
               + "function fix(u){if(!need(u))return u;if(u.charAt(0)==='/')return P+u;var loc=locParts();var base=u.indexOf(loc.http)===0?loc.http:loc.ws;return base+P+u.slice(base.length);}"
               + "function rewriteInput(input){var h=hrefOf(input);if(!h||!need(h))return input;var rewritten=fix(h);if(typeof Request==='function'&&input instanceof Request)return new Request(rewritten,input);return rewritten;}"
               + "if(typeof fetch==='function'){var of=fetch;window.fetch=function(i,n){try{i=rewriteInput(i);}catch(e){}return of.call(this,i,n);};}"
               + "if(typeof XMLHttpRequest!=='undefined'){var oo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){try{var h=hrefOf(u);if(h)u=fix(h);}catch(e){}arguments[1]=u;return oo.apply(this,arguments);};}"
               + "function wrapHistory(name){var orig=history[name];if(typeof orig==='function'){history[name]=function(s,t,u){try{if(typeof u==='string')u=fix(u);}catch(e){}return orig.call(this,s,t,u);};}}"
               + "if(typeof history!=='undefined'){wrapHistory('pushState');wrapHistory('replaceState');}"
               + "if(typeof Element!=='undefined'){var osa=Element.prototype.setAttribute;var A={src:1,href:1,action:1,formaction:1,poster:1,background:1,'data-src':1,'data-href':1};Element.prototype.setAttribute=function(n,v){try{if(n&&A[String(n).toLowerCase()]&&typeof v==='string')v=fix(v);}catch(e){}return osa.call(this,n,v);};}"
               + "function wrapAttr(N,p){var C=window[N];if(typeof C!=='function'||!C.prototype)return;var proto=C.prototype,from=proto,d;while(from&&!(d=Object.getOwnPropertyDescriptor(from,p)))from=Object.getPrototypeOf(from);if(!d||typeof d.set!=='function')return;var desc={configurable:true,enumerable:d.enumerable,set:function(v){try{if(typeof v==='string')v=fix(v);}catch(e){}d.set.call(this,v);}};if(d.get)desc.get=function(){return d.get.call(this);};Object.defineProperty(proto,p,desc);}"
               + "var S=['HTMLScriptElement','HTMLImageElement','HTMLIFrameElement','HTMLSourceElement','HTMLVideoElement','HTMLAudioElement','HTMLEmbedElement','HTMLInputElement','HTMLMediaElement'];for(var si=0;si<S.length;si++){wrapAttr(S[si],'src');wrapAttr(S[si],'srcset');wrapAttr(S[si],'poster');}"
               + "var H=['HTMLLinkElement','HTMLAnchorElement','HTMLBaseElement','SVGAElement','SVGImageElement'];for(var hi=0;hi<H.length;hi++)wrapAttr(H[hi],'href');wrapAttr('HTMLFormElement','action');wrapAttr('HTMLObjectElement','data');"
               + "if(typeof EventSource==='function'){var OE=EventSource;window.EventSource=function(u,c){try{var h=hrefOf(u);if(h)u=fix(h);}catch(e){}return new OE(u,c);};window.EventSource.prototype=OE.prototype;}"
               + "if(typeof WebSocket==='function'){var OW=WebSocket;window.WebSocket=function(u,p){try{var h=hrefOf(u);if(h)u=fix(h);}catch(e){}return p===undefined?new OW(u):new OW(u,p);};window.WebSocket.prototype=OW.prototype;}"
               + "}catch(e){console&&console.warn&&console.warn('specus polyfill failed',e);}})();</script>";
    }

    private static string? ContentType(IReadOnlyList<string>? headers)
    {
        var raw = HeaderValue(headers, "content-type");
        if (raw is null)
        {
            return null;
        }
        var semicolon = raw.IndexOf(';', StringComparison.Ordinal);
        return (semicolon >= 0 ? raw[..semicolon] : raw).Trim().ToLowerInvariant();
    }

    private static string? HeaderValue(IReadOnlyList<string>? headers, string name)
    {
        if (headers is null)
        {
            return null;
        }
        foreach (var header in headers)
        {
            var separator = header.IndexOf(':', StringComparison.Ordinal);
            if (separator <= 0)
            {
                continue;
            }
            if (header[..separator].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return header[(separator + 1)..].Trim();
            }
        }
        return null;
    }

    private static byte[]? DecompressIfNeeded(byte[] body, IReadOnlyList<string>? headers)
    {
        var encoding = HeaderValue(headers, "content-encoding")?.ToLowerInvariant();
        return encoding switch
        {
            null or "" or "identity" => body,
            "gzip" or "x-gzip" => ReadCompressed(body, s => new GZipStream(s, CompressionMode.Decompress)),
            "deflate" => ReadCompressed(body, s => new ZLibStream(s, CompressionMode.Decompress))
                         ?? ReadCompressed(body, s => new DeflateStream(s, CompressionMode.Decompress)),
            _ => body,
        };
    }

    private static byte[]? ReadCompressed(byte[] body, Func<Stream, Stream> create)
    {
        try
        {
            using var input = new MemoryStream(body);
            using var compressed = create(input);
            // Bounded: this is the most exposed decompression path in the server, and copying an
            // upstream decompressor to the end lets a few kilobytes of crafted gzip cost gigabytes.
            return DecompressionLimits.ReadAllBounded(compressed, body.Length);
        }
        catch (Exception error) when (error is InvalidDataException
                                          or DecompressionLimits.LimitExceededException)
        {
            return null;
        }
    }

    [GeneratedRegex("(href|src|action|data-href|data-src|poster|background|formaction|cite|longdesc|usemap)(\\s*=\\s*)\"(/[^\"]*)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RewriteHtmlAttributeDouble();

    [GeneratedRegex("(href|src|action|data-href|data-src|poster|background|formaction|cite|longdesc|usemap)(\\s*=\\s*)'(/[^']*)'", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RewriteHtmlAttributeSingle();

    [GeneratedRegex("(srcset)(\\s*=\\s*)\"([^\"]*)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RewriteSrcsetDouble();

    [GeneratedRegex("(srcset)(\\s*=\\s*)'([^']*)'", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RewriteSrcsetSingle();

    [GeneratedRegex("url\\(\\s*(['\"]?)(/[^'\")\\s]+)['\"]?\\s*\\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RewriteCssUrl();

    [GeneratedRegex("(@import\\s+)(['\"])(/[^'\"]*)['\"]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RewriteCssImport();

    [GeneratedRegex("<head\\b[^>]*>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HeadTag();

    [GeneratedRegex("<html\\b[^>]*>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HtmlTag();
}
