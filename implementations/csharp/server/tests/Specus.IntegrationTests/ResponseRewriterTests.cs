using System.Reflection;
using System.Text;
using Specus.Server.Authentication;

namespace Specus.IntegrationTests;

public sealed class ResponseRewriterTests
{
    [Fact]
    public void RuntimePolyfillCoversJavaNavigationAndStreamingHooks()
    {
        var body = Encoding.UTF8.GetBytes("<html><head></head><body><img src=\"/img/logo.png\"></body></html>");
        var rewritten = Rewrite(body, "Demo client", "web", ["Content-Type: text/html; charset=UTF-8"]);
        var text = Encoding.UTF8.GetString(rewritten);

        Assert.Contains("src=\"/http/Demo%20client/web/img/logo.png\"", text);
        Assert.Contains("wrapHistory('pushState')", text);
        Assert.Contains("wrapHistory('replaceState')", text);
        Assert.Contains("window.EventSource=function", text);
        Assert.Contains("window.WebSocket=function", text);
        Assert.Contains("function wrapAttr(", text);
        Assert.Contains("HTMLScriptElement", text);
        Assert.Contains("function hrefOf(", text);
        Assert.Contains("function rewriteInput(", text);
        Assert.Contains("loc.ws", text);
        Assert.Contains("location.origin", text);
    }

    private static byte[] Rewrite(byte[] body, string clientName, string route, IReadOnlyList<string> headers)
    {
        var type = typeof(ClientAccountService).Assembly.GetType("Specus.Server.Http.ResponseRewriter", throwOnError: true)!;
        var method = type.GetMethod("TryRewrite", BindingFlags.Public | BindingFlags.Static)
            ?? throw new MissingMethodException(type.FullName, "TryRewrite");
        object?[] args = [body, clientName, route, headers, 1024 * 1024, Array.Empty<byte>()];
        var ok = (bool)method.Invoke(null, args)!;
        Assert.True(ok);
        return Assert.IsType<byte[]>(args[5]);
    }
}
