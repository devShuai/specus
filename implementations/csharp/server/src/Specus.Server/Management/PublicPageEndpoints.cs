namespace Specus.Server.Management;

public static class PublicPageEndpoints
{
    public static WebApplication MapPublicPageEntries(this WebApplication app)
    {
        // Exact document entries only. Never turn unknown APIs, assets, or target
        // application/share paths into a successful management document.
        foreach (var entry in new[] { "/nat-detect", "/transfer", "/diagram", "/diagram-embed", "/download" })
        {
            // Endpoint routing already matches an optional trailing slash. The
            // internal static lookup keeps the original browser URL and query.
            app.MapFallbackToFile(entry, "index.html", new StaticFileOptions
            {
                OnPrepareResponse = context => context.Context.Response.Headers.CacheControl = "no-cache"
            });
        }
        return app;
    }
}
