namespace Specus.Server.Management;

/// <summary>
/// Security headers for the management SPA and API responses. The directives mirror Java's
/// <c>SecurityConfig</c> CSP. Scripts stay same-origin (Vite emits external module bundles);
/// <c>'unsafe-inline'</c> is allowed for styles because the React/HeroUI bundle sets inline
/// style attributes (framer-motion). WebSocket connects target the same origin, while the public
/// GitHub API supplies the latest client release metadata.
/// </summary>
public static class ManagementPageSecurityHeaders
{
    private const string ContentSecurityPolicy =
        "default-src 'self'; "
        + "script-src 'self' https://www.googletagmanager.com https://challenges.cloudflare.com "
        + "'sha256-18LyML/37soz5WqRSkGT3SWKUgOA6TN/LeY+x9y/X/Q=' "
        + "'sha256-sTRDNOsQlwtkSpNEy6tDUxqi0/WSUG1VrhzE550hzwo='; "
        + "style-src 'self' 'unsafe-inline'; "
        + "img-src 'self' blob: data: https://www.google-analytics.com https://*.googletagmanager.com; "
        + "media-src 'self' blob: data:; "
        + "object-src 'self' blob:; "
        + "font-src 'self' data:; "
        + "frame-src 'self' https://challenges.cloudflare.com; "
        + "connect-src 'self' ws: wss: https://api.github.com https://www.google-analytics.com "
        + "https://*.analytics.google.com https://*.googletagmanager.com; "
        + "form-action 'self'; "
        + "frame-ancestors 'none'; "
        + "base-uri 'self'";

    public static WebApplication UseManagementSecurityHeaders(this WebApplication app)
    {
        app.Use(static (context, next) =>
        {
            if (IsHttpSpecusIngress(context.Request.Path))
            {
                return next();
            }
            var headers = context.Response.Headers;
            headers["Content-Security-Policy"] = ContentSecurityPolicy;
            headers["X-Frame-Options"] = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            headers["X-Content-Type-Options"] = "nosniff";
            return next();
        });
        return app;
    }

    private static bool IsHttpSpecusIngress(PathString path) =>
        path.StartsWithSegments("/http");
}
