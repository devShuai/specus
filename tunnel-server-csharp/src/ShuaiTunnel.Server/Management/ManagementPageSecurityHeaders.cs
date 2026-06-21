namespace ShuaiTunnel.Server.Management;

/// <summary>
/// Security headers for the management SPA and API responses. The directives mirror Java's
/// <c>SecurityConfig</c> CSP. Scripts stay same-origin (Vite emits external module bundles);
/// <c>'unsafe-inline'</c> is allowed for styles because the React/HeroUI bundle sets inline
/// style attributes (framer-motion). WebSocket connects target the same origin.
/// </summary>
public static class ManagementPageSecurityHeaders
{
    private const string ContentSecurityPolicy =
        "default-src 'self'; "
        + "script-src 'self'; "
        + "style-src 'self' 'unsafe-inline'; "
        + "img-src 'self' data:; "
        + "font-src 'self' data:; "
        + "connect-src 'self' ws: wss:; "
        + "form-action 'self'; "
        + "frame-ancestors 'none'; "
        + "base-uri 'self'";

    public static WebApplication UseManagementSecurityHeaders(this WebApplication app)
    {
        app.Use(static (context, next) =>
        {
            var headers = context.Response.Headers;
            headers["Content-Security-Policy"] = ContentSecurityPolicy;
            headers["X-Frame-Options"] = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            headers["X-Content-Type-Options"] = "nosniff";
            return next();
        });
        return app;
    }
}
