namespace ShuaiTunnel.Server.Management;

/// <summary>
/// Security headers for the management SPA and API responses. The directives mirror Java's
/// <c>SecurityConfig</c> CSP while documenting the functional boundary: static assets, OIDC
/// helpers, WebSocket connects, and admin fetches all stay same-origin.
/// </summary>
public static class ManagementPageSecurityHeaders
{
    private const string ContentSecurityPolicy =
        "default-src 'self'; "
        + "script-src 'self'; "
        + "style-src 'self'; "
        + "img-src 'self' data:; "
        + "connect-src 'self'; "
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
