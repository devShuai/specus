using System.Security.Claims;
using Specus.Server.Configuration;
using Specus.Server.Data.Entities;

namespace Specus.Server.Management;

public sealed record ManagementContext(
    string TenantId,
    string Username,
    ManagementRole Role,
    bool BuiltInAdmin)
{
    public bool IsAdmin => Role == ManagementRole.Admin;

    public static ManagementContext From(HttpContext httpContext, AuthOptions auth)
    {
        var username = httpContext.User.Identity?.Name
            ?? httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? string.Empty;
        if (string.IsNullOrWhiteSpace(username))
        {
            throw new UnauthorizedAccessException("未授权");
        }

        var tenantId = NormalizeTenant(httpContext.User.FindFirst("tenant_id")?.Value ?? auth.TenantId);
        var role = ParseRole(httpContext.User.FindFirst(ClaimTypes.Role)?.Value
            ?? httpContext.User.FindFirst("role")?.Value);
        var builtIn = string.Equals(username, auth.Username, StringComparison.OrdinalIgnoreCase);
        if (builtIn)
        {
            role = ManagementRole.Admin;
        }
        return new ManagementContext(tenantId, username, role, builtIn);
    }

    public bool CanAccess(ClientAccount account) =>
        SameTenant(TenantId, account.TenantId)
        && (IsAdmin || string.Equals(account.OwnerUsername, Username, StringComparison.Ordinal));

    public bool CanAccess(ClientCredential credential) =>
        SameTenant(TenantId, credential.TenantId)
        && (IsAdmin || string.Equals(credential.OwnerUsername, Username, StringComparison.Ordinal));

    public static string NormalizeTenant(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "default" : value.Trim();

    public static ManagementRole ParseRole(string? value) =>
        string.Equals(value, "ADMIN", StringComparison.OrdinalIgnoreCase)
        || string.Equals(value, "Admin", StringComparison.Ordinal)
            ? ManagementRole.Admin
            : ManagementRole.User;

    public static string RoleWire(ManagementRole role) => role == ManagementRole.Admin ? "ADMIN" : "USER";

    public static bool SameTenant(string? left, string? right) =>
        string.Equals(NormalizeTenant(left), NormalizeTenant(right), StringComparison.Ordinal);
}
