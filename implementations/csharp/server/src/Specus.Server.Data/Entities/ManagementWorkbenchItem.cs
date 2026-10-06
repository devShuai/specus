namespace Specus.Server.Data.Entities;

/// <summary>
/// One reference on a management identity's service workbench (protocol/spec/service-workbench.md):
/// a favourite or a recent open of an HTTP route, TCP mapping or Peer service. The row holds the
/// identity, the reference and one time, nothing else -- no names, addresses, ports or anything
/// about the access itself. The key is (tenant, username, list, kind, object id); there is no
/// surrogate id and no foreign key, so object and account deletions clean these rows explicitly.
/// </summary>
public sealed class ManagementWorkbenchItem
{
    public string TenantId { get; set; } = "default";

    /// <summary>The account's canonical username, as <c>GET /api/admin/me</c> returns it.</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary><c>favorite</c> or <c>recent</c>.</summary>
    public string List { get; set; } = string.Empty;

    /// <summary><c>http-route</c>, <c>tcp-mapping</c> or <c>peer-service</c>.</summary>
    public string Kind { get; set; } = string.Empty;

    public long ObjectId { get; set; }

    /// <summary>
    /// Epoch milliseconds from the server clock: when a favourite was added, or when a recent entry
    /// was last opened.
    /// </summary>
    public long AtMs { get; set; }
}
