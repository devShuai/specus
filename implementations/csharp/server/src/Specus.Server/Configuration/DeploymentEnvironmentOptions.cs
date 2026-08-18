namespace Specus.Server.Configuration;

/// <summary>
/// Deployment environment that gates demo data and default-credential checks. Unset or unknown
/// values resolve to <see cref="DeploymentEnvironment.Prod"/> so a typo never disables a
/// production guard.
/// </summary>
public enum DeploymentEnvironment
{
    Prod,
    Dev,
    Test,
}

public static class DeploymentEnvironments
{
    /// <summary>Values published in the repository, docs and demo data, plus throwaway passwords.</summary>
    private static readonly HashSet<string> KnownDefaultPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "admin", "password", "123456", "12345678", "changeme", "specus", "test1234", "demo",
    };

    public static DeploymentEnvironment Parse(string? value) =>
        (value ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "dev" or "development" or "local" => DeploymentEnvironment.Dev,
            "test" or "testing" => DeploymentEnvironment.Test,
            _ => DeploymentEnvironment.Prod,
        };

    public static bool AllowsDemoData(this DeploymentEnvironment environment) =>
        environment != DeploymentEnvironment.Prod;

    public static bool IsProd(this DeploymentEnvironment environment) =>
        environment == DeploymentEnvironment.Prod;

    public static bool IsKnownDefaultPassword(string? password) =>
        !string.IsNullOrWhiteSpace(password) && KnownDefaultPasswords.Contains(password.Trim());

    /// <summary>
    /// Returns the startup failure message when a production deployment still carries a credential
    /// that ships with the project, or null when the configuration is acceptable.
    /// </summary>
    public static string? DescribeSecurityBaselineViolation(
        DeploymentEnvironment environment,
        bool passwordLoginEnabled,
        string? password)
    {
        if (!environment.IsProd() || !passwordLoginEnabled || string.IsNullOrWhiteSpace(password))
        {
            return null;
        }
        return IsKnownDefaultPassword(password)
            ? "Specus:Auth:Password is a known default credential and is refused in prod; set "
              + "SPECUS_AUTH_PASSWORD to a unique value or leave it blank to disable password login"
            : null;
    }
}
