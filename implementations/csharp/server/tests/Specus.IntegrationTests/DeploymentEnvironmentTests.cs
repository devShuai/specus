using Specus.Server.Configuration;

namespace Specus.IntegrationTests;

/// <summary>
/// The production deployment gate: a server that still carries a credential shipped with the
/// project must refuse to start rather than run with it.
///
/// <para>Java has <c>SecurityBaselineValidatorTests</c> and Go has <c>environment_test.go</c>;
/// .NET implemented the same rule but nothing asserted it, so the behaviour could have been
/// weakened without a failing test. The rule matters most in exactly the case nobody exercises
/// locally, because the whole point is what happens on a production host.</para>
/// </summary>
public sealed class DeploymentEnvironmentTests
{
    /// <summary>
    /// An unset or misspelled value must resolve to production. Resolving to dev would mean a typo
    /// silently disables every check this gate exists to enforce.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("prod")]
    [InlineData("PROD")]
    [InlineData("production")]
    [InlineData("prd")]
    [InlineData("not-an-environment")]
    public void UnsetOrUnknownEnvironmentsResolveToProd(string? configured)
    {
        Assert.True(DeploymentEnvironments.Parse(configured).IsProd());
    }

    [Theory]
    [InlineData("dev")]
    [InlineData("DEV")]
    [InlineData("test")]
    public void RecognisedNonProductionEnvironmentsResolveAsSuch(string configured)
    {
        var resolved = DeploymentEnvironments.Parse(configured);
        Assert.False(resolved.IsProd());
    }

    /// <summary>A credential published in this repository is not a credential.</summary>
    [Fact]
    public void ProductionRefusesAKnownDefaultPassword()
    {
        var violation = DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Prod, passwordLoginEnabled: true, password: "admin");

        Assert.NotNull(violation);
        // The message has to say what to do, or the refusal is just an obstacle.
        Assert.Contains("SPECUS_AUTH_PASSWORD", violation!, StringComparison.Ordinal);
    }

    [Fact]
    public void ProductionRefusesAKnownPlaceholderJwtSecret()
    {
        var knownPlaceholder = FindKnownJwtSecret();
        if (knownPlaceholder is null)
        {
            // Nothing is on the list; there is no behaviour to assert rather than a silent pass.
            Assert.Fail("no known placeholder JWT secret is configured to test against");
        }

        var violation = DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Prod, passwordLoginEnabled: false, password: null,
            jwtSecret: knownPlaceholder);

        Assert.NotNull(violation);
        Assert.Contains("SPECUS_AUTH_JWT_SECRET", violation!, StringComparison.Ordinal);
    }

    /// <summary>
    /// A unique credential must start, or the gate would block every legitimate deployment.
    /// </summary>
    [Fact]
    public void ProductionAcceptsAUniqueCredential()
    {
        Assert.Null(DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Prod, passwordLoginEnabled: true,
            password: "a-unique-operator-chosen-password", jwtSecret: "a-unique-random-jwt-secret"));
    }

    /// <summary>
    /// Blank means password login is off, which is a deliberate configuration rather than a weak
    /// one, so it must not be refused.
    /// </summary>
    [Fact]
    public void ProductionAcceptsABlankPasswordBecauseThatDisablesPasswordLogin()
    {
        Assert.Null(DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Prod, passwordLoginEnabled: false, password: ""));
        Assert.False(DeploymentEnvironments.IsKnownDefaultPassword(null));
        Assert.False(DeploymentEnvironments.IsKnownDefaultPassword("   "));
    }

    /// <summary>
    /// The gate is deliberately production-only: refusing a default password in dev would make
    /// local development harder without protecting anything.
    /// </summary>
    [Theory]
    [InlineData("dev")]
    [InlineData("test")]
    public void NonProductionEnvironmentsAllowDefaults(string configured)
    {
        var environment = DeploymentEnvironments.Parse(configured);

        Assert.Null(DeploymentEnvironments.DescribeSecurityBaselineViolation(
            environment, passwordLoginEnabled: true, password: "admin"));
    }

    /// <summary>Surrounding whitespace must not smuggle a default credential past the check.</summary>
    [Fact]
    public void WhitespaceDoesNotDefeatTheCheck()
    {
        Assert.True(DeploymentEnvironments.IsKnownDefaultPassword("  admin  "));
    }

    private static string? FindKnownJwtSecret()
    {
        foreach (var candidate in new[] { "replace-with-a-long-random-secret" })
        {
            if (DeploymentEnvironments.IsKnownDefaultJwtSecret(candidate))
            {
                return candidate;
            }
        }
        return null;
    }
}
