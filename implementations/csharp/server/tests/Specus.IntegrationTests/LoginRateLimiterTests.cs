using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

public sealed class LoginRateLimiterTests
{
    [Fact]
    public void BlocksPerSourceIpAcrossDifferentAccounts()
    {
        var limiter = Limiter(perIp: 3, perAccount: 100);
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            Assert.True(limiter.TryAcquire("203.0.113.10", $"user-{attempt}", out _));
        }

        Assert.False(limiter.TryAcquire("203.0.113.10", "user-4", out var retryAfter));
        Assert.InRange(retryAfter, 1, 300);
        // A different source IP is unaffected by another IP's budget.
        Assert.True(limiter.TryAcquire("203.0.113.11", "user-4", out _));
    }

    [Fact]
    public void BlocksPerAccountAcrossRotatingSourceIps()
    {
        var limiter = Limiter(perIp: 100, perAccount: 3);
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            Assert.True(limiter.TryAcquire($"203.0.113.{attempt}", "victim", out _));
        }

        Assert.False(limiter.TryAcquire("203.0.113.99", "victim", out _));
        // Account keys are case-insensitive so casing cannot reset the budget.
        Assert.False(limiter.TryAcquire("203.0.113.98", "VICTIM", out _));
        Assert.True(limiter.TryAcquire("203.0.113.97", "other-account", out _));
    }

    [Fact]
    public void RejectionDoesNotRevealWhetherAccountExists()
    {
        var limiter = Limiter(perIp: 1, perAccount: 100);
        limiter.TryAcquire("203.0.113.10", "known-account", out _);

        Assert.False(limiter.TryAcquire("203.0.113.10", "known-account", out var knownRetry));
        Assert.False(limiter.TryAcquire("203.0.113.10", "does-not-exist", out var unknownRetry));
        Assert.InRange(knownRetry, 1, 300);
        Assert.InRange(unknownRetry, 1, 300);
    }

    [Fact]
    public void SuccessClearsAccountBudgetButKeepsSourceIpBudget()
    {
        var limiter = Limiter(perIp: 3, perAccount: 2);
        limiter.TryAcquire("203.0.113.10", "alice", out _);
        limiter.TryAcquire("203.0.113.10", "alice", out _);
        limiter.RecordSuccess("alice");

        Assert.True(limiter.TryAcquire("203.0.113.10", "alice", out _));
        Assert.False(limiter.TryAcquire("203.0.113.10", "bob", out _));
    }

    [Fact]
    public void DisabledConfigurationSkipsThrottling()
    {
        var limiter = Limiter(perIp: 1, perAccount: 1, enabled: false);
        for (var attempt = 0; attempt < 10; attempt++)
        {
            Assert.True(limiter.TryAcquire("203.0.113.10", "alice", out _));
        }
    }

    [Theory]
    [InlineData(null, DeploymentEnvironment.Prod)]
    [InlineData("", DeploymentEnvironment.Prod)]
    [InlineData("staging", DeploymentEnvironment.Prod)]
    [InlineData(" DEV ", DeploymentEnvironment.Dev)]
    [InlineData("Test", DeploymentEnvironment.Test)]
    public void UnknownEnvironmentResolvesToProd(string? value, DeploymentEnvironment expected)
    {
        Assert.Equal(expected, DeploymentEnvironments.Parse(value));
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("password")]
    [InlineData("123456")]
    [InlineData("12345678")]
    [InlineData(" test1234 ")]
    [InlineData("changeme")]
    [InlineData("change_me_admin_password")]
    [InlineData("change-me-before-exposure")]
    [InlineData("change-me")]
    [InlineData("specus")]
    [InlineData("demo")]
    public void ProdRefusesKnownDefaultPasswords(string password)
    {
        Assert.NotNull(DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Prod, true, password));
    }

    [Fact]
    public void ProdAcceptsOnlyNonDefaultOrDisabledPasswordLogin()
    {
        // Strong password, blank password and disabled password login are all acceptable.
        Assert.Null(DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Prod, true, "8Qb!x2s7Lm#4pTz"));
        Assert.Null(DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Prod, true, ""));
        Assert.Null(DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Prod, false, "admin"));
        // Non-prod only warns.
        Assert.Null(DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Dev, true, "admin"));
    }

    [Fact]
    public void ProdRefusesPublishedJwtPlaceholderEvenWhenPasswordLoginIsDisabled()
    {
        Assert.NotNull(DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Prod, false, string.Empty, " replace-with-a-long-random-secret "));
        Assert.Null(DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Prod, false, string.Empty, "unique-random-deployment-secret"));
        Assert.Null(DeploymentEnvironments.DescribeSecurityBaselineViolation(
            DeploymentEnvironment.Test, false, string.Empty, "replace-with-a-long-random-secret"));
    }

    [Fact]
    public void OnlyNonProdEnvironmentsAllowDemoData()
    {
        Assert.False(DeploymentEnvironment.Prod.AllowsDemoData());
        Assert.True(DeploymentEnvironment.Dev.AllowsDemoData());
        Assert.True(DeploymentEnvironment.Test.AllowsDemoData());
    }

    [Fact]
    public void DefaultOptionsShipNoPasswordCredential()
    {
        var options = new AuthOptions();
        Assert.Equal(string.Empty, options.Password);
        Assert.True(options.LoginRateLimitEnabled);
        Assert.True(options.LoginRateLimitPerIp > 0);
        Assert.True(options.LoginRateLimitPerAccount > 0);
    }

    private static LoginRateLimiter Limiter(int perIp, int perAccount, bool enabled = true)
    {
        var options = new AuthOptions
        {
            LoginRateLimitEnabled = enabled,
            LoginRateLimitPerIp = perIp,
            LoginRateLimitPerAccount = perAccount,
            LoginRateLimitWindowSeconds = 300,
        };
        return new LoginRateLimiter(Options.Create(options), NullLogger<LoginRateLimiter>.Instance);
    }
}
