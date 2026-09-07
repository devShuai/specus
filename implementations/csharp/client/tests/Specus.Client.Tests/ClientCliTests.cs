using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Specus.Client.Cli;
using Specus.Client.Control;
using Specus.Client.Configuration;
using System.Diagnostics;

namespace Specus.Client.Tests;

public class ClientCliTests
{
    [Theory]
    [InlineData(401, false, 3)]
    [InlineData(403, false, 3)]
    [InlineData(409, false, 3)]
    [InlineData(429, true, 1)]
    [InlineData(503, true, 1)]
    [InlineData(302, false, 1)]
    public void SharedHttpAuthenticationClassificationIsSafe(int status, bool retryable, int exitCode)
    {
        using var response = new HttpResponseMessage((System.Net.HttpStatusCode)status) { Content = new StringContent("DO_NOT_PRINT_TOKEN") };
        response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(120));
        var failure = HttpLoginFailure.FromResponse(response);
        Assert.Equal(retryable, failure.Retryable); Assert.Equal(exitCode, failure.ExitCode);
        Assert.DoesNotContain("DO_NOT_PRINT_TOKEN", failure.ToString());
        Assert.Equal(TimeSpan.FromSeconds(120), failure.RetryAfter);
    }

    [Fact]
    public void EffectiveConfigRedactsCredentialsAndUrlSecretsWithoutMutatingInput()
    {
        var config = new SpecusClientConfig { ApiKey = "DO_NOT_PRINT_KEY", Secret = "DO_NOT_PRINT_SECRET",
            ServerBaseUrl = "http://user:DO_NOT_PRINT_SECRET@localhost:80/base?token=DO_NOT_PRINT_TOKEN#private" };
        var json = CliOutput.RedactedConfig(config).ToJsonString();
        Assert.DoesNotContain("DO_NOT_PRINT", json); Assert.DoesNotContain("#private", json);
        Assert.Equal("DO_NOT_PRINT_SECRET", config.Secret);
    }
    [Theory]
    [InlineData("--help", 0, "Usage:")]
    [InlineData("--version", 0, "")]
    [InlineData("unknown-command", 2, "Unknown command")]
    [InlineData("--config", 2, "requires a path")]
    [InlineData("--config=missing.jsonc", 2, "configuration")]
    [InlineData("validate-test", 0, "offline")]
    [InlineData("invalid-test", 2, "apiKey")]
    [InlineData("diagnostics-test", 0, "Warning:")]
    public async Task ProcessEntryDoesNotRequireConfigForHelpOrStartOnInvalidArgs(string arg, int code, string text)
    {
        var directory = Directory.CreateTempSubdirectory("specus-cli-test-");
        try
        {
            var start = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = directory.FullName,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.ArgumentList.Add(typeof(SpecusControlClient).Assembly.Location);
            if (arg is "validate-test" or "invalid-test" or "diagnostics-test")
            {
                var path = Path.Combine(directory.FullName, "path with spaces.jsonc");
                await File.WriteAllTextAsync(path, arg == "invalid-test"
                    ? "{\"serverBaseUrl\":\"http://127.0.0.1:1\"}" : arg == "diagnostics-test" ? """
                    {"serverBaseUrl":"http://127.0.0.1:1","apiKey":"test","secret":"DO_NOT_PRINT_SECRET","peerMeshMtu":9999,"typo":"DO_NOT_PRINT_SECRET"}
                    """ : """
                    {"serverBaseUrl":"http://127.0.0.1:1","apiKey":"test","secret":"DO_NOT_PRINT_SECRET"}
                    """);
                foreach (var value in new[] { "config", "validate", "--config", path }) start.ArgumentList.Add(value);
            }
            else start.ArgumentList.Add(arg);
            using var process = Process.Start(start)!;
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); throw; }
            var output = await stdout;
            var errors = await stderr;
            Assert.Equal(code, process.ExitCode);
            Assert.Contains(text, output + errors);
            Assert.DoesNotContain("DO_NOT_PRINT_SECRET", output + errors);
            if (arg == "diagnostics-test")
            {
                Assert.Contains("peerMeshMtu normalized to 1280", errors);
                Assert.DoesNotContain("Warning:", output);
            }
            else Assert.Empty(code == 0 ? errors : output);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Theory]
    [InlineData("unknown-command")]
    [InlineData("--unknown")]
    [InlineData("--config")]
    [InlineData("--config=")]
    [InlineData("--config", "--version")]
    [InlineData("--help", "extra")]
    [InlineData("config")]
    [InlineData("config", "unknown")]
    public void InvalidArgumentsAreRejectedBeforeConfiguration(params string[] args) =>
        Assert.Throws<ArgumentException>(() => ClientCliOptions.Parse(args));

    [Fact]
    public void ConfigPathAndAliasesArePreserved()
    {
        var options = ClientCliOptions.Parse(["config", "validate", "-c", "path with spaces/client.jsonc"]);
        Assert.Equal("validate", options.Command);
        Assert.Equal("path with spaces/client.jsonc", options.ConfigPath);
        Assert.True(ClientCliOptions.Parse(["--help"]).Help);
        Assert.True(ClientCliOptions.Parse(["--version"]).Version);
        Assert.True(ClientCliOptions.Parse(["--no-update"]).NoUpdate);
    }

    [Fact]
    public void DiagnosticsWarnForNestedUnknownAndNormalizedFieldsWithoutValues()
    {
        var warnings = new List<string>();
        ConfigDiagnostics.Report("""
            {"APIKEY":"DO_NOT_PRINT_KEY","secret":"DO_NOT_PRINT_SECRET","peerMeshMtu":9999,
             "updateCheckIntervalHours":9999,"typo":"DO_NOT_PRINT_UNKNOWN",
             "controlTls":{"serverNmae":"DO_NOT_PRINT_HOST","ENABLED":false},
             "upstreamTls":{},"openUpdatePage":true,"bad\nname":"DO_NOT_PRINT_UNKNOWN"}
            """, new SpecusClientConfig { UpdateCheckIntervalHours = 168 }, warnings.Add);
        var text = string.Join("|", warnings);
        Assert.Contains("controlTls.serverNmae", text);
        Assert.Contains("peerMeshMtu normalized to 1280", text);
        Assert.Contains("updateCheckIntervalHours normalized to 168", text);
        Assert.Contains("not used by .NET", text);
        Assert.DoesNotContain("DO_NOT_PRINT", text);
        Assert.DoesNotContain("APIKEY", text);
        Assert.DoesNotContain("ENABLED", text);
        Assert.DoesNotContain('\n', text);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TerminalReturnOrExceptionStopsHostWithFailure(bool throws)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<ClientExitStatus>();
        builder.Services.AddHostedService(sp => new ClientRunHostedService(
            _ => throws ? Task.FromException(new InvalidOperationException("injected")) : Task.CompletedTask,
            sp.GetRequiredService<IHostApplicationLifetime>(), sp.GetRequiredService<ClientExitStatus>(),
            sp.GetRequiredService<ILogger<ClientRunHostedService>>()));
        using var host = builder.Build();
        var exit = host.Services.GetRequiredService<ClientExitStatus>();
        await host.RunAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, exit.Code);
    }

    [Fact]
    public async Task UserShutdownKeepsSuccessfulExitCode()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<ClientExitStatus>();
        builder.Services.AddHostedService(sp => new ClientRunHostedService(async token =>
        {
            started.SetResult();
            await Task.Delay(Timeout.Infinite, token);
        }, sp.GetRequiredService<IHostApplicationLifetime>(), sp.GetRequiredService<ClientExitStatus>(),
            sp.GetRequiredService<ILogger<ClientRunHostedService>>()));
        using var host = builder.Build();
        var exit = host.Services.GetRequiredService<ClientExitStatus>();
        var lifetime = host.Services.GetRequiredService<IHostApplicationLifetime>();
        var run = host.RunAsync();
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        lifetime.StopApplication();
        await run.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, exit.Code);
    }
}
