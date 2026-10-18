using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Specus.Client.Control;

namespace Specus.Client.Tests;

public sealed class ClientHostConfigurationTests
{
    [Theory]
    [InlineData("appsettings.json")]
    [InlineData("appsettings.Production.json")]
    [InlineData("specus-client.settings.json")]
    public async Task ExplicitJsoncRunDoesNotReadUnrelatedWorkingDirectorySettings(string foreignFile)
    {
        var directory = Directory.CreateTempSubdirectory("specus-cli-host-config-");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var accepted = listener.AcceptTcpClientAsync(deadline.Token).AsTask();
        Process? process = null;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(directory.FullName, foreignFile), "{\"DO_NOT_PRINT_FOREIGN_SETTING\":");
            var config = Path.Combine(directory.FullName, "explicit config.jsonc");
            await File.WriteAllTextAsync(config, JsonSerializer.Serialize(new {
                serverBaseUrl = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}",
                apiKey = "test", secret = "DO_NOT_PRINT_SECRET", peerMeshDevice = "noop"
            }));
            var start = new ProcessStartInfo("dotnet") {
                WorkingDirectory = directory.FullName, UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            foreach (var arg in new[] {typeof(SpecusControlClient).Assembly.Location, "run", "--config", config,
                "--no-update-check", "--login-timeout", "1"}) { start.ArgumentList.Add(arg); }
            start.Environment["SPECUS_CLI_STATE_DIR"] = Path.Combine(directory.FullName, "state");
            start.Environment["DOTNET_ENVIRONMENT"] = "Production";
            process = Process.Start(start)!;
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync(deadline.Token);
            var text = await stdout + await stderr;
            Assert.Contains("loaded config from", text);
            Assert.True(accepted.IsCompletedSuccessfully, "the explicit configuration never reached HTTP login");
            Assert.Equal(4, process.ExitCode); // The owned listener causes the documented network-timeout exit.
            Assert.DoesNotContain("DO_NOT_PRINT", text);
            Assert.DoesNotContain(foreignFile, text);
        }
        finally
        {
            if (process is not null)
            {
                if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); }
                process.Dispose();
            }
            listener.Stop();
            try { using var connection = await accepted; }
            catch (Exception error) when (error is SocketException or OperationCanceledException) { }
            directory.Delete(recursive: true);
        }
    }
}
