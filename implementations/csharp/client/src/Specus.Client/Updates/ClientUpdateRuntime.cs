using System.Reflection;

namespace Specus.Client.Updates;

public static class ClientUpdateRuntime
{
    public static ClientUpdateInstallationRequest CreateCurrentProcessRequest()
    {
        var applicationDirectory = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(AppContext.BaseDirectory));
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath) || !Path.IsPathFullyQualified(processPath))
        {
            throw new InvalidOperationException("The current client process cannot be restarted safely");
        }
        processPath = Path.GetFullPath(processPath);

        // Assembly.Location is empty for the single-file desktop release. In that case the
        // apphost itself is both the restart command and the package entry we require.
        var assemblyPath = Assembly.GetEntryAssembly()?.Location;
        var entryPath = ExistingContainedFile(assemblyPath, applicationDirectory)
            ?? ExistingContainedFile(processPath, applicationDirectory)
            ?? throw new InvalidOperationException("The current client entry file cannot be located");

        var commandLine = Environment.GetCommandLineArgs();
        IReadOnlyList<string> restartArguments;
        if (string.Equals(Path.GetFileNameWithoutExtension(processPath), "dotnet",
                StringComparison.OrdinalIgnoreCase))
        {
            restartArguments = new[] { entryPath }.Concat(commandLine.Skip(1)).ToArray();
        }
        else
        {
            restartArguments = commandLine.Skip(1).ToArray();
        }

        return new ClientUpdateInstallationRequest(
            applicationDirectory,
            entryPath,
            processPath,
            restartArguments,
            Environment.ProcessId);
    }

    private static string? ExistingContainedFile(string? path, string directory)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }
        var fullPath = Path.GetFullPath(path);
        var prefix = directory + Path.DirectorySeparatorChar;
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        return File.Exists(fullPath) && fullPath.StartsWith(prefix, comparison) ? fullPath : null;
    }
}
