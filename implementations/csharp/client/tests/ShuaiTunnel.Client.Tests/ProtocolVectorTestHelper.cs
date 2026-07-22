using System.Text.Json;

namespace ShuaiTunnel.Client.Tests;

internal static class ProtocolVectorTestHelper
{
    internal static T Read<T>(string relative) where T : class
    {
        var path = FindRepositoryFile(relative);
        return JsonSerializer.Deserialize<T>(
            File.ReadAllText(path),
            new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new InvalidDataException($"invalid protocol vector {relative}");
    }

    private static string FindRepositoryFile(string relative)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, relative.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException($"cannot locate repository file {relative}");
    }
}
