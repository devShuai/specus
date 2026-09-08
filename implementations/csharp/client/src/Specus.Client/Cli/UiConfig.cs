using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Specus.Client.Configuration;

namespace Specus.Client.Cli;

/// <summary>Byte-span JSONC edits preserve comments, unknown fields and secret references.</summary>
internal static class UiConfig
{
    internal static readonly string[] Fields = ["serverBaseUrl", "apiKey", "secret", "peerMeshDevice"];
    internal sealed record Snapshot(byte[] Bytes, string Revision);
    internal sealed record Document(JsonObject Raw, Dictionary<string, (int Start, int End)> Spans, int Opening);
    internal static LocalUi.Failure Invalid() => new(422, "无法安全编辑配置，请使用外部编辑器检查语法、重复字段和权限");
    internal static Snapshot Read(string path)
    {
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            try
            {
                var attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0 || current == path && (attributes & (FileAttributes.Directory | FileAttributes.Device)) != 0) throw Invalid();
            }
            catch (FileNotFoundException) when (current == path) { }
        }
        if (!File.Exists(path)) return new("{}"u8.ToArray(), "missing");
        // Empty existing configs are invalid JSON; reject them before open as well.
        // This also avoids blocking on Unix FIFO/device entries reporting zero size.
        long length = new FileInfo(path).Length;
        if (length <= 0 || length > 1024 * 1024) throw Invalid();
        using var stream = File.OpenRead(path);
        if (stream.Length > 1024 * 1024) throw Invalid();
        byte[] bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw Invalid();
        return new(bytes, Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }
    internal static Document Parse(byte[] bytes)
    {
        try
        {
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) throw Invalid();
            int opening = (int)reader.TokenStartIndex;
            var spans = new Dictionary<string, (int, int)>();
            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                if (reader.TokenType != JsonTokenType.PropertyName) throw Invalid();
                string key = reader.GetString()!;
                if (spans.ContainsKey(key) || Fields.Any(f => f.Equals(key, StringComparison.OrdinalIgnoreCase) && f != key)) throw Invalid();
                if (!reader.Read()) throw Invalid();
                int start = (int)reader.TokenStartIndex; reader.Skip(); spans.Add(key, (start, (int)reader.BytesConsumed));
            }
            if (reader.TokenType != JsonTokenType.EndObject || reader.Read()) throw Invalid();
            var raw = JsonNode.Parse(bytes, documentOptions: new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true }) as JsonObject ?? throw Invalid();
            return new(raw, spans, opening);
        }
        catch (JsonException) { throw Invalid(); }
    }
    internal static object View(string path)
    {
        var snapshot = Read(path); var raw = Parse(snapshot.Bytes).Raw;
        return new { schemaVersion = 1, revision = snapshot.Revision, exists = snapshot.Revision != "missing", configPath = path,
            fields = new { serverBaseUrl = CliOutput.SafeUrl(raw["serverBaseUrl"]?.GetValue<string>() ?? ""), peerMeshDevice = raw["peerMeshDevice"]?.GetValue<string>() ?? "noop" },
            hasApiKey = !string.IsNullOrWhiteSpace(raw["apiKey"]?.GetValue<string>()), hasSecret = !string.IsNullOrWhiteSpace(raw["secret"]?.GetValue<string>()), editableFields = Fields };
    }
    internal static void CheckRevision(Snapshot snapshot, string revision)
    { if (snapshot.Revision != revision) throw new LocalUi.Failure(409, "配置已被修改，请重新载入后再操作"); }
    internal static byte[] Prepare(string path, JsonObject edit, List<string> warnings)
    {
        var snapshot = Read(path); CheckRevision(snapshot, edit["revision"]?.GetValue<string>() ?? "");
        var doc = Parse(snapshot.Bytes);
        var changes = edit["changes"] as JsonObject ?? throw Invalid();
        var replacements = new List<(int Start, int End, byte[] Bytes)>(); var additions = new List<string>();
        foreach (var (key, node) in changes)
        {
            if (!Fields.Contains(key) || node is not JsonValue scalar || !scalar.TryGetValue<string>(out var value)) throw Invalid();
            if ((key is "apiKey" or "secret") && string.IsNullOrWhiteSpace(value)) continue;
            if (key == "serverBaseUrl" && (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "")) throw Invalid();
            if (key == "peerMeshDevice" && value is not ("noop" or "auto")) throw Invalid();
            var quoted = JsonSerializer.Serialize(value);
            if (doc.Spans.TryGetValue(key, out var span)) replacements.Add((span.Start, span.End, Encoding.UTF8.GetBytes(quoted)));
            else additions.Add(JsonSerializer.Serialize(key) + ": " + quoted);
        }
        if (additions.Count > 0) replacements.Add((doc.Opening + 1, doc.Opening + 1, Encoding.UTF8.GetBytes("\n  " + string.Join(",\n  ", additions) + (doc.Spans.Count == 0 ? "\n" : ","))));
        using var output = new MemoryStream(); int offset = 0;
        foreach (var replacement in replacements.OrderBy(r => r.Start))
        { output.Write(snapshot.Bytes.AsSpan(offset, replacement.Start - offset)); output.Write(replacement.Bytes); offset = replacement.End; }
        output.Write(snapshot.Bytes.AsSpan(offset)); var bytes = output.ToArray();
        if (bytes.Length > 1024 * 1024) throw Invalid();
        SpecusClientConfigLoader.Parse(new UTF8Encoding(false, true).GetString(bytes), path, warnings.Add);
        return bytes;
    }
    internal static void Save(string path, string revision, byte[] bytes)
    {
        CheckRevision(Read(path), revision);
        if (File.Exists(path) && ((File.GetAttributes(path) & FileAttributes.ReadOnly) != 0 || !OperatingSystem.IsWindows() && (File.GetUnixFileMode(path) & UnixFileMode.UserWrite) == 0)) throw Invalid();
        string directory = Path.Combine(Path.GetDirectoryName(path)!, ".specus-ui-save-" + Guid.NewGuid().ToString("N"));
        string temp = Path.Combine(directory, "config");
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var owner = WindowsIdentity.GetCurrent().User!; var acl = new DirectorySecurity();
                acl.SetOwner(owner); acl.SetAccessRuleProtection(true, false);
                acl.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                new DirectoryInfo(directory).Create(acl);
            }
            else Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            CliState.CheckPrivate(directory);
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temp, options)) { stream.Write(bytes); stream.Flush(true); }
            CheckRevision(Read(path), revision); File.Move(temp, path, overwrite: true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); if (Directory.Exists(directory)) Directory.Delete(directory); }
    }
}
