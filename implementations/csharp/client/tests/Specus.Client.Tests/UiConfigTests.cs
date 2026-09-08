using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Specus.Client.Cli;

namespace Specus.Client.Tests;

public class UiConfigTests
{
    [Fact]
    public void ArgumentsAreUiOnlyAndBounded()
    {
        var options = ClientCliOptions.Parse(["ui", "--no-open", "--port=8765"]);
        Assert.True(options.NoOpen); Assert.Equal(8765, options.UiPort);
        foreach (string[] args in new string[][] { ["--no-open"], ["--port=0"], ["ui", "--port=-1"], ["ui", "--port=65536"], ["ui", "--port"], ["ui", "--json"], ["ui", "--debug"], ["ui", "--auto-update"], ["ui", "--no-update"] })
            Assert.Throws<ArgumentException>(() => ClientCliOptions.Parse(args));
    }
    [Fact]
    public void EditsAreLosslessRedactedValidatedAndConflictChecked()
    {
        var directory = Directory.CreateTempSubdirectory("ui-config-test-");
        try
        {
            string path = Path.Combine(directory.FullName, "config.jsonc");
            string text = "/* { 前导注释 */\n{\n // 凭据\n \"apiKey\":\"PRIVATE_KEY\",\"secret\":\"PRIVATE_SECRET\",\n \"serverBaseUrl\":\"http://localhost:1\",\"unknown\":{\"nested\":[1,{\"x\":true}]},\n}\n// 尾部";
            File.WriteAllText(path, text); var revision = UiConfig.Read(path).Revision;
            var edit = JsonSerializer.SerializeToNode(new { revision, changes = new { serverBaseUrl = "http://localhost:2", secret = "", peerMeshDevice = "noop" } })!.AsObject();
            var prepared = UiConfig.Prepare(path, edit, []); Assert.Equal(text, File.ReadAllText(path));
            string output = Encoding.UTF8.GetString(prepared);
            Assert.Contains("/* { 前导注释 */", output); Assert.Contains("// 尾部", output); Assert.Contains("\"unknown\":{\"nested\":[1,{\"x\":true}]}", output); Assert.Contains("PRIVATE_SECRET", output);
            UiConfig.Save(path, revision, prepared); CliState.CheckPrivate(path);
            var view = JsonSerializer.Serialize(UiConfig.View(path)); Assert.DoesNotContain("PRIVATE_KEY", view); Assert.DoesNotContain("PRIVATE_SECRET", view);
            Assert.Equal(409, Assert.Throws<LocalUi.Failure>(() => UiConfig.Save(path, revision, prepared)).Status);
        }
        finally { directory.Delete(true); }
    }
    [Theory]
    [InlineData("{\"secret\":\"a\",\"secret\":\"b\"}")]
    [InlineData("{\"Secret\":\"x\"}")]
    [InlineData("{\"secret\":\"a\",\"secr\\u0065t\":\"b\"}")]
    [InlineData("{\"x\":[1}}")]
    [InlineData("{}{}")]
    [InlineData("[]")]
    [InlineData("{\"x\":\"unterminated}")]
    public void MalformedOrAmbiguousDocumentsAreRejected(string text) => Assert.Throws<LocalUi.Failure>(() => UiConfig.Parse(Encoding.UTF8.GetBytes(text)));
    [Fact]
    public void UnsafeChangesAndPathsAreRejectedWithoutWriting()
    {
        var directory = Directory.CreateTempSubdirectory("ui-config-test-");
        try
        {
            string path = Path.Combine(directory.FullName, "new.jsonc");
            foreach (string changes in new[] { "{\"serverBaseUrl\":\"http://user:pass@localhost\"}", "{\"serverBaseUrl\":\"http://localhost/?token=x\"}", "{\"peerMeshDevice\":\"tun\"}", "{\"unknown\":\"x\"}", "{\"secret\":12}" })
            {
                var edit = JsonNode.Parse("{\"revision\":\"missing\",\"changes\":" + changes + "}")!.AsObject();
                Assert.Throws<LocalUi.Failure>(() => UiConfig.Prepare(path, edit, []));
            }
            Assert.False(File.Exists(path)); Assert.Throws<LocalUi.Failure>(() => UiConfig.Read(directory.FullName));
        }
        finally { directory.Delete(true); }
    }
}
