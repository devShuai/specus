using Specus.Client.Configuration;

namespace Specus.Client.Tests;

public sealed class MachineCredentialTests
{
    /// <summary>An existing configuration carries the secret inline; that has to keep working.</summary>
    [Fact]
    public void PlainSecretIsUsedAsIs()
    {
        Assert.Equal("s3cret-value", MachineCredential.Resolve("  s3cret-value  "));
        Assert.False(MachineCredential.IsIndirect("s3cret-value"));
    }

    /// <summary>Naming the secret indirectly keeps it out of a file that gets copied around.</summary>
    [Fact]
    public void SecretCanComeFromTheEnvironment()
    {
        const string name = "SPECUS_DOTNET_SECRET_TEST";
        Environment.SetEnvironmentVariable(name, "from-the-environment");
        try
        {
            Assert.Equal("from-the-environment", MachineCredential.Resolve($"env:{name}"));
            Assert.True(MachineCredential.IsIndirect($"env:{name}"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }

        Assert.Throws<InvalidDataException>(() => MachineCredential.Resolve($"env:{name}"));
        Assert.Throws<InvalidDataException>(() => MachineCredential.Resolve("env:"));
    }

    [Fact]
    public void SecretCanComeFromItsOwnFile()
    {
        var path = WriteSecret("from-the-file\n");
        try
        {
            Assert.Equal("from-the-file", MachineCredential.Resolve($"file:{path}"));
            Assert.True(MachineCredential.IsIndirect($"file:{path}"));
        }
        finally
        {
            File.Delete(path);
        }

        Assert.Throws<InvalidDataException>(() => MachineCredential.Resolve("file:"));
        Assert.Throws<InvalidDataException>(
            () => MachineCredential.Resolve($"file:{Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))}"));
    }

    /// <summary>An empty file must be an error rather than an empty credential.</summary>
    [Fact]
    public void EmptySecretFileIsRejected()
    {
        var path = WriteSecret("   \n");
        try
        {
            Assert.Throws<InvalidDataException>(() => MachineCredential.Resolve($"file:{path}"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// A credential every other local account can read is already leaked, so this refuses rather
    /// than warning. Mode bits only mean something off Windows.
    /// </summary>
    [Fact]
    public void SecretFileReadableByOthersIsRefused()
    {
        if (OperatingSystem.IsWindows())
        {
            // Mode bits are not the access control mechanism here; the Unix behaviour is exercised
            // on Linux, where this assertion is the point of the test.
            return;
        }

        var path = WriteSecret("exposed");
        try
        {
            File.SetUnixFileMode(path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead
                | UnixFileMode.OtherRead);

            var error = Assert.Throws<InvalidDataException>(
                () => MachineCredential.Resolve($"file:{path}"));
            // The message has to say how to fix it, or the refusal is just an obstacle.
            Assert.Contains("chmod 600", error.Message, StringComparison.Ordinal);

            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            Assert.Equal("exposed", MachineCredential.Resolve($"file:{path}"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// Rotation takes effect on the next reconnect, which is only possible because the reference
    /// is resolved each time rather than cached.
    /// </summary>
    [Fact]
    public void RotatingTheFileIsPickedUp()
    {
        var path = WriteSecret("original");
        try
        {
            Assert.Equal("original", MachineCredential.Resolve($"file:{path}"));

            File.WriteAllText(path, "rotated");
            Assert.Equal("rotated", MachineCredential.Resolve($"file:{path}"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string WriteSecret(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"specus-secret-{Guid.NewGuid():N}");
        File.WriteAllText(path, content);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        return path;
    }

    /// <summary>
    /// The rule itself, asserted without needing a filesystem that can express these modes.
    /// Windows cannot set them, so without this the decision would go untested on the machine most
    /// of this is developed on.
    /// </summary>
    [Theory]
    [InlineData(UnixFileMode.UserRead | UnixFileMode.UserWrite, false)]
    [InlineData(UnixFileMode.UserRead, false)]
    [InlineData(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead, true)]
    [InlineData(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead, true)]
    [InlineData(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupWrite, true)]
    [InlineData(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherExecute, true)]
    public void OwnerOnlyIsTheOnlyAcceptableMode(UnixFileMode mode, bool reachable)
    {
        Assert.Equal(reachable, MachineCredential.ReachableByOtherAccounts(mode));
    }
}
