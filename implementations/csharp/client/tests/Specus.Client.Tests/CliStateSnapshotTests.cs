using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Specus.Client.Cli;
using Xunit;

namespace Specus.Client.Tests;

public sealed class CliStateSnapshotTests
{
    [Fact]
    public void HeldSnapshotDoesNotBlockAtomicPublicationAndReadsItsOwnGeneration()
    {
        string root = CliState.EnsureRoot(Path.Combine(Path.GetTempPath(), "specus-state-snapshot-" + Guid.NewGuid().ToString("N")));
        string current = Path.Combine(root, "current.json"), next = Path.Combine(root, "next.tmp");
        try
        {
            Write(current, "{\"generation\":1}"); Write(next, "{\"generation\":2}");
            using (var old = CliState.OpenSnapshot(current))
            {
                CliState.PublishSnapshot(next, current);
                using var previous = JsonDocument.Parse(old);
                Assert.Equal(1, previous.RootElement.GetProperty("generation").GetInt32());
                using var latest = CliState.OpenSnapshot(current);
                using var published = JsonDocument.Parse(latest);
                Assert.Equal(2, published.RootElement.GetProperty("generation").GetInt32());
            }
            CliState.CheckPrivate(current);
        }
        finally { File.Delete(current); File.Delete(next); Directory.Delete(root); }
    }

    [Fact]
    public void SharedDeleteDoesNotPermitUnsafeFilePermissions()
    {
        string root = CliState.EnsureRoot(Path.Combine(Path.GetTempPath(), "specus-state-snapshot-" + Guid.NewGuid().ToString("N")));
        string path = Path.Combine(root, "unsafe.json");
        try
        {
            Write(path, "{}"); using (CliState.OpenSnapshot(path)) { }
            if (OperatingSystem.IsWindows())
            {
                var info = new FileInfo(path); var acl = info.GetAccessControl();
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.Read, AccessControlType.Allow));
                info.SetAccessControl(acl);
            }
            else File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            var failure = Assert.Throws<IOException>(() => CliState.OpenSnapshot(path));
            Assert.Contains("owner-only", failure.Message);
        }
        finally { File.Delete(path); Directory.Delete(root); }
    }

    private static void Write(string path, string content)
    {
        File.WriteAllText(path, content); CliState.ProtectNewFile(path);
    }

    [Fact]
    public void SharingRetryRecoversOnlyOnWindows()
    {
        int calls = 0;
        int Read()
        {
            if (++calls < 3) throw new IOException("replacement window", unchecked((int)0x80070020));
            return 7;
        }
        if (OperatingSystem.IsWindows()) { Assert.Equal(7, CliState.RetrySnapshotSharing(Read)); Assert.Equal(3, calls); }
        else { Assert.Throws<IOException>(() => CliState.RetrySnapshotSharing(Read)); Assert.Equal(1, calls); }
    }

    [Fact]
    public void PersistentSharingFailureIsBoundedAndStillFails()
    {
        int calls = 0;
        var failure = new IOException("still locked", unchecked((int)0x80070020));
        Assert.Same(failure, Assert.Throws<IOException>(() => CliState.RetrySnapshotSharing<int>(() => { calls++; throw failure; })));
        Assert.Equal(OperatingSystem.IsWindows() ? 6 : 1, calls);
    }

    [Fact]
    public void PrivacyAndOtherIoFailuresAreNeverRetried()
    {
        foreach (Exception failure in new Exception[] { new IOException("owner-only"), new UnauthorizedAccessException(),
                     new IOException("denied", unchecked((int)0x80070005)), new FileNotFoundException() })
        {
            int calls = 0;
            var actual = Record.Exception(() => CliState.RetrySnapshotSharing<int>(() => { calls++; throw failure; }));
            Assert.Same(failure, actual); Assert.Equal(1, calls);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PublicationDoesNotWriteIntoUnsafeDestinationOrRoot(bool unsafeRoot)
    {
        string root = CliState.EnsureRoot(Path.Combine(Path.GetTempPath(), "specus-state-snapshot-" + Guid.NewGuid().ToString("N")));
        string current = Path.Combine(root, "current.json"), next = Path.Combine(root, "next.tmp");
        try
        {
            Write(current, "old"); Write(next, "new");
            string unsafePath = unsafeRoot ? root : current;
            if (OperatingSystem.IsWindows())
            {
                FileSystemSecurity acl = unsafeRoot ? new DirectoryInfo(root).GetAccessControl() : new FileInfo(current).GetAccessControl();
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.Read, AccessControlType.Allow));
                if (unsafeRoot) new DirectoryInfo(root).SetAccessControl((DirectorySecurity)acl);
                else new FileInfo(current).SetAccessControl((FileSecurity)acl);
            }
            else File.SetUnixFileMode(unsafePath, File.GetUnixFileMode(unsafePath) | UnixFileMode.GroupRead);
            Assert.Throws<IOException>(() => CliState.PublishSnapshot(next, current));
            Assert.Equal("old", File.ReadAllText(current)); Assert.Equal("new", File.ReadAllText(next));
        }
        finally { File.Delete(current); File.Delete(next); Directory.Delete(root); }
    }
}
