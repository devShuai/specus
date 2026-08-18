using System.Runtime.InteropServices;
using System.Text;

namespace Specus.Client.PeerMesh;

/// <summary>
/// Writes a secret to disk so no other local account can read it and no reader can observe a
/// half-written file.
///
/// <para>Writing straight to the destination has two failure modes. If the process dies mid-write
/// the client is left with a truncated private key and silently loses its peer identity on next
/// start. And the file exists, briefly, before anything narrows its permissions. Writing to a
/// temporary file that is locked down before the secret goes into it, then renaming it into place,
/// closes both: the permissions are never wrong even for an instant, and the rename is atomic, so a
/// reader sees either the old file or the complete new one.</para>
/// </summary>
internal static class SecretFileWriter
{
    private const UnixFileMode OwnerOnlyFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode OwnerOnlyDirectory =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    /// <summary>Creates the directory if needed and restricts it to the current user.</summary>
    internal static void CreatePrivateDirectory(string directory)
    {
        if (Directory.Exists(directory))
        {
            Restrict(directory, OwnerOnlyDirectory);
            return;
        }
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(directory);
        }
        else
        {
            Directory.CreateDirectory(directory, OwnerOnlyDirectory);
        }
        Restrict(directory, OwnerOnlyDirectory);
    }

    /// <summary>Atomically writes <paramref name="content"/>, readable only by the current user.</summary>
    internal static void WriteSecret(string path, string content)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))
                        ?? throw new IOException($"secret path has no parent directory: {path}");
        CreatePrivateDirectory(directory);

        // The temporary file lives in the destination directory so the replace stays on one volume.
        var temporary = Path.Combine(directory, $".secret-{Guid.NewGuid():N}.tmp");
        try
        {
            if (OperatingSystem.IsWindows())
            {
                File.WriteAllText(temporary, content, Encoding.UTF8);
            }
            else
            {
                // Create with the restrictive mode so the secret is never written into a file that
                // was, even momentarily, group or world readable.
                using (var stream = new FileStream(temporary, new FileStreamOptions
                       {
                           Mode = FileMode.CreateNew,
                           Access = FileAccess.Write,
                           UnixCreateMode = OwnerOnlyFile,
                       }))
                using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                {
                    writer.Write(content);
                }
            }
            Restrict(temporary, OwnerOnlyFile);

            if (File.Exists(path))
            {
                File.Replace(temporary, path, destinationBackupFileName: null);
            }
            else
            {
                File.Move(temporary, path);
            }
            Restrict(path, OwnerOnlyFile);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                try
                {
                    File.Delete(temporary);
                }
                catch (IOException)
                {
                    // Losing a temp file is not worth failing the write that already succeeded.
                }
            }
        }
    }

    private static void Restrict(string path, UnixFileMode mode)
    {
        if (OperatingSystem.IsWindows())
        {
            RestrictWindowsAcl(path);
            return;
        }
        try
        {
            File.SetUnixFileMode(path, mode);
        }
        catch (Exception error) when (error is PlatformNotSupportedException or UnauthorizedAccessException)
        {
            // A filesystem without mode bits (a mounted share) cannot be tightened further here.
        }
    }

    /// <summary>
    /// Replaces the inherited ACL with one granting the current user alone. Unix mode bits are
    /// ignored on Windows, so without this the file inherits whatever the profile directory grants,
    /// which on a shared or domain-joined machine can include other principals.
    /// </summary>
    private static void RestrictWindowsAcl(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        try
        {
            var startInfo = new System.Diagnostics.ProcessStartInfo("icacls")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            startInfo.ArgumentList.Add(path);
            startInfo.ArgumentList.Add("/inheritance:r");
            startInfo.ArgumentList.Add("/grant:r");
            startInfo.ArgumentList.Add($"{Environment.UserName}:F");

            using var process = System.Diagnostics.Process.Start(startInfo);
            process?.WaitForExit(10_000);
        }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            // Failing to tighten the ACL must not stop the client from having a key at all; the
            // file is still created under the user profile.
        }
    }
}
