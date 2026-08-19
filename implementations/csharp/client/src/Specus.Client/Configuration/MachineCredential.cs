namespace Specus.Client.Configuration;

/// <summary>
/// Resolves the machine credential, which is this client's identity to the server.
///
/// <para>The secret could only live as plaintext in the config file, with nothing checking who
/// else could read it. The exposure is the file itself: configs get copied to new hosts, committed
/// to repositories, and left group-readable on shared machines, and the credential travels with
/// them.</para>
///
/// <para>Keeping the secret out of the config file is the larger of the two protections.
/// <c>env:NAME</c> reads it from the environment and <c>file:PATH</c> from a file of its own, so
/// the file that gets copied around carries a reference rather than the credential. A plain string
/// is still the secret, so existing configurations keep working.</para>
///
/// <para>Refusing to read a secret other local accounts can also read is what protects it on disk.
/// Encrypting the file would not: the key would have to live somewhere this process can reach
/// unaided, so anyone running as this user could decrypt it too, and anyone who could not read the
/// file could not read the key either. Permissions separate those cases, which is why OpenSSH
/// refuses an over-permissive private key rather than encrypting it by default.</para>
///
/// <para>The reference is resolved on every login rather than cached, so rotating the credential
/// takes effect on the next reconnect instead of the next restart.</para>
/// </summary>
public static class MachineCredential
{
    private const string EnvPrefix = "env:";
    private const string FilePrefix = "file:";

    private const UnixFileMode ForbiddenModes =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    /// <summary>Whether the configured value names the credential rather than being it.</summary>
    public static bool IsIndirect(string? configured)
    {
        var value = configured?.Trim() ?? string.Empty;
        return value.StartsWith(EnvPrefix, StringComparison.Ordinal)
               || value.StartsWith(FilePrefix, StringComparison.Ordinal);
    }

    /// <summary>Returns the secret, following an env or file reference if that is what was given.</summary>
    public static string Resolve(string? configured)
    {
        var value = configured?.Trim() ?? string.Empty;

        if (value.StartsWith(EnvPrefix, StringComparison.Ordinal))
        {
            var name = value[EnvPrefix.Length..].Trim();
            if (name.Length == 0)
            {
                throw new InvalidDataException("secret env reference names no variable");
            }
            var fromEnvironment = Environment.GetEnvironmentVariable(name)?.Trim();
            if (string.IsNullOrEmpty(fromEnvironment))
            {
                throw new InvalidDataException(
                    $"secret environment variable {name} is empty or unset");
            }
            return fromEnvironment;
        }

        if (value.StartsWith(FilePrefix, StringComparison.Ordinal))
        {
            var path = value[FilePrefix.Length..].Trim();
            if (path.Length == 0)
            {
                throw new InvalidDataException("secret file reference names no path");
            }
            return ReadSecretFile(path);
        }

        return value;
    }

    private static string ReadSecretFile(string path)
    {
        AssertPrivate(path);
        var secret = File.ReadAllText(path).Trim();
        if (secret.Length == 0)
        {
            throw new InvalidDataException($"secret file {path} is empty");
        }
        return secret;
    }

    /// <summary>
    /// Whether a mode lets any account other than the owner reach the file. Split out so the rule
    /// can be asserted on a platform whose filesystem has no Unix permissions to set.
    /// </summary>
    internal static bool ReachableByOtherAccounts(UnixFileMode mode) => (mode & ForbiddenModes) != 0;

    /// <summary>
    /// Refuses a credential file that group or others can read. A refusal rather than a warning:
    /// a credential every local account can read is already leaked, and a warning would scroll past.
    /// </summary>
    private static void AssertPrivate(string path)
    {
        if (!File.Exists(path))
        {
            throw new InvalidDataException($"secret file {path} does not exist");
        }
        if (OperatingSystem.IsWindows())
        {
            // Mode bits carry no meaning here, and reading an ACL well enough to judge "too open"
            // means resolving group memberships and inherited entries.
            return;
        }
        var mode = File.GetUnixFileMode(path);
        if (ReachableByOtherAccounts(mode))
        {
            throw new InvalidDataException(
                $"credential file is readable by other accounts: {path} has mode {mode}; "
                + $"run chmod 600 {path}");
        }
    }
}
