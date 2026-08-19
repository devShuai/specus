package com.theshuai.specusclient.bean;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/**
 * Resolves the machine credential, which is this client's identity to the server.
 *
 * <p>The secret could only live as plaintext in the config file, with nothing checking who else
 * could read it. The exposure is the file itself: configs get copied to new hosts, committed to
 * repositories, and left group-readable on shared machines, and the credential travels with them.
 *
 * <p>Two things address that, and it is worth being clear about which does the work.
 *
 * <p>Keeping the secret out of the config file is the larger of the two. {@code env:NAME} reads it
 * from the environment and {@code file:PATH} from a file of its own, so the file that gets copied
 * around carries a reference rather than the credential. A plain string is still the secret, so
 * existing configurations keep working.
 *
 * <p>Refusing to read a secret other local accounts can also read is what protects it on disk.
 * Encrypting the file would not: the key would have to live somewhere this process can reach
 * unaided, so anyone running as this user could decrypt it too, and anyone who could not read the
 * file could not read the key either. File permissions are the mechanism that actually separates
 * those cases, which is why OpenSSH refuses an over-permissive private key rather than encrypting
 * it by default.
 *
 * <p>The reference is resolved on every login rather than cached, so rotating the credential takes
 * effect on the next reconnect instead of the next restart.
 */
public final class MachineCredential {
    private static final String ENV_PREFIX = "env:";
    private static final String FILE_PREFIX = "file:";
    private static final Set<PosixFilePermission> FORBIDDEN = Set.of(
            PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.OTHERS_READ,
            PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE);

    private MachineCredential() {
    }

    /** Whether the configured value names the credential rather than being it. */
    public static boolean isIndirect(String configured) {
        String value = configured == null ? "" : configured.trim();
        return value.startsWith(ENV_PREFIX) || value.startsWith(FILE_PREFIX);
    }

    /** Returns the secret itself, following an env or file reference if that is what was given. */
    public static String resolve(String configured) {
        String value = configured == null ? "" : configured.trim();

        if (value.startsWith(ENV_PREFIX)) {
            String name = value.substring(ENV_PREFIX.length()).trim();
            if (name.isEmpty()) {
                throw new IllegalStateException("secret env reference names no variable");
            }
            String secret = System.getenv(name);
            secret = secret == null ? "" : secret.trim();
            if (secret.isEmpty()) {
                throw new IllegalStateException(
                        "secret environment variable " + name + " is empty or unset");
            }
            return secret;
        }

        if (value.startsWith(FILE_PREFIX)) {
            String path = value.substring(FILE_PREFIX.length()).trim();
            if (path.isEmpty()) {
                throw new IllegalStateException("secret file reference names no path");
            }
            return readSecretFile(Path.of(path));
        }

        return value;
    }

    private static String readSecretFile(Path path) {
        assertPrivate(path);
        try {
            String secret = Files.readString(path, StandardCharsets.UTF_8).trim();
            if (secret.isEmpty()) {
                throw new IllegalStateException("secret file " + path + " is empty");
            }
            return secret;
        } catch (IOException error) {
            throw new IllegalStateException("read secret file " + path + ": " + error.getMessage(),
                    error);
        }
    }

    /**
     * Whether a permission set lets any account other than the owner reach the file. Split out so
     * the rule can be asserted on a platform whose filesystem has no POSIX permissions to set.
     */
    static boolean reachableByOtherAccounts(Set<PosixFilePermission> permissions) {
        return permissions.stream().anyMatch(FORBIDDEN::contains);
    }

    /**
     * Refuses a credential file that group or others can read. A refusal rather than a warning: a
     * credential every local account can read is already leaked, and a warning would scroll past.
     */
    private static void assertPrivate(Path path) {
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException("secret file " + path + " does not exist");
        }
        if (!FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            // Mode bits carry no meaning on Windows, and reading an ACL well enough to judge
            // "too open" means resolving group memberships and inherited entries.
            return;
        }
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
            if (reachableByOtherAccounts(permissions)) {
                throw new IllegalStateException("credential file is readable by other accounts: "
                        + path + " grants " + permissions + "; run chmod 600 " + path);
            }
        } catch (IOException error) {
            throw new IllegalStateException(
                    "cannot check permissions on secret file " + path, error);
        }
    }
}
