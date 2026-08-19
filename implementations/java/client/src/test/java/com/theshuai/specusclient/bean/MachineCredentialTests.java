package com.theshuai.specusclient.bean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class MachineCredentialTests {
    /** An existing configuration carries the secret inline; that has to keep working. */
    @Test
    void plainSecretIsUsedAsIs() {
        assertEquals("s3cret-value", MachineCredential.resolve("  s3cret-value  "));
        assertFalse(MachineCredential.isIndirect("s3cret-value"));
    }

    /** Naming the secret indirectly keeps it out of a file that gets copied around. */
    @Test
    void secretCanComeFromItsOwnFile(@TempDir Path directory) throws IOException {
        Path path = directory.resolve("secret");
        Files.writeString(path, "from-the-file\n", StandardCharsets.UTF_8);
        restrictIfPosix(path);

        assertEquals("from-the-file", MachineCredential.resolve("file:" + path));
        assertTrue(MachineCredential.isIndirect("file:" + path));
    }

    @Test
    void emptyAndMissingSourcesAreRejected(@TempDir Path directory) throws IOException {
        assertThrows(IllegalStateException.class, () -> MachineCredential.resolve("file:"));
        assertThrows(IllegalStateException.class, () -> MachineCredential.resolve("env:"));
        assertThrows(IllegalStateException.class,
                () -> MachineCredential.resolve("file:" + directory.resolve("absent")));
        assertThrows(IllegalStateException.class,
                () -> MachineCredential.resolve("env:SPECUS_DEFINITELY_ABSENT_VARIABLE"));

        Path empty = directory.resolve("empty");
        Files.writeString(empty, "  \n", StandardCharsets.UTF_8);
        restrictIfPosix(empty);
        // An empty file must be an error rather than an empty credential.
        assertThrows(IllegalStateException.class, () -> MachineCredential.resolve("file:" + empty));
    }

    /**
     * A credential every other local account can read is already leaked, so this refuses rather
     * than warning.
     */
    @Test
    void secretFileReadableByOthersIsRefused(@TempDir Path directory) throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
                "mode bits are not the access control mechanism on Windows");

        Path path = directory.resolve("secret");
        Files.writeString(path, "exposed", StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"));

        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> MachineCredential.resolve("file:" + path));
        // The message has to say how to fix it, or the refusal is just an obstacle.
        assertTrue(error.getMessage().contains("chmod 600"), error.getMessage());

        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        assertEquals("exposed", MachineCredential.resolve("file:" + path));
    }

    /**
     * Rotation has to take effect on the next reconnect, which is only possible because the
     * reference is resolved each time rather than cached.
     */
    @Test
    void rotatingTheFileIsPickedUp(@TempDir Path directory) throws IOException {
        Path path = directory.resolve("secret");
        Files.writeString(path, "original", StandardCharsets.UTF_8);
        restrictIfPosix(path);
        assertEquals("original", MachineCredential.resolve("file:" + path));

        Files.writeString(path, "rotated", StandardCharsets.UTF_8);
        restrictIfPosix(path);
        assertEquals("rotated", MachineCredential.resolve("file:" + path),
                "the client would still be signing with the old credential");
    }

    private static void restrictIfPosix(Path path) throws IOException {
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        }
    }

    /**
     * The rule itself, asserted without needing a filesystem that can express these modes. Windows
     * cannot set them, so without this the decision would go untested on the machine most of this
     * is developed on.
     */
    @Test
    void ownerOnlyIsTheOnlyAcceptableMode() {
        assertFalse(MachineCredential.reachableByOtherAccounts(
                PosixFilePermissions.fromString("rw-------")));
        assertFalse(MachineCredential.reachableByOtherAccounts(
                PosixFilePermissions.fromString("r--------")));

        for (String mode : new String[]{
                "rw-r-----", "rw----r--", "rw-rw----", "rw----rw-",
                "rw---x---", "rw------x", "rw-rwxrwx", "rw-r--r--"}) {
            assertTrue(MachineCredential.reachableByOtherAccounts(
                            PosixFilePermissions.fromString(mode)),
                    mode + " lets another account reach the credential");
        }
    }
}
