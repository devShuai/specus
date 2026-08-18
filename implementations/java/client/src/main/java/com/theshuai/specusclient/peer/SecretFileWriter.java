package com.theshuai.specusclient.peer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Writes a secret to disk so that no other local account can read it and no reader can ever observe
 * a half-written file.
 *
 * <p>Two separate problems are being solved. Writing directly to the destination leaves the file
 * world-readable for the window between creation and any later permission change, and leaves a
 * truncated key behind if the process dies mid-write — on next start the client would read a
 * corrupt private key and silently lose its peer identity. Writing to a temporary file that is
 * locked down <em>before</em> the secret goes into it, then renaming it into place, closes both:
 * the permissions are never wrong even briefly, and the rename is atomic, so a reader sees either
 * the old file or the complete new one.
 */
final class SecretFileWriter {
    private static final Set<PosixFilePermission> OWNER_ONLY_FILE =
            PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> OWNER_ONLY_DIRECTORY =
            PosixFilePermissions.fromString("rwx------");

    private SecretFileWriter() {
    }

    /** Creates the directory if needed and restricts it to the current user. */
    static void createPrivateDirectory(Path directory) throws IOException {
        if (!Files.exists(directory)) {
            if (posixSupported()) {
                Files.createDirectories(directory,
                        PosixFilePermissions.asFileAttribute(OWNER_ONLY_DIRECTORY));
                return;
            }
            Files.createDirectories(directory);
            restrictWindowsAcl(directory);
            return;
        }
        restrictExisting(directory, OWNER_ONLY_DIRECTORY);
    }

    /** Atomically writes {@code content}, readable only by the current user. */
    static void writeSecret(Path target, String content) throws IOException {
        Path directory = target.toAbsolutePath().getParent();
        if (directory == null) {
            throw new IOException("secret path has no parent directory: " + target);
        }
        createPrivateDirectory(directory);

        // The temporary file lives in the destination directory so the rename stays on one
        // filesystem, which is what makes it atomic.
        Path temporary = Files.createTempFile(directory, ".secret", ".tmp");
        try {
            restrictExisting(temporary, OWNER_ONLY_FILE);
            Files.writeString(temporary, content, StandardCharsets.UTF_8);
            try {
                Files.move(temporary, target,
                        StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException atomicUnsupported) {
                // Some filesystems refuse ATOMIC_MOVE. A plain replace is still better than
                // writing the secret into the destination directly.
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
            restrictExisting(target, OWNER_ONLY_FILE);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void restrictExisting(Path path, Set<PosixFilePermission> permissions)
            throws IOException {
        if (posixSupported()) {
            Files.setPosixFilePermissions(path, permissions);
            return;
        }
        restrictWindowsAcl(path);
    }

    private static boolean posixSupported() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    /**
     * Replaces the inherited ACL with a single entry for the owner. Without this the file inherits
     * whatever the parent directory grants, which on a shared machine can include other users.
     */
    private static void restrictWindowsAcl(Path path) throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
        if (view == null) {
            return;
        }
        UserPrincipal owner = Files.getOwner(path);
        if (owner == null) {
            return;
        }
        AclEntry entry = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                .build();
        view.setAcl(List.of(entry));
    }
}
