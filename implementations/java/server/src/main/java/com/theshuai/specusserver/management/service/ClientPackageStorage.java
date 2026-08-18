package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.ClientPackageProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

/** Bounded, symlink-resistant local package storage rooted at {@code data/packages}. */
@Component
public class ClientPackageStorage {
    private static final int BUFFER_SIZE = 64 * 1024;

    private final Path packageRoot;
    private final long maxPackageBytes;

    public ClientPackageStorage(ClientPackageProperties properties) {
        Path dataRoot = Path.of(properties.getDataDirectory()).toAbsolutePath().normalize();
        this.packageRoot = dataRoot.resolve("packages").normalize();
        if (!packageRoot.startsWith(dataRoot)) {
            throw new IllegalArgumentException("client package directory escapes the configured data directory");
        }
        this.maxPackageBytes = Math.max(1L, properties.getMaxPackageBytes());
    }

    public StagedPackage stage(InputStream source, long declaredSize) {
        if (source == null) {
            throw new IllegalArgumentException("file cannot be empty");
        }
        if (declaredSize < 0) {
            throw new IllegalArgumentException("declared file size cannot be negative");
        }
        if (declaredSize > maxPackageBytes) {
            throw new IllegalArgumentException("file exceeds max package size of " + maxPackageBytes + " bytes");
        }
        try {
            ensureRoot();
            Path temporary = Files.createTempFile(packageRoot, ".upload-", ".tmp");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long total = 0;
            try (InputStream input = new DigestInputStream(source, digest);
                 var output = Files.newOutputStream(temporary)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read == 0) {
                        continue;
                    }
                    total = Math.addExact(total, read);
                    if (total > maxPackageBytes) {
                        throw new IllegalArgumentException(
                                "file exceeds max package size of " + maxPackageBytes + " bytes");
                    }
                    output.write(buffer, 0, read);
                }
            } catch (RuntimeException | IOException exception) {
                deleteQuietly(temporary);
                throw exception;
            }
            if (total == 0) {
                deleteQuietly(temporary);
                throw new IllegalArgumentException("file cannot be empty");
            }
            return new StagedPackage(temporary, total, HexFormat.of().formatHex(digest.digest()));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        } catch (IOException exception) {
            throw new IllegalStateException("cannot stage client package", exception);
        }
    }

    public Path publish(StagedPackage staged, long packageId) {
        Path source = requireStaged(staged);
        Path destination = pathFor(packageId);
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("package file already exists: " + packageId);
        }
        try {
            try {
                Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException exception) {
                Files.move(source, destination);
            }
            return destination;
        } catch (IOException exception) {
            throw new IllegalStateException("cannot publish client package", exception);
        }
    }

    private Path requireStaged(StagedPackage staged) {
        if (staged == null || staged.path() == null) {
            throw new IllegalArgumentException("staged package is required");
        }
        Path source = staged.path().toAbsolutePath().normalize();
        String fileName = source.getFileName() == null ? "" : source.getFileName().toString();
        if (!packageRoot.equals(source.getParent())
                || !fileName.startsWith(".upload-")
                || !fileName.endsWith(".tmp")
                || !Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("staged package must be a regular upload inside data/packages");
        }
        if (staged.fileSize() <= 0 || staged.fileSize() > maxPackageBytes
                || staged.sha256() == null || !staged.sha256().matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("staged package metadata is invalid");
        }
        try {
            if (Files.size(source) != staged.fileSize()) {
                throw new IllegalArgumentException("staged package size does not match its metadata");
            }
        } catch (IOException exception) {
            throw new IllegalStateException("cannot inspect staged client package", exception);
        }
        return source;
    }

    public Path requireReadable(long packageId) {
        Path candidate = pathFor(packageId);
        try {
            ensureRoot();
            if (!Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalArgumentException("client package not found: " + packageId);
            }
            Path realRoot = packageRoot.toRealPath(LinkOption.NOFOLLOW_LINKS);
            Path realFile = candidate.toRealPath(LinkOption.NOFOLLOW_LINKS);
            if (!realFile.getParent().equals(realRoot)) {
                throw new IllegalStateException("client package path escaped the storage root");
            }
            return realFile;
        } catch (IOException exception) {
            throw new IllegalStateException("cannot resolve client package", exception);
        }
    }

    public Optional<Path> quarantine(long packageId) {
        Path source = pathFor(packageId);
        if (!Files.exists(source, LinkOption.NOFOLLOW_LINKS)) {
            return Optional.empty();
        }
        Path quarantine = packageRoot.resolve(".delete-" + packageId + "-" + UUID.randomUUID() + ".tmp");
        try {
            Files.move(source, quarantine, StandardCopyOption.ATOMIC_MOVE);
            return Optional.of(quarantine);
        } catch (AtomicMoveNotSupportedException exception) {
            try {
                Files.move(source, quarantine);
                return Optional.of(quarantine);
            } catch (IOException nested) {
                throw new IllegalStateException("cannot quarantine client package", nested);
            }
        } catch (IOException exception) {
            throw new IllegalStateException("cannot quarantine client package", exception);
        }
    }

    public void restore(Path quarantine, long packageId) {
        if (quarantine == null || !Files.exists(quarantine, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try {
            Files.move(quarantine, pathFor(packageId));
        } catch (IOException exception) {
            throw new IllegalStateException("cannot restore client package after rollback", exception);
        }
    }

    public void deleteQuietly(Path path) {
        if (path == null) {
            return;
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // Best-effort rollback cleanup; stale hidden temporary files are never downloadable.
        }
    }

    Path root() {
        return packageRoot;
    }

    private Path pathFor(long packageId) {
        if (packageId <= 0) {
            throw new IllegalArgumentException("packageId must be positive");
        }
        Path path = packageRoot.resolve(Long.toString(packageId)).normalize();
        if (!path.getParent().equals(packageRoot)) {
            throw new IllegalArgumentException("invalid packageId");
        }
        return path;
    }

    private void ensureRoot() throws IOException {
        Files.createDirectories(packageRoot);
        if (!Files.isDirectory(packageRoot, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("client package root is not a directory");
        }
    }

    public record StagedPackage(Path path, long fileSize, String sha256) { }
}
