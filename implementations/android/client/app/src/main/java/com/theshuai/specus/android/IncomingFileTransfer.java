package com.theshuai.specus.android;

import org.json.JSONObject;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Pure-Java receive state machine for STXFER1.
 *
 * <p>The transport may deliver the same frame through both the authenticated peer channel and the
 * server fallback. It may also deliver {@code done} before a delayed chunk. All operations are
 * serialized on this object so frames for the same authenticated sender and transfer id cannot
 * race each other. Keeping Android APIs outside this class also lets local JVM tests exercise disk
 * failures and cleanup without instrumentation.</p>
 */
final class IncomingFileTransfer {
    private static final int MAX_EARLY_DONE = 64;
    private static final int MAX_COMPLETED_TOMBSTONES = 256;
    private static final int MAX_TOMBSTONES_PER_SENDER = 64;
    private static final int MAX_TRANSFER_ID_LENGTH = 128;
    private static final int MAX_ENCODED_CHUNK_LENGTH =
            4 * ((FileTransferManager.CHUNK_BYTES + 2) / 3);

    interface EventSink {
        void emit(String from, String text);
    }

    interface WritableFile extends Closeable {
        void setLength(long length) throws Exception;

        void seek(long offset) throws Exception;

        void write(byte[] data) throws Exception;
    }

    /** Filesystem seam used by JVM tests to inject every resource-acquisition failure. */
    interface FileOps {
        long nowMillis();

        WritableFile open(File file) throws Exception;

        default void beforeRegister() throws Exception {
        }

        default void afterRegister() throws Exception {
        }

        String sha256(File file) throws Exception;

        boolean createNew(File file) throws Exception;

        boolean publishNoReplace(File ownedPartial, File target) throws Exception;

        void copy(File source, File target) throws Exception;

        void delete(File file);
    }

    static final FileOps SYSTEM_FILE_OPS = new FileOps() {
        @Override
        public long nowMillis() {
            return System.currentTimeMillis();
        }

        @Override
        public WritableFile open(File file) throws Exception {
            RandomAccessFile randomAccess = new RandomAccessFile(file, "rw");
            return new WritableFile() {
                @Override
                public void setLength(long length) throws Exception {
                    randomAccess.setLength(length);
                }

                @Override
                public void seek(long offset) throws Exception {
                    randomAccess.seek(offset);
                }

                @Override
                public void write(byte[] data) throws Exception {
                    randomAccess.write(data);
                }

                @Override
                public void close() throws java.io.IOException {
                    randomAccess.close();
                }
            };
        }

        @Override
        public String sha256(File file) throws Exception {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (FileInputStream input = new FileInputStream(file)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) > 0) {
                    digest.update(buffer, 0, read);
                }
            }
            return toHex(digest.digest());
        }

        @Override
        public boolean createNew(File file) throws Exception {
            try {
                Files.createFile(file.toPath());
                return true;
            } catch (FileAlreadyExistsException ignored) {
                return false;
            }
        }

        @Override
        public boolean publishNoReplace(File ownedPartial, File target) throws Exception {
            try {
                Files.move(ownedPartial.toPath(), target.toPath());
                return true;
            } catch (FileAlreadyExistsException ignored) {
                return false;
            }
        }

        @Override
        public void copy(File source, File target) throws Exception {
            try (FileInputStream input = new FileInputStream(source);
                 FileOutputStream output = new FileOutputStream(target)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) > 0) {
                    output.write(buffer, 0, read);
                }
                output.flush();
                output.getFD().sync();
            }
        }

        @Override
        public void delete(File file) {
            if (file != null) {
                try {
                    Files.deleteIfExists(file.toPath());
                } catch (Exception ignored) {
                    //noinspection ResultOfMethodCallIgnored
                    file.delete();
                }
            }
        }
    };

    private final Map<SessionKey, IncomingSession> incoming = new HashMap<>();
    /** A tombstone suppresses every late frame, not only a repeated {@code done}. */
    private final Map<SessionKey, Long> completed = new HashMap<>();
    /** Slots are reserved before disk resources, so a completed session always gets a tombstone. */
    private final Set<SessionKey> reservedCompletionSlots = new HashSet<>();
    private final Map<String, Integer> completionSlotsBySender = new HashMap<>();
    private int completionSlotCount;
    /** A bounded reorder buffer for a {@code done} that beats its offer over another channel. */
    private final Map<SessionKey, Long> earlyDone = new HashMap<>();
    private long pendingBytes;

    synchronized void onFrame(File tempDirectory,
                              File downloadDirectory,
                              FileOps fileOps,
                              EventSink events,
                              String authenticatedSender,
                              JSONObject frame) {
        String id = frame == null ? "" : frame.optString("id", "");
        if (id.trim().isEmpty()
                || id.codePointCount(0, id.length()) > MAX_TRANSFER_ID_LENGTH) {
            return;
        }
        String from = authenticatedSender == null ? "" : authenticatedSender.trim();
        if (from.isEmpty()) {
            return;
        }
        SessionKey key = new SessionKey(from, id);
        if (completed.containsKey(key)) {
            return;
        }
        String type = frame.optString("t", "");
        try {
            switch (type) {
                case "offer":
                    handleOffer(key, from, frame, tempDirectory, downloadDirectory, fileOps, events);
                    break;
                case "chunk":
                    handleChunk(key, from, frame, events);
                    break;
                case "done":
                    handleDone(key, from, fileOps, events);
                    break;
                case "abort":
                    earlyDone.remove(key);
                    IncomingSession aborted = removeSession(key, false);
                    if (!reserveCompletionSlot(key)) {
                        break;
                    }
                    rememberCompleted(key, fileOps.nowMillis());
                    if (aborted != null) {
                        events.emit(from, "对方取消发送 · " + aborted.name);
                    }
                    break;
                default:
                    break;
            }
        } catch (OfferConflictException error) {
            // A conflicting replay must not destroy the valid session already in progress.
            events.emit(from, "文件接收失败 · " + error.getMessage());
        } catch (DigestMismatchException error) {
            events.emit(from, "文件校验失败 · " + error.fileName);
        } catch (Exception error) {
            dropSession(key);
            events.emit(from, "文件接收失败 · " + message(error));
        }
    }

    private void handleOffer(SessionKey key,
                             String from,
                             JSONObject frame,
                             File tempDirectory,
                             File downloadDirectory,
                             FileOps fileOps,
                             EventSink events) throws Exception {
        Offer offer = Offer.parse(frame);
        IncomingSession existing = incoming.get(key);
        if (existing != null) {
            if (!existing.offer.equals(offer)) {
                throw new OfferConflictException("conflicting offer");
            }
            existing.lastTouchedAtMillis = fileOps.nowMillis();
            return;
        }
        if (incoming.size() >= FileTransferManager.MAX_CONCURRENT_SESSIONS) {
            throw new IllegalStateException("接收会话过多");
        }
        if (pendingBytes + offer.size > FileTransferManager.MAX_PENDING_BYTES) {
            throw new IllegalStateException("接收缓冲已满");
        }
        requireDirectory(tempDirectory, "transfer dir unavailable");
        requireDirectory(downloadDirectory, "download dir unavailable");
        File temp = new File(tempDirectory,
                UUID.randomUUID().toString().replace("-", "") + ".part");
        requireContained(tempDirectory, temp);
        if (!reserveCompletionSlot(key)) {
            throw new IllegalStateException("replay protection capacity reached");
        }

        WritableFile writable = null;
        IncomingSession session = null;
        boolean reserved = false;
        boolean committed = false;
        try {
            writable = fileOps.open(temp);
            writable.setLength(offer.size);
            fileOps.beforeRegister();
            session = new IncomingSession(from, offer, temp, downloadDirectory, writable,
                    fileOps, fileOps.nowMillis());
            incoming.put(key, session);
            pendingBytes += offer.size;
            reserved = true;
            fileOps.afterRegister();
            committed = true;
        } finally {
            if (!committed) {
                if (session != null && incoming.get(key) == session) {
                    incoming.remove(key);
                }
                if (reserved) {
                    pendingBytes = Math.max(0L, pendingBytes - offer.size);
                }
                closeQuietly(writable);
                deleteQuietly(fileOps, temp);
                releaseCompletionSlot(key);
            }
        }

        Long reorderedDone = earlyDone.remove(key);
        if (reorderedDone != null) {
            session.doneReceived = true;
        }
        events.emit(from, "接收中 " + session.name + " · " + FileTransferManager.formatBytes(offer.size));
        finishIfReady(key, session, events);
    }

    private void handleChunk(SessionKey key,
                             String from,
                             JSONObject frame,
                             EventSink events) throws Exception {
        IncomingSession session = incoming.get(key);
        if (session == null) {
            return;
        }
        int seq = frame.optInt("seq", -1);
        if (seq < 0 || seq >= session.offer.chunks) {
            throw new IllegalArgumentException("invalid chunk seq");
        }
        String encoded = frame.optString("data", "");
        if (encoded.length() > MAX_ENCODED_CHUNK_LENGTH) {
            throw new IllegalArgumentException("chunk data too large");
        }
        byte[] data = Base64.getDecoder().decode(encoded);
        long offset = (long) seq * FileTransferManager.CHUNK_BYTES;
        int expected = (int) Math.min(FileTransferManager.CHUNK_BYTES, session.offer.size - offset);
        if (data.length != expected) {
            throw new IllegalArgumentException("chunk length mismatch");
        }
        session.lastTouchedAtMillis = session.fileOps.nowMillis();
        if (session.receivedChunks[seq]) {
            return;
        }
        session.writable.seek(offset);
        session.writable.write(data);
        session.receivedChunks[seq] = true;
        session.received++;
        session.receivedBytes += data.length;
        if (session.received > 0 && session.received % FileTransferManager.PROGRESS_EVERY_CHUNKS == 0) {
            int percent = (int) ((session.received * 100L) / Math.max(1, session.offer.chunks));
            events.emit(from, "接收中 " + session.name + " · " + percent + "%");
        }
        finishIfReady(key, session, events);
    }

    private void handleDone(SessionKey key,
                            String from,
                            FileOps fileOps,
                            EventSink events) throws Exception {
        IncomingSession session = incoming.get(key);
        if (session == null) {
            rememberEarlyDone(key, fileOps.nowMillis());
            return;
        }
        session.doneReceived = true;
        session.lastTouchedAtMillis = session.fileOps.nowMillis();
        finishIfReady(key, session, events);
    }

    /** Completes only after both the terminal frame and every distinct chunk have arrived. */
    private void finishIfReady(SessionKey key,
                               IncomingSession session,
                               EventSink events) throws Exception {
        if (!session.doneReceived
                || session.received != session.offer.chunks
                || session.receivedBytes != session.offer.size) {
            return;
        }

        File ownedPartial = null;
        boolean published = false;
        try {
            // A close failure is terminal: do not hash a file whose buffered writes may not have
            // reached disk. Keep ownership until a best-effort retry in the failure cleanup.
            if (session.writable != null) {
                session.writable.close();
                session.writable = null;
            }
            String actual = session.fileOps.sha256(session.tempFile);
            if (!session.offer.sha256.equalsIgnoreCase(actual)) {
                throw new DigestMismatchException(session.name);
            }
            ownedPartial = createOwnedPublishPartial(session.downloadDirectory, session.fileOps);
            session.fileOps.copy(session.tempFile, ownedPartial);
            File target = null;
            for (int attempt = 0; attempt < 1000 && target == null; attempt++) {
                File candidate = targetCandidate(session.downloadDirectory, session.name, attempt);
                if (session.fileOps.publishNoReplace(ownedPartial, candidate)) {
                    target = candidate;
                    ownedPartial = null;
                }
            }
            if (target == null) {
                throw new IllegalStateException("download name space exhausted");
            }
            deleteQuietly(session.fileOps, session.tempFile);
            removeRegistered(key, session);
            rememberCompleted(key, session.fileOps.nowMillis());
            published = true;
            events.emit(session.from,
                    "已接收 " + session.name + " · " + FileTransferManager.formatBytes(session.offer.size)
                            + "\n保存到 " + target.getAbsolutePath());
        } finally {
            if (!published) {
                removeRegistered(key, session);
                closeQuietly(session.writable);
                deleteQuietly(session.fileOps, session.tempFile);
                // Only this random partial is ours. Never delete a candidate another process won.
                deleteQuietly(session.fileOps, ownedPartial);
                releaseCompletionSlot(key);
            }
        }
    }

    synchronized void sweepExpired(EventSink events) {
        long now = System.currentTimeMillis();
        sweepExpired(now, events);
    }

    synchronized void sweepExpired(long now, EventSink events) {
        Iterator<Map.Entry<SessionKey, Long>> completedIterator = completed.entrySet().iterator();
        while (completedIterator.hasNext()) {
            Map.Entry<SessionKey, Long> entry = completedIterator.next();
            if (now - entry.getValue() > FileTransferManager.SESSION_TTL_MILLIS) {
                completedIterator.remove();
                releaseCountedCompletionSlot(entry.getKey());
            }
        }
        earlyDone.entrySet().removeIf(entry -> now - entry.getValue()
                > FileTransferManager.SESSION_TTL_MILLIS);
        Iterator<Map.Entry<SessionKey, IncomingSession>> iterator = incoming.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<SessionKey, IncomingSession> entry = iterator.next();
            IncomingSession session = entry.getValue();
            if (now - session.lastTouchedAtMillis <= FileTransferManager.SESSION_TTL_MILLIS) {
                continue;
            }
            iterator.remove();
            pendingBytes = Math.max(0L, pendingBytes - session.offer.size);
            closeQuietly(session.writable);
            deleteQuietly(session.fileOps, session.tempFile);
            releaseCompletionSlot(entry.getKey());
            events.emit(session.from, "接收超时 · " + session.name);
        }
    }

    private IncomingSession dropSession(SessionKey key) {
        return removeSession(key, true);
    }

    private IncomingSession removeSession(SessionKey key, boolean releaseSlot) {
        IncomingSession session = incoming.remove(key);
        if (session != null) {
            pendingBytes = Math.max(0L, pendingBytes - session.offer.size);
            closeQuietly(session.writable);
            deleteQuietly(session.fileOps, session.tempFile);
        }
        if (releaseSlot) {
            releaseCompletionSlot(key);
        }
        return session;
    }

    private void removeRegistered(SessionKey key, IncomingSession session) {
        if (incoming.get(key) == session) {
            incoming.remove(key);
            pendingBytes = Math.max(0L, pendingBytes - session.offer.size);
        }
    }

    private void rememberEarlyDone(SessionKey key, long now) {
        if (earlyDone.size() >= MAX_EARLY_DONE && !earlyDone.containsKey(key)) {
            SessionKey oldestKey = null;
            long oldest = Long.MAX_VALUE;
            for (Map.Entry<SessionKey, Long> entry : earlyDone.entrySet()) {
                if (entry.getValue() < oldest) {
                    oldest = entry.getValue();
                    oldestKey = entry.getKey();
                }
            }
            if (oldestKey != null) {
                earlyDone.remove(oldestKey);
            }
        }
        earlyDone.put(key, now);
    }

    private void rememberCompleted(SessionKey key, long now) {
        if (completed.containsKey(key)) {
            completed.put(key, now);
            return;
        }
        if (!reservedCompletionSlots.remove(key)) {
            throw new IllegalStateException("completion slot was not reserved");
        }
        completed.put(key, now);
    }

    private boolean reserveCompletionSlot(SessionKey key) {
        if (completed.containsKey(key) || reservedCompletionSlots.contains(key)) {
            return true;
        }
        int senderSlots = completionSlotsBySender.getOrDefault(key.sender, 0);
        if (completionSlotCount >= MAX_COMPLETED_TOMBSTONES
                || senderSlots >= MAX_TOMBSTONES_PER_SENDER) {
            return false;
        }
        reservedCompletionSlots.add(key);
        completionSlotCount++;
        completionSlotsBySender.put(key.sender, senderSlots + 1);
        return true;
    }

    private void releaseCompletionSlot(SessionKey key) {
        if (reservedCompletionSlots.remove(key)) {
            releaseCountedCompletionSlot(key);
        }
    }

    private void releaseCountedCompletionSlot(SessionKey key) {
        completionSlotCount = Math.max(0, completionSlotCount - 1);
        int senderSlots = completionSlotsBySender.getOrDefault(key.sender, 0);
        if (senderSlots <= 1) {
            completionSlotsBySender.remove(key.sender);
        } else {
            completionSlotsBySender.put(key.sender, senderSlots - 1);
        }
    }

    private static File createOwnedPublishPartial(File directory, FileOps fileOps) throws Exception {
        requireDirectory(directory, "download dir unavailable");
        for (int attempt = 0; attempt < 32; attempt++) {
            File partial = new File(directory,
                    ".specus-" + UUID.randomUUID().toString().replace("-", "") + ".part");
            requireContained(directory, partial);
            if (fileOps.createNew(partial)) {
                return partial;
            }
        }
        throw new IllegalStateException("publish temp unavailable");
    }

    private static File targetCandidate(File directory, String name, int attempt) throws Exception {
        requireDirectory(directory, "download dir unavailable");
        if (attempt == 0) {
            File target = new File(directory, name);
            requireContained(directory, target);
            return target;
        }
        String base = name;
        String extension = "";
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            base = name.substring(0, dot);
            extension = name.substring(dot);
        }
        File candidate = new File(directory, base + " (" + attempt + ")" + extension);
        requireContained(directory, candidate);
        return candidate;
    }

    private static void requireDirectory(File directory, String message) {
        if (directory == null || (!directory.isDirectory() && !directory.mkdirs())) {
            throw new IllegalStateException(message);
        }
    }

    private static void requireContained(File directory, File candidate) throws Exception {
        String root = directory.getCanonicalPath();
        if (!root.endsWith(File.separator)) {
            root += File.separator;
        }
        if (!candidate.getCanonicalPath().startsWith(root)) {
            throw new IllegalArgumentException("resolved path escapes the transfer directory");
        }
    }

    private static boolean isHexDigest(String value) {
        if (value == null || value.length() != 64) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (!((current >= '0' && current <= '9')
                    || (current >= 'a' && current <= 'f')
                    || (current >= 'A' && current <= 'F'))) {
                return false;
            }
        }
        return true;
    }

    private static String toHex(byte[] value) {
        StringBuilder hex = new StringBuilder(value.length * 2);
        for (byte current : value) {
            hex.append(Character.forDigit((current >> 4) & 0xF, 16));
            hex.append(Character.forDigit(current & 0xF, 16));
        }
        return hex.toString();
    }

    private static void closeQuietly(Closeable closeable) {
        if (closeable == null) {
            return;
        }
        for (int attempt = 0; attempt < 2; attempt++) {
            try {
                closeable.close();
                return;
            } catch (Exception ignored) {
                // A failed close can be transient; one retry also makes cleanup fault-testable.
            }
        }
    }

    private static void deleteQuietly(FileOps fileOps, File file) {
        try {
            if (file != null) {
                fileOps.delete(file);
            }
        } catch (RuntimeException ignored) {
        }
    }

    private static String message(Exception error) {
        return error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
    }

    static final class SessionKey {
        final String sender;
        final String transferId;

        SessionKey(String sender, String transferId) {
            // Authentication identities are case-sensitive unless the server explicitly says
            // otherwise. Only transport whitespace is normalized; Alice and ALICE stay isolated.
            this.sender = sender == null ? "" : sender.trim();
            this.transferId = transferId == null ? "" : transferId;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof SessionKey)) {
                return false;
            }
            SessionKey that = (SessionKey) other;
            return sender.equals(that.sender) && transferId.equals(that.transferId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(sender, transferId);
        }
    }

    private static final class Offer {
        final String name;
        final String mime;
        final long size;
        final int chunks;
        final String sha256;

        Offer(String name, String mime, long size, int chunks, String sha256) {
            this.name = name;
            this.mime = mime;
            this.size = size;
            this.chunks = chunks;
            this.sha256 = sha256;
        }

        static Offer parse(JSONObject frame) {
            long size = frame.optLong("size", -1L);
            int chunks = frame.optInt("chunks", -1);
            int expectedChunks = size < 0 ? -1
                    : (int) ((size + FileTransferManager.CHUNK_BYTES - 1)
                    / FileTransferManager.CHUNK_BYTES);
            if (size < 0 || size > FileTransferManager.MAX_FILE_BYTES
                    || chunks < 0 || chunks != expectedChunks) {
                throw new IllegalArgumentException("invalid offer");
            }
            String digest = frame.optString("sha256", "").trim();
            if (!isHexDigest(digest)) {
                throw new IllegalArgumentException("invalid sha256");
            }
            return new Offer(
                    FileTransferManager.sanitizeName(frame.optString("name", "file")),
                    frame.optString("mime", "application/octet-stream").trim(),
                    size,
                    chunks,
                    digest.toLowerCase(Locale.ROOT));
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof Offer)) {
                return false;
            }
            Offer that = (Offer) other;
            return size == that.size
                    && chunks == that.chunks
                    && name.equals(that.name)
                    && mime.equals(that.mime)
                    && sha256.equals(that.sha256);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, mime, size, chunks, sha256);
        }
    }

    private static final class IncomingSession {
        final String from;
        final String name;
        final Offer offer;
        final File tempFile;
        final File downloadDirectory;
        final FileOps fileOps;
        final boolean[] receivedChunks;
        WritableFile writable;
        int received;
        long receivedBytes;
        boolean doneReceived;
        long lastTouchedAtMillis;

        IncomingSession(String from,
                        Offer offer,
                        File tempFile,
                        File downloadDirectory,
                        WritableFile writable,
                        FileOps fileOps,
                        long now) {
            this.from = from;
            this.name = offer.name;
            this.offer = offer;
            this.tempFile = tempFile;
            this.downloadDirectory = downloadDirectory;
            this.writable = writable;
            this.fileOps = fileOps;
            this.receivedChunks = new boolean[offer.chunks];
            this.lastTouchedAtMillis = now;
        }
    }

    private static final class OfferConflictException extends Exception {
        OfferConflictException(String message) {
            super(message);
        }
    }

    private static final class DigestMismatchException extends Exception {
        final String fileName;

        DigestMismatchException(String fileName) {
            super("digest mismatch");
            this.fileName = fileName;
        }
    }

    // Test observations deliberately expose counts, not mutable state.
    synchronized int activeSessionCount() {
        return incoming.size();
    }

    synchronized long pendingBytes() {
        return pendingBytes;
    }

    synchronized boolean isCompleted(String sender, String transferId) {
        return completed.containsKey(new SessionKey(sender, transferId));
    }

    synchronized int completionSlotCount() {
        return completionSlotCount;
    }
}
