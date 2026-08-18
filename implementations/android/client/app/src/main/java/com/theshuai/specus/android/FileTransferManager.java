package com.theshuai.specus.android;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

final class FileTransferManager {
    private static final String PREFIX = "STXFER1\n";
    private static final int CHUNK_BYTES = 600;
    private static final long MAX_FILE_BYTES = 8L * 1024 * 1024;
    private static final long SESSION_TTL_MILLIS = 120_000L;
    private static final long SWEEP_INTERVAL_MILLIS = 15_000L;
    private static final int PROGRESS_EVERY_CHUNKS = 32;
    /** Concurrent inbound sessions across all peers. */
    static final int MAX_CONCURRENT_SESSIONS = 16;
    /** Total bytes reserved on disk by in-flight inbound sessions. */
    static final long MAX_PENDING_BYTES = 64L * 1024 * 1024;
    private static final int MAX_NAME_LENGTH = 180;

    private static FileTransferManager instance;

    private final Map<String, IncomingSession> incoming = new HashMap<>();
    /** Sessions finished recently, so a replayed "done" is ignored instead of re-delivered. */
    private final Map<String, Long> completed = new HashMap<>();
    private ScheduledExecutorService sweeper;
    private long pendingBytes;

    private FileTransferManager() {
    }

    /** Expiry must not depend on the next inbound message; a stalled sender would pin resources. */
    private synchronized void ensureSweeper(Context context) {
        if (sweeper != null) {
            return;
        }
        final Context appContext = context.getApplicationContext();
        sweeper = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "specus-transfer-sweeper");
            thread.setDaemon(true);
            return thread;
        });
        sweeper.scheduleWithFixedDelay(() -> {
            try {
                sweepExpired(appContext);
            } catch (Exception ignored) {
                // Sweeping is best effort; a failure must not kill the scheduler.
            }
        }, SWEEP_INTERVAL_MILLIS, SWEEP_INTERVAL_MILLIS, TimeUnit.MILLISECONDS);
    }

    static synchronized FileTransferManager get() {
        if (instance == null) {
            instance = new FileTransferManager();
        }
        return instance;
    }

    static boolean isTransferMessage(String body) {
        return body != null && body.startsWith(PREFIX);
    }

    static String buildOffer(String id, String name, long size, String mime, int chunks) throws Exception {
        return buildOffer(id, name, size, mime, chunks, null);
    }

    static String buildOffer(String id, String name, long size, String mime, int chunks, String sha256)
            throws Exception {
        JSONObject json = new JSONObject();
        json.put("t", "offer");
        json.put("id", id);
        json.put("name", name);
        json.put("size", size);
        json.put("mime", mime);
        json.put("chunks", chunks);
        if (sha256 != null && !sha256.isEmpty()) {
            json.put("sha256", sha256);
        }
        return PREFIX + json.toString();
    }

    static String buildChunk(String id, int seq, byte[] data, int length) throws Exception {
        JSONObject json = new JSONObject();
        json.put("t", "chunk");
        json.put("id", id);
        json.put("seq", seq);
        json.put("data", Base64.getEncoder().encodeToString(
                length == data.length ? data : java.util.Arrays.copyOf(data, length)));
        return PREFIX + json.toString();
    }

    static String buildDone(String id) throws Exception {
        JSONObject json = new JSONObject();
        json.put("t", "done");
        json.put("id", id);
        return PREFIX + json.toString();
    }

    static String buildAbort(String id, String reason) throws Exception {
        JSONObject json = new JSONObject();
        json.put("t", "abort");
        json.put("id", id);
        json.put("reason", reason == null ? "" : reason);
        return PREFIX + json.toString();
    }

    static JSONObject parseTransfer(String body) {
        if (!isTransferMessage(body)) {
            return null;
        }
        try {
            return new JSONObject(body.substring(PREFIX.length()));
        } catch (Exception ignored) {
            return null;
        }
    }

    synchronized boolean onIncomingMessage(Context context, String from, String body) {
        ensureSweeper(context);
        JSONObject json = parseTransfer(body);
        if (json == null) {
            return false;
        }
        String type = json.optString("t", "");
        String id = json.optString("id", "");
        if (id.trim().isEmpty()) {
            return true;
        }
        // The envelope's own sender field is peer-controlled and must never override the
        // authenticated sender the transport gives us.
        String sessionKey = sessionKey(from, id);
        try {
            switch (type) {
                case "offer":
                    handleOffer(context, sessionKey, from, json);
                    break;
                case "chunk":
                    handleChunk(context, sessionKey, from, json);
                    break;
                case "done":
                    handleDone(context, sessionKey, from, json);
                    break;
                case "abort":
                    handleAbort(context, sessionKey, from, json);
                    break;
                default:
                    break;
            }
        } catch (Exception error) {
            dropSession(sessionKey);
            ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                    "文件接收失败 · " + error.getMessage());
        }
        return true;
    }

    void sendFile(Context context, SpecusCore.Runtime runtime, String target, Uri uri) {
        String name = "file";
        long size = -1L;
        String mime = "application/octet-stream";
        String id = UUID.randomUUID().toString().replace("-", "");
        try {
            Cursor cursor = context.getContentResolver().query(uri, null, null, null, null);
            if (cursor != null) {
                try {
                    if (cursor.moveToFirst()) {
                        int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                        int sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE);
                        if (nameIndex >= 0 && cursor.getString(nameIndex) != null) {
                            name = cursor.getString(nameIndex);
                        }
                        if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) {
                            size = cursor.getLong(sizeIndex);
                        }
                    }
                } finally {
                    cursor.close();
                }
            }
            String declaredMime = context.getContentResolver().getType(uri);
            if (declaredMime != null && !declaredMime.trim().isEmpty()) {
                mime = declaredMime;
            }
            if (size > MAX_FILE_BYTES) {
                ChatEvents.send(context, ChatEvents.DIRECTION_OUT, ChatEvents.KIND_FILE, target,
                        "文件过大 · 上限 " + formatBytes(MAX_FILE_BYTES));
                return;
            }
            InputStream in = context.getContentResolver().openInputStream(uri);
            if (in == null) {
                ChatEvents.send(context, ChatEvents.DIRECTION_OUT, ChatEvents.KIND_FILE, target,
                        "无法读取文件 · " + name);
                return;
            }
            long total = 0L;
            int chunks = 0;
            try (InputStream input = in) {
                byte[] probe = new byte[CHUNK_BYTES];
                java.util.List<byte[]> buffered = new java.util.ArrayList<>();
                java.util.List<Integer> lengths = new java.util.ArrayList<>();
                int read;
                while ((read = readFully(input, probe)) > 0) {
                    byte[] copy = new byte[read];
                    System.arraycopy(probe, 0, copy, 0, read);
                    buffered.add(copy);
                    lengths.add(read);
                    total += read;
                    chunks++;
                    if (total > MAX_FILE_BYTES) {
                        ChatEvents.send(context, ChatEvents.DIRECTION_OUT, ChatEvents.KIND_FILE, target,
                                "文件过大 · 上限 " + formatBytes(MAX_FILE_BYTES));
                        return;
                    }
                }
                runtime.sendClientMessage(target, buildOffer(id, name, total, mime, chunks,
                        digestOf(buffered, lengths)));
                ChatEvents.send(context, ChatEvents.DIRECTION_OUT, ChatEvents.KIND_FILE, target,
                        "发送中 " + name + " · " + formatBytes(total));
                for (int seq = 0; seq < chunks; seq++) {
                    runtime.sendClientMessage(target, buildChunk(id, seq, buffered.get(seq), lengths.get(seq)));
                    if ((seq + 1) % PROGRESS_EVERY_CHUNKS == 0 || seq + 1 == chunks) {
                        int percent = chunks == 0 ? 100 : (int) (((long) (seq + 1) * 100) / chunks);
                        ChatEvents.send(context, ChatEvents.DIRECTION_OUT, ChatEvents.KIND_FILE, target,
                                "发送中 " + name + " · " + percent + "%");
                    }
                }
                runtime.sendClientMessage(target, buildDone(id));
                ChatEvents.send(context, ChatEvents.DIRECTION_OUT, ChatEvents.KIND_FILE, target,
                        "已发送 " + name + " · " + formatBytes(total));
            }
        } catch (Exception error) {
            try {
                runtime.sendClientMessage(target, buildAbort(id, error.getMessage()));
            } catch (Exception ignored) {
            }
            ChatEvents.send(context, ChatEvents.DIRECTION_OUT, ChatEvents.KIND_FILE, target,
                    "文件发送失败 · " + (error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage()));
        }
    }

    private void handleOffer(Context context, String sessionKey, String from, JSONObject json)
            throws Exception {
        long size = json.optLong("size", -1L);
        int chunks = json.optInt("chunks", -1);
        int expectedChunks = (int) ((size + CHUNK_BYTES - 1) / CHUNK_BYTES);
        if (size < 0 || size > MAX_FILE_BYTES || chunks < 0 || chunks != expectedChunks) {
            throw new IllegalArgumentException("invalid offer");
        }
        String sha256 = json.optString("sha256", "");
        if (!sha256.isEmpty() && !isHexDigest(sha256)) {
            throw new IllegalArgumentException("invalid digest");
        }
        // A repeated offer for the same sender+id restarts the transfer; it must not leak the
        // previous temp file or its reserved bytes.
        dropSession(sessionKey);
        if (incoming.size() >= MAX_CONCURRENT_SESSIONS) {
            throw new IllegalStateException("session limit reached");
        }
        if (pendingBytes + size > MAX_PENDING_BYTES) {
            throw new IllegalStateException("pending buffer full");
        }
        File dir = new File(context.getFilesDir(), "transfers");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IllegalStateException("transfer dir unavailable");
        }
        // The remote id never reaches the filesystem: the temp name is locally generated and the
        // resolved path is verified to stay inside our own directory.
        File temp = new File(dir, UUID.randomUUID().toString().replace("-", "") + ".part");
        requireContained(dir, temp);
        IncomingSession session = new IncomingSession();
        session.name = sanitizeName(json.optString("name", "file"));
        session.size = size;
        session.chunks = chunks;
        session.sha256 = sha256.isEmpty() ? null : sha256;
        session.from = from == null ? "" : from;
        session.file = temp;
        session.randomAccess = new RandomAccessFile(temp, "rw");
        session.randomAccess.setLength(size);
        session.receivedChunks = new boolean[chunks];
        session.lastTouchedAtMillis = System.currentTimeMillis();
        incoming.put(sessionKey, session);
        pendingBytes += size;
        ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                "接收中 " + session.name + " · " + formatBytes(size));
    }

    private void handleChunk(Context context, String sessionKey, String from, JSONObject json)
            throws Exception {
        IncomingSession session = incoming.get(sessionKey);
        if (session == null) {
            return;
        }
        int seq = json.optInt("seq", -1);
        byte[] data = Base64.getDecoder().decode(json.optString("data", ""));
        if (seq < 0 || seq >= session.chunks) {
            throw new IllegalArgumentException("invalid chunk seq");
        }
        long offset = (long) seq * CHUNK_BYTES;
        // Every chunk but the last must be exactly CHUNK_BYTES, so a short chunk cannot silently
        // leave a hole that the bitmap would still count as received.
        int expected = (int) Math.min(CHUNK_BYTES, session.size - offset);
        if (data.length != expected) {
            throw new IllegalArgumentException("chunk length mismatch");
        }
        session.lastTouchedAtMillis = System.currentTimeMillis();
        if (session.receivedChunks[seq]) {
            // Duplicate delivery (peer retry or server fallback): the completion count must not move.
            return;
        }
        session.randomAccess.seek(offset);
        session.randomAccess.write(data);
        session.receivedChunks[seq] = true;
        session.received++;
        session.receivedBytes += data.length;
        if (session.received % PROGRESS_EVERY_CHUNKS == 0) {
            int percent = (int) ((session.received * 100L) / Math.max(1, session.chunks));
            ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                    "接收中 " + session.name + " · " + percent + "%");
        }
    }

    private void handleDone(Context context, String sessionKey, String from, JSONObject json)
            throws Exception {
        if (completed.containsKey(sessionKey)) {
            // The sender retried "done" after its ACK was lost; the file is already delivered.
            return;
        }
        IncomingSession session = incoming.remove(sessionKey);
        if (session == null) {
            return;
        }
        pendingBytes = Math.max(0L, pendingBytes - session.size);
        session.randomAccess.close();
        if (session.received != session.chunks || session.receivedBytes != session.size) {
            //noinspection ResultOfMethodCallIgnored
            session.file.delete();
            ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                    "文件不完整 · " + session.name + " (" + session.received + "/" + session.chunks + ")");
            return;
        }
        if (session.sha256 != null && !session.sha256.equalsIgnoreCase(fileDigest(session.file))) {
            //noinspection ResultOfMethodCallIgnored
            session.file.delete();
            ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                    "文件校验失败 · " + session.name);
            return;
        }
        completed.put(sessionKey, System.currentTimeMillis());
        File target = uniqueTarget(context, session.name);
        if (!session.file.renameTo(target)) {
            copyFile(session.file, target);
            //noinspection ResultOfMethodCallIgnored
            session.file.delete();
        }
        ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                "已接收 " + session.name + " · " + formatBytes(session.size) + "\n保存到 " + target.getAbsolutePath());
    }

    private void handleAbort(Context context, String sessionKey, String from, JSONObject json) {
        IncomingSession session = dropSession(sessionKey);
        if (session != null) {
            ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                    "对方取消发送 · " + session.name);
        }
    }

    synchronized void sweepExpired(Context context) {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Long>> completedIterator = completed.entrySet().iterator();
        while (completedIterator.hasNext()) {
            if (now - completedIterator.next().getValue() > SESSION_TTL_MILLIS) {
                completedIterator.remove();
            }
        }
        Iterator<Map.Entry<String, IncomingSession>> iterator = incoming.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, IncomingSession> entry = iterator.next();
            IncomingSession session = entry.getValue();
            if (now - session.lastTouchedAtMillis <= SESSION_TTL_MILLIS) {
                continue;
            }
            iterator.remove();
            pendingBytes = Math.max(0L, pendingBytes - session.size);
            closeQuietly(session.randomAccess);
            //noinspection ResultOfMethodCallIgnored
            session.file.delete();
            ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, session.from,
                    "接收超时 · " + session.name);
        }
    }

    private IncomingSession dropSession(String sessionKey) {
        IncomingSession session = incoming.remove(sessionKey);
        if (session != null) {
            pendingBytes = Math.max(0L, pendingBytes - session.size);
            closeQuietly(session.randomAccess);
            //noinspection ResultOfMethodCallIgnored
            session.file.delete();
        }
        return session;
    }

    private static File uniqueTarget(Context context, String name) {
        File dir = context.getExternalFilesDir(android.os.Environment.DIRECTORY_DOWNLOADS);
        if (dir == null) {
            dir = new File(context.getFilesDir(), "downloads");
        }
        if (!dir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
        }
        File target = new File(dir, name);
        if (!target.exists()) {
            return target;
        }
        String base = name;
        String extension = "";
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            base = name.substring(0, dot);
            extension = name.substring(dot);
        }
        for (int i = 1; i < 1000; i++) {
            File candidate = new File(dir, base + " (" + i + ")" + extension);
            if (!candidate.exists()) {
                return candidate;
            }
        }
        return new File(dir, System.currentTimeMillis() + "-" + name);
    }

    private static void copyFile(File source, File target) throws Exception {
        try (FileInputStream in = new FileInputStream(source);
             FileOutputStream out = new FileOutputStream(target)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
            }
        }
    }

    private static int readFully(InputStream in, byte[] buffer) throws Exception {
        int offset = 0;
        while (offset < buffer.length) {
            int read = in.read(buffer, offset, buffer.length - offset);
            if (read < 0) {
                break;
            }
            offset += read;
        }
        return offset;
    }

    /** Sessions are per authenticated sender, so peers cannot collide on transfer ids. */
    private static String sessionKey(String from, String id) {
        return (from == null ? "" : from) + " " + id;
    }

    /**
     * Reduces a peer-supplied name to a bare file name: directory components, traversal segments and
     * separators are all removed before the name reaches the filesystem.
     */
    static String sanitizeName(String name) {
        String value = name == null ? "" : name.trim();
        int lastSeparator = Math.max(value.lastIndexOf('/'), value.lastIndexOf('\\'));
        if (lastSeparator >= 0) {
            value = value.substring(lastSeparator + 1);
        }
        StringBuilder builder = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            builder.append(current < 0x20 || current == ':' || current == '*' || current == '?'
                    || current == '"' || current == '<' || current == '>' || current == '|'
                    ? '_' : current);
        }
        value = builder.toString().trim();
        while (value.endsWith(".") || value.endsWith(" ")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.isEmpty() || value.equals(".") || value.equals("..")) {
            return "file";
        }
        return value.length() > MAX_NAME_LENGTH ? value.substring(value.length() - MAX_NAME_LENGTH) : value;
    }

    /** Rejects any candidate that resolves outside the directory we own. */
    private static void requireContained(File directory, File candidate) throws Exception {
        String root = directory.getCanonicalPath();
        if (!root.endsWith(File.separator)) {
            root = root + File.separator;
        }
        if (!candidate.getCanonicalPath().startsWith(root)) {
            throw new IllegalArgumentException("resolved path escapes the transfer directory");
        }
    }

    private static boolean isHexDigest(String value) {
        if (value.length() != 64) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            boolean hex = (current >= '0' && current <= '9')
                    || (current >= 'a' && current <= 'f')
                    || (current >= 'A' && current <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    /** Digest of the buffered outgoing chunks, so the receiver can verify the whole file. */
    private static String digestOf(java.util.List<byte[]> chunks, java.util.List<Integer> lengths)
            throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (int index = 0; index < chunks.size(); index++) {
            digest.update(chunks.get(index), 0, lengths.get(index));
        }
        return toHex(digest.digest());
    }

    static String fileDigest(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
        }
        return toHex(digest.digest());
    }

    private static String toHex(byte[] value) {
        StringBuilder hex = new StringBuilder(value.length * 2);
        for (byte current : value) {
            hex.append(Character.forDigit((current >> 4) & 0xF, 16));
            hex.append(Character.forDigit(current & 0xF, 16));
        }
        return hex.toString();
    }

    static String formatBytes(long bytes) {
        String[] units = {"B", "KB", "MB", "GB"};
        double value = Math.max(0L, bytes);
        int unit = 0;
        while (value >= 1024.0 && unit < units.length - 1) {
            value /= 1024.0;
            unit++;
        }
        return String.format(Locale.ROOT, value >= 10 || unit == 0 ? "%.0f %s" : "%.1f %s", value, units[unit]);
    }

    private static void closeQuietly(java.io.Closeable closeable) {
        try {
            if (closeable != null) {
                closeable.close();
            }
        } catch (Exception ignored) {
        }
    }

    private static final class IncomingSession {
        String name;
        String from;
        long size;
        int chunks;
        int received;
        long receivedBytes;
        boolean[] receivedChunks;
        String sha256;
        File file;
        RandomAccessFile randomAccess;
        long lastTouchedAtMillis;
    }
}
