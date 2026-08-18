package com.theshuai.specus.android;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

final class FileTransferManager {
    private static final String PREFIX = "STXFER1\n";
    static final int MAX_TRANSFER_FRAME_BYTES = 8 * 1024;
    static final int CHUNK_BYTES = 600;
    static final long MAX_FILE_BYTES = 8L * 1024 * 1024;
    static final long SESSION_TTL_MILLIS = 120_000L;
    private static final long SWEEP_INTERVAL_MILLIS = 15_000L;
    static final int PROGRESS_EVERY_CHUNKS = 32;
    /** Concurrent inbound sessions across all peers. */
    static final int MAX_CONCURRENT_SESSIONS = 16;
    /** Total bytes reserved on disk by in-flight inbound sessions. */
    static final long MAX_PENDING_BYTES = 64L * 1024 * 1024;
    private static final int MAX_NAME_LENGTH = 180;

    private static FileTransferManager instance;

    private final IncomingFileTransfer receiver = new IncomingFileTransfer();
    private ScheduledExecutorService sweeper;

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

    static String buildOffer(String id, String name, long size, String mime, int chunks, String sha256)
            throws Exception {
        if (!isHexDigest(sha256 == null ? "" : sha256)) {
            throw new IllegalArgumentException("sha256 must be 64 hexadecimal characters");
        }
        JSONObject json = new JSONObject();
        json.put("t", "offer");
        json.put("id", id);
        json.put("name", name);
        json.put("size", size);
        json.put("mime", mime);
        json.put("chunks", chunks);
        json.put("sha256", sha256.toLowerCase(Locale.ROOT));
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
        if (!isTransferMessage(body) || utf8LengthExceeds(body, MAX_TRANSFER_FRAME_BYTES)) {
            return null;
        }
        try {
            return new JSONObject(body.substring(PREFIX.length()));
        } catch (Exception ignored) {
            return null;
        }
    }

    /** Counts UTF-8 bytes without allocating a second attacker-sized byte array. */
    static boolean utf8LengthExceeds(String value, int limit) {
        if (value == null) {
            return false;
        }
        int bytes = 0;
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current <= 0x7F) {
                bytes++;
            } else if (current <= 0x7FF) {
                bytes += 2;
            } else if (Character.isHighSurrogate(current)
                    && index + 1 < value.length()
                    && Character.isLowSurrogate(value.charAt(index + 1))) {
                bytes += 4;
                index++;
            } else {
                // Conservatively count an unpaired surrogate as a three-byte code unit.
                bytes += 3;
            }
            if (bytes > limit) {
                return true;
            }
        }
        return false;
    }

    boolean onIncomingMessage(Context context, String from, String body) {
        ensureSweeper(context);
        if (!isTransferMessage(body)) {
            return false;
        }
        JSONObject json = parseTransfer(body);
        if (json == null) {
            // A malformed reserved frame is consumed rather than rendered as chat text.
            return true;
        }
        receiver.onFrame(transferDirectory(context), downloadDirectory(context),
                IncomingFileTransfer.SYSTEM_FILE_OPS,
                (peer, text) -> ChatEvents.send(context, ChatEvents.DIRECTION_IN,
                        ChatEvents.KIND_FILE, peer, text),
                from, json);
        return true;
    }

    void sendFile(Context context, SpecusCore.Runtime runtime, String target, Uri uri) {
        String name = "file";
        long size = -1L;
        String mime = "application/octet-stream";
        String id = UUID.randomUUID().toString().replace("-", "");
        boolean offerSent = false;
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
            if (size >= 0L) {
                runtime.requireFileTransferTarget(target, size);
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
                // Re-check with the authoritative measured size immediately before the first
                // STXFER frame. A rejected/legacy target receives no transfer protocol traffic.
                runtime.requireFileTransferTarget(target, total);
                runtime.sendClientMessage(target, buildOffer(id, name, total, mime, chunks,
                        digestOf(buffered, lengths)));
                offerSent = true;
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
            if (offerSent) {
                try {
                    runtime.sendClientMessage(target, buildAbort(id, error.getMessage()));
                } catch (Exception ignored) {
                }
            }
            ChatEvents.send(context, ChatEvents.DIRECTION_OUT, ChatEvents.KIND_FILE, target,
                    "文件发送失败 · " + (error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage()));
        }
    }

    private void sweepExpired(Context context) {
        receiver.sweepExpired((peer, text) -> ChatEvents.send(context, ChatEvents.DIRECTION_IN,
                ChatEvents.KIND_FILE, peer, text));
    }

    private static File transferDirectory(Context context) {
        return new File(context.getFilesDir(), "transfers");
    }

    private static File downloadDirectory(Context context) {
        File directory = context.getExternalFilesDir(android.os.Environment.DIRECTORY_DOWNLOADS);
        return directory == null ? new File(context.getFilesDir(), "downloads") : directory;
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

}
