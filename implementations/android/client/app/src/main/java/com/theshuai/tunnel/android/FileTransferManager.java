package com.theshuai.tunnel.android;

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
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

final class FileTransferManager {
    private static final String PREFIX = "STXFER1\n";
    private static final int CHUNK_BYTES = 600;
    private static final long MAX_FILE_BYTES = 8L * 1024 * 1024;
    private static final long SESSION_TTL_MILLIS = 120_000L;
    private static final int PROGRESS_EVERY_CHUNKS = 32;

    private static FileTransferManager instance;

    private final Map<String, IncomingSession> incoming = new HashMap<>();

    private FileTransferManager() {
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
        JSONObject json = new JSONObject();
        json.put("t", "offer");
        json.put("id", id);
        json.put("name", name);
        json.put("size", size);
        json.put("mime", mime);
        json.put("chunks", chunks);
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
        JSONObject json = parseTransfer(body);
        if (json == null) {
            sweepExpired(context);
            return false;
        }
        String type = json.optString("t", "");
        String id = json.optString("id", "");
        if (id.trim().isEmpty()) {
            return true;
        }
        try {
            switch (type) {
                case "offer":
                    handleOffer(context, from, json);
                    break;
                case "chunk":
                    handleChunk(context, from, json);
                    break;
                case "done":
                    handleDone(context, from, json);
                    break;
                case "abort":
                    handleAbort(context, from, json);
                    break;
                default:
                    break;
            }
        } catch (Exception error) {
            dropSession(id);
            ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                    "文件接收失败 · " + error.getMessage());
        }
        return true;
    }

    void sendFile(Context context, TunnelCore.Runtime runtime, String target, Uri uri) {
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
                runtime.sendClientMessage(target, buildOffer(id, name, total, mime, chunks));
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

    private void handleOffer(Context context, String from, JSONObject json) throws Exception {
        String id = json.getString("id");
        long size = json.optLong("size", -1L);
        int chunks = json.optInt("chunks", 0);
        if (size < 0 || size > MAX_FILE_BYTES || chunks <= 0 || chunks > (MAX_FILE_BYTES / CHUNK_BYTES + 1)) {
            throw new IllegalArgumentException("invalid offer");
        }
        dropSession(id);
        File dir = new File(context.getFilesDir(), "transfers");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IllegalStateException("transfer dir unavailable");
        }
        File temp = new File(dir, id + ".part");
        IncomingSession session = new IncomingSession();
        session.id = id;
        session.name = sanitizeName(json.optString("name", "file"));
        session.size = size;
        session.chunks = chunks;
        session.from = from == null ? "" : from;
        session.file = temp;
        session.randomAccess = new RandomAccessFile(temp, "rw");
        session.randomAccess.setLength(size);
        session.lastTouchedAtMillis = System.currentTimeMillis();
        incoming.put(id, session);
        ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                "接收中 " + session.name + " · " + formatBytes(size));
    }

    private void handleChunk(Context context, String from, JSONObject json) throws Exception {
        String id = json.getString("id");
        IncomingSession session = incoming.get(id);
        if (session == null) {
            return;
        }
        int seq = json.optInt("seq", -1);
        byte[] data = Base64.getDecoder().decode(json.optString("data", ""));
        if (seq < 0 || seq >= session.chunks) {
            throw new IllegalArgumentException("invalid chunk seq");
        }
        long offset = (long) seq * CHUNK_BYTES;
        if (offset + data.length > session.size) {
            throw new IllegalArgumentException("chunk out of range");
        }
        session.randomAccess.seek(offset);
        session.randomAccess.write(data);
        session.received++;
        session.lastTouchedAtMillis = System.currentTimeMillis();
        if (session.received % PROGRESS_EVERY_CHUNKS == 0) {
            int percent = (int) ((session.received * 100L) / session.chunks);
            ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                    "接收中 " + session.name + " · " + percent + "%");
        }
    }

    private void handleDone(Context context, String from, JSONObject json) throws Exception {
        String id = json.getString("id");
        IncomingSession session = incoming.remove(id);
        if (session == null) {
            return;
        }
        session.randomAccess.close();
        if (session.received != session.chunks) {
            //noinspection ResultOfMethodCallIgnored
            session.file.delete();
            ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                    "文件不完整 · " + session.name + " (" + session.received + "/" + session.chunks + ")");
            return;
        }
        File target = uniqueTarget(context, session.name);
        if (!session.file.renameTo(target)) {
            copyFile(session.file, target);
            //noinspection ResultOfMethodCallIgnored
            session.file.delete();
        }
        ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                "已接收 " + session.name + " · " + formatBytes(session.size) + "\n保存到 " + target.getAbsolutePath());
    }

    private void handleAbort(Context context, String from, JSONObject json) {
        String id = json.optString("id", "");
        IncomingSession session = dropSession(id);
        if (session != null) {
            ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, from,
                    "对方取消发送 · " + session.name);
        }
    }

    private void sweepExpired(Context context) {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, IncomingSession>> iterator = incoming.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, IncomingSession> entry = iterator.next();
            IncomingSession session = entry.getValue();
            if (now - session.lastTouchedAtMillis <= SESSION_TTL_MILLIS) {
                continue;
            }
            iterator.remove();
            closeQuietly(session.randomAccess);
            //noinspection ResultOfMethodCallIgnored
            session.file.delete();
            ChatEvents.send(context, ChatEvents.DIRECTION_IN, ChatEvents.KIND_FILE, session.from,
                    "接收超时 · " + session.name);
        }
    }

    private IncomingSession dropSession(String id) {
        IncomingSession session = incoming.remove(id);
        if (session != null) {
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

    private static String sanitizeName(String name) {
        String value = name == null || name.trim().isEmpty() ? "file" : name.trim();
        return value.replace('/', '_').replace('\\', '_');
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
        String id;
        String name;
        String from;
        long size;
        int chunks;
        int received;
        File file;
        RandomAccessFile randomAccess;
        long lastTouchedAtMillis;
    }
}
