package com.theshuai.specus.android;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;

/** Process-session memory only: no chat plaintext on disk, bounded retention. */
final class GuiSessionStore {
    static final int MAX_MESSAGES = 100;
    static final int MAX_TEXT_CHARS = 16_384;
    static final class Status {
        final String title, detail;
        final boolean running, ready;
        Status(String title, String detail, boolean running, boolean ready) {
            this.title = title; this.detail = detail; this.running = running; this.ready = ready;
        }
    }
    static final class Message {
        final String id, direction, kind, peer, text, state;
        final long timestamp;
        Message(String id, String direction, String kind, String peer, String text, String state, long timestamp) {
            this.id = id; this.direction = direction; this.kind = kind; this.peer = peer;
            this.text = text; this.state = state; this.timestamp = timestamp;
        }
    }
    private static Status status = new Status("未连接", "填写连接设置后启动", false, false);
    private static final LinkedHashMap<String, Message> messages = new LinkedHashMap<>();
    static String draft = "";
    private static List<String> targets = List.of();
    static synchronized void targets(List<String> names) { targets = List.copyOf(names); }
    static synchronized List<String> targets() { return status.ready ? targets : List.of(); }

    static synchronized Status status() { return status; }
    static synchronized void status(String title, String detail, boolean running) {
        String reason = detail == null ? "" : detail;
        if (!running) {
            targets = List.of();
            // Runtime cleanup must not erase the actionable terminal reason.
            if (!status.running && (reason.isEmpty() || "Service destroyed".equals(reason))) return;
            status = new Status(title, reason, false, false);
        } else if ("Connected".equals(title)) {
            status = new Status("转发通道就绪", reason + " · 目标服务尚未探测", true, true);
        } else if ("Control authenticated".equals(title)) {
            status = new Status("控制通道已认证", "正在连接数据通道，尚不能转发", true, false);
        } else if (title.equals("Starting") || title.equals("HTTP login") || title.equals("HTTP relogin")
                || title.equals("Control connecting") || title.equals("Reconnect pending")
                || title.equals("Disconnected") || title.equals("Error") || title.equals("Data channel closed")) {
            status = new Status(title.equals("Reconnect pending") ? "等待重连" : title, reason, true, false);
        } else if (title.equals("VPN stopped") || title.equals("NAT register failed")) {
            status = new Status("部分功能不可用", reason, true, status.ready);
        }
        // Chat/roster/heartbeat events are not connection state transitions.
    }

    static synchronized String add(String direction, String kind, String peer, String text, String state) {
        String id = UUID.randomUUID().toString();
        messages.put(id, new Message(id, direction, kind, peer == null ? "" : peer,
                bounded(text), state, System.currentTimeMillis()));
        while (messages.size() > MAX_MESSAGES) messages.remove(messages.keySet().iterator().next());
        return id;
    }
    static synchronized Message message(String id) { return messages.get(id); }
    static synchronized void result(String id, String state) {
        Message old = messages.get(id);
        if (old != null) messages.put(id, new Message(id, old.direction, old.kind, old.peer, old.text, state, old.timestamp));
    }
    static synchronized List<Message> messages() { return new ArrayList<>(messages.values()); }
    static synchronized void clearMessages() { messages.clear(); draft = ""; }
    private static String bounded(String value) {
        if (value == null) return "";
        return value.length() <= MAX_TEXT_CHARS ? value : value.substring(0, MAX_TEXT_CHARS) + "\n[记录已截断]";
    }
}
