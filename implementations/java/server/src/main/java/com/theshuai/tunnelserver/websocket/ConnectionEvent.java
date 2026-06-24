package com.theshuai.tunnelserver.websocket;

import com.theshuai.tunnelserver.management.model.ConnectionRecordView;

/**
 * 推给管理 UI 的连接事件 DTO。{@code type} 取 {@link Type#code()}。
 * <p>同时作为 Spring {@code ApplicationEvent} 由 {@link ConnectionEventBroadcaster} 监听并广播，
 * 拼成 JSON 之后通过 {@code /ws/connections} 推给所有在线管理浏览器。
 */
public record ConnectionEvent(String tenantId, String type, ConnectionRecordView connection) {

    public static ConnectionEvent created(String tenantId, ConnectionRecordView record) {
        return new ConnectionEvent(tenantId, Type.CREATED.code(), record);
    }

    public static ConnectionEvent updated(String tenantId, ConnectionRecordView record) {
        return new ConnectionEvent(tenantId, Type.UPDATED.code(), record);
    }

    public enum Type {
        CREATED("created"),
        UPDATED("updated");

        private final String code;

        Type(String code) {
            this.code = code;
        }

        public String code() {
            return code;
        }
    }
}
