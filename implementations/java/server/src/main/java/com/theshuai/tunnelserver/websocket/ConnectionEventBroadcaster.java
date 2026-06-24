package com.theshuai.tunnelserver.websocket;

import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * 在数据库事务真正提交后再把 {@link ConnectionEvent} 推给同租户在线管理浏览器。
 * <p>挂 {@code @TransactionalEventListener(AFTER_COMMIT)} 的关键收益：
 * 如果 {@code ConnectionRecordService.recordConnection} / {@code recordDisconnect}
 * 持久化失败回滚，UI 就不会收到"幽灵" record；事务真提交后再广播。
 */
@Component
public class ConnectionEventBroadcaster {

    private final ConnectionEventsWebSocketHandler handler;

    public ConnectionEventBroadcaster(ConnectionEventsWebSocketHandler handler) {
        this.handler = handler;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onConnectionEvent(ConnectionEvent event) {
        handler.broadcast(event.tenantId(), event);
    }
}
