package com.theshuai.specusserver.management.model;

import io.netty.channel.Channel;
import io.netty.util.AttributeKey;

/**
 * 控制连接断开的原因。覆盖：服务端主动踢、客户端正常 FIN、协议违规、空闲超时、注册失败、
 * 服务端优雅停机 / 重启清扫等。
 *
 * <p>跨模块用 Netty 通道属性传递：specus-common 与 specus-server 通过同名 AttributeKey
 * （{@link #CHANNEL_ATTR_NAME}）共享，value 为本枚举的 {@link #name()}。
 *
 * <p>规则：</p>
 * <ul>
 *   <li>谁先关谁先打标 —— 使用 {@link #markIfAbsent(Channel, DisconnectReason)} 避免被覆盖；</li>
 *   <li>{@code channelInactive} 里读取，缺省视为 {@link #CLIENT_CLOSED}（peer 主动 FIN）。</li>
 * </ul>
 */
public enum DisconnectReason {
    LOGIN_FAILURE          ("登录失败"),
    CLIENT_CLOSED          ("客户端正常断开"),
    IO_ERROR               ("传输异常"),
    IDLE_TIMEOUT           ("读空闲超时(60s)"),
    HEARTBEAT_WRITE_FAILED ("心跳发送失败"),
    PROTOCOL_VIOLATION     ("协议违规"),
    REGISTER_FAILED        ("注册失败"),
    REPLACED_BY_NEW_LOGIN  ("被新登录替换"),
    ADMIN_DISABLED         ("管理员停用账号"),
    ADMIN_RENAMED          ("管理员修改账号名"),
    ADMIN_DELETED          ("管理员删除账号"),
    SERVER_BUSY            ("服务端繁忙拒绝"),
    SERVER_SHUTDOWN        ("服务端优雅停机"),
    SERVER_RESTARTED       ("服务端重启时清理"),
    UNKNOWN                ("未知");

    /** AttributeKey 名称；specus-common 用同名字符串引用同一属性。 */
    public static final String CHANNEL_ATTR_NAME = "disconnectReason";

    public static final AttributeKey<String> CHANNEL_ATTR = AttributeKey.valueOf(CHANNEL_ATTR_NAME);

    private final String label;

    DisconnectReason(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    /** 首次打标生效，避免链式 close 时被晚到的事件覆盖掉真正主因。 */
    public static void markIfAbsent(Channel channel, DisconnectReason reason) {
        if (channel == null || reason == null) {
            return;
        }
        channel.attr(CHANNEL_ATTR).compareAndSet(null, reason.name());
    }

    /** 从通道属性还原 enum；未打标返回 null（由调用方决定如何兜底）。 */
    public static DisconnectReason readFrom(Channel channel) {
        if (channel == null) {
            return null;
        }
        String raw = channel.attr(CHANNEL_ATTR).get();
        return parse(raw);
    }

    /** 解析字符串码；未知值返回 {@link #UNKNOWN}；null 返回 null（区分"没有"与"不认识"）。 */
    public static DisconnectReason parse(String code) {
        if (code == null) {
            return null;
        }
        try {
            return DisconnectReason.valueOf(code);
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }
}
