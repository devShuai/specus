package com.theshuai.specusserver.attribute;

import com.theshuai.common.session.Session;
import io.netty.util.AttributeKey;

/**
 * 服务端控制连接 channel 上挂的本地属性。这些值是服务端 only 的状态，因此不放在
 * specus-common 共享模块——客户端从不读它们。
 */
public final class ServerAttributes {
    private ServerAttributes() {
    }

    /** 控制连接登录成功的本地时间戳（System.currentTimeMillis），用于展示"在线时长"。 */
    public static final AttributeKey<Long> LOGIN_TIME_MS = AttributeKey.valueOf("loginTimeMs");

    /** 已登录客户端账号所属租户。 */
    public static final AttributeKey<String> TENANT_ID = AttributeKey.valueOf("tenantId");

    /** HTTP 登录产生的客户端会话 ID，仅新 token 登录路径有值。 */
    public static final AttributeKey<Long> CLIENT_SESSION_ID = AttributeKey.valueOf("clientSessionId");

    /** Mandatory v2 role: {@code control} or {@code data}. */
    public static final AttributeKey<String> CONNECTION_ROLE = AttributeKey.valueOf("connectionRole");

    /** 已登录会话上下文。绑定 = 已登录；移除 = 未登录。 */
    public static final AttributeKey<Session> SESSION = AttributeKey.valueOf("session");
}
