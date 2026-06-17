package com.theshuai.common.attribute;

import com.theshuai.common.session.Session;
import io.netty.util.AttributeKey;

public interface Attributes {
    AttributeKey<Session> SESSION = AttributeKey.newInstance("session");
    /** 控制连接登录成功的本地时间戳（System.currentTimeMillis），用于展示"在线时长"。 */
    AttributeKey<Long> LOGIN_TIME_MS = AttributeKey.newInstance("loginTimeMs");
}
