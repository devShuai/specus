package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ClientAccount;

/**
 * 登录认证结果。由 server pipeline 用来决定是否绑定会话；
 * {@link ConnectionRecordService#recordConnection} 把它持久化为一条连接记录。
 */
public record AuthenticationResult(boolean success, ClientAccount account, String reason, Long clientSessionId) {
    public static AuthenticationResult success(ClientAccount account, Long clientSessionId) {
        return new AuthenticationResult(true, account, null, clientSessionId);
    }

    public static AuthenticationResult failure(ClientAccount account, String reason) {
        return new AuthenticationResult(false, account, reason, null);
    }
}
