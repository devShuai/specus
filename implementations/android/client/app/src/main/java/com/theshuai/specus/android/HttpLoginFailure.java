package com.theshuai.specus.android;

import java.io.IOException;

/** Same status policy as Java/Go/.NET CLI; never contains response bodies. */
final class HttpLoginFailure extends IOException {
    final boolean retryable;
    HttpLoginFailure(String message, boolean retryable) {
        super(message);
        this.retryable = retryable;
    }

    static HttpLoginFailure fromStatus(int status) {
        boolean retry = status == 408 || status == 425 || status == 429 || status >= 500 && status <= 599;
        String advice = status == 400 || status == 401 || status == 403 || status == 409
                ? "请检查 API Key、Secret、系统时钟、账户权限与网关规则；修改后重试"
                : retry ? "服务暂不可用或请求受限，将退避重试"
                : "请检查服务地址与客户端兼容性后重试";
        return new HttpLoginFailure("HTTP 登录失败（" + status + "）· " + advice, retry);
    }
}
