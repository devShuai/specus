package com.theshuai.common.protocol;

public enum NatMessageType {
    REGISTER(1),
    REGISTER_RESULT(2),
    CONNECTED(3),
    DISCONNECTED(4),
    DATA(5),
    KEEPALIVE(6),
    UNREGISTER(7),
    /**
     * 客户端登录后向服务端上报当前生效的 HTTP 路由（{@code httpTunnelConfigList}）。
     * 服务端缓存于 {@code HttpRouteRegistry}，仅用于管理 UI 展示，不影响实际转发逻辑。
     * 旧客户端不发，服务端收到未知 type 走 default 分支只打日志，向前兼容。
     */
    HTTP_ROUTES_REPORT(8);

    private int code;

    NatMessageType(int code) {
        this.code = code;
    }

    public static NatMessageType valueOf(int code) {
        for (NatMessageType item : NatMessageType.values()) {
            if (item.code == code) {
                return item;
            }
        }
        return null;
    }

    public int getCode() {
        return code;
    }
}
