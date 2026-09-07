package com.theshuai.specus.android;

/** A direct frame may have reached its peer; server fallback would risk duplicate delivery. */
final class MessageDeliveryUnknownException extends java.io.IOException {
    MessageDeliveryUnknownException() {
        super("等待设备确认超时，发送结果未知；请确认对方未收到后再重试");
    }
}
