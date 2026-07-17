package com.theshuai.tunnel.android;

import android.content.Context;
import android.content.Intent;

final class ChatEvents {
    static final String ACTION_CHAT = "com.theshuai.tunnel.android.CHAT";
    static final String EXTRA_DIRECTION = "direction";
    static final String EXTRA_KIND = "kind";
    static final String EXTRA_PEER = "peer";
    static final String EXTRA_TEXT = "text";
    static final String EXTRA_TIMESTAMP = "timestamp";

    static final String DIRECTION_IN = "in";
    static final String DIRECTION_OUT = "out";
    static final String DIRECTION_SYSTEM = "system";

    static final String KIND_TEXT = "text";
    static final String KIND_FILE = "file";

    private ChatEvents() {
    }

    static void send(Context context, String direction, String kind, String peer, String text) {
        if (context == null) {
            return;
        }
        Intent intent = new Intent(ACTION_CHAT)
                .setPackage(context.getPackageName())
                .putExtra(EXTRA_DIRECTION, direction == null ? DIRECTION_SYSTEM : direction)
                .putExtra(EXTRA_KIND, kind == null ? KIND_TEXT : kind)
                .putExtra(EXTRA_PEER, peer == null ? "" : peer)
                .putExtra(EXTRA_TEXT, text == null ? "" : text)
                .putExtra(EXTRA_TIMESTAMP, System.currentTimeMillis());
        context.sendBroadcast(intent);
    }
}
