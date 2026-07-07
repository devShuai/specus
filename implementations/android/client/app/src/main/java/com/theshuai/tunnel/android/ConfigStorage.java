package com.theshuai.tunnel.android;

import android.content.Context;
import android.content.SharedPreferences;

final class ConfigStorage {
    private static final String PREFS = "shuai_tunnel_android";
    private static final String KEY_CONFIG = "client_jsonc";
    private static final String KEY_MACHINE_ID = "machine_id";

    private ConfigStorage() {
    }

    static String loadConfig(Context context) {
        return prefs(context).getString(KEY_CONFIG, defaultConfig());
    }

    static void saveConfig(Context context, String config) {
        prefs(context).edit().putString(KEY_CONFIG, config == null ? "" : config).apply();
    }

    static String machineId(Context context) {
        SharedPreferences prefs = prefs(context);
        String existing = prefs.getString(KEY_MACHINE_ID, null);
        if (existing != null && !existing.trim().isEmpty()) {
            return existing;
        }
        String generated = "m_android_" + java.util.UUID.randomUUID();
        prefs.edit().putString(KEY_MACHINE_ID, generated).apply();
        return generated;
    }

    static String defaultConfig() {
        return "{\n"
                + "  \"$schema\": \"https://tunnel.devshuai.com/schemas/client-startup-config.schema.json\",\n"
                + "  // Android client config. Comments and trailing commas are supported.\n"
                + "  \"serverBaseUrl\": \"https://tunnel.devshuai.com\",\n"
                + "  \"apiKey\": \"YOUR_CLIENT_API_KEY\",\n"
                + "  \"secret\": \"YOUR_CLIENT_SECRET\",\n"
                + "  \"peerMeshDevice\": \"noop\",\n"
                + "  \"peerMeshTunName\": \"shuai0\",\n"
                + "  \"peerMeshMtu\": 1280\n"
                + "}\n";
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
