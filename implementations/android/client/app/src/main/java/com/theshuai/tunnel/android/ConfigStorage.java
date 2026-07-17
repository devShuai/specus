package com.theshuai.tunnel.android;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;

final class ConfigStorage {
    private static final String PREFS = "shuai_tunnel_android";
    private static final String KEY_CONFIG = "client_jsonc";
    private static final String KEY_MACHINE_ID = "machine_id";
    private static final String KEY_LAST_TARGET = "last_target";

    private ConfigStorage() {
    }

    static String loadConfig(Context context) {
        return prefs(context).getString(KEY_CONFIG, defaultConfig());
    }

    static void saveConfig(Context context, String config) {
        prefs(context).edit().putString(KEY_CONFIG, config == null ? "" : config).apply();
    }

    static String loadLastTarget(Context context) {
        return prefs(context).getString(KEY_LAST_TARGET, "");
    }

    static void saveLastTarget(Context context, String target) {
        prefs(context).edit().putString(KEY_LAST_TARGET, target == null ? "" : target.trim()).apply();
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

    static String updateBasicConfig(Context context, String serverBaseUrl, String apiKey,
                                    String secret, boolean peerMeshEnabled) throws Exception {
        JSONObject json = parseConfig(loadConfig(context));
        json.put("serverBaseUrl", serverBaseUrl == null ? "" : serverBaseUrl.trim());
        json.put("apiKey", apiKey == null ? "" : apiKey.trim());
        json.put("secret", secret == null ? "" : secret.trim());
        if (peerMeshEnabled) {
            String current = json.optString("peerMeshDevice", "noop");
            if (current.trim().isEmpty() || "noop".equalsIgnoreCase(current.trim())) {
                json.put("peerMeshDevice", "auto");
            }
        } else {
            json.put("peerMeshDevice", "noop");
        }
        String updated = json.toString(2);
        saveConfig(context, updated);
        return updated;
    }

    static JSONObject parseConfig(String jsonc) throws Exception {
        String json = TunnelCore.Jsonc.toJson(jsonc == null ? "" : jsonc);
        JSONObject parsed = new JSONObject(json.trim().isEmpty() ? "{}" : json);
        return parsed;
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
