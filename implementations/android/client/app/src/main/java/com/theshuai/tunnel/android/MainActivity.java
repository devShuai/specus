package com.theshuai.tunnel.android;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;

public class MainActivity extends Activity {
    private static final int VPN_REQUEST = 4208;
    private static final int COLOR_INK = Color.rgb(18, 30, 38);
    private static final int COLOR_MUTED = Color.rgb(99, 116, 126);
    private static final int COLOR_PAGE = Color.rgb(236, 242, 245);
    private static final int COLOR_PANEL = Color.rgb(255, 255, 255);
    private static final int COLOR_MESH = Color.rgb(29, 119, 109);
    private static final int COLOR_MESH_DARK = Color.rgb(17, 91, 85);
    private static final int COLOR_WARN = Color.rgb(201, 126, 44);
    private static final int COLOR_DANGER = Color.rgb(176, 62, 71);
    private static final int COLOR_CODE = Color.rgb(15, 24, 31);

    private TextView statusPill;
    private TextView statusTitle;
    private TextView statusDetail;
    private TextView serverValue;
    private TextView credentialValue;
    private TextView meshValue;
    private TextView mtuValue;
    private TextView eventLogView;
    private EditText configEditor;
    private EditText messageTargetEditor;
    private EditText messageBodyEditor;

    private final Deque<String> eventLog = new ArrayDeque<>();

    private final BroadcastReceiver statusReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!StatusEvents.ACTION_STATUS.equals(intent.getAction())) {
                return;
            }
            String status = intent.getStringExtra(StatusEvents.EXTRA_STATUS);
            String detail = intent.getStringExtra(StatusEvents.EXTRA_DETAIL);
            boolean running = intent.getBooleanExtra(StatusEvents.EXTRA_RUNNING, false);
            updateStatus(status, detail, running);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        maybeRequestNotifications();
        setContentView(buildContent());
        configEditor.setText(ConfigStorage.loadConfig(this));
        updateConfigSummary();
        updateStatus("Ready", "", false);
    }

    @Override
    protected void onStart() {
        super.onStart();
        IntentFilter filter = new IntentFilter(StatusEvents.ACTION_STATUS);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(statusReceiver, filter);
        }
    }

    @Override
    protected void onStop() {
        unregisterReceiver(statusReceiver);
        super.onStop();
    }

    private View buildContent() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(COLOR_PAGE);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(16), dp(16), dp(18));
        scroll.addView(root, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        root.addView(buildCommandPanel());
        root.addView(space(14));
        root.addView(buildMessagePanel());
        root.addView(space(14));
        root.addView(buildConfigPanel());
        root.addView(space(14));
        root.addView(buildLogPanel());
        return scroll;
    }

    private View buildCommandPanel() {
        LinearLayout panel = panel(COLOR_INK, 18, 0);
        panel.setPadding(dp(18), dp(18), dp(18), dp(18));
        panel.setMinimumHeight(dp(210));
        if (Build.VERSION.SDK_INT >= 21) {
            panel.setElevation(dp(3));
        }

        LinearLayout top = new LinearLayout(this);
        top.setGravity(Gravity.CENTER_VERTICAL);
        top.setOrientation(LinearLayout.HORIZONTAL);
        panel.addView(top, matchWrap());

        LinearLayout titleBlock = new LinearLayout(this);
        titleBlock.setOrientation(LinearLayout.VERTICAL);
        top.addView(titleBlock, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView eyebrow = label("SHUAI TUNNEL", Color.rgb(153, 220, 209), 11, Typeface.BOLD);
        titleBlock.addView(eyebrow);

        TextView title = label("Tunnel console", Color.WHITE, 24, Typeface.BOLD);
        title.setPadding(0, dp(2), 0, 0);
        titleBlock.addView(title);

        statusPill = label("STOPPED", Color.WHITE, 11, Typeface.BOLD);
        statusPill.setGravity(Gravity.CENTER);
        statusPill.setPadding(dp(10), dp(6), dp(10), dp(6));
        statusPill.setBackground(round(Color.rgb(84, 98, 108), 999));
        top.addView(statusPill);

        statusTitle = label("Ready", Color.WHITE, 20, Typeface.BOLD);
        statusTitle.setPadding(0, dp(22), 0, 0);
        panel.addView(statusTitle, matchWrap());

        statusDetail = label("No active tunnel", Color.rgb(182, 198, 206), 14, Typeface.NORMAL);
        statusDetail.setPadding(0, dp(6), 0, dp(16));
        panel.addView(statusDetail, matchWrap());

        LinearLayout summary = new LinearLayout(this);
        summary.setOrientation(LinearLayout.VERTICAL);
        summary.setPadding(dp(14), dp(12), dp(14), dp(12));
        summary.setBackground(stroke(Color.rgb(25, 41, 51), Color.rgb(52, 78, 89), 1, 14));
        panel.addView(summary, matchWrap());

        serverValue = addSummaryRow(summary, "Server", "-");
        credentialValue = addSummaryRow(summary, "Credential", "-");
        meshValue = addSummaryRow(summary, "Peer mesh", "-");
        mtuValue = addSummaryRow(summary, "MTU", "-");

        LinearLayout actions = new LinearLayout(this);
        actions.setGravity(Gravity.CENTER_VERTICAL);
        actions.setPadding(0, dp(16), 0, 0);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        panel.addView(actions, matchWrap());

        Button startButton = actionButton("Start", COLOR_MESH, Color.WHITE);
        startButton.setOnClickListener(v -> {
            ConfigStorage.saveConfig(this, configEditor.getText().toString());
            updateConfigSummary();
            requestVpnThenStart();
        });
        actions.addView(startButton, new LinearLayout.LayoutParams(0, dp(48), 1.35f));

        actions.addView(space(10, 1));

        Button stopButton = actionButton("Stop", Color.TRANSPARENT, Color.rgb(239, 214, 216));
        stopButton.setBackground(stroke(Color.TRANSPARENT, Color.rgb(126, 65, 74), 1, 12));
        stopButton.setOnClickListener(v -> startService(new Intent(this, TunnelForegroundService.class)
                .setAction(TunnelForegroundService.ACTION_STOP)));
        actions.addView(stopButton, new LinearLayout.LayoutParams(0, dp(48), 1f));

        return panel;
    }

    private View buildMessagePanel() {
        LinearLayout panel = panel(COLOR_PANEL, 16, Color.rgb(219, 228, 233));
        panel.setPadding(dp(16), dp(16), dp(16), dp(16));

        TextView title = label("Client messages", COLOR_INK, 18, Typeface.BOLD);
        panel.addView(title);

        messageTargetEditor = messageInput("Target client", false);
        panel.addView(space(12));
        panel.addView(messageTargetEditor, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48)));

        messageBodyEditor = messageInput("Message", true);
        panel.addView(space(10));
        panel.addView(messageBodyEditor, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(112)));

        Button sendButton = actionButton("Send", COLOR_MESH, Color.WHITE);
        sendButton.setOnClickListener(v -> sendClientMessage());
        panel.addView(space(12));
        panel.addView(sendButton, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(46)));
        return panel;
    }

    private View buildConfigPanel() {
        LinearLayout panel = panel(COLOR_PANEL, 16, Color.rgb(219, 228, 233));
        panel.setPadding(dp(16), dp(16), dp(16), dp(16));

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);
        panel.addView(head, matchWrap());

        TextView title = label("Client config", COLOR_INK, 18, Typeface.BOLD);
        head.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button resetButton = smallButton("Reset");
        resetButton.setOnClickListener(v -> {
            configEditor.setText(ConfigStorage.defaultConfig());
            updateConfigSummary();
            Toast.makeText(this, "Example restored", Toast.LENGTH_SHORT).show();
        });
        head.addView(resetButton, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(40)));

        configEditor = new EditText(this);
        configEditor.setGravity(Gravity.START | Gravity.TOP);
        configEditor.setMinLines(16);
        configEditor.setTextSize(13);
        configEditor.setTextColor(Color.rgb(226, 238, 241));
        configEditor.setHintTextColor(Color.rgb(116, 139, 148));
        configEditor.setTypeface(Typeface.MONOSPACE);
        configEditor.setSingleLine(false);
        configEditor.setHorizontallyScrolling(false);
        configEditor.setPadding(dp(14), dp(14), dp(14), dp(14));
        configEditor.setBackground(round(COLOR_CODE, 14));
        configEditor.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        configEditor.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                updateConfigSummary();
            }

            @Override
            public void afterTextChanged(Editable s) {
            }
        });

        panel.addView(space(12));
        panel.addView(configEditor, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(360)));

        LinearLayout actions = new LinearLayout(this);
        actions.setGravity(Gravity.END);
        actions.setPadding(0, dp(14), 0, 0);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        panel.addView(actions, matchWrap());

        Button saveButton = actionButton("Save changes", COLOR_INK, Color.WHITE);
        saveButton.setOnClickListener(v -> {
            ConfigStorage.saveConfig(this, configEditor.getText().toString());
            updateConfigSummary();
            Toast.makeText(this, "Config saved", Toast.LENGTH_SHORT).show();
        });
        actions.addView(saveButton, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(46)));
        return panel;
    }

    private View buildLogPanel() {
        LinearLayout panel = panel(COLOR_PANEL, 16, Color.rgb(219, 228, 233));
        panel.setPadding(dp(16), dp(16), dp(16), dp(16));

        TextView title = label("Runtime events", COLOR_INK, 18, Typeface.BOLD);
        panel.addView(title);

        eventLogView = label("Waiting for tunnel activity", COLOR_MUTED, 13, Typeface.NORMAL);
        eventLogView.setLineSpacing(dp(2), 1f);
        eventLogView.setPadding(0, dp(10), 0, 0);
        panel.addView(eventLogView, matchWrap());
        return panel;
    }

    private void updateStatus(String status, String detail, boolean running) {
        String primary = status == null || status.trim().isEmpty() ? (running ? "Running" : "Ready") : status.trim();
        String secondary = detail == null || detail.trim().isEmpty() ? (running ? "Tunnel service active" : "No active tunnel") : detail.trim();
        statusTitle.setText(primary);
        statusDetail.setText(secondary);
        statusPill.setText(running ? "RUNNING" : "STOPPED");
        statusPill.setBackground(round(running ? COLOR_MESH : Color.rgb(84, 98, 108), 999));
        addEvent((running ? "RUNNING" : "STOPPED") + "  " + primary
                + (secondary.trim().isEmpty() ? "" : " - " + secondary));
    }

    private void updateConfigSummary() {
        if (serverValue == null || configEditor == null) {
            return;
        }
        try {
            JSONObject json = new JSONObject(toJson(configEditor.getText().toString()));
            serverValue.setText(compact(json.optString("serverBaseUrl", "-"), 44));
            String apiKey = json.optString("apiKey", "");
            credentialValue.setText(apiKey.trim().isEmpty() ? "Missing" : compact(apiKey, 24));
            String peerMode = json.optString("peerMeshDevice", "noop");
            meshValue.setText(peerMode + ("noop".equalsIgnoreCase(peerMode) ? "" : " enabled"));
            mtuValue.setText(String.format(Locale.ROOT, "%d", json.optInt("peerMeshMtu", 1280)));
        } catch (Exception e) {
            serverValue.setText("Invalid JSONC");
            credentialValue.setText("-");
            meshValue.setText("-");
            mtuValue.setText("-");
        }
    }

    private void addEvent(String text) {
        if (text == null || text.trim().isEmpty()) {
            return;
        }
        eventLog.addFirst(text);
        while (eventLog.size() > 6) {
            eventLog.removeLast();
        }
        StringBuilder builder = new StringBuilder();
        for (String item : eventLog) {
            if (builder.length() > 0) {
                builder.append('\n');
            }
            builder.append(item);
        }
        eventLogView.setText(builder.toString());
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST) {
            if (resultCode == RESULT_OK) {
                startTunnelService();
            } else {
                Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void requestVpnThenStart() {
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            startActivityForResult(prepare, VPN_REQUEST);
        } else {
            startTunnelService();
        }
    }

    private void startTunnelService() {
        Intent intent = new Intent(this, TunnelForegroundService.class)
                .setAction(TunnelForegroundService.ACTION_START);
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
    }

    private void sendClientMessage() {
        String target = messageTargetEditor == null ? "" : messageTargetEditor.getText().toString().trim();
        String message = messageBodyEditor == null ? "" : messageBodyEditor.getText().toString().trim();
        if (target.isEmpty()) {
            Toast.makeText(this, "Target client is required", Toast.LENGTH_SHORT).show();
            return;
        }
        if (message.isEmpty()) {
            Toast.makeText(this, "Message is required", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent intent = new Intent(this, TunnelForegroundService.class)
                .setAction(TunnelForegroundService.ACTION_SEND_MESSAGE)
                .putExtra(TunnelForegroundService.EXTRA_TO_CLIENT_NAME, target)
                .putExtra(TunnelForegroundService.EXTRA_MESSAGE, message);
        startService(intent);
        addEvent("OUT  " + target + " - " + compact(message, 72));
        messageBodyEditor.setText("");
    }

    private void maybeRequestNotifications() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1001);
        }
    }

    private TextView addSummaryRow(LinearLayout parent, String label, String value) {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, dp(4), 0, dp(4));
        parent.addView(row, matchWrap());

        TextView left = label(label, Color.rgb(136, 156, 166), 12, Typeface.BOLD);
        row.addView(left, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.8f));

        TextView right = label(value, Color.rgb(230, 241, 245), 13, Typeface.BOLD);
        right.setGravity(Gravity.END);
        row.addView(right, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.4f));
        return right;
    }

    private LinearLayout panel(int color, int radius, int strokeColor) {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setBackground(strokeColor == 0 ? round(color, radius) : stroke(color, strokeColor, 1, radius));
        return layout;
    }

    private TextView label(String text, int color, int sp, int style) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(color);
        view.setTextSize(sp);
        view.setIncludeFontPadding(true);
        view.setTypeface(Typeface.DEFAULT, style);
        return view;
    }

    private Button actionButton(String text, int background, int foreground) {
        Button button = new Button(this);
        button.setAllCaps(false);
        button.setText(text);
        button.setTextSize(14);
        button.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        button.setTextColor(foreground);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setPadding(dp(12), 0, dp(12), 0);
        button.setBackground(round(background, 12));
        return button;
    }

    private EditText messageInput(String hint, boolean multiLine) {
        EditText input = new EditText(this);
        input.setTextSize(14);
        input.setTextColor(COLOR_INK);
        input.setHintTextColor(COLOR_MUTED);
        input.setSingleLine(!multiLine);
        input.setGravity(multiLine ? (Gravity.START | Gravity.TOP) : Gravity.CENTER_VERTICAL);
        input.setPadding(dp(12), 0, dp(12), 0);
        input.setHint(hint);
        input.setBackground(stroke(Color.rgb(248, 251, 252), Color.rgb(206, 218, 225), 1, 12));
        if (multiLine) {
            input.setMinLines(3);
            input.setPadding(dp(12), dp(10), dp(12), dp(10));
            input.setInputType(InputType.TYPE_CLASS_TEXT
                    | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                    | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
        } else {
            input.setInputType(InputType.TYPE_CLASS_TEXT
                    | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        }
        return input;
    }

    private Button smallButton(String text) {
        Button button = actionButton(text, Color.rgb(232, 240, 243), COLOR_INK);
        button.setTextSize(13);
        button.setPadding(dp(12), 0, dp(12), 0);
        return button;
    }

    private GradientDrawable round(int color, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(radiusDp));
        return drawable;
    }

    private GradientDrawable stroke(int fill, int stroke, int widthDp, int radiusDp) {
        GradientDrawable drawable = round(fill, radiusDp);
        drawable.setStroke(dp(widthDp), stroke);
        return drawable;
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private View space(int height) {
        View view = new View(this);
        view.setLayoutParams(new LinearLayout.LayoutParams(1, dp(height)));
        return view;
    }

    private View space(int width, int height) {
        View view = new View(this);
        view.setLayoutParams(new LinearLayout.LayoutParams(dp(width), dp(height)));
        return view;
    }

    private String compact(String value, int max) {
        if (value == null) {
            return "-";
        }
        String trimmed = value.trim();
        if (trimmed.length() <= max) {
            return trimmed;
        }
        return trimmed.substring(0, Math.max(0, max - 3)) + "...";
    }

    private String toJson(String jsonc) {
        return removeTrailingCommas(stripComments(jsonc == null ? "" : jsonc));
    }

    private String stripComments(String input) {
        StringBuilder out = new StringBuilder(input.length());
        boolean string = false;
        boolean escape = false;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (string) {
                out.append(c);
                if (escape) {
                    escape = false;
                } else if (c == '\\') {
                    escape = true;
                } else if (c == '"') {
                    string = false;
                }
                continue;
            }
            if (c == '"') {
                string = true;
                out.append(c);
                continue;
            }
            if (c == '/' && i + 1 < input.length()) {
                char next = input.charAt(i + 1);
                if (next == '/') {
                    i += 2;
                    while (i < input.length() && input.charAt(i) != '\n' && input.charAt(i) != '\r') {
                        i++;
                    }
                    if (i < input.length()) {
                        out.append(input.charAt(i));
                    }
                    continue;
                }
                if (next == '*') {
                    i += 2;
                    while (i + 1 < input.length() && !(input.charAt(i) == '*' && input.charAt(i + 1) == '/')) {
                        i++;
                    }
                    i++;
                    continue;
                }
            }
            out.append(c);
        }
        return out.toString();
    }

    private String removeTrailingCommas(String input) {
        StringBuilder out = new StringBuilder(input.length());
        boolean string = false;
        boolean escape = false;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (string) {
                out.append(c);
                if (escape) {
                    escape = false;
                } else if (c == '\\') {
                    escape = true;
                } else if (c == '"') {
                    string = false;
                }
                continue;
            }
            if (c == '"') {
                string = true;
                out.append(c);
                continue;
            }
            if (c == ',') {
                int j = i + 1;
                while (j < input.length() && Character.isWhitespace(input.charAt(j))) {
                    j++;
                }
                if (j < input.length() && (input.charAt(j) == '}' || input.charAt(j) == ']')) {
                    continue;
                }
            }
            out.append(c);
        }
        return out.toString();
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
