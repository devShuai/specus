package com.theshuai.specus.android;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Deque;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

public class MainActivity extends Activity {
    private static final int VPN_REQUEST = 4208;
    private static final int FILE_REQUEST = 4209;
    private static final int MAX_BUBBLES = 100;
    private int COLOR_INK, COLOR_MUTED, COLOR_PAGE, COLOR_PANEL, COLOR_LINE, COLOR_MESH, COLOR_DANGER;
    private static final int COLOR_BUBBLE_OUT = Color.rgb(29, 119, 109);
    private static final int COLOR_CODE = Color.rgb(15, 24, 31);
    private static volatile Supplier<String> peerServicesSnapshotSource = PeerServiceRuntime::lastSnapshotJson;

    private View statusDot;
    private TextView statusTitle;
    private TextView statusDetail;
    private Button toggleButton;
    private boolean specusRunning;

    private EditText targetEditor;
    private LinearLayout chatContainer;
    private ScrollView chatScroll;
    private EditText messageEditor;

    private LinearLayout settingsBody;
    private TextView settingsChevron;
    private EditText serverEditor;
    private EditText apiKeyEditor;
    private EditText secretEditor;
    private Switch meshSwitch;

    private LinearLayout advancedBody;
    private TextView advancedChevron;
    private EditText configEditor;
    private TextView eventLogView;
    private LinearLayout servicesList;
    private View[] pages;
    private int selectedPage;
    private View statusCard;
    private Button[] pageButtons;

    private final Deque<String> eventLog = new ArrayDeque<>();
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm", Locale.ROOT);
    private final ExecutorService updateExecutor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "specus-update-check");
        thread.setDaemon(true);
        return thread;
    });

    private final BroadcastReceiver statusReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!StatusEvents.ACTION_STATUS.equals(intent.getAction())) {
                return;
            }
            restoreSessionStatus();
        }
    };

    private final BroadcastReceiver servicesReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!PeerServiceEvents.ACTION_SERVICES.equals(intent.getAction())) {
                return;
            }
            renderServices(intent.getStringExtra(PeerServiceEvents.EXTRA_JSON));
        }
    };

    private final BroadcastReceiver chatReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!ChatEvents.ACTION_CHAT.equals(intent.getAction())) {
                return;
            }
            restoreMessages();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        COLOR_INK = getColor(R.color.gui_ink);
        COLOR_MUTED = getColor(R.color.gui_muted);
        COLOR_PAGE = getColor(R.color.gui_page);
        COLOR_PANEL = getColor(R.color.gui_panel);
        COLOR_LINE = getColor(R.color.gui_line);
        COLOR_MESH = getColor(R.color.gui_accent);
        COLOR_DANGER = getColor(R.color.gui_danger);
        maybeRequestNotifications();
        setContentView(buildContent());
        fillSettingsFromConfig();
        targetEditor.setText(ConfigStorage.loadLastTarget(this));
        messageEditor.setText(savedInstanceState == null ? GuiSessionStore.draft : savedInstanceState.getString("draft", ""));
        restoreSessionStatus();
        boolean configured = ConfigStorage.hasSavedConfig(this)
                && !apiKeyEditor.getText().toString().isBlank() && !secretEditor.getText().toString().isBlank();
        showPage(savedInstanceState == null ? (configured ? 0 : 2) : savedInstanceState.getInt("page", 0));
        if (!configured) {
            settingsBody.setVisibility(View.VISIBLE);
            settingsChevron.setText("▼");
        }
        reconcilePeerServices();
    }

    @Override
    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    protected void onStart() {
        super.onStart();
        IntentFilter statusFilter = new IntentFilter(StatusEvents.ACTION_STATUS);
        IntentFilter chatFilter = new IntentFilter(ChatEvents.ACTION_CHAT);
        IntentFilter servicesFilter = new IntentFilter(PeerServiceEvents.ACTION_SERVICES);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, statusFilter, Context.RECEIVER_NOT_EXPORTED);
            registerReceiver(chatReceiver, chatFilter, Context.RECEIVER_NOT_EXPORTED);
            registerReceiver(servicesReceiver, servicesFilter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            // The flags overload is API 33. Older releases use the compatible overload; these
            // receivers only handle in-process status events and are unregistered on stop.
            registerReceiver(statusReceiver, statusFilter);
            registerReceiver(chatReceiver, chatFilter);
            registerReceiver(servicesReceiver, servicesFilter);
        }
        // A full snapshot is authoritative. Broadcasts received while this Activity was stopped
        // are intentionally not queued, so always reconcile the UI when returning to foreground.
        reconcilePeerServices();
        restoreSessionStatus();
        restoreMessages();
        maybeCheckForUpdate();
    }

    @Override
    protected void onStop() {
        GuiSessionStore.draft = messageEditor.getText().toString();
        unregisterReceiver(statusReceiver);
        unregisterReceiver(chatReceiver);
        unregisterReceiver(servicesReceiver);
        super.onStop();
    }

    @Override protected void onSaveInstanceState(Bundle out) {
        out.putString("draft", messageEditor.getText().toString());
        out.putInt("page", selectedPage);
        super.onSaveInstanceState(out);
    }

    private void restoreSessionStatus() {
        GuiSessionStore.Status snapshot = GuiSessionStore.status();
        updateStatus(snapshot.title, snapshot.detail, snapshot.running);
        statusDot.setBackground(round(snapshot.ready && !snapshot.title.equals("部分功能不可用")
                ? COLOR_MESH : snapshot.running ? 0xffad7400 : COLOR_MUTED, 999));
    }

    private void restoreMessages() {
        chatContainer.removeAllViews();
        for (GuiSessionStore.Message item : GuiSessionStore.messages()) {
            addBubble(item.direction, item.kind, item.peer, item.text + "\n" + item.state, item.timestamp);
            View bubbleRow = chatContainer.getChildAt(chatContainer.getChildCount() - 1);
            bubbleRow.setOnLongClickListener(v -> {
                targetEditor.setText(item.peer);
                messageEditor.setText(item.text);
                Toast.makeText(this, "已恢复到输入框；结果未知时请确认对方未收到再发送", Toast.LENGTH_LONG).show();
                return true;
            });
        }
    }

    @Override
    protected void onDestroy() {
        updateExecutor.shutdownNow();
        super.onDestroy();
    }

    private void maybeCheckForUpdate() {
        if (!ConfigStorage.hasSavedConfig(this)) return;
        final String serverBaseUrl;
        try {
            JSONObject config = ConfigStorage.parseConfig(ConfigStorage.loadConfig(this));
            if (!config.optBoolean("updateCheckEnabled", true)) {
                return;
            }
            serverBaseUrl = config.optString("serverBaseUrl", "");
        } catch (Exception ignored) {
            return;
        }
        long claimedAt = System.currentTimeMillis();
        if (!ConfigStorage.claimUpdateCheck(this, claimedAt)) {
            return;
        }
        updateExecutor.execute(() -> {
            try {
                ClientUpdateChecker.Result result = ClientUpdateChecker.check(
                        serverBaseUrl, BuildConfig.VERSION_NAME);
                if (result.updateAvailable()) {
                    runOnUiThread(() -> showUpdatePrompt(result));
                }
            } catch (Exception ignored) {
                // Update discovery must never prevent the tunnel from starting. A transient error
                // releases the 24-hour claim so the next process start can retry.
                ConfigStorage.releaseUpdateCheck(getApplicationContext(), claimedAt);
            }
        });
    }

    private void showUpdatePrompt(ClientUpdateChecker.Result result) {
        if (isFinishing() || isDestroyed()) {
            return;
        }
        String title = result.mandatory() ? "需要更新客户端" : "发现新版本";
        String message = "当前版本 " + BuildConfig.VERSION_NAME + "，最新版本 "
                + result.latestVersion() + "。\n\n下载后由 Android 确认安装，现有配置会保留。";
        AlertDialog.Builder dialog = new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton("下载更新", (ignored, which) -> openExternalUrl(result.downloadUrl()))
                .setNegativeButton("稍后", null);
        if (result.changelogUrl() != null) {
            dialog.setNeutralButton("更新说明", (ignored, which) -> openExternalUrl(result.changelogUrl()));
        }
        dialog.show();
    }

    private void openExternalUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (RuntimeException error) {
            Toast.makeText(this, "无法打开下载链接", Toast.LENGTH_SHORT).show();
        }
    }

    private View buildContent() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(COLOR_PAGE);
        root.setPadding(dp(10), dp(10), dp(10), dp(12));
        statusCard = buildStatusCard();
        root.addView(statusCard);
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            int bottom = insets.getSystemWindowInsetBottom();
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(android.view.WindowInsets.Type.systemBars());
                android.graphics.Insets ime = insets.getInsets(android.view.WindowInsets.Type.ime());
                root.setPadding(dp(10) + bars.left, dp(10) + bars.top, dp(10) + bars.right, dp(10) + Math.max(bars.bottom, ime.bottom));
                statusCard.setVisibility(insets.isVisible(android.view.WindowInsets.Type.ime()) ? View.GONE : View.VISIBLE);
            } else root.setPadding(dp(10), dp(10) + insets.getSystemWindowInsetTop(), dp(10), dp(10) + bottom);
            return insets;
        });
        LinearLayout navigation = new LinearLayout(this);
        String[] titles = {"设备", "互传", "设置"};
        pageButtons = new Button[3];
        for (int index = 0; index < titles.length; index++) {
            final int page = index;
            Button tab = smallButton(titles[index]);
            pageButtons[index] = tab;
            tab.setOnClickListener(v -> showPage(page));
            navigation.addView(tab, new LinearLayout.LayoutParams(0, dp(48), 1f));
        }
        root.addView(navigation);
        LinearLayout settings = new LinearLayout(this);
        settings.setOrientation(LinearLayout.VERTICAL);
        settings.addView(buildSettingsCard());
        settings.addView(buildAdvancedCard());
        pages = new View[]{scrollPage(buildServicesCard()), buildChatCard(), scrollPage(settings)};
        for (View page : pages) root.addView(page, new LinearLayout.LayoutParams(-1, 0, 1f));
        return root;
    }

    private View scrollPage(View content) {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(content);
        return scroll;
    }

    private void showPage(int index) {
        selectedPage = Math.max(0, Math.min(2, index));
        for (int i = 0; i < pages.length; i++) pages[i].setVisibility(i == selectedPage ? View.VISIBLE : View.GONE);
        for (int i = 0; i < pageButtons.length; i++) {
            pageButtons[i].setSelected(i == selectedPage);
            pageButtons[i].setTextColor(i == selectedPage ? Color.WHITE : COLOR_INK);
            pageButtons[i].setBackground(round(i == selectedPage ? COLOR_MESH : COLOR_PAGE, 10));
        }
    }

    private View buildStatusCard() {
        LinearLayout panel = panel(COLOR_PANEL, 14, COLOR_LINE);
        panel.setPadding(dp(12), dp(10), dp(12), dp(10));

        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setOrientation(LinearLayout.HORIZONTAL);
        panel.addView(row, matchWrap());

        statusDot = new View(this);
        statusDot.setBackground(round(Color.rgb(84, 98, 108), 999));
        row.addView(statusDot, new LinearLayout.LayoutParams(dp(10), dp(10)));
        row.addView(space(8, 1));

        statusTitle = label("未连接", COLOR_INK, 15, Typeface.BOLD);
        row.addView(statusTitle, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        toggleButton = actionButton("启动", COLOR_MESH, Color.WHITE);
        toggleButton.setOnClickListener(v -> onToggleClicked());
        row.addView(toggleButton, new LinearLayout.LayoutParams(dp(84), dp(48)));
        Button retry = smallButton("重试");
        retry.setOnClickListener(v -> {
            if (!specusRunning) onToggleClicked();
            else startService(new Intent(this, SpecusForegroundService.class).setAction(SpecusForegroundService.ACTION_RETRY));
        });
        row.addView(retry, new LinearLayout.LayoutParams(dp(68), dp(48)));

        statusDetail = label("", COLOR_MUTED, 12, Typeface.NORMAL);
        statusDetail.setPadding(dp(18), dp(2), 0, 0);
        statusDetail.setMaxLines(3);
        panel.addView(statusDetail, matchWrap());
        return panel;
    }

    private View buildServicesCard() {
        LinearLayout panel = panel(COLOR_PANEL, 14, COLOR_LINE);
        panel.setPadding(dp(12), dp(10), dp(12), dp(10));
        panel.addView(label("共享服务", COLOR_INK, 14, Typeface.BOLD), matchWrap());
        TextView hint = label("对端按运行实例分组。本机开关只影响当前实例。", COLOR_MUTED, 12, Typeface.NORMAL);
        hint.setPadding(0, dp(2), 0, dp(4));
        panel.addView(hint, matchWrap());
        servicesList = new LinearLayout(this);
        servicesList.setOrientation(LinearLayout.VERTICAL);
        servicesList.setContentDescription("Peer 服务列表");
        panel.addView(servicesList, matchWrap());
        TextView empty = label("暂无对端服务", COLOR_MUTED, 12, Typeface.NORMAL);
        empty.setPadding(0, dp(6), 0, 0);
        servicesList.addView(empty, matchWrap());
        return panel;
    }

    void reconcilePeerServices() {
        renderServices(peerServicesSnapshotSource.get());
    }

    static void setPeerServicesSnapshotSourceForTest(Supplier<String> source) {
        peerServicesSnapshotSource = source == null ? PeerServiceRuntime::lastSnapshotJson : source;
    }

    void renderServices(String json) {
        if (servicesList == null) {
            return;
        }
        servicesList.removeAllViews();
        JSONArray remotes = new JSONArray();
        JSONArray locals = new JSONArray();
        try {
            String raw = json == null || json.isBlank() ? "{}" : json.trim();
            if (raw.startsWith("[")) {
                remotes = new JSONArray(raw);
            } else {
                JSONObject root = new JSONObject(raw);
                remotes = root.optJSONArray("remotes");
                locals = root.optJSONArray("locals");
                if (remotes == null) {
                    remotes = new JSONArray();
                }
                if (locals == null) {
                    locals = new JSONArray();
                }
            }
        } catch (Exception ignored) {
            remotes = new JSONArray();
            locals = new JSONArray();
        }
        if (remotes.length() == 0) {
            TextView empty = label("暂无对端服务", COLOR_MUTED, 12, Typeface.NORMAL);
            empty.setPadding(0, dp(6), 0, 0);
            servicesList.addView(empty, matchWrap());
        } else {
            for (int i = 0; i < remotes.length(); i++) {
                JSONObject item = remotes.optJSONObject(i);
                if (item != null) {
                    servicesList.addView(serviceRow(item), matchWrap());
                }
            }
        }
        if (locals.length() > 0) {
            TextView localTitle = label("本机发布", COLOR_INK, 13, Typeface.BOLD);
            localTitle.setPadding(0, dp(10), 0, dp(4));
            servicesList.addView(localTitle, matchWrap());
            for (int i = 0; i < locals.length(); i++) {
                JSONObject item = locals.optJSONObject(i);
                if (item != null) {
                    servicesList.addView(localRow(item), matchWrap());
                }
            }
        }
    }

    private View serviceRow(JSONObject item) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(0, dp(8), 0, dp(4));

        String publisher = item.optString("publisherClientName", "-");
        long sessionId = item.optLong("publisherSessionId", 0L);
        String serviceId = item.optString("serviceId", "");
        String serviceName = item.optString("name", serviceId.isBlank() ? "未命名服务" : serviceId);
        String application = item.optString("application", "tcp");
        String target = item.optString("accessTarget", "");
        String reason = item.optString("unavailableReason", "");
        boolean openable = item.optBoolean("openable", false);
        boolean copyable = item.optBoolean("copyable", false);

        TextView title = label(publisher + " · 实例 " + sessionId, COLOR_INK, 13, Typeface.BOLD);
        row.addView(title, matchWrap());
        TextView service = label(serviceName + " · " + application, COLOR_INK, 12, Typeface.BOLD);
        service.setContentDescription("服务 " + serviceName + "，发布实例 " + publisher + " " + sessionId);
        row.addView(service, matchWrap());
        TextView detail = label(target.isEmpty() ? reason : target, COLOR_MUTED, 12, Typeface.NORMAL);
        row.addView(detail, matchWrap());
        if (!reason.isEmpty()) {
            TextView reasonView = label(reason, COLOR_DANGER, 12, Typeface.NORMAL);
            row.addView(reasonView, matchWrap());
        }

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setPadding(0, dp(6), 0, 0);
        row.addView(actions, matchWrap());

        Button open = actionButton("打开", COLOR_MESH, Color.WHITE);
        open.setContentDescription("打开服务 " + serviceName);
        open.setEnabled(openable);
        open.setOnClickListener(v -> openExternalUrl(target));
        actions.addView(open, new LinearLayout.LayoutParams(dp(88), dp(48)));
        actions.addView(space(8, 1));
        Button copy = actionButton("复制", COLOR_PAGE, COLOR_INK);
        copy.setContentDescription("复制服务地址 " + serviceName);
        copy.setEnabled(copyable);
        copy.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (clipboard != null) {
                clipboard.setPrimaryClip(ClipData.newPlainText("peer-service", target));
                Toast.makeText(this, "已复制 " + target, Toast.LENGTH_SHORT).show();
            }
        });
        actions.addView(copy, new LinearLayout.LayoutParams(dp(88), dp(48)));
        return row;
    }

    private View localRow(JSONObject item) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(8), 0, dp(4));
        row.setMinimumHeight(dp(48));

        String serviceId = item.optString("serviceId", "");
        String name = item.optString("name", serviceId);
        String target = item.optString("target", "");
        boolean configEnabled = item.optBoolean("configEnabled", false);
        boolean locallyPublished = item.optBoolean("locallyPublished", false);
        boolean canToggle = item.optBoolean("canToggle", false);
        String publicationStatus = !configEnabled ? "配置已关闭"
                : !canToggle ? "已配置但未发布 · 全局共享关闭"
                : locallyPublished ? "已启用本实例发布资格"
                : "已配置但未发布 · 本实例已暂停";

        LinearLayout text = new LinearLayout(this);
        text.setOrientation(LinearLayout.VERTICAL);
        text.addView(label(name + " · " + item.optString("application", "tcp"), COLOR_INK, 13, Typeface.BOLD), matchWrap());
        text.addView(label(target + " → :" + item.optInt("publishedPort", 0)
                + (configEnabled ? "" : "（配置关闭）"), COLOR_MUTED, 12, Typeface.NORMAL), matchWrap());
        text.addView(label(publicationStatus, COLOR_MUTED, 12, Typeface.NORMAL), matchWrap());
        row.addView(text, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Switch publish = new Switch(this);
        publish.setMinHeight(dp(48));
        publish.setMinimumHeight(dp(48));
        publish.setEnabled(configEnabled && canToggle);
        publish.setContentDescription("发布本机服务 " + name);
        publish.setOnCheckedChangeListener(null);
        publish.setChecked(configEnabled && locallyPublished);
        publish.setOnCheckedChangeListener((button, checked) ->
                PeerServiceRuntime.setActiveLocalPublished(serviceId, checked));
        row.addView(publish, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return row;
    }

    private View buildChatCard() {
        LinearLayout panel = panel(COLOR_PANEL, 14, COLOR_LINE);
        panel.setPadding(dp(12), dp(10), dp(12), dp(10));

        LinearLayout targetRow = new LinearLayout(this);
        targetRow.setGravity(Gravity.CENTER_VERTICAL);
        targetRow.setOrientation(LinearLayout.HORIZONTAL);
        panel.addView(targetRow, matchWrap());

        TextView targetLabel = label("发送给", COLOR_MUTED, 12, Typeface.BOLD);
        targetRow.addView(targetLabel, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        targetRow.addView(space(8, 1));

        targetEditor = input("对方客户端名称", false);
        targetEditor.setHint("选择在线设备");
        targetEditor.setFocusable(false);
        targetEditor.setOnClickListener(v -> {
            String[] names = GuiSessionStore.targets().toArray(new String[0]);
            if (names.length == 0) {
                Toast.makeText(this, "暂无在线且支持消息接收的设备，请先连接并等待设备目录", Toast.LENGTH_LONG).show();
                return;
            }
            new AlertDialog.Builder(this).setTitle("发送给哪台设备？")
                    .setItems(names, (d, index) -> targetEditor.setText(names[index])).show();
        });
        targetRow.addView(targetEditor, new LinearLayout.LayoutParams(0, dp(48), 1f));

        chatScroll = new ScrollView(this);
        chatContainer = new LinearLayout(this);
        chatContainer.setOrientation(LinearLayout.VERTICAL);
        chatContainer.setPadding(0, dp(4), 0, dp(4));
        chatScroll.addView(chatContainer, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        scrollParams.setMargins(0, dp(8), 0, dp(8));
        chatScroll.setBackground(stroke(COLOR_PAGE, COLOR_LINE, 1, 10));
        panel.addView(chatScroll, scrollParams);

        LinearLayout inputRow = new LinearLayout(this);
        inputRow.setGravity(Gravity.CENTER_VERTICAL);
        inputRow.setOrientation(LinearLayout.HORIZONTAL);
        panel.addView(inputRow, matchWrap());

        Button attachButton = actionButton("文件", COLOR_PAGE, COLOR_INK);
        attachButton.setTextSize(13);
        attachButton.setPadding(0, 0, 0, 0);
        attachButton.setSingleLine(true);
        attachButton.setOnClickListener(v -> pickFile());
        inputRow.addView(attachButton, new LinearLayout.LayoutParams(dp(56), dp(48)));
        inputRow.addView(space(6, 1));

        messageEditor = input("输入消息", false);
        inputRow.addView(messageEditor, new LinearLayout.LayoutParams(0, dp(48), 1f));
        inputRow.addView(space(6, 1));

        Button sendButton = actionButton("发送", COLOR_MESH, Color.WHITE);
        sendButton.setOnClickListener(v -> sendMessage());
        inputRow.addView(sendButton, new LinearLayout.LayoutParams(dp(64), dp(48)));
        TextView retention = label("本次进程最近 100 条 · 长按重新编辑", COLOR_MUTED, 12, Typeface.NORMAL);
        panel.addView(retention);
        Button clear = smallButton("⋯");
        clear.setContentDescription("互传记录保留说明与清除");
        clear.setPadding(0, 0, 0, 0);
        clear.setOnClickListener(v -> new AlertDialog.Builder(this).setTitle("清除本次互传记录？")
                .setMessage("仅保留本次应用进程最近 100 条；长按恢复内容，不自动重发。\n\n清除仅影响本机显示记录与草稿，不删除已下载文件或对方记录。")
                .setNegativeButton("取消", null).setPositiveButton("清除", (d, w) -> {
                    GuiSessionStore.clearMessages(); messageEditor.setText(""); restoreMessages();
                }).show());
        targetRow.addView(clear, new LinearLayout.LayoutParams(dp(48), dp(48)));
        return panel;
    }

    private View buildSettingsCard() {
        LinearLayout panel = panel(COLOR_PANEL, 14, COLOR_LINE);
        panel.setPadding(dp(12), dp(10), dp(12), dp(12));

        LinearLayout header = new LinearLayout(this);
        header.setMinimumHeight(dp(48));
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setOrientation(LinearLayout.HORIZONTAL);
        panel.addView(header, matchWrap());

        TextView title = label("连接设置", COLOR_INK, 14, Typeface.BOLD);
        header.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        settingsChevron = label("▶", COLOR_MUTED, 12, Typeface.NORMAL);
        header.addView(settingsChevron, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        settingsBody = new LinearLayout(this);
        settingsBody.setOrientation(LinearLayout.VERTICAL);
        settingsBody.setVisibility(View.GONE);
        panel.addView(settingsBody, matchWrap());

        header.setOnClickListener(v -> toggleSection(settingsBody, settingsChevron, this::fillSettingsFromConfig));

        serverEditor = settingsField("服务地址", "https://specus.devshuai.com");
        apiKeyEditor = settingsField("API Key", "管理后台提供的 API Key");
        secretEditor = settingsField("Secret", "", true);

        LinearLayout meshRow = new LinearLayout(this);
        meshRow.setGravity(Gravity.CENTER_VERTICAL);
        meshRow.setOrientation(LinearLayout.HORIZONTAL);
        meshRow.setPadding(0, dp(8), 0, 0);
        settingsBody.addView(meshRow, matchWrap());

        TextView meshLabel = label("私有组网（Peer Mesh）", COLOR_INK, 13, Typeface.NORMAL);
        meshRow.addView(meshLabel, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        meshSwitch = new Switch(this);
        meshSwitch.setContentDescription("启用私有组网，需要 VPN 授权");
        meshSwitch.setMinHeight(dp(48));
        meshSwitch.setMinimumHeight(dp(48));
        meshRow.addView(meshSwitch, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        settingsBody.addView(label("从管理后台「接入凭证」获取 API Key 和 Secret。私有组网需要 VPN 授权；关闭后仍可使用转发与互传。", COLOR_MUTED, 12, Typeface.NORMAL));
        Button saveButton = actionButton("保存设置", COLOR_MESH, Color.WHITE);
        saveButton.setOnClickListener(v -> saveSettings());
        LinearLayout.LayoutParams saveParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(48));
        saveParams.setMargins(0, dp(10), 0, 0);
        settingsBody.addView(saveButton, saveParams);
        return panel;
    }

    private EditText settingsField(String caption, String hint) {
        return settingsField(caption, hint, false);
    }

    private EditText settingsField(String caption, String hint, boolean password) {
        TextView labelView = label(caption, COLOR_MUTED, 12, Typeface.BOLD);
        labelView.setPadding(0, dp(8), 0, dp(4));
        settingsBody.addView(labelView, matchWrap());

        EditText editor = input(hint, false);
        if (password) {
            editor.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        }
        settingsBody.addView(editor, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(48)));
        return editor;
    }

    private View buildAdvancedCard() {
        LinearLayout panel = panel(COLOR_PANEL, 14, COLOR_LINE);
        panel.setPadding(dp(12), dp(10), dp(12), dp(12));

        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setOrientation(LinearLayout.HORIZONTAL);
        panel.addView(header, matchWrap());

        TextView title = label("高级", COLOR_INK, 14, Typeface.BOLD);
        header.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        advancedChevron = label("▶", COLOR_MUTED, 12, Typeface.NORMAL);
        header.addView(advancedChevron, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        advancedBody = new LinearLayout(this);
        advancedBody.setOrientation(LinearLayout.VERTICAL);
        advancedBody.setVisibility(View.GONE);
        panel.addView(advancedBody, matchWrap());

        header.setOnClickListener(v -> toggleSection(advancedBody, advancedChevron, () ->
                configEditor.setText(ConfigStorage.loadConfig(this))));

        TextView configCaption = label("原始配置（JSONC）", COLOR_MUTED, 12, Typeface.BOLD);
        configCaption.setPadding(0, dp(8), 0, dp(4));
        advancedBody.addView(configCaption, matchWrap());

        configEditor = new EditText(this);
        configEditor.setGravity(Gravity.START | Gravity.TOP);
        configEditor.setMinLines(10);
        configEditor.setTextSize(12);
        configEditor.setTextColor(Color.rgb(226, 238, 241));
        configEditor.setHintTextColor(Color.rgb(116, 139, 148));
        configEditor.setTypeface(Typeface.MONOSPACE);
        configEditor.setSingleLine(false);
        configEditor.setPadding(dp(12), dp(12), dp(12), dp(12));
        configEditor.setBackground(round(COLOR_CODE, 10));
        configEditor.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        advancedBody.addView(configEditor, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(240)));

        LinearLayout configActions = new LinearLayout(this);
        configActions.setGravity(Gravity.END);
        configActions.setPadding(0, dp(8), 0, 0);
        configActions.setOrientation(LinearLayout.HORIZONTAL);
        advancedBody.addView(configActions, matchWrap());

        Button resetButton = smallButton("重置示例");
        resetButton.setOnClickListener(v -> {
            configEditor.setText(ConfigStorage.defaultConfig());
            Toast.makeText(this, "已恢复示例", Toast.LENGTH_SHORT).show();
        });
        configActions.addView(resetButton, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, dp(48)));
        configActions.addView(space(8, 1));

        Button saveConfigButton = actionButton("保存配置", COLOR_MESH, Color.WHITE);
        saveConfigButton.setOnClickListener(v -> {
            ConfigStorage.saveConfig(this, configEditor.getText().toString());
            fillSettingsFromConfig();
            Toast.makeText(this, "配置已保存", Toast.LENGTH_SHORT).show();
        });
        configActions.addView(saveConfigButton, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, dp(48)));

        TextView logCaption = label("运行事件", COLOR_MUTED, 12, Typeface.BOLD);
        logCaption.setPadding(0, dp(12), 0, dp(4));
        advancedBody.addView(logCaption, matchWrap());

        eventLogView = label("暂无事件", COLOR_MUTED, 12, Typeface.NORMAL);
        eventLogView.setLineSpacing(dp(2), 1f);
        advancedBody.addView(eventLogView, matchWrap());
        return panel;
    }

    private void toggleSection(LinearLayout body, TextView chevron, Runnable onExpand) {
        boolean show = body.getVisibility() != View.VISIBLE;
        body.setVisibility(show ? View.VISIBLE : View.GONE);
        chevron.setText(show ? "▼" : "▶");
        if (show && onExpand != null) {
            onExpand.run();
        }
    }

    private void fillSettingsFromConfig() {
        try {
            JSONObject json = ConfigStorage.parseConfig(ConfigStorage.loadConfig(this));
            serverEditor.setText(json.optString("serverBaseUrl", ""));
            apiKeyEditor.setText(json.optString("apiKey", ""));
            secretEditor.setText(json.optString("secret", ""));
            if (!ConfigStorage.hasSavedConfig(this)) {
                apiKeyEditor.setText("");
                secretEditor.setText("");
            }
            String device = json.optString("peerMeshDevice", "noop");
            meshSwitch.setChecked(!device.trim().isEmpty() && !"noop".equalsIgnoreCase(device.trim()));
        } catch (Exception ignored) {
            meshSwitch.setChecked(false);
        }
    }

    private void saveSettings() {
        try {
            ConfigStorage.updateBasicConfig(this,
                    serverEditor.getText().toString(),
                    apiKeyEditor.getText().toString(),
                    secretEditor.getText().toString(),
                    meshSwitch.isChecked());
            Toast.makeText(this, "设置已保存", Toast.LENGTH_SHORT).show();
        } catch (Exception error) {
            Toast.makeText(this, "保存失败：配置格式错误", Toast.LENGTH_SHORT).show();
        }
    }

    private void onToggleClicked() {
        if (specusRunning) {
            startService(new Intent(this, SpecusForegroundService.class)
                    .setAction(SpecusForegroundService.ACTION_STOP));
            return;
        }
        if (apiKeyEditor.getText().toString().isBlank() || secretEditor.getText().toString().isBlank()) {
            showPage(2);
            settingsBody.setVisibility(View.VISIBLE);
            settingsChevron.setText("▼");
            Toast.makeText(this, "请填写管理后台提供的 API Key 和 Secret", Toast.LENGTH_LONG).show();
            return;
        }
        String updatedConfig;
        try {
            updatedConfig = ConfigStorage.updateBasicConfig(this,
                    serverEditor.getText().toString(),
                    apiKeyEditor.getText().toString(),
                    secretEditor.getText().toString(),
                    meshSwitch.isChecked());
        } catch (Exception error) {
            Toast.makeText(this, "配置格式错误，请检查高级配置", Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            if (SpecusCore.StartupConfig.parse(updatedConfig).requiresVpnPermission()) {
                requestVpnThenStart();
            } else {
                startSpecusService();
            }
        } catch (Exception error) {
            Toast.makeText(this, "配置格式错误，请检查高级配置", Toast.LENGTH_SHORT).show();
        }
    }

    private void sendMessage() {
        String target = targetEditor.getText().toString().trim();
        String message = messageEditor.getText().toString().trim();
        if (target.isEmpty()) {
            Toast.makeText(this, "请填写对方客户端名称", Toast.LENGTH_SHORT).show();
            return;
        }
        if (message.isEmpty()) {
            return;
        }
        if (!GuiSessionStore.status().ready) {
            Toast.makeText(this, "转发通道尚未就绪，内容已保留", Toast.LENGTH_LONG).show();
            return;
        }
        if (!GuiSessionStore.targets().contains(target)) {
            Toast.makeText(this, "所选设备已离线或不支持接收，请重新选择", Toast.LENGTH_LONG).show();
            return;
        }
        if (message.length() > GuiSessionStore.MAX_TEXT_CHARS) {
            Toast.makeText(this, "消息过长，请拆分后发送", Toast.LENGTH_LONG).show();
            return;
        }
        ConfigStorage.saveLastTarget(this, target);
        String id = GuiSessionStore.add(ChatEvents.DIRECTION_OUT, ChatEvents.KIND_TEXT, target, message, "发送中");
        try {
        startService(new Intent(this, SpecusForegroundService.class)
                .setAction(SpecusForegroundService.ACTION_SEND_MESSAGE)
                .putExtra(SpecusForegroundService.EXTRA_TO_CLIENT_NAME, target)
                .putExtra(SpecusForegroundService.EXTRA_MESSAGE, message)
                .putExtra(SpecusForegroundService.EXTRA_MESSAGE_ID, id));
        messageEditor.setText("");
        GuiSessionStore.draft = "";
        } catch (RuntimeException error) {
            GuiSessionStore.result(id, "失败 · 系统未允许发送，内容已保留");
        }
        restoreMessages();
    }

    private void pickFile() {
        String target = targetEditor.getText().toString().trim();
        if (target.isEmpty()) {
            Toast.makeText(this, "请先填写对方客户端名称", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*");
        startActivityForResult(intent, FILE_REQUEST);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST) {
            if (resultCode == RESULT_OK) {
                startSpecusService();
            } else {
                new AlertDialog.Builder(this).setTitle("VPN 未授权")
                        .setMessage("私有组网暂不可用。你可以重新授权，或在设置中关闭私有组网，继续使用端口转发和互传。")
                        .setPositiveButton("返回设置", (dialog, which) -> showPage(2)).show();
            }
            return;
        }
        if (requestCode == FILE_REQUEST && resultCode == RESULT_OK && data != null && data.getData() != null) {
            String target = targetEditor.getText().toString().trim();
            ConfigStorage.saveLastTarget(this, target);
            startService(new Intent(this, SpecusForegroundService.class)
                    .setAction(SpecusForegroundService.ACTION_SEND_FILE)
                    .putExtra(SpecusForegroundService.EXTRA_TO_CLIENT_NAME, target)
                    .putExtra(SpecusForegroundService.EXTRA_FILE_URI, data.getData().toString()));
        }
    }

    private void requestVpnThenStart() {
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            startActivityForResult(prepare, VPN_REQUEST);
        } else {
            startSpecusService();
        }
    }

    private void startSpecusService() {
        Intent intent = new Intent(this, SpecusForegroundService.class)
                .setAction(SpecusForegroundService.ACTION_START);
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
    }

    private void updateStatus(String status, String detail, boolean running) {
        specusRunning = running;
        String primary = status == null || status.trim().isEmpty() ? (running ? "运行中" : "就绪") : status.trim();
        String secondary = detail == null ? "" : detail.trim();
        statusTitle.setText(primary);
        statusDetail.setText(secondary);
        statusDetail.setVisibility(secondary.isEmpty() ? View.GONE : View.VISIBLE);
        statusDot.setBackground(round(running ? COLOR_MESH : Color.rgb(84, 98, 108), 999));
        toggleButton.setText(running ? "停止" : "启动");
        toggleButton.setBackground(round(running ? COLOR_DANGER : COLOR_MESH, 12));
        addEvent((running ? "RUNNING" : "STOPPED") + "  " + primary
                + (secondary.isEmpty() ? "" : " - " + secondary));
    }

    private void addBubble(String direction, String kind, String peer, String text, long timestamp) {
        boolean outgoing = ChatEvents.DIRECTION_OUT.equals(direction);
        String safeText = text == null || text.trim().isEmpty() ? "(空消息)" : text.trim();

        TextView caption = label(
                (outgoing ? "我 → " + peer : (peer == null || peer.isEmpty() ? "对方" : peer))
                        + " · " + timeFormat.format(new Date(timestamp)),
                COLOR_MUTED, 10, Typeface.NORMAL);
        caption.setGravity(outgoing ? Gravity.END : Gravity.START);
        caption.setPadding(dp(4), dp(6), dp(4), 0);
        chatContainer.addView(caption, matchWrap());

        TextView bubble = label(safeText,
                outgoing ? Color.WHITE : COLOR_INK, 14, Typeface.NORMAL);
        bubble.setPadding(dp(12), dp(8), dp(12), dp(8));
        bubble.setBackground(outgoing
                ? round(COLOR_BUBBLE_OUT, 12)
                : stroke(COLOR_PANEL, COLOR_LINE, 1, 12));
        LinearLayout bubbleRow = new LinearLayout(this);
        bubbleRow.setOrientation(LinearLayout.HORIZONTAL);
        bubbleRow.setGravity(outgoing ? Gravity.END : Gravity.START);
        bubbleRow.setPadding(0, dp(2), 0, 0);
        LinearLayout.LayoutParams bubbleParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        bubbleRow.addView(bubble, bubbleParams);
        chatContainer.addView(bubbleRow, matchWrap());

        while (chatContainer.getChildCount() > MAX_BUBBLES * 2) {
            chatContainer.removeViewAt(0);
            if (chatContainer.getChildCount() > 0) {
                chatContainer.removeViewAt(0);
            }
        }
        chatScroll.post(() -> chatScroll.fullScroll(View.FOCUS_DOWN));
    }

    private void addEvent(String text) {
        if (text == null || text.trim().isEmpty()) {
            return;
        }
        eventLog.addFirst(text);
        while (eventLog.size() > 8) {
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

    private void maybeRequestNotifications() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1001);
        }
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
        button.setMinHeight(dp(48));
        button.setMinWidth(0);
        button.setPadding(dp(10), 0, dp(10), 0);
        button.setBackground(round(background, 12));
        return button;
    }

    private Button smallButton(String text) {
        Button button = actionButton(text, COLOR_PAGE, COLOR_INK);
        button.setTextSize(13);
        return button;
    }

    private EditText input(String hint, boolean multiLine) {
        EditText editor = new EditText(this);
        editor.setTextSize(14);
        editor.setTextColor(COLOR_INK);
        editor.setHintTextColor(COLOR_MUTED);
        editor.setSingleLine(!multiLine);
        editor.setGravity(multiLine ? (Gravity.START | Gravity.TOP) : Gravity.CENTER_VERTICAL);
        editor.setPadding(dp(10), 0, dp(10), 0);
        editor.setHint(hint);
        editor.setBackground(stroke(COLOR_PAGE, COLOR_LINE, 1, 10));
        editor.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        return editor;
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

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
