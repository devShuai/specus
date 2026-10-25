package com.theshuai.specus.android;

import android.Manifest;
import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.animation.StateListAnimator;
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
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.LayerDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ImageView;
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
    private static volatile Supplier<String> peerServicesSnapshotSource = PeerServiceRuntime::lastSnapshotJson;

    // Liquid Glass Base tokens for the views built in code, in dp (sp for type). Colours live in
    // res/values{,-night}/gui-theme.xml so the night qualifier switches the whole palette.
    private static final int SPACE_1 = 4, SPACE_2 = 8, SPACE_3 = 12, SPACE_4 = 16, SPACE_8 = 32;
    private static final int RADIUS_SM = 8, RADIUS_MD = 10, RADIUS_LG = 14, RADIUS_XL = 20, RADIUS_FULL = 999;
    /** Every control keeps a 48dp touch box. Its visible body is control-lg (44dp, the phone size of
     *  buttons and inputs) or, in list rows, control-md (36dp); the focus ring is drawn in the gap. */
    private static final int TOUCH_TARGET = 48;
    private static final int CONTROL_INSET = 2;
    private static final int CONTROL_INSET_ROW = 6;
    private static final int FOCUS_RING = 2;
    private static final float DISABLED_ALPHA = 0.45f;
    private static final float TEXT_PAGE_TITLE = 26, TEXT_HEADING = 20, TEXT_CARD_TITLE = 16, TEXT_BODY = 15,
            TEXT_INPUT = 16, TEXT_LABEL = 14, TEXT_META = 13, TEXT_SMALL = 12;
    private static final int SWITCH_THUMB = 22, SWITCH_GAP = 2;

    private static final int TONE_PLAIN = 0, TONE_SUCCESS = 1, TONE_INFO = 2, TONE_WARNING = 3, TONE_DANGER = 4;
    private static final int BUTTON_PRIMARY = 0, BUTTON_SECONDARY = 1, BUTTON_GHOST = 2, BUTTON_DANGER = 3;
    private static final int[][] ENABLED_STATES = {{-android.R.attr.state_enabled}, {}};
    private static final int[][] PRESS_STATES = {{-android.R.attr.state_enabled}, {android.R.attr.state_pressed}, {}};
    private static final int[][] FOCUS_STATES = {{android.R.attr.state_focused}, {}};
    private static final int[][] SELECT_STATES = {{android.R.attr.state_selected}, {}};

    private int COLOR_BG, COLOR_SURFACE, COLOR_SURFACE_MUTED, COLOR_MUTED_FILL, COLOR_BORDER;
    private int COLOR_FIELD_BG, COLOR_FIELD_BORDER, COLOR_PRESSED, COLOR_SELECTED, COLOR_SHADOW;
    private int COLOR_TEXT, COLOR_TEXT_MUTED, COLOR_TEXT_SUBTLE;
    private int COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_ACCENT_SOFT, COLOR_ON_PRIMARY, COLOR_FOCUS_RING;
    private int COLOR_SUCCESS, COLOR_SUCCESS_BG, COLOR_INFO, COLOR_INFO_BG, COLOR_WARNING, COLOR_WARNING_BG;
    private int COLOR_DANGER, COLOR_DANGER_BG, COLOR_DANGER_SOLID, COLOR_DANGER_PRESSED, COLOR_ON_DANGER;
    private int COLOR_SECONDARY_BG, COLOR_SECONDARY_PRESSED, COLOR_SWITCH_OFF, COLOR_TAG_BG;

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
    private ImageView settingsChevron;
    private EditText serverEditor;
    private EditText apiKeyEditor;
    private EditText secretEditor;
    private Switch meshSwitch;

    private LinearLayout advancedBody;
    private ImageView advancedChevron;
    private EditText configEditor;
    private TextView eventLogView;
    private LinearLayout servicesList;
    private View[] pages;
    private int selectedPage;
    private View pageHeader;
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
        loadPalette();
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
            setExpanded(settingsChevron, true);
        }
        reconcilePeerServices();
    }

    private void loadPalette() {
        COLOR_BG = getColor(R.color.gui_bg);
        COLOR_SURFACE = getColor(R.color.gui_surface);
        COLOR_SURFACE_MUTED = getColor(R.color.gui_surface_muted);
        COLOR_MUTED_FILL = getColor(R.color.gui_muted_fill);
        COLOR_BORDER = getColor(R.color.gui_border);
        COLOR_FIELD_BG = getColor(R.color.gui_field_bg);
        COLOR_FIELD_BORDER = getColor(R.color.gui_field_border);
        COLOR_PRESSED = getColor(R.color.gui_pressed);
        COLOR_SELECTED = getColor(R.color.gui_selected);
        COLOR_SHADOW = getColor(R.color.gui_shadow);
        COLOR_TEXT = getColor(R.color.gui_text);
        COLOR_TEXT_MUTED = getColor(R.color.gui_text_muted);
        COLOR_TEXT_SUBTLE = getColor(R.color.gui_text_subtle);
        COLOR_ACCENT = getColor(R.color.gui_accent);
        COLOR_ACCENT_HOVER = getColor(R.color.gui_accent_hover);
        COLOR_ACCENT_SOFT = getColor(R.color.gui_accent_soft);
        COLOR_ON_PRIMARY = getColor(R.color.gui_on_primary);
        COLOR_FOCUS_RING = getColor(R.color.gui_focus_ring);
        COLOR_SUCCESS = getColor(R.color.gui_success);
        COLOR_SUCCESS_BG = getColor(R.color.gui_success_bg);
        COLOR_INFO = getColor(R.color.gui_info);
        COLOR_INFO_BG = getColor(R.color.gui_info_bg);
        COLOR_WARNING = getColor(R.color.gui_warning);
        COLOR_WARNING_BG = getColor(R.color.gui_warning_bg);
        COLOR_DANGER = getColor(R.color.gui_danger);
        COLOR_DANGER_BG = getColor(R.color.gui_danger_bg);
        COLOR_DANGER_SOLID = getColor(R.color.gui_danger_solid);
        COLOR_DANGER_PRESSED = getColor(R.color.gui_danger_pressed);
        COLOR_ON_DANGER = getColor(R.color.gui_on_danger);
        COLOR_SECONDARY_BG = getColor(R.color.gui_secondary_bg);
        COLOR_SECONDARY_PRESSED = getColor(R.color.gui_secondary_pressed);
        COLOR_SWITCH_OFF = getColor(R.color.gui_switch_off);
        COLOR_TAG_BG = getColor(R.color.gui_tag_bg);
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
        // Status colours only carry status: ready is success, a degraded run needs attention
        // (warning), anything still connecting is in progress (info), stopped is neutral.
        boolean degraded = snapshot.title.equals("部分功能不可用");
        statusDot.setBackground(dot(snapshot.ready && !degraded ? COLOR_SUCCESS
                : snapshot.running ? (degraded ? COLOR_WARNING : COLOR_INFO) : COLOR_TEXT_SUBTLE, 8));
    }

    private void restoreMessages() {
        chatContainer.removeAllViews();
        for (GuiSessionStore.Message item : GuiSessionStore.messages()) {
            addBubble(item.direction, item.kind, item.peer, item.text + "\n" + item.state, item.state, item.timestamp);
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
        root.setBackgroundColor(COLOR_BG);
        gap(root, SPACE_3);
        root.setPadding(dp(SPACE_4), dp(SPACE_3), dp(SPACE_4), dp(SPACE_3));
        pageHeader = buildPageHeader();
        root.addView(pageHeader, matchWrap());
        statusCard = buildStatusCard();
        root.addView(statusCard);
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            int bottom = insets.getSystemWindowInsetBottom();
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(android.view.WindowInsets.Type.systemBars());
                android.graphics.Insets ime = insets.getInsets(android.view.WindowInsets.Type.ime());
                root.setPadding(dp(SPACE_4) + bars.left, dp(SPACE_3) + bars.top, dp(SPACE_4) + bars.right, dp(SPACE_3) + Math.max(bars.bottom, ime.bottom));
                int chrome = insets.isVisible(android.view.WindowInsets.Type.ime()) ? View.GONE : View.VISIBLE;
                pageHeader.setVisibility(chrome);
                statusCard.setVisibility(chrome);
            } else root.setPadding(dp(SPACE_4), dp(SPACE_3) + insets.getSystemWindowInsetTop(), dp(SPACE_4), dp(SPACE_3) + bottom);
            return insets;
        });
        // Section switcher: a pill segmented control. The track is drawn 2dp inside the 48dp row,
        // the selected segment floats 4dp inside the track.
        LinearLayout navigation = new LinearLayout(this);
        navigation.setBackground(inset(round(COLOR_MUTED_FILL, RADIUS_FULL), 0, CONTROL_INSET, 0, CONTROL_INSET));
        navigation.setPadding(dp(2), 0, dp(2), 0);
        String[] titles = {"设备", "互传", "设置"};
        pageButtons = new Button[3];
        for (int index = 0; index < titles.length; index++) {
            final int page = index;
            Button tab = segmentButton(titles[index]);
            pageButtons[index] = tab;
            tab.setOnClickListener(v -> showPage(page));
            navigation.addView(tab, new LinearLayout.LayoutParams(0, dp(TOUCH_TARGET), 1f));
        }
        root.addView(navigation);
        LinearLayout settings = new LinearLayout(this);
        settings.setOrientation(LinearLayout.VERTICAL);
        gap(settings, SPACE_4);
        settings.addView(buildSettingsCard());
        settings.addView(buildAdvancedCard());
        pages = new View[]{scrollPage(buildServicesCard()), buildChatCard(), scrollPage(settings)};
        for (View page : pages) root.addView(page, new LinearLayout.LayoutParams(-1, 0, 1f));
        return root;
    }

    private View buildPageHeader() {
        TextView title = label(getString(R.string.app_name), COLOR_TEXT, TEXT_PAGE_TITLE, 700);
        title.setLetterSpacing(-0.02f);
        markHeading(title);
        return title;
    }

    private View scrollPage(View content) {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        content.setPadding(content.getPaddingLeft(), content.getPaddingTop(),
                content.getPaddingRight(), content.getPaddingBottom() + dp(SPACE_2));
        scroll.addView(content);
        return scroll;
    }

    private void showPage(int index) {
        selectedPage = Math.max(0, Math.min(2, index));
        for (int i = 0; i < pages.length; i++) pages[i].setVisibility(i == selectedPage ? View.VISIBLE : View.GONE);
        for (int i = 0; i < pageButtons.length; i++) {
            boolean selected = i == selectedPage;
            pageButtons[i].setSelected(selected);
            pageButtons[i].setTypeface(weight(selected ? 600 : 400));
        }
    }

    private View buildStatusCard() {
        LinearLayout panel = card();
        // Controls draw 2dp inside their box, so the right padding puts the button edge on 16dp.
        panel.setPadding(dp(SPACE_4), dp(SPACE_3), dp(SPACE_4 - CONTROL_INSET), dp(SPACE_3));

        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setOrientation(LinearLayout.HORIZONTAL);
        panel.addView(row, matchWrap());

        statusDot = new View(this);
        statusDot.setBackground(dot(COLOR_TEXT_SUBTLE, 8));
        row.addView(statusDot, new LinearLayout.LayoutParams(dp(8), dp(8)));
        row.addView(space(SPACE_2, 1));

        statusTitle = label("未连接", COLOR_TEXT, TEXT_CARD_TITLE, 600);
        row.addView(statusTitle, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        // Secondary before primary: the primary action sits rightmost.
        Button retry = button("重试", BUTTON_SECONDARY, false);
        retry.setMinWidth(dp(64));
        retry.setOnClickListener(v -> {
            if (!specusRunning) onToggleClicked();
            else startService(new Intent(this, SpecusForegroundService.class).setAction(SpecusForegroundService.ACTION_RETRY));
        });
        row.addView(retry, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(TOUCH_TARGET)));
        row.addView(space(SPACE_1, 1));

        toggleButton = button("启动", BUTTON_PRIMARY, false);
        toggleButton.setMinWidth(dp(72));
        toggleButton.setOnClickListener(v -> onToggleClicked());
        row.addView(toggleButton, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(TOUCH_TARGET)));

        statusDetail = label("", COLOR_TEXT_MUTED, TEXT_META, 400);
        statusDetail.setPadding(dp(SPACE_4), 0, 0, dp(SPACE_1));
        statusDetail.setMaxLines(3);
        panel.addView(statusDetail, matchWrap());
        return panel;
    }

    private View buildServicesCard() {
        LinearLayout section = new LinearLayout(this);
        section.setOrientation(LinearLayout.VERTICAL);
        gap(section, SPACE_3);

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.VERTICAL);
        gap(head, SPACE_1);
        head.setPadding(0, dp(SPACE_1), 0, 0);
        head.addView(heading("共享服务"), matchWrap());
        head.addView(label("对端按运行实例分组。本机开关只影响当前实例。", COLOR_TEXT_SUBTLE, TEXT_SMALL, 400), matchWrap());
        section.addView(head, matchWrap());

        servicesList = new LinearLayout(this);
        servicesList.setOrientation(LinearLayout.VERTICAL);
        gap(servicesList, SPACE_3);
        servicesList.setContentDescription("Peer 服务列表");
        section.addView(servicesList, matchWrap());
        servicesList.addView(emptyServicesCard(), matchWrap());
        return section;
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
            servicesList.addView(emptyServicesCard(), matchWrap());
        } else {
            LinearLayout remoteCard = listCard();
            for (int i = 0; i < remotes.length(); i++) {
                JSONObject item = remotes.optJSONObject(i);
                if (item != null) {
                    addListRow(remoteCard, serviceRow(item));
                }
            }
            if (remoteCard.getChildCount() > 0) {
                servicesList.addView(remoteCard, matchWrap());
            }
        }
        if (locals.length() > 0) {
            TextView localTitle = label("本机发布", COLOR_TEXT, TEXT_CARD_TITLE, 600);
            localTitle.setPadding(0, dp(SPACE_3), 0, 0);
            markHeading(localTitle);
            servicesList.addView(localTitle, matchWrap());
            LinearLayout localCard = listCard();
            for (int i = 0; i < locals.length(); i++) {
                JSONObject item = locals.optJSONObject(i);
                if (item != null) {
                    addListRow(localCard, localRow(item));
                }
            }
            if (localCard.getChildCount() > 0) {
                servicesList.addView(localCard, matchWrap());
            }
        }
    }

    private View emptyServicesCard() {
        LinearLayout panel = card();
        panel.setGravity(Gravity.CENTER_HORIZONTAL);
        panel.setPadding(dp(SPACE_4), dp(SPACE_8), dp(SPACE_4), dp(SPACE_8));
        gap(panel, SPACE_3);
        ImageView icon = new ImageView(this);
        icon.setImageResource(R.drawable.gui_server);
        icon.setScaleType(ImageView.ScaleType.CENTER);
        icon.setBackground(dot(COLOR_MUTED_FILL, 56));
        icon.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        panel.addView(icon, new LinearLayout.LayoutParams(dp(56), dp(56)));
        TextView empty = label("暂无对端服务", COLOR_TEXT, 17, 600);
        empty.setGravity(Gravity.CENTER_HORIZONTAL);
        panel.addView(empty, wrapWrap());
        return panel;
    }

    private View serviceRow(JSONObject item) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        gap(row, SPACE_1);
        // The row buttons draw 6dp inside their 48dp box; this keeps 12dp under them.
        row.setPadding(0, dp(SPACE_3), 0, dp(SPACE_3 - CONTROL_INSET_ROW));

        String publisher = item.optString("publisherClientName", "-");
        long sessionId = item.optLong("publisherSessionId", 0L);
        String serviceId = item.optString("serviceId", "");
        String serviceName = item.optString("name", serviceId.isBlank() ? "未命名服务" : serviceId);
        String application = item.optString("application", "tcp");
        String target = item.optString("accessTarget", "");
        String reason = item.optString("unavailableReason", "");
        boolean openable = item.optBoolean("openable", false);
        boolean copyable = item.optBoolean("copyable", false);

        TextView title = label(publisher + " · 实例 " + sessionId, COLOR_TEXT_MUTED, TEXT_META, 400);
        row.addView(title, matchWrap());
        TextView service = label(serviceName + " · " + application, COLOR_TEXT, TEXT_BODY, 600);
        service.setContentDescription("服务 " + serviceName + "，发布实例 " + publisher + " " + sessionId);
        row.addView(service, matchWrap());
        TextView detail = label(target.isEmpty() ? reason : target, COLOR_TEXT_MUTED, TEXT_META, 400);
        row.addView(detail, matchWrap());
        if (!reason.isEmpty()) {
            TextView reasonView = tag(reason, TONE_DANGER);
            row.addView(reasonView, wrapWrap());
        }

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        row.addView(actions, matchWrap());

        Button open = button("打开", BUTTON_SECONDARY, true);
        open.setMinWidth(dp(72));
        open.setContentDescription("打开服务 " + serviceName);
        open.setEnabled(openable);
        open.setOnClickListener(v -> openExternalUrl(target));
        actions.addView(open, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(TOUCH_TARGET)));
        actions.addView(space(SPACE_1, 1));
        Button copy = button("复制", BUTTON_SECONDARY, true);
        copy.setMinWidth(dp(72));
        copy.setContentDescription("复制服务地址 " + serviceName);
        copy.setEnabled(copyable);
        copy.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (clipboard != null) {
                clipboard.setPrimaryClip(ClipData.newPlainText("peer-service", target));
                Toast.makeText(this, "已复制 " + target, Toast.LENGTH_SHORT).show();
            }
        });
        actions.addView(copy, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(TOUCH_TARGET)));
        return row;
    }

    private View localRow(JSONObject item) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(SPACE_3), 0, dp(SPACE_3));
        row.setMinimumHeight(dp(TOUCH_TARGET));

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
        // Closed or globally off is a neutral state; published is fine; paused needs attention.
        int publicationTone = !configEnabled || !canToggle ? TONE_PLAIN
                : locallyPublished ? TONE_SUCCESS : TONE_WARNING;

        LinearLayout text = new LinearLayout(this);
        text.setOrientation(LinearLayout.VERTICAL);
        gap(text, SPACE_1);
        text.addView(label(name + " · " + item.optString("application", "tcp"), COLOR_TEXT, TEXT_BODY, 600), matchWrap());
        text.addView(label(target + " → :" + item.optInt("publishedPort", 0)
                + (configEnabled ? "" : "（配置关闭）"), COLOR_TEXT_MUTED, TEXT_META, 400), matchWrap());
        text.addView(tag(publicationStatus, publicationTone), wrapWrap());
        row.addView(text, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(space(SPACE_3, 1));

        Switch publish = switchView();
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
        // A card with a header (recipient), a body (messages) and a footer (composer), separated by
        // hairlines that run the full card width.
        LinearLayout panel = card();

        LinearLayout targetRow = new LinearLayout(this);
        targetRow.setGravity(Gravity.CENTER_VERTICAL);
        targetRow.setOrientation(LinearLayout.HORIZONTAL);
        targetRow.setPadding(dp(SPACE_4), dp(SPACE_1), dp(SPACE_1), dp(SPACE_1));
        panel.addView(targetRow, matchWrap());

        TextView targetLabel = label("发送给", COLOR_TEXT_MUTED, TEXT_META, 500);
        targetRow.addView(targetLabel, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        targetRow.addView(space(SPACE_2, 1));

        targetEditor = input("对方客户端名称", false);
        targetEditor.setHint("选择在线设备");
        targetEditor.setFocusable(false);
        targetEditor.setCompoundDrawablesRelativeWithIntrinsicBounds(
                null, null, getDrawable(R.drawable.gui_chevron_down), null);
        targetEditor.setCompoundDrawablePadding(dp(SPACE_2));
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

        panel.addView(divider());

        chatScroll = new ScrollView(this);
        chatContainer = new LinearLayout(this);
        chatContainer.setOrientation(LinearLayout.VERTICAL);
        chatContainer.setPadding(dp(SPACE_4), 0, dp(SPACE_4), dp(SPACE_3));
        chatScroll.addView(chatContainer, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        panel.addView(chatScroll, scrollParams);

        panel.addView(divider());

        LinearLayout inputRow = new LinearLayout(this);
        inputRow.setGravity(Gravity.CENTER_VERTICAL);
        inputRow.setOrientation(LinearLayout.HORIZONTAL);
        inputRow.setPadding(dp(SPACE_4 - CONTROL_INSET), dp(SPACE_2), dp(SPACE_4 - CONTROL_INSET), 0);
        panel.addView(inputRow, matchWrap());

        Button attachButton = button("文件", BUTTON_SECONDARY, false);
        attachButton.setMinWidth(dp(60));
        attachButton.setPadding(dp(SPACE_3), 0, dp(SPACE_3), 0);
        attachButton.setSingleLine(true);
        attachButton.setOnClickListener(v -> pickFile());
        inputRow.addView(attachButton, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(48)));
        inputRow.addView(space(SPACE_1, 1));

        messageEditor = input("输入消息", false);
        inputRow.addView(messageEditor, new LinearLayout.LayoutParams(0, dp(48), 1f));
        inputRow.addView(space(SPACE_1, 1));

        Button sendButton = button("发送", BUTTON_PRIMARY, false);
        sendButton.setMinWidth(dp(64));
        sendButton.setOnClickListener(v -> sendMessage());
        inputRow.addView(sendButton, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(48)));
        TextView retention = label("本次进程最近 100 条 · 长按重新编辑", COLOR_TEXT_SUBTLE, TEXT_SMALL, 400);
        retention.setPadding(dp(SPACE_4), dp(SPACE_1), dp(SPACE_4), dp(SPACE_3));
        panel.addView(retention);
        ImageButton clear = iconButton(R.drawable.gui_more);
        clear.setContentDescription("互传记录保留说明与清除");
        clear.setOnClickListener(v -> new AlertDialog.Builder(this).setTitle("清除本次互传记录？")
                .setMessage("仅保留本次应用进程最近 100 条；长按恢复内容，不自动重发。\n\n清除仅影响本机显示记录与草稿，不删除已下载文件或对方记录。")
                .setNegativeButton("取消", null).setPositiveButton("清除", (d, w) -> {
                    GuiSessionStore.clearMessages(); messageEditor.setText(""); restoreMessages();
                }).show());
        targetRow.addView(clear, new LinearLayout.LayoutParams(dp(48), dp(48)));
        return panel;
    }

    private View buildSettingsCard() {
        LinearLayout panel = card();

        LinearLayout header = sectionHeader();
        panel.addView(header, matchWrap());

        TextView title = label("连接设置", COLOR_TEXT, TEXT_CARD_TITLE, 600);
        header.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        settingsChevron = chevron();
        header.addView(settingsChevron, new LinearLayout.LayoutParams(dp(20), dp(20)));

        settingsBody = new LinearLayout(this);
        settingsBody.setOrientation(LinearLayout.VERTICAL);
        settingsBody.setVisibility(View.GONE);
        settingsBody.setPadding(dp(SPACE_4), 0, dp(SPACE_4), dp(SPACE_4));
        panel.addView(settingsBody, matchWrap());

        header.setOnClickListener(v -> toggleSection(settingsBody, settingsChevron, this::fillSettingsFromConfig));

        serverEditor = settingsField("服务地址", "https://specus.devshuai.com");
        apiKeyEditor = settingsField("API Key", "管理后台提供的 API Key");
        secretEditor = settingsField("Secret", "", true);

        LinearLayout meshRow = new LinearLayout(this);
        meshRow.setGravity(Gravity.CENTER_VERTICAL);
        meshRow.setOrientation(LinearLayout.HORIZONTAL);
        meshRow.setPadding(0, dp(SPACE_3), 0, 0);
        settingsBody.addView(meshRow, matchWrap());

        TextView meshLabel = label("私有组网（Peer Mesh）", COLOR_TEXT, TEXT_BODY, 400);
        meshRow.addView(meshLabel, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        meshSwitch = switchView();
        meshSwitch.setContentDescription("启用私有组网，需要 VPN 授权");
        meshSwitch.setMinHeight(dp(48));
        meshSwitch.setMinimumHeight(dp(48));
        meshRow.addView(meshSwitch, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView help = label("从管理后台「接入凭证」获取 API Key 和 Secret。私有组网需要 VPN 授权；关闭后仍可使用转发与互传。", COLOR_TEXT_MUTED, TEXT_SMALL, 400);
        help.setPadding(0, dp(SPACE_1), 0, 0);
        settingsBody.addView(help);
        Button saveButton = button("保存设置", BUTTON_PRIMARY, false);
        saveButton.setOnClickListener(v -> saveSettings());
        LinearLayout.LayoutParams saveParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(48));
        saveParams.setMargins(0, dp(SPACE_3), 0, 0);
        settingsBody.addView(saveButton, saveParams);
        return panel;
    }

    private EditText settingsField(String caption, String hint) {
        return settingsField(caption, hint, false);
    }

    private EditText settingsField(String caption, String hint, boolean password) {
        TextView labelView = label(caption, COLOR_TEXT, TEXT_LABEL, 500);
        labelView.setPadding(0, dp(SPACE_3), 0, dp(SPACE_1));
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
        LinearLayout panel = card();

        LinearLayout header = sectionHeader();
        panel.addView(header, matchWrap());

        TextView title = label("高级", COLOR_TEXT, TEXT_CARD_TITLE, 600);
        header.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        advancedChevron = chevron();
        header.addView(advancedChevron, new LinearLayout.LayoutParams(dp(20), dp(20)));

        advancedBody = new LinearLayout(this);
        advancedBody.setOrientation(LinearLayout.VERTICAL);
        advancedBody.setVisibility(View.GONE);
        advancedBody.setPadding(dp(SPACE_4), 0, dp(SPACE_4), dp(SPACE_4));
        panel.addView(advancedBody, matchWrap());

        header.setOnClickListener(v -> toggleSection(advancedBody, advancedChevron, () ->
                configEditor.setText(ConfigStorage.loadConfig(this))));

        TextView configCaption = label("原始配置（JSONC）", COLOR_TEXT, TEXT_LABEL, 500);
        configCaption.setPadding(0, dp(SPACE_1), 0, dp(SPACE_1));
        advancedBody.addView(configCaption, matchWrap());

        configEditor = new EditText(this);
        configEditor.setGravity(Gravity.START | Gravity.TOP);
        configEditor.setMinLines(10);
        configEditor.setTextSize(TEXT_META);
        configEditor.setTextColor(COLOR_TEXT);
        configEditor.setHintTextColor(COLOR_TEXT_SUBTLE);
        configEditor.setTypeface(Typeface.MONOSPACE);
        configEditor.setSingleLine(false);
        configEditor.setPadding(dp(SPACE_3 + CONTROL_INSET), dp(SPACE_3), dp(SPACE_3 + CONTROL_INSET), dp(SPACE_3));
        configEditor.setBackground(fieldBackground());
        configEditor.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        advancedBody.addView(configEditor, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(240)));

        LinearLayout configActions = new LinearLayout(this);
        configActions.setGravity(Gravity.END);
        configActions.setPadding(0, dp(SPACE_2), 0, 0);
        configActions.setOrientation(LinearLayout.HORIZONTAL);
        advancedBody.addView(configActions, matchWrap());

        Button resetButton = button("重置示例", BUTTON_GHOST, false);
        resetButton.setOnClickListener(v -> {
            configEditor.setText(ConfigStorage.defaultConfig());
            Toast.makeText(this, "已恢复示例", Toast.LENGTH_SHORT).show();
        });
        configActions.addView(resetButton, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, dp(48)));
        configActions.addView(space(SPACE_1, 1));

        Button saveConfigButton = button("保存配置", BUTTON_PRIMARY, false);
        saveConfigButton.setOnClickListener(v -> {
            ConfigStorage.saveConfig(this, configEditor.getText().toString());
            fillSettingsFromConfig();
            Toast.makeText(this, "配置已保存", Toast.LENGTH_SHORT).show();
        });
        configActions.addView(saveConfigButton, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, dp(48)));

        TextView logCaption = label("运行事件", COLOR_TEXT, TEXT_LABEL, 500);
        logCaption.setPadding(0, dp(SPACE_4), 0, dp(SPACE_2));
        advancedBody.addView(logCaption, matchWrap());

        eventLogView = label("暂无事件", COLOR_TEXT_MUTED, TEXT_SMALL, 400);
        eventLogView.setLineSpacing(dp(2), 1f);
        eventLogView.setPadding(dp(SPACE_3), dp(SPACE_3), dp(SPACE_3), dp(SPACE_3));
        eventLogView.setBackground(round(COLOR_SURFACE_MUTED, RADIUS_MD));
        advancedBody.addView(eventLogView, matchWrap());
        return panel;
    }

    private void toggleSection(LinearLayout body, ImageView chevron, Runnable onExpand) {
        boolean show = body.getVisibility() != View.VISIBLE;
        body.setVisibility(show ? View.VISIBLE : View.GONE);
        setExpanded(chevron, show);
        if (show && onExpand != null) {
            onExpand.run();
        }
    }

    private void setExpanded(ImageView chevron, boolean expanded) {
        chevron.setImageResource(expanded ? R.drawable.gui_chevron_down : R.drawable.gui_chevron_right);
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
            setExpanded(settingsChevron, true);
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
        toggleButton.setText(running ? "停止" : "启动");
        styleButton(toggleButton, running ? BUTTON_DANGER : BUTTON_PRIMARY, false);
        addEvent((running ? "RUNNING" : "STOPPED") + "  " + primary
                + (secondary.isEmpty() ? "" : " - " + secondary));
    }

    private void addBubble(String direction, String kind, String peer, String text, String state, long timestamp) {
        boolean outgoing = ChatEvents.DIRECTION_OUT.equals(direction);
        boolean system = ChatEvents.DIRECTION_SYSTEM.equals(direction);
        String safeText = text == null || text.trim().isEmpty() ? "(空消息)" : text.trim();

        TextView caption = label(
                (outgoing ? "我 → " + peer : (peer == null || peer.isEmpty() ? "对方" : peer))
                        + " · " + timeFormat.format(new Date(timestamp)),
                COLOR_TEXT_SUBTLE, TEXT_SMALL, 400);
        caption.setGravity(outgoing ? Gravity.END : Gravity.START);
        caption.setPadding(dp(SPACE_1), dp(SPACE_3), dp(SPACE_1), dp(SPACE_1));
        chatContainer.addView(caption, matchWrap());

        // Outgoing in the accent, incoming on the muted surface, transfer events as an outlined note.
        TextView bubble = label(withState(safeText, state,
                        outgoing ? withAlpha(COLOR_ON_PRIMARY, 0.8f) : COLOR_TEXT_MUTED),
                outgoing ? COLOR_ON_PRIMARY : COLOR_TEXT, TEXT_BODY, 400);
        bubble.setPadding(dp(SPACE_3), dp(SPACE_2), dp(SPACE_3), dp(SPACE_2));
        bubble.setMaxWidth(Math.round(getResources().getDisplayMetrics().widthPixels * 0.8f));
        bubble.setBackground(outgoing
                ? round(COLOR_ACCENT, RADIUS_LG)
                : system ? stroke(COLOR_SURFACE, COLOR_BORDER, 1, RADIUS_LG)
                : round(COLOR_SURFACE_MUTED, RADIUS_LG));
        LinearLayout bubbleRow = new LinearLayout(this);
        bubbleRow.setOrientation(LinearLayout.HORIZONTAL);
        bubbleRow.setGravity(outgoing ? Gravity.END : Gravity.START);
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

    /** The delivery state is the bubble's last line; show it smaller and quieter. Same characters. */
    private static CharSequence withState(String text, String state, int stateColor) {
        if (state == null || state.isEmpty() || !text.endsWith(state)) {
            return text;
        }
        int start = text.length() - state.length();
        if (start < 1 || text.charAt(start - 1) != '\n') {
            return text;
        }
        SpannableString styled = new SpannableString(text);
        styled.setSpan(new RelativeSizeSpan(0.8f), start, text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        styled.setSpan(new ForegroundColorSpan(stateColor), start, text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        return styled;
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

    // ---- Liquid Glass Base components built in code ------------------------------------------

    /** Card: surface, hairline border, radius-xl, with shadow-sm as a 1dp lip (none in dark). */
    private LinearLayout card() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        LayerDrawable background = new LayerDrawable(new Drawable[]{
                round(COLOR_SHADOW, RADIUS_XL), stroke(COLOR_SURFACE, COLOR_BORDER, 1, RADIUS_XL)});
        background.setLayerInset(0, 0, dp(1), 0, 0);
        background.setLayerInset(1, 0, 0, 0, dp(1));
        layout.setBackground(background);
        return layout;
    }

    /** A card whose rows are separated by inset hairlines. */
    private LinearLayout listCard() {
        LinearLayout panel = card();
        panel.setPadding(dp(SPACE_4), 0, dp(SPACE_4), dp(1));
        return panel;
    }

    private void addListRow(LinearLayout list, View row) {
        if (list.getChildCount() > 0) {
            list.addView(divider());
        }
        list.addView(row, matchWrap());
    }

    /** Collapsible card header: a 48dp+ row whose pressed state is an inset pill of the overlay. */
    private LinearLayout sectionHeader() {
        LinearLayout header = new LinearLayout(this);
        header.setMinimumHeight(dp(56));
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setPadding(dp(SPACE_4), 0, dp(SPACE_4), 0);
        header.setBackground(inset(shape(new ColorStateList(
                        new int[][]{{android.R.attr.state_pressed}, {android.R.attr.state_focused}, {}},
                        new int[]{COLOR_PRESSED, COLOR_ACCENT_SOFT, Color.TRANSPARENT}), null, RADIUS_XL - SPACE_1),
                SPACE_1, SPACE_1, SPACE_1, SPACE_1));
        return header;
    }

    private ImageView chevron() {
        ImageView chevron = new ImageView(this);
        chevron.setScaleType(ImageView.ScaleType.CENTER);
        chevron.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        setExpanded(chevron, false);
        return chevron;
    }

    private TextView heading(String text) {
        TextView view = label(text, COLOR_TEXT, TEXT_HEADING, 700);
        view.setLetterSpacing(-0.01f);
        markHeading(view);
        return view;
    }

    private static void markHeading(View view) {
        if (Build.VERSION.SDK_INT >= 28) {
            view.setAccessibilityHeading(true);
        }
    }

    /** Tag: a pill with the status colour on its *-bg tint and a leading dot; plain is neutral. */
    private TextView tag(String text, int tone) {
        int foreground;
        int background;
        switch (tone) {
            case TONE_SUCCESS: foreground = COLOR_SUCCESS; background = COLOR_SUCCESS_BG; break;
            case TONE_INFO: foreground = COLOR_INFO; background = COLOR_INFO_BG; break;
            case TONE_WARNING: foreground = COLOR_WARNING; background = COLOR_WARNING_BG; break;
            case TONE_DANGER: foreground = COLOR_DANGER; background = COLOR_DANGER_BG; break;
            default: foreground = COLOR_TEXT_MUTED; background = COLOR_TAG_BG; break;
        }
        TextView view = label(text, foreground, TEXT_SMALL, 500);
        view.setGravity(Gravity.CENTER_VERTICAL);
        view.setMinHeight(dp(22));
        view.setPadding(dp(SPACE_2), dp(2), dp(SPACE_2 + 2), dp(2));
        view.setBackground(round(background, RADIUS_FULL));
        if (tone != TONE_PLAIN) {
            view.setCompoundDrawablesRelativeWithIntrinsicBounds(dot(foreground, 6), null, null, null);
            view.setCompoundDrawablePadding(dp(SPACE_1));
        } else {
            view.setPadding(dp(SPACE_2 + 2), dp(2), dp(SPACE_2 + 2), dp(2));
        }
        return view;
    }

    private TextView label(CharSequence text, int color, float sp, int weight) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(color);
        view.setTextSize(sp);
        view.setIncludeFontPadding(true);
        view.setTypeface(weight(weight));
        return view;
    }

    /** System sans at a design weight (400/500/600/700); exact weights need API 28. */
    private static Typeface weight(int weight) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Typeface.create(Typeface.DEFAULT, weight, false);
        }
        if (weight >= 600) {
            return Typeface.DEFAULT_BOLD;
        }
        return weight >= 500 ? Typeface.create("sans-serif-medium", Typeface.NORMAL) : Typeface.DEFAULT;
    }

    private Button button(String text, int variant, boolean inRow) {
        Button button = new Button(this);
        button.setAllCaps(false);
        button.setText(text);
        button.setTextSize(inRow ? TEXT_LABEL : TEXT_BODY);
        button.setTypeface(weight(500));
        button.setMinHeight(dp(48));
        button.setMinWidth(0);
        button.setMinimumWidth(0);
        button.setPadding(dp(SPACE_4), 0, dp(SPACE_4), 0);
        button.setStateListAnimator(pressScale());
        styleButton(button, variant, inRow);
        return button;
    }

    /** Primary, secondary, ghost or danger; pressed and disabled (45%) come from state lists. */
    private void styleButton(Button button, int variant, boolean inRow) {
        int fill;
        int pressed;
        int foreground;
        ColorStateList border = null;
        switch (variant) {
            case BUTTON_PRIMARY:
                fill = COLOR_ACCENT; pressed = COLOR_ACCENT_HOVER; foreground = COLOR_ON_PRIMARY;
                break;
            case BUTTON_DANGER:
                fill = COLOR_DANGER_SOLID; pressed = COLOR_DANGER_PRESSED; foreground = COLOR_ON_DANGER;
                break;
            case BUTTON_SECONDARY:
                fill = COLOR_SECONDARY_BG; pressed = COLOR_SECONDARY_PRESSED; foreground = COLOR_TEXT;
                border = enabledStates(COLOR_BORDER);
                break;
            default:
                fill = Color.TRANSPARENT; pressed = COLOR_PRESSED; foreground = COLOR_TEXT;
                break;
        }
        button.setTextColor(enabledStates(foreground));
        button.setBackground(control(pressStates(fill, pressed), border, FOCUS_STATES, COLOR_FOCUS_RING,
                inRow ? RADIUS_SM : RADIUS_MD, FOCUS_RING, inRow ? CONTROL_INSET_ROW : CONTROL_INSET));
    }

    private ImageButton iconButton(int iconRes) {
        ImageButton button = new ImageButton(this);
        button.setImageResource(iconRes);
        button.setScaleType(ImageView.ScaleType.CENTER);
        button.setPadding(0, 0, 0, 0);
        button.setStateListAnimator(null);
        button.setBackground(control(pressStates(Color.TRANSPARENT, COLOR_PRESSED), null, FOCUS_STATES,
                COLOR_FOCUS_RING, RADIUS_MD, CONTROL_INSET_ROW, CONTROL_INSET_ROW));
        return button;
    }

    /** Pill segmented control item: selected = the selected surface with shadow-sm, else muted text. */
    private Button segmentButton(String text) {
        Button tab = new Button(this);
        tab.setAllCaps(false);
        tab.setText(text);
        tab.setTextSize(TEXT_BODY);
        tab.setTypeface(weight(400));
        tab.setMinHeight(dp(48));
        tab.setMinWidth(0);
        tab.setMinimumWidth(0);
        tab.setPadding(dp(SPACE_2), 0, dp(SPACE_2), 0);
        tab.setStateListAnimator(null);
        tab.setTextColor(new ColorStateList(SELECT_STATES, new int[]{COLOR_TEXT, COLOR_TEXT_MUTED}));
        LayerDrawable background = new LayerDrawable(new Drawable[]{
                shape(new ColorStateList(FOCUS_STATES, new int[]{COLOR_FOCUS_RING, Color.TRANSPARENT}), null, RADIUS_FULL),
                shape(new ColorStateList(SELECT_STATES, new int[]{COLOR_SHADOW, Color.TRANSPARENT}), null, RADIUS_FULL),
                shape(new ColorStateList(new int[][]{{android.R.attr.state_selected}, {android.R.attr.state_pressed}, {}},
                        new int[]{COLOR_SELECTED, COLOR_PRESSED, Color.TRANSPARENT}), null, RADIUS_FULL)});
        background.setLayerInset(0, 0, dp(4), 0, dp(4));
        background.setLayerInset(1, dp(2), dp(7), dp(2), dp(5));
        background.setLayerInset(2, dp(2), dp(6), dp(2), dp(6));
        tab.setBackground(background);
        return tab;
    }

    private EditText input(String hint, boolean multiLine) {
        EditText editor = new EditText(this);
        editor.setTextSize(TEXT_INPUT);
        editor.setTextColor(COLOR_TEXT);
        editor.setHintTextColor(COLOR_TEXT_SUBTLE);
        editor.setSingleLine(!multiLine);
        editor.setGravity(multiLine ? (Gravity.START | Gravity.TOP) : Gravity.CENTER_VERTICAL);
        editor.setPadding(dp(SPACE_3 + CONTROL_INSET), 0, dp(SPACE_3 + CONTROL_INSET), 0);
        editor.setHint(hint);
        editor.setBackground(fieldBackground());
        editor.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        return editor;
    }

    /** Input: field-bg, field-border; focused = accent border plus an accent-soft ring. */
    private Drawable fieldBackground() {
        return control(new ColorStateList(ENABLED_STATES, new int[]{COLOR_SURFACE_MUTED, COLOR_FIELD_BG}),
                new ColorStateList(FOCUS_STATES, new int[]{COLOR_ACCENT, COLOR_FIELD_BORDER}),
                FOCUS_STATES, COLOR_ACCENT_SOFT, RADIUS_MD, FOCUS_RING, CONTROL_INSET);
    }

    /**
     * Switch: a pill track (accent when on, sunken when off) with a white knob, 48x26dp. Disabled
     * dims the accent and the knob; the off track keeps its colour, because the light sunken track
     * at 45% would vanish into a white card.
     */
    private Switch switchView() {
        Switch view = new Switch(this);
        GradientDrawable track = shape(new ColorStateList(new int[][]{
                        {-android.R.attr.state_enabled, android.R.attr.state_checked},
                        {android.R.attr.state_checked},
                        {}},
                new int[]{withAlpha(COLOR_ACCENT, DISABLED_ALPHA), COLOR_ACCENT, COLOR_SWITCH_OFF}), null, RADIUS_FULL);
        track.setSize(dp(2 * SWITCH_THUMB + 2 * SWITCH_GAP), dp(SWITCH_THUMB + 2 * SWITCH_GAP));
        // The track's padding is the knob's gap: Switch offsets the knob by it and adds it to the width.
        LayerDrawable trackLayer = new LayerDrawable(new Drawable[]{track});
        trackLayer.setPadding(dp(SWITCH_GAP), dp(SWITCH_GAP), dp(SWITCH_GAP), dp(SWITCH_GAP));

        GradientDrawable shadow = new GradientDrawable();
        shadow.setShape(GradientDrawable.OVAL);
        shadow.setColor(new ColorStateList(ENABLED_STATES, new int[]{0x14000000, 0x26000000}));
        shadow.setSize(dp(SWITCH_THUMB), dp(SWITCH_THUMB));
        GradientDrawable knob = new GradientDrawable();
        knob.setShape(GradientDrawable.OVAL);
        knob.setColor(new ColorStateList(ENABLED_STATES, new int[]{withAlpha(Color.WHITE, 0.6f), Color.WHITE}));
        knob.setSize(dp(SWITCH_THUMB), dp(SWITCH_THUMB));
        LayerDrawable thumb = new LayerDrawable(new Drawable[]{shadow, knob});
        thumb.setLayerInset(0, dp(SWITCH_GAP), dp(SWITCH_GAP + 1), dp(SWITCH_GAP), dp(SWITCH_GAP - 1));
        thumb.setLayerInset(1, dp(SWITCH_GAP), dp(SWITCH_GAP), dp(SWITCH_GAP), dp(SWITCH_GAP));
        thumb.setPadding(dp(SWITCH_GAP), dp(SWITCH_GAP), dp(SWITCH_GAP), dp(SWITCH_GAP));

        view.setThumbDrawable(thumb);
        view.setTrackDrawable(trackLayer);
        view.setSwitchMinWidth(dp(2 * SWITCH_THUMB + 2 * SWITCH_GAP));
        view.setGravity(Gravity.CENTER_VERTICAL);
        // Thumb and track only receive state on the next state change; give them the current one.
        view.refreshDrawableState();
        return view;
    }

    /**
     * A control's background inside its touch box: the body inset by {@code insetH}/{@code insetV},
     * and a ring layer {@code ringWidth} larger that shows in {@code ringStates} (focus).
     */
    private Drawable control(ColorStateList fill, ColorStateList border, int[][] ringStates, int ringColor,
                             int radiusDp, int insetH, int insetV) {
        GradientDrawable ring = shape(new ColorStateList(ringStates, new int[]{ringColor, Color.TRANSPARENT}),
                null, radiusDp + FOCUS_RING);
        GradientDrawable body = shape(fill, border, radiusDp);
        LayerDrawable layers = new LayerDrawable(new Drawable[]{ring, body});
        layers.setLayerInset(0, dp(insetH - FOCUS_RING), dp(insetV - FOCUS_RING),
                dp(insetH - FOCUS_RING), dp(insetV - FOCUS_RING));
        layers.setLayerInset(1, dp(insetH), dp(insetV), dp(insetH), dp(insetV));
        return layers;
    }

    /** Pressed state: buttons shrink to 98%, as in the design; instant when animations are off. */
    private static StateListAnimator pressScale() {
        StateListAnimator animator = new StateListAnimator();
        animator.addState(new int[]{android.R.attr.state_pressed, android.R.attr.state_enabled}, scaleTo(0.98f));
        animator.addState(new int[0], scaleTo(1f));
        return animator;
    }

    private static Animator scaleTo(float scale) {
        ObjectAnimator animator = ObjectAnimator.ofPropertyValuesHolder((Object) null,
                PropertyValuesHolder.ofFloat(View.SCALE_X, scale),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, scale));
        animator.setDuration(100);
        return animator;
    }

    private static ColorStateList enabledStates(int color) {
        return new ColorStateList(ENABLED_STATES, new int[]{withAlpha(color, DISABLED_ALPHA), color});
    }

    private static ColorStateList pressStates(int color, int pressed) {
        return new ColorStateList(PRESS_STATES, new int[]{withAlpha(color, DISABLED_ALPHA), pressed, color});
    }

    private static int withAlpha(int color, float factor) {
        return (Math.round(Color.alpha(color) * factor) << 24) | (color & 0x00FFFFFF);
    }

    private GradientDrawable shape(ColorStateList fill, ColorStateList border, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setShape(GradientDrawable.RECTANGLE);
        drawable.setCornerRadius(dp(radiusDp));
        drawable.setColor(fill);
        if (border != null) {
            drawable.setStroke(dp(1), border);
        }
        return drawable;
    }

    private Drawable inset(Drawable drawable, int left, int top, int right, int bottom) {
        LayerDrawable layers = new LayerDrawable(new Drawable[]{drawable});
        layers.setLayerInset(0, dp(left), dp(top), dp(right), dp(bottom));
        return layers;
    }

    private GradientDrawable dot(int color, int sizeDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setShape(GradientDrawable.OVAL);
        drawable.setColor(color);
        drawable.setSize(dp(sizeDp), dp(sizeDp));
        return drawable;
    }

    private View divider() {
        View line = new View(this);
        line.setBackgroundColor(COLOR_BORDER);
        line.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1)));
        return line;
    }

    /** Lay children out with a fixed gap (the design's flex gap); gone children leave no gap. */
    private void gap(LinearLayout layout, int dpValue) {
        GradientDrawable spacer = new GradientDrawable();
        spacer.setColor(Color.TRANSPARENT);
        spacer.setSize(dp(dpValue), dp(dpValue));
        layout.setDividerDrawable(spacer);
        layout.setShowDividers(LinearLayout.SHOW_DIVIDER_MIDDLE);
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

    private LinearLayout.LayoutParams wrapWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
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
