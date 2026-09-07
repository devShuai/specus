package com.theshuai.specus.android;

import android.Manifest;
import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.rule.GrantPermissionRule;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class GuiSessionInstrumentationTest {
    @Rule public final GrantPermissionRule notificationPermission = GrantPermissionRule.grant(Manifest.permission.POST_NOTIFICATIONS);
    private Context context;
    private String original;
    @Before public void prepare() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        original = ConfigStorage.loadConfig(context);
        ConfigStorage.saveConfig(context, "{\"serverBaseUrl\":\"http://127.0.0.1:1\",\"apiKey\":\"\",\"secret\":\"\",\"updateCheckEnabled\":false,\"peerMeshDevice\":\"noop\"}");
        GuiSessionStore.clearMessages();
        GuiSessionStore.status("Starting", "", true);
        GuiSessionStore.status("Stopped", "fixture idle", false);
    }
    @After public void restore() {
        ConfigStorage.saveConfig(context, original);
        GuiSessionStore.clearMessages();
        GuiSessionStore.status("Stopped", "fixture finished", false);
    }

    @Test public void backgroundMessagesStatusAndDraftSurviveActivityRecreation() {
        try (ActivityScenario<MainActivity> scenario = ActivityScenario.launch(MainActivity.class)) {
            scenario.onActivity(activity -> {
                findText(activity.getWindow().getDecorView(), "互传").performClick();
                ((EditText)findHint(activity.getWindow().getDecorView(), "输入消息")).setText("unsent draft");
            });
            scenario.moveToState(Lifecycle.State.CREATED);
            GuiSessionStore.status("Connected", "fixture control + data", true);
            ChatEvents.send(context, "in", "text", "fixture-peer", "background message");
            scenario.moveToState(Lifecycle.State.RESUMED);
            scenario.onActivity(activity -> {
                assertNotNull(findText(activity.getWindow().getDecorView(), "转发通道就绪"));
                assertEquals(1, countText(activity.getWindow().getDecorView(), "background message\n已收到"));
            });
            scenario.recreate();
            scenario.onActivity(activity -> {
                assertEquals("unsent draft", ((EditText)findHint(activity.getWindow().getDecorView(), "输入消息")).getText().toString());
                assertEquals(1, countText(activity.getWindow().getDecorView(), "background message\n已收到"));
                assertNotNull(findText(activity.getWindow().getDecorView(), "转发通道就绪"));
            });
        }
    }

    @Test public void failedSendKeepsOneRecordAndFirstRunExposesSetup() {
        String id = GuiSessionStore.add("out", "text", "fixture-peer", "failed message", "发送中");
        GuiSessionStore.result(id, "失败 · 内容已保留");
        try (ActivityScenario<MainActivity> scenario = ActivityScenario.launch(MainActivity.class)) {
            scenario.onActivity(activity -> {
                assertTrue(findText(activity.getWindow().getDecorView(), "保存设置").isShown());
                assertEquals(1, countText(activity.getWindow().getDecorView(), "failed message\n失败 · 内容已保留"));
                assertFalse(GuiSessionStore.status().ready);
            });
        }
    }

    @Test public void nonVpnServiceStartsWithoutVpnConsentAndStopsOnHttpPolicyRejection() throws Exception {
        java.util.concurrent.atomic.AtomicInteger requests = new java.util.concurrent.atomic.AtomicInteger();
        try (java.net.ServerSocket server = new java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))) {
            server.setSoTimeout(5000);
            Thread response = new Thread(() -> {
                try (java.net.Socket client = server.accept()) {
                    requests.incrementAndGet();
                    var input = new java.io.BufferedReader(new java.io.InputStreamReader(client.getInputStream()));
                    String line;
                    while ((line = input.readLine()) != null && !line.isEmpty()) { }
                    byte[] body = "fixture-secret-must-not-appear".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    client.getOutputStream().write(("HTTP/1.1 403 Forbidden\r\nContent-Length: " + body.length
                            + "\r\nConnection: close\r\n\r\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                    client.getOutputStream().write(body);
                } catch (Exception ignored) { }
            });
            response.setDaemon(true);
            response.start();
            ConfigStorage.saveConfig(context, "{\"serverBaseUrl\":\"http://127.0.0.1:" + server.getLocalPort()
                    + "\",\"apiKey\":\"fixture\",\"secret\":\"fixture-secret\",\"updateCheckEnabled\":false,\"peerMeshDevice\":\"noop\"}");
            try (ActivityScenario<MainActivity> scenario = ActivityScenario.launch(MainActivity.class)) {
                scenario.onActivity(activity -> activity.startForegroundService(new android.content.Intent(activity, SpecusForegroundService.class)
                        .setAction(SpecusForegroundService.ACTION_START)));
                long end = System.nanoTime() + 8_000_000_000L;
                while (System.nanoTime() < end && !GuiSessionStore.status().detail.contains("403")) Thread.sleep(50);
                assertEquals(GuiSessionStore.status().title + ": " + GuiSessionStore.status().detail, 1, requests.get());
                assertFalse(GuiSessionStore.status().running);
                assertTrue(GuiSessionStore.status().detail, GuiSessionStore.status().detail.contains("403"));
                assertTrue(GuiSessionStore.status().detail.contains("网关"));
                assertFalse(GuiSessionStore.status().detail.contains("fixture-secret"));
                Thread.sleep(500);
                assertEquals(1, requests.get());
                assertTrue(GuiSessionStore.status().detail.contains("403"));
            } finally {
                context.stopService(new android.content.Intent(context, SpecusForegroundService.class));
            }
            response.join(1000);
        }
    }

    private static View findHint(View view, String hint) {
        if (view instanceof EditText && hint.contentEquals(((EditText)view).getHint())) return view;
        if (view instanceof ViewGroup) for (int i = 0; i < ((ViewGroup)view).getChildCount(); i++) {
            View found = findHint(((ViewGroup)view).getChildAt(i), hint); if (found != null) return found;
        }
        return null;
    }
    private static TextView findText(View view, String text) {
        if (view instanceof TextView && text.contentEquals(((TextView)view).getText())) return (TextView)view;
        if (view instanceof ViewGroup) for (int i = 0; i < ((ViewGroup)view).getChildCount(); i++) {
            TextView found = findText(((ViewGroup)view).getChildAt(i), text); if (found != null) return found;
        }
        return null;
    }
    private static int countText(View view, String text) {
        int count = view instanceof TextView && text.contentEquals(((TextView)view).getText()) ? 1 : 0;
        if (view instanceof ViewGroup) for (int i = 0; i < ((ViewGroup)view).getChildCount(); i++) count += countText(((ViewGroup)view).getChildAt(i), text);
        return count;
    }
}
