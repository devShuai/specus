package com.theshuai.specus.android;

import android.Manifest;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.Switch;
import android.widget.TextView;

import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.rule.GrantPermissionRule;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class MainActivityPeerServiceInstrumentationTest {
    @Rule
    public final GrantPermissionRule notificationPermission =
            GrantPermissionRule.grant(Manifest.permission.POST_NOTIFICATIONS);

    @After
    public void resetSnapshotSource() {
        MainActivity.setPeerServicesSnapshotSourceForTest(null);
    }

    @Test
    public void resumeAndRecreateReadTheLatestAuthoritativeSnapshot() {
        AtomicReference<String> snapshot = new AtomicReference<>(remoteSnapshot("first-service", true, ""));
        MainActivity.setPeerServicesSnapshotSourceForTest(snapshot::get);

        try (ActivityScenario<MainActivity> scenario = ActivityScenario.launch(MainActivity.class)) {
            scenario.onActivity(activity -> assertNotNull(findText(activity.getWindow().getDecorView(), "first-service · http")));

            scenario.moveToState(Lifecycle.State.CREATED);
            snapshot.set("{\"remotes\":[],\"locals\":[]}");
            scenario.moveToState(Lifecycle.State.RESUMED);
            scenario.onActivity(activity -> {
                assertNull(findText(activity.getWindow().getDecorView(), "first-service · http"));
                assertNotNull(findText(activity.getWindow().getDecorView(), "暂无对端服务"));
            });

            snapshot.set(remoteSnapshot("second-service", true, ""));
            scenario.recreate();
            scenario.onActivity(activity -> assertNotNull(findText(activity.getWindow().getDecorView(), "second-service · http")));
        }
    }

    @Test
    public void disabledActionsExposeReasonAndMeetTouchTargetSize() {
        MainActivity.setPeerServicesSnapshotSourceForTest(() -> remoteAndLocalDisabledSnapshot());

        try (ActivityScenario<MainActivity> scenario = ActivityScenario.launch(MainActivity.class)) {
            scenario.onActivity(activity -> {
                View root = activity.getWindow().getDecorView();
                assertNotNull(findText(root, "发布端离线"));
                assertNotNull(findText(root, "已配置但未发布 · 全局共享关闭"));

                Button open = (Button) findByDescription(root, "打开服务 private-web");
                Button copy = (Button) findByDescription(root, "复制服务地址 private-web");
                assertNotNull(open);
                assertNotNull(copy);
                assertFalse(open.isEnabled());
                assertFalse(copy.isEnabled());
                assertTrue(open.getLayoutParams().height >= dp(activity, 48));
                assertTrue(copy.getLayoutParams().height >= dp(activity, 48));

                Switch publish = (Switch) findByDescription(root, "发布本机服务 local-web");
                assertNotNull(publish);
                assertFalse(publish.isEnabled());
                assertFalse(publish.isChecked());
                assertTrue(publish.getMinimumHeight() >= dp(activity, 48));
            });
        }
    }

    private static String remoteSnapshot(String name, boolean available, String reason) {
        return "{\"remotes\":[{"
                + "\"publisherClientId\":7,\"publisherClientName\":\"peer-a\",\"publisherSessionId\":71,"
                + "\"serviceId\":\"svc-web\",\"name\":\"" + name + "\",\"application\":\"http\","
                + "\"accessTarget\":\"http://100.96.0.7:8080/\",\"openable\":" + available + ","
                + "\"copyable\":false,\"unavailableReason\":\"" + reason + "\"}],\"locals\":[]}";
    }

    private static String remoteAndLocalDisabledSnapshot() {
        return "{\"remotes\":[{"
                + "\"publisherClientId\":7,\"publisherClientName\":\"peer-a\",\"publisherSessionId\":71,"
                + "\"serviceId\":\"svc-web\",\"name\":\"private-web\",\"application\":\"http\","
                + "\"accessTarget\":\"http://100.96.0.7:8080/\",\"openable\":false,\"copyable\":false,"
                + "\"unavailableReason\":\"发布端离线\"}],\"locals\":[{"
                + "\"serviceId\":\"local-web\",\"name\":\"local-web\",\"application\":\"http\","
                + "\"target\":\"127.0.0.1:80\",\"publishedPort\":8080,\"configEnabled\":true,"
                + "\"canToggle\":false,\"locallyPublished\":false}]}";
    }

    private static View findByDescription(View root, String description) {
        if (description.contentEquals(root.getContentDescription())) {
            return root;
        }
        if (root instanceof ViewGroup group) {
            for (int i = 0; i < group.getChildCount(); i++) {
                View found = findByDescription(group.getChildAt(i), description);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static TextView findText(View root, String text) {
        if (root instanceof TextView view && text.contentEquals(view.getText())) {
            return view;
        }
        if (root instanceof ViewGroup group) {
            for (int i = 0; i < group.getChildCount(); i++) {
                TextView found = findText(group.getChildAt(i), text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static int dp(MainActivity activity, int value) {
        return Math.round(value * activity.getResources().getDisplayMetrics().density);
    }
}
