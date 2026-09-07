package com.theshuai.specus.android;

import org.junit.Test;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

public class GuiReliabilityTest {
    @Test public void runtimeAndChatDoNotPretendToBeReady() {
        GuiSessionStore.status("Starting", "", true);
        assertFalse(GuiSessionStore.status().ready);
        GuiSessionStore.status("VPN active", "10.0.0.1", true);
        assertFalse(GuiSessionStore.status().ready);
        GuiSessionStore.status("Control authenticated", "test", true);
        assertFalse(GuiSessionStore.status().ready);
        GuiSessionStore.status("Connected", "test", true);
        GuiSessionStore.status("Message sent", "test", true);
        assertTrue(GuiSessionStore.status().ready);
        GuiSessionStore.status("Stopped", "请修改凭据", false);
        GuiSessionStore.status("Stopped", "", false);
        GuiSessionStore.status("Stopped", "Service destroyed", false);
        assertEquals("请修改凭据", GuiSessionStore.status().detail);
        assertFalse(GuiSessionStore.status().ready);
    }
    @Test public void messageResultsUpdateOneRecordAndRetentionIsBounded() {
        GuiSessionStore.clearMessages();
        String id = GuiSessionStore.add("out", "text", "peer", "draft", "发送中");
        GuiSessionStore.result(id, "失败");
        assertEquals(1, GuiSessionStore.messages().size());
        assertEquals("draft", GuiSessionStore.message(id).text);
        assertEquals("失败", GuiSessionStore.message(id).state);
        for (int i = 0; i < 120; i++) GuiSessionStore.add("in", "text", "peer", "message", "received");
        assertEquals(100, GuiSessionStore.messages().size());
        GuiSessionStore.clearMessages();
        assertTrue(GuiSessionStore.messages().isEmpty());
    }
    @Test public void retryHintsAreCoalescedAndBackoffBounded() throws Exception {
        ReconnectSignal signal = new ReconnectSignal();
        assertTrue(signal.request());
        assertFalse(signal.request());
        long start = System.nanoTime();
        signal.await(60_000);
        assertTrue(System.nanoTime() - start < 1_000_000_000L);
        assertEquals(45_000, ReconnectSignal.delayMillis(100, 0));
        assertEquals(60_000, ReconnectSignal.delayMillis(100, 1));
    }
    @Test public void authenticationPolicyDoesNotLeakBodiesOrMislabel403() {
        for (int status : new int[]{408, 425, 429, 500, 503}) assertTrue(HttpLoginFailure.fromStatus(status).retryable);
        for (int status : new int[]{301, 400, 401, 403, 409}) assertFalse(HttpLoginFailure.fromStatus(status).retryable);
        assertTrue(HttpLoginFailure.fromStatus(403).getMessage().contains("网关"));
    }
    @Test public void multipleAddressesFallbackAndFamiliesInterleave() throws Exception {
        InetAddress v4 = InetAddress.getByName("127.0.0.1"), v6 = InetAddress.getByName("::1");
        assertEquals(List.of(v6, v4), MultiAddressDialer.interleave(new InetAddress[]{v6, v6, v4}));
        AtomicInteger attempts = new AtomicInteger();
        try (Socket result = MultiAddressDialer.connect("fixture", 500, () -> false,
                host -> new InetAddress[]{v6, v4}, (address, left) -> {
                    assertTrue(left > 0 && left <= 500);
                    if (attempts.incrementAndGet() == 1) throw new SocketTimeoutException();
                    return new Socket();
                })) { assertEquals(2, attempts.get()); }
    }
    @Test public void dnsAndCancellationAreBounded() throws Exception {
        long start = System.nanoTime();
        try {
            MultiAddressDialer.connect("fixture", 100, () -> false,
                    host -> { Thread.sleep(5000); return new InetAddress[0]; }, (a, t) -> new Socket());
            fail();
        } catch (SocketTimeoutException expected) {
            assertTrue(System.nanoTime() - start < 1_000_000_000L);
        }
        AtomicInteger attempts = new AtomicInteger();
        try {
            MultiAddressDialer.connect("fixture", 500, () -> true,
                    host -> new InetAddress[0], (a, t) -> { attempts.incrementAndGet(); return new Socket(); });
            fail();
        } catch (java.io.IOException expected) { assertEquals(0, attempts.get()); }
    }
}
