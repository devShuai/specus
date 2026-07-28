package com.theshuai.specus.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@SuppressWarnings("deprecation")
public class SpecusForegroundService extends VpnService implements SpecusCore.VpnPlatform {
    static final String ACTION_START = "com.theshuai.specus.android.START";
    static final String ACTION_STOP = "com.theshuai.specus.android.STOP";
    static final String ACTION_SEND_MESSAGE = "com.theshuai.specus.android.SEND_MESSAGE";
    static final String ACTION_SEND_FILE = "com.theshuai.specus.android.SEND_FILE";
    static final String EXTRA_TO_CLIENT_NAME = "toClientName";
    static final String EXTRA_MESSAGE = "message";
    static final String EXTRA_FILE_URI = "fileUri";

    private static final String CHANNEL_ID = "specus_client";
    private static final int NOTIFICATION_ID = 4207;

    private ExecutorService executor;
    private ExecutorService messageExecutor;
    private ExecutorService vpnExecutor;
    private SpecusCore.Runtime runtime;
    private ParcelFileDescriptor vpnInterface;
    private FileOutputStream vpnOutput;
    private volatile boolean vpnRunning;
    private volatile String vpnKey = "";
    private volatile SpecusCore.VpnPacketHandler vpnPacketHandler;

    @Override
    public void onCreate() {
        super.onCreate();
        ensureChannel();
        executor = Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "specus-runtime");
            thread.setDaemon(true);
            return thread;
        });
        messageExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "specus-message");
            thread.setDaemon(true);
            return thread;
        });
        vpnExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "specus-vpn");
            thread.setDaemon(true);
            return thread;
        });
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopRuntime("Stopped by user");
            stopForegroundCompat();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_SEND_MESSAGE.equals(action)) {
            sendClientMessage(intent);
            SpecusCore.Runtime active = runtime;
            return active != null && active.isRunning() ? START_STICKY : START_NOT_STICKY;
        }
        if (ACTION_SEND_FILE.equals(action)) {
            sendFile(intent);
            SpecusCore.Runtime active = runtime;
            return active != null && active.isRunning() ? START_STICKY : START_NOT_STICKY;
        }
        startForeground(NOTIFICATION_ID, notification("Starting"));
        startRuntime();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopRuntime("Service destroyed");
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
        if (messageExecutor != null) {
            messageExecutor.shutdownNow();
            messageExecutor = null;
        }
        stopVpn();
        if (vpnExecutor != null) {
            vpnExecutor.shutdownNow();
            vpnExecutor = null;
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        if (intent != null && VpnService.SERVICE_INTERFACE.equals(intent.getAction())) {
            return super.onBind(intent);
        }
        return null;
    }

    private synchronized void startRuntime() {
        if (runtime != null && runtime.isRunning()) {
            publish("Already running", "", true);
            return;
        }
        String configText = ConfigStorage.loadConfig(this);
        runtime = new SpecusCore.Runtime(getApplicationContext(), configText, this::onRuntimeStatus, this);
        runtime.setAppMessageListener((from, body) -> {
            Context appContext = getApplicationContext();
            if (FileTransferManager.get().onIncomingMessage(appContext, from, body)) {
                return;
            }
            ChatEvents.send(appContext, ChatEvents.DIRECTION_IN, ChatEvents.KIND_TEXT, from, body);
        });
        executor.submit(runtime::run);
    }

    private synchronized void stopRuntime(String reason) {
        if (runtime != null) {
            runtime.stop();
            runtime = null;
        }
        publish("Stopped", reason, false);
    }

    private void sendClientMessage(Intent intent) {
        String toClientName = intent == null ? "" : intent.getStringExtra(EXTRA_TO_CLIENT_NAME);
        String message = intent == null ? "" : intent.getStringExtra(EXTRA_MESSAGE);
        SpecusCore.Runtime active = runtime;
        if (active == null || !active.isRunning()) {
            publish("Message not sent", "Specus is not running", false);
            stopSelf();
            return;
        }
        ExecutorService worker = messageExecutor;
        if (worker == null || worker.isShutdown()) {
            publish("Message not sent", "Message worker is stopped", active.isRunning());
            return;
        }
        worker.submit(() -> {
            try {
                active.sendClientMessage(toClientName, message);
            } catch (Exception error) {
                publish("Message not sent", error.getMessage() == null
                        ? error.getClass().getSimpleName()
                        : error.getMessage(), active.isRunning());
            }
        });
    }

    private void sendFile(Intent intent) {
        String toClientName = intent == null ? "" : intent.getStringExtra(EXTRA_TO_CLIENT_NAME);
        String uriText = intent == null ? "" : intent.getStringExtra(EXTRA_FILE_URI);
        SpecusCore.Runtime active = runtime;
        if (active == null || !active.isRunning()) {
            ChatEvents.send(getApplicationContext(), ChatEvents.DIRECTION_OUT, ChatEvents.KIND_FILE,
                    toClientName, "文件未发送 · 隧道未运行");
            stopSelf();
            return;
        }
        ExecutorService worker = messageExecutor;
        if (worker == null || worker.isShutdown()) {
            ChatEvents.send(getApplicationContext(), ChatEvents.DIRECTION_OUT, ChatEvents.KIND_FILE,
                    toClientName, "文件未发送 · 发送线程不可用");
            return;
        }
        android.net.Uri uri = android.net.Uri.parse(uriText);
        worker.submit(() -> FileTransferManager.get().sendFile(getApplicationContext(), active, toClientName, uri));
    }

    private void onRuntimeStatus(String status, String detail, boolean running) {
        publish(status, detail, running);
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification(status));
        }
    }

    private void publish(String status, String detail, boolean running) {
        Intent intent = new Intent(StatusEvents.ACTION_STATUS)
                .setPackage(getPackageName())
                .putExtra(StatusEvents.EXTRA_STATUS, status)
                .putExtra(StatusEvents.EXTRA_DETAIL, detail)
                .putExtra(StatusEvents.EXTRA_RUNNING, running);
        sendBroadcast(intent);
    }

    @Override
    public synchronized void startVpn(SpecusCore.PeerMeshConfig config, SpecusCore.VpnPacketHandler packetHandler) throws Exception {
        if (config == null || !config.enabled || isBlank(config.virtualIp) || isBlank(config.cidr)) {
            stopVpn();
            return;
        }
        Cidr.parse(config.cidr); // Validate the advertised mesh network.
        List<String> peerRoutes = SpecusCore.PeerMeshConfig.normalizePeerRoutes(
                config.peerRoutes, config.virtualIp);
        int mtu = SpecusCore.PeerMeshConfig.normalizeMtu(config.mtu);
        String key = config.virtualIp + "|" + config.cidr + "|" + mtu
                + "|" + String.join(",", peerRoutes);
        if (vpnRunning && key.equals(vpnKey)) {
            vpnPacketHandler = packetHandler;
            return;
        }
        stopVpn();
        vpnPacketHandler = packetHandler;

        Builder builder = new Builder()
                .setSession("specus")
                .setMtu(mtu)
                .addAddress(config.virtualIp, 32);
        for (String peerRoute : peerRoutes) {
            builder.addRoute(peerRoute, 32);
        }
        try {
            builder.addDisallowedApplication(getPackageName());
        } catch (PackageManager.NameNotFoundException ignored) {
        }
        vpnInterface = builder.establish();
        if (vpnInterface == null) {
            throw new IllegalStateException("VPN establish returned null");
        }
        vpnOutput = new FileOutputStream(vpnInterface.getFileDescriptor());
        vpnRunning = true;
        vpnKey = key;
        publish("VPN active", config.virtualIp + "/32 peers=" + peerRoutes.size(), true);

        ParcelFileDescriptor active = vpnInterface;
        vpnExecutor.submit(() -> readVpnLoop(active));
    }

    @Override
    public synchronized void stopVpn() {
        vpnRunning = false;
        vpnKey = "";
        vpnPacketHandler = null;
        closeQuietly(vpnOutput);
        vpnOutput = null;
        closeQuietly(vpnInterface);
        vpnInterface = null;
    }

    @Override
    public boolean protectSocket(Socket socket) {
        return socket != null && protect(socket);
    }

    @Override
    public boolean protectDatagramSocket(DatagramSocket socket) {
        return socket != null && protect(socket);
    }

    @Override
    public void writeVpnPacket(byte[] packet) throws Exception {
        FileOutputStream out = vpnOutput;
        if (out != null && packet != null && packet.length > 0) {
            out.write(packet);
            out.flush();
        }
    }

    private void readVpnLoop(ParcelFileDescriptor descriptor) {
        byte[] buffer = new byte[64 * 1024];
        try (FileInputStream in = new FileInputStream(descriptor.getFileDescriptor())) {
            while (vpnRunning && descriptor == vpnInterface) {
                int read = in.read(buffer);
                SpecusCore.VpnPacketHandler handler = vpnPacketHandler;
                if (read > 0 && handler != null) {
                    handler.onPacket(Arrays.copyOf(buffer, read));
                }
            }
        } catch (Exception error) {
            if (vpnRunning) {
                publish("VPN stopped", error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage(), true);
            }
        }
    }

    private Notification notification(String status) {
        Intent launch = new Intent(this, MainActivity.class);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, launch, flags);
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        return builder
                .setContentTitle("specus")
                .setContentText(status == null ? "Running" : status)
                .setSmallIcon(R.drawable.ic_stat_specus)
                .setOngoing(true)
                .setContentIntent(pendingIntent)
                .build();
    }

    private void stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } else {
            stopForeground(true);
        }
    }

    private void ensureChannel() {
        if (Build.VERSION.SDK_INT < 26) {
            return;
        }
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel),
                NotificationManager.IMPORTANCE_LOW);
        manager.createNotificationChannel(channel);
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static void closeQuietly(java.io.Closeable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (Exception ignored) {
        }
    }

    private static final class Cidr {
        final String address;
        final int prefix;

        private Cidr(String address, int prefix) {
            this.address = address;
            this.prefix = prefix;
        }

        static Cidr parse(String value) {
            String[] parts = value.split("/", 2);
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid CIDR: " + value);
            }
            int prefix = Integer.parseInt(parts[1].trim());
            if (prefix < 0 || prefix > 32) {
                throw new IllegalArgumentException("Invalid CIDR prefix: " + value);
            }
            return new Cidr(parts[0].trim(), prefix);
        }
    }
}
