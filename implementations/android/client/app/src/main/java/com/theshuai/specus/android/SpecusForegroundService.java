package com.theshuai.specus.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.content.pm.ServiceInfo;
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
    static final String ACTION_RETRY = "com.theshuai.specus.android.RETRY";
    static final String EXTRA_MESSAGE_ID = "messageId";
    static final String EXTRA_TO_CLIENT_NAME = "toClientName";
    static final String EXTRA_MESSAGE = "message";
    static final String EXTRA_FILE_URI = "fileUri";

    private static final String CHANNEL_ID = "specus_client";
    private static final int NOTIFICATION_ID = 4207;

    private ExecutorService executor;
    private ExecutorService messageExecutor;
    private ExecutorService vpnExecutor;
    private volatile SpecusCore.Runtime runtime;
    private ConnectivityManager connectivityManager;
    private Network lastNetwork;
    private boolean callbackRegistered;
    private volatile boolean vpnRequested;
    private final ConnectivityManager.NetworkCallback networkCallback = new ConnectivityManager.NetworkCallback() {
        @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                    || !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return;
            if (network.equals(lastNetwork)) return;
            lastNetwork = network;
            SpecusCore.Runtime active = runtime;
            if (active != null) active.requestReconnect();
        }
        @Override public void onLost(Network network) {
            if (network.equals(lastNetwork)) {
                lastNetwork = null;
                SpecusCore.Runtime active = runtime;
                if (active != null) active.requestReconnect();
            }
        }
    };
    private ParcelFileDescriptor vpnInterface;
    private FileOutputStream vpnOutput;
    private volatile boolean vpnRunning;
    private volatile String vpnKey = "";
    private volatile SpecusCore.VpnPacketHandler vpnPacketHandler;

    @Override
    public void onCreate() {
        super.onCreate();
        ensureChannel();
        connectivityManager = getSystemService(ConnectivityManager.class);
        if (connectivityManager != null) {
            try {
                connectivityManager.registerDefaultNetworkCallback(networkCallback);
                callbackRegistered = true;
            } catch (RuntimeException error) {
                android.util.Log.w("specus", "Network callbacks unavailable", error);
            }
        }
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
        String action = intent == null ? ACTION_STOP : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopRuntime("Stopped by user");
            stopForegroundCompat();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_SEND_MESSAGE.equals(action)) {
            sendClientMessage(intent);
            return START_NOT_STICKY;
        }
        if (ACTION_RETRY.equals(action)) {
            SpecusCore.Runtime active = runtime;
            if (active != null && active.isRunning()) active.requestReconnect();
            else stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_SEND_FILE.equals(action)) {
            sendFile(intent);
            return START_NOT_STICKY;
        }
        try {
            boolean vpn = SpecusCore.StartupConfig.parse(ConfigStorage.loadConfig(this)).requiresVpnPermission();
            vpnRequested = vpn;
            if (vpn && VpnService.prepare(this) != null) throw new IllegalStateException("请返回应用授予 VPN 权限后启动");
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION_ID, notification("连接中"), vpn
                        ? ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
                        : ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else startForeground(NOTIFICATION_ID, notification("连接中"));
            publish("Starting", "正在建立连接", true);
            startRuntime();
        } catch (Exception error) {
            stopRuntime("无法启动：" + error.getMessage());
            stopForegroundCompat();
            stopSelf();
        }
        return START_NOT_STICKY;
    }

    /**
     * Stop promptly if the platform imposes a foreground-service limit. Never restart to evade it.
     */
    @Override
    public void onTimeout(int startId) {
        onTimeout(startId, 0);
    }

    /** Android 15 supplies the service type; the one-argument callback is for shortService. */
    @Override
    public void onTimeout(int startId, int foregroundServiceType) {
        stopRuntime("系统已限制后台运行；请打开应用检查权限并手动重新连接");
        stopVpn();
        stopForeground(true);
        stopSelf(startId);
    }

    @Override
    public void onDestroy() {
        if (callbackRegistered && connectivityManager != null) {
            connectivityManager.unregisterNetworkCallback(networkCallback);
            callbackRegistered = false;
        }
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

    @Override public void onRevoke() {
        stopRuntime("VPN 授权已撤销；可重新授权，或关闭私有组网后使用转发和互传");
        stopForegroundCompat();
        stopSelf();
        super.onRevoke();
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
        final SpecusCore.Runtime[] owner = new SpecusCore.Runtime[1];
        runtime = new SpecusCore.Runtime(getApplicationContext(), configText, (status, detail, running) -> {
            if (runtime == owner[0]) onRuntimeStatus(status, detail, running);
        }, this);
        owner[0] = runtime;
        runtime.setAppMessageListener((from, body) -> {
            Context appContext = getApplicationContext();
            if (FileTransferManager.get().onIncomingMessage(appContext, from, body)) {
                return;
            }
            ChatEvents.send(appContext, ChatEvents.DIRECTION_IN, ChatEvents.KIND_TEXT, from, body);
        });
        SpecusCore.Runtime started = runtime;
        executor.submit(() -> {
            started.run();
            new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
                if (runtime == started) {
                    runtime = null;
                    stopForegroundCompat();
                    stopSelf();
                }
            });
        });
    }

    private synchronized void stopRuntime(String reason) {
        if (runtime != null) {
            SpecusCore.Runtime old = runtime;
            runtime = null;
            old.stop();
        }
        publish("Stopped", reason, false);
    }

    private void sendClientMessage(Intent intent) {
        String toClientName = intent == null ? "" : intent.getStringExtra(EXTRA_TO_CLIENT_NAME);
        String message = intent == null ? "" : intent.getStringExtra(EXTRA_MESSAGE);
        String messageId = intent == null ? "" : intent.getStringExtra(EXTRA_MESSAGE_ID);
        SpecusCore.Runtime active = runtime;
        if (active == null || !active.isRunning()) {
            messageResult(messageId, "失败 · 未连接；内容已保留，可长按重新编辑");
            stopSelf();
            return;
        }
        ExecutorService worker = messageExecutor;
        if (worker == null || worker.isShutdown()) {
            messageResult(messageId, "失败 · 发送线程不可用；内容已保留");
            return;
        }
        worker.submit(() -> {
            try {
                active.sendClientMessage(toClientName, message);
                messageResult(messageId, "已提交 · 不代表对方已送达或已读");
            } catch (Exception error) {
                messageResult(messageId, "失败或结果未知 · " + error.getClass().getSimpleName()
                        + "；内容已保留，重发前请确认对方未收到");
            }
        });
    }

    private void messageResult(String id, String result) {
        GuiSessionStore.result(id, result);
        sendBroadcast(new Intent(ChatEvents.ACTION_CHAT).setPackage(getPackageName()));
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
            manager.notify(NOTIFICATION_ID, notification(GuiSessionStore.status().title));
        }
    }

    private void publish(String status, String detail, boolean running) {
        GuiSessionStore.status(status, detail, running);
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
        return socket != null && (!vpnRequested || protect(socket));
    }

    @Override
    public boolean protectDatagramSocket(DatagramSocket socket) {
        return socket != null && (!vpnRequested || protect(socket));
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
        PendingIntent stopIntent = PendingIntent.getService(this, 1,
                new Intent(this, SpecusForegroundService.class).setAction(ACTION_STOP), flags);
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        return builder
                .setContentTitle("specus")
                .setContentText(status == null ? "Running" : status)
                .setSmallIcon(R.drawable.ic_stat_specus)
                .setOngoing(true)
                .setContentIntent(pendingIntent)
                .addAction(new Notification.Action.Builder(null, "停止连接", stopIntent).build())
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
