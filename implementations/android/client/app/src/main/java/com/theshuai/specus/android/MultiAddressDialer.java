package com.theshuai.specus.android;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

/** Bounded DNS + family-interleaved address fallback, deliberately not called Happy Eyeballs. */
final class MultiAddressDialer {
    interface Resolver { InetAddress[] resolve(String host) throws Exception; }
    interface Attempt { Socket connect(InetAddress address, int remainingMillis) throws Exception; }
    private static final ThreadPoolExecutor DNS = new ThreadPoolExecutor(2, 2, 30, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(2), runnable -> {
                Thread thread = new Thread(runnable, "specus-control-dns");
                thread.setDaemon(true); return thread;
            }, new ThreadPoolExecutor.AbortPolicy());

    static Socket connect(String host, int budgetMillis, BooleanSupplier cancelled, Resolver resolver, Attempt attempt) throws Exception {
        long deadline = System.nanoTime() + budgetMillis * 1_000_000L;
        Future<InetAddress[]> query = DNS.submit(() -> resolver.resolve(host));
        InetAddress[] resolved;
        try {
            while (true) {
                if (cancelled.getAsBoolean()) throw new IOException("连接已取消");
                long left = deadline - System.nanoTime();
                if (left <= 0) throw new SocketTimeoutException("服务端 DNS 查询超时，请检查网络或 DNS");
                try { resolved = query.get(Math.min(100, Math.max(1, left / 1_000_000)), TimeUnit.MILLISECONDS); break; }
                catch (TimeoutException ignored) { }
            }
        } finally { query.cancel(true); DNS.purge(); }
        Exception last = null;
        for (InetAddress address : interleave(resolved)) {
            if (cancelled.getAsBoolean()) throw new IOException("连接已取消");
            long left = (deadline - System.nanoTime()) / 1_000_000;
            if (left <= 0) break;
            try { return attempt.connect(address, (int) left); }
            catch (javax.net.ssl.SSLException error) { throw error; }
            catch (IOException error) { last = error; }
        }
        if (last != null) throw last;
        throw new SocketTimeoutException("服务端多地址连接超时或 DNS 未返回地址");
    }

    static List<InetAddress> interleave(InetAddress[] addresses) {
        List<InetAddress> v4 = new ArrayList<>(), v6 = new ArrayList<>(), ordered = new ArrayList<>();
        for (InetAddress address : addresses) {
            List<InetAddress> family = address instanceof Inet6Address ? v6 : v4;
            if (!family.contains(address)) family.add(address);
        }
        boolean preferV6 = addresses.length > 0 && addresses[0] instanceof Inet6Address;
        List<InetAddress> first = preferV6 ? v6 : v4, second = preferV6 ? v4 : v6;
        for (int i = 0; ordered.size() < 8 && (i < first.size() || i < second.size()); i++) {
            if (i < first.size()) ordered.add(first.get(i));
            if (i < second.size() && ordered.size() < 8) ordered.add(second.get(i));
        }
        return ordered;
    }
}
