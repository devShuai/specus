package com.theshuai.specusclient.peer.portmap;

import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 把 UPnP / NAT-PMP / PCP 三种 mapper 串成一个统一服务：
 *
 * <ul>
 *   <li>并发跑三个，第一个成功的就返回，其余的标记为「未使用，不释放」（多个映射不互斥，
 *       但保持单一来源便于运营）；</li>
 *   <li>统一的全局超时（默认 3 秒）兜底，避免坏路由器把整个客户端卡住；</li>
 *   <li>失败统一吞掉，{@code null} 当作 「没拿到映射」，调用方退回 STUN 即可。</li>
 * </ul>
 *
 * <p>没有 daemon 线程常驻——每次 {@link #tryAcquireMapping} / {@link #renewMapping} / {@link #releaseMapping}
 * 都是阻塞调用，{@link com.theshuai.specusclient.peer.PeerMeshClient PeerMeshClient} 的
 * maintenance 调度负责按 lease 时间触发续期。
 */
@Slf4j
public class NatPortMappingService {

    private static final int DEFAULT_OVERALL_TIMEOUT_SECONDS = 4;
    /** weupnp 内部 SSDP 多播超时本身就接近 3 秒，给一些 headroom。 */
    private final int overallTimeoutSeconds;
    private final List<NatPortMapper> mappers;

    public NatPortMappingService() {
        this(DEFAULT_OVERALL_TIMEOUT_SECONDS, defaultMappers());
    }

    public NatPortMappingService(int overallTimeoutSeconds, List<NatPortMapper> mappers) {
        this.overallTimeoutSeconds = Math.max(1, overallTimeoutSeconds);
        this.mappers = List.copyOf(mappers);
    }

    private static List<NatPortMapper> defaultMappers() {
        // 顺序无所谓，全部并发跑。这里按"中国家用网络命中率"排序，纯粹为了日志可读性。
        return List.of(new UpnpPortMapper(), new NatPmpPortMapper(), new PcpPortMapper());
    }

    /**
     * 尝试拿到一条端口映射。成功返回 {@link NatPortMapping}，全部失败返回 {@code null}。
     *
     * @param internalPort      本机 UDP 端口（需先 bind）
     * @param preferredExternal 期望的公网端口，{@code 0} 表示由路由器自选
     * @param leaseSeconds      期望租约（多数实现会被路由器钳到一个上限值）
     * @param description       UPnP 路由器后台显示的描述，其它协议忽略
     */
    public NatPortMapping tryAcquireMapping(int internalPort,
                                            int preferredExternal,
                                            int leaseSeconds,
                                            String description) {
        if (internalPort <= 0 || internalPort > 65_535) {
            return null;
        }
        ExecutorService executor = Executors.newFixedThreadPool(
                mappers.size(),
                task -> {
                    Thread thread = new Thread(task, "nat-port-mapper");
                    thread.setDaemon(true);
                    return thread;
                });
        List<Future<NatPortMapping>> futures = new ArrayList<>(mappers.size());
        try {
            for (NatPortMapper mapper : mappers) {
                Callable<NatPortMapping> task = () -> {
                    if (!mapper.isLikelyAvailable()) {
                        return null;
                    }
                    return mapper.addMapping(internalPort, preferredExternal, leaseSeconds, description);
                };
                futures.add(executor.submit(task));
            }

            long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(overallTimeoutSeconds);
            NatPortMapping winner = null;

            for (Future<NatPortMapping> future : futures) {
                long remaining = deadlineNanos - System.nanoTime();
                if (remaining <= 0) {
                    break;
                }
                try {
                    NatPortMapping result = future.get(remaining, TimeUnit.NANOSECONDS);
                    if (result != null) {
                        winner = result;
                        break; // 拿到一个就够了
                    }
                } catch (TimeoutException e) {
                    break;
                } catch (ExecutionException e) {
                    Throwable cause = e.getCause();
                    log.debug("NAT port mapping protocol failed: {}",
                            cause == null ? e.getMessage() : cause.getMessage());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            if (winner == null) {
                // 把剩余 future 的结果也消费一遍，给日志更完整的失败原因。
                drainResults(futures, deadlineNanos);
                log.info("NAT port mapping: all protocols failed or timed out within {}s", overallTimeoutSeconds);
                return null;
            }
            return winner;
        } finally {
            // 取消还没完成的，避免长时间挂在那里
            for (Future<NatPortMapping> future : futures) {
                if (!future.isDone()) {
                    future.cancel(true);
                }
            }
            executor.shutdownNow();
        }
    }

    /**
     * 续期一条已有映射。如果失败，调用方可以选择丢掉这个 mapping 重新 {@link #tryAcquireMapping}。
     */
    public NatPortMapping renewMapping(NatPortMapping mapping, int leaseSeconds, String description) {
        if (mapping == null) {
            return null;
        }
        NatPortMapper mapper = mapperByProtocol(mapping.protocol());
        if (mapper == null) {
            return null;
        }
        try {
            return mapper.addMapping(mapping.internalPort(), mapping.externalPort(), leaseSeconds, description);
        } catch (PortMappingException e) {
            log.debug("NAT port mapping renew failed for {}:{}: {}",
                    mapping.protocol(), mapping.externalPort(), e.getMessage());
            return null;
        }
    }

    /**
     * Best-effort 释放。即使失败也只 log 不抛。
     */
    public void releaseMapping(NatPortMapping mapping) {
        if (mapping == null) {
            return;
        }
        NatPortMapper mapper = mapperByProtocol(mapping.protocol());
        if (mapper != null) {
            mapper.deleteMapping(mapping);
        }
    }

    private NatPortMapper mapperByProtocol(PortMappingProtocol protocol) {
        for (NatPortMapper mapper : mappers) {
            if (mapper.protocol() == protocol) {
                return mapper;
            }
        }
        return null;
    }

    private void drainResults(List<Future<NatPortMapping>> futures, long deadlineNanos) {
        for (Future<NatPortMapping> future : futures) {
            if (future.isDone()) {
                try {
                    future.get();
                } catch (Exception ignored) {
                }
            } else {
                long remaining = deadlineNanos - System.nanoTime();
                if (remaining > 0) {
                    try {
                        future.get(Math.min(remaining, TimeUnit.MILLISECONDS.toNanos(200)), TimeUnit.NANOSECONDS);
                    } catch (Exception ignored) {
                    }
                }
            }
        }
    }

    /**
     * 仅用于测试或调试：当前服务可识别的所有 protocol。
     */
    public List<PortMappingProtocol> supportedProtocols() {
        List<PortMappingProtocol> list = new ArrayList<>(mappers.size());
        for (NatPortMapper m : mappers) {
            list.add(m.protocol());
        }
        return list;
    }

    /**
     * 给单元测试用：把当前服务伪造成「现在就续期」状态。
     */
    public static Instant nowForTesting() {
        return Instant.now();
    }
}
