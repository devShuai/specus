package com.theshuai.specusclient.peer.portmap;

/**
 * 跟 NAT 设备（路由器）协商显式端口映射的通用抽象。
 *
 * <p>三种实现 ({@link UpnpPortMapper} / {@link NatPmpPortMapper} / {@link PcpPortMapper}) 都遵守同一份
 * 契约：尝试在本地路由器上把 {@code (publicAddress, externalPort) → (localAddress, internalPort)} 映射开起来，
 * 成功就返回 {@link NatPortMapping}，失败抛 {@link PortMappingException}。
 *
 * <p>每次 {@link #addMapping} 是幂等的：路由器上已经存在等价映射时，多数实现会更新 lease 并返回新的映射；
 * 这样调用方可以周期性 renew 而不需要先 delete 再 add。
 *
 * <p>所有方法都是阻塞的。调用方负责加超时（推荐 ≤ 3 秒），避免坏路由器把整个客户端卡住。
 */
public interface NatPortMapper {

    PortMappingProtocol protocol();

    /**
     * 添加或刷新一条 UDP 端口映射。
     *
     * @param internalPort       本地 UDP socket 绑定的端口
     * @param preferredExternal  期望的公网端口；多数实现允许传 {@code 0} 表示由路由器自选
     * @param leaseSeconds       期望的租约时长（秒）。路由器可能给一个更短的值，实际值放在返回里
     * @param description        路由器管理界面里展示的描述文本（仅 UPnP 用得到，其它实现忽略）
     * @return 成功的映射结果
     * @throws PortMappingException 协议层失败（无可用的网关、不支持、被拒绝等）
     */
    NatPortMapping addMapping(int internalPort,
                              int preferredExternal,
                              int leaseSeconds,
                              String description) throws PortMappingException;

    /**
     * 主动释放一条端口映射。多数实现是 best-effort——失败不抛异常，只 log 一下。
     * 客户端关停时调用即可，租约本身也会自动过期。
     */
    void deleteMapping(NatPortMapping mapping);

    /**
     * 该协议在本地网络上是否「貌似可用」。提供给 {@link NatPortMappingService} 用来做快速预探，
     * 避免每次启动都把三个协议都重跑一遍（虽然失败也只多花几百毫秒）。
     *
     * <p>默认返回 {@code true}（让 {@link #addMapping} 真正去试）。子类可以重写做轻量探测。
     */
    default boolean isLikelyAvailable() {
        return true;
    }
}
