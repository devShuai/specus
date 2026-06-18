package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.ClientAccountView;
import com.theshuai.tunnelserver.management.model.HttpRouteView;
import com.theshuai.tunnelserver.management.service.ClientAccountService;
import com.theshuai.tunnelserver.management.service.HttpRouteRegistry;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HTTP 路由（{@code httpTunnelConfigList}）展示视图。
 *
 * <p>纯查询，数据来源是 {@link HttpRouteRegistry}（内存缓存，由在线客户端通过
 * {@code HTTP_ROUTES_REPORT} 上报）。本端点不提供写操作——HTTP 路由表是客户端
 * {@code tunnelClientConfig.json} 的派生信息，服务端不持久化、不可远程修改。
 *
 * <ul>
 *   <li>{@code GET /api/admin/http-routes}                所有在线客户端的 HTTP 路由</li>
 *   <li>{@code GET /api/admin/http-routes?clientId=123}   仅返回指定 clientId 的</li>
 * </ul>
 *
 * <p>断线即清空，因此返回的 list 自动反映"当前在线"状态；从未上报或老客户端的条目都不会出现。
 */
@RestController
@RequestMapping("/api/admin")
public class HttpRouteResource {

    private final HttpRouteRegistry httpRouteRegistry;
    private final ClientAccountService clientAccountService;

    public HttpRouteResource(HttpRouteRegistry httpRouteRegistry,
                             ClientAccountService clientAccountService) {
        this.httpRouteRegistry = httpRouteRegistry;
        this.clientAccountService = clientAccountService;
    }

    @GetMapping("/http-routes")
    public List<HttpRouteView> listHttpRoutes(@RequestParam(required = false) Long clientId) {
        // 单次拉取账号列表既用于 id→name 反查（带 clientId 时），也用于 name→id 反查（全量时）。
        List<ClientAccountView> accounts = clientAccountService.listClients();
        if (clientId != null) {
            return accounts.stream()
                    .filter(a -> a.id() == clientId)
                    .findFirst()
                    .map(a -> httpRouteRegistry.listByClientName(a.clientName(), a.id()))
                    .orElse(List.of());
        }
        Map<String, Long> nameToId = new HashMap<>(accounts.size() * 2);
        for (ClientAccountView a : accounts) {
            nameToId.put(a.clientName(), a.id());
        }
        return httpRouteRegistry.listAll(nameToId::get);
    }
}
