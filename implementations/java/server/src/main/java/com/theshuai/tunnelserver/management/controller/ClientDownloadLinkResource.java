package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.ClientDownloadLinkView;
import com.theshuai.tunnelserver.management.service.ClientDownloadLinkService;
import com.theshuai.tunnelserver.management.service.ClientDownloadLinkService.LinkMutation;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 客户端下载链接资源。
 *
 * <p>路径分两组：
 * <ul>
 *   <li>{@code /api/admin/client-downloads/**}：管理员维护（CRUD），需要 Bearer JWT</li>
 *   <li>{@code /api/public/client-downloads}：仅 GET，公开可见，只返回 enabled 的链接，
 *       供登录页和未登录用户读取下载入口</li>
 * </ul>
 * 公开路径走 {@link com.theshuai.tunnelserver.config.SecurityConfig} 的 {@code /api/public/**} 放行规则。
 */
@RestController
public class ClientDownloadLinkResource {

    private final ClientDownloadLinkService service;

    public ClientDownloadLinkResource(ClientDownloadLinkService service) {
        this.service = service;
    }

    // ---- 管理面：全量、CRUD ----

    @GetMapping("/api/admin/client-downloads")
    public List<ClientDownloadLinkView> list() {
        return service.listAll();
    }

    @PostMapping("/api/admin/client-downloads")
    public ResponseEntity<ClientDownloadLinkView> create(@RequestBody LinkMutation body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(body));
    }

    @PutMapping("/api/admin/client-downloads/{id}")
    public ClientDownloadLinkView update(@PathVariable long id, @RequestBody LinkMutation body) {
        return service.update(id, body);
    }

    @DeleteMapping("/api/admin/client-downloads/{id}")
    public ResponseEntity<Void> delete(@PathVariable long id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }

    // ---- 公开：仅 enabled 列表 ----

    @GetMapping("/api/public/client-downloads")
    public List<ClientDownloadLinkView> listPublic() {
        return service.listEnabled();
    }
}
