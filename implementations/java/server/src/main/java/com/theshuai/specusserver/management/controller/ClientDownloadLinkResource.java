package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.ClientDownloadLinkView;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.ClientDownloadLinkService;
import com.theshuai.specusserver.management.service.ClientDownloadLinkService.DownloadablePackage;
import com.theshuai.specusserver.management.service.ClientDownloadLinkService.LinkMutation;
import com.theshuai.specusserver.management.service.ClientDownloadLinkService.PackageUpload;
import com.theshuai.specusserver.management.service.ClientDownloadLinkService.VersionCheckView;
import com.theshuai.specusserver.management.service.ClientPackageRateLimiter;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.security.ClientAddressResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

/** Public version catalogue/package delivery plus administrator package management. */
@RestController
public class ClientDownloadLinkResource {
    private final ClientDownloadLinkService service;
    private final ClientPackageRateLimiter rateLimiter;
    private final ClientAddressResolver addressResolver;
    private final ManagementContextResolver contextResolver;
    private final ManagementUserService managementUserService;

    public ClientDownloadLinkResource(ClientDownloadLinkService service,
                                      ClientPackageRateLimiter rateLimiter,
                                      ClientAddressResolver addressResolver,
                                      ManagementContextResolver contextResolver,
                                      ManagementUserService managementUserService) {
        this.service = service;
        this.rateLimiter = rateLimiter;
        this.addressResolver = addressResolver;
        this.contextResolver = contextResolver;
        this.managementUserService = managementUserService;
    }

    @GetMapping("/api/admin/client-downloads")
    public List<ClientDownloadLinkView> list(@AuthenticationPrincipal Jwt jwt) {
        requireAdmin(jwt);
        return service.listAll();
    }

    /** Existing JSON CRUD remains available for external links and old management clients. */
    @PostMapping("/api/admin/client-downloads")
    public ResponseEntity<ClientDownloadLinkView> create(@AuthenticationPrincipal Jwt jwt,
                                                         @RequestBody LinkMutation body) {
        requireAdmin(jwt);
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(body));
    }

    @PostMapping(value = "/api/admin/client-packages", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ClientDownloadLinkView> upload(
            @AuthenticationPrincipal Jwt jwt,
            @RequestPart("file") MultipartFile file,
            @RequestParam String implementation,
            @RequestParam String platform,
            @RequestParam String arch,
            @RequestParam String version,
            @RequestParam String displayName,
            @RequestParam(required = false) String description,
            @RequestParam(required = false) String changelogUrl,
            @RequestParam(required = false) String minSupportedVersion,
            @RequestParam(required = false) Integer displayOrder,
            @RequestParam(required = false) Boolean enabled,
            @RequestParam(name = "isLatest", required = false) Boolean isLatest) throws IOException {
        requireAdmin(jwt);
        PackageUpload metadata = new PackageUpload(
                implementation, platform, arch, version, displayName, description, changelogUrl,
                minSupportedVersion, displayOrder, enabled, isLatest);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(service.upload(file.getInputStream(), file.getSize(), metadata));
    }

    @PutMapping("/api/admin/client-downloads/{id}")
    public ClientDownloadLinkView update(@AuthenticationPrincipal Jwt jwt,
                                         @PathVariable long id,
                                         @RequestBody LinkMutation body) {
        requireAdmin(jwt);
        return service.update(id, body);
    }

    @PostMapping("/api/admin/client-downloads/{id}/latest")
    public ClientDownloadLinkView markLatest(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        requireAdmin(jwt);
        return service.markLatest(id);
    }

    @DeleteMapping("/api/admin/client-downloads/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        requireAdmin(jwt);
        service.delete(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/api/public/client-downloads")
    public List<ClientDownloadLinkView> listPublic(HttpServletRequest request) {
        checkRate(request);
        return service.listEnabled();
    }

    @GetMapping("/api/public/client-version-check")
    public ResponseEntity<VersionCheckView> checkVersion(
            HttpServletRequest request,
            @RequestParam String implementation,
            @RequestParam String platform,
            @RequestParam String arch,
            @RequestParam String current) {
        checkRate(request);
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(service.checkVersion(implementation, platform, arch, current));
    }

    @GetMapping("/api/public/client-packages/{id}/download")
    public ResponseEntity<Resource> download(HttpServletRequest request, @PathVariable long id) throws IOException {
        checkRate(request);
        DownloadablePackage downloadable = service.downloadable(id);
        long actualSize = Files.size(downloadable.path());
        if (actualSize != downloadable.fileSize()) {
            throw new IllegalStateException("client package size no longer matches its catalogue metadata");
        }
        FileSystemResource resource = new FileSystemResource(downloadable.path());
        ResponseEntity.BodyBuilder response = ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(actualSize)
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment()
                                .filename(downloadable.fileName(), StandardCharsets.UTF_8)
                                .build().toString())
                .header("X-Content-Type-Options", "nosniff");
        if (downloadable.sha256() != null) {
            response.eTag("\"sha256-" + downloadable.sha256() + "\"");
            response.header("X-Checksum-SHA256", downloadable.sha256());
        }
        return response.body(resource);
    }

    private void checkRate(HttpServletRequest request) {
        rateLimiter.check(addressResolver.resolve(request));
    }

    private void requireAdmin(Jwt jwt) {
        managementUserService.requireAdmin(contextResolver.resolve(jwt));
    }
}
