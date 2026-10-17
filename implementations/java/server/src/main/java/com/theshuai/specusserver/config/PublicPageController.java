package com.theshuai.specusserver.config;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/** Explicit SPA documents, not a fallback for missing APIs, assets or proxied applications. */
@Controller
public class PublicPageController {
    @GetMapping({"/nat-detect", "/nat-detect/", "/transfer", "/transfer/", "/diagram", "/diagram/",
            "/diagram-embed", "/diagram-embed/", "/download", "/download/"})
    public ResponseEntity<Resource> index() {
        Resource index = new ClassPathResource("static/index.html");
        if (!index.exists()) {
            return ResponseEntity.notFound().build();
        }
        // Serve the document in this dispatch: a servlet forward may lose the
        // original portal security-header writer. Never redirect invitation state.
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).cacheControl(CacheControl.noCache()).body(index);
    }
}
