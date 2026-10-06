package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.service.HttpShareService;
import com.theshuai.specusserver.security.ClientAddressResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;

/**
 * {@code POST /api/public/http-shares/exchange}: the share landing page posts the token it read
 * from the link fragment and receives the HttpOnly share cookie scoped to the share path. Only JSON
 * is accepted, so another site cannot submit it with a plain form, and there is no CORS.
 */
@RestController
public class PublicHttpShareResource {
    private static final int MAX_BODY_BYTES = 4096;

    private final HttpShareService httpShareService;
    private final ClientAddressResolver clientAddressResolver;

    public PublicHttpShareResource(HttpShareService httpShareService, ClientAddressResolver clientAddressResolver) {
        this.httpShareService = httpShareService;
        this.clientAddressResolver = clientAddressResolver;
    }

    @PostMapping("/api/public/http-shares/exchange")
    public ResponseEntity<byte[]> exchange(HttpServletRequest request) throws IOException {
        try {
            HttpShareService.ApiResult result = httpShareService.exchange(
                    request.getContentType(), readBounded(request), clientAddressResolver.resolve(request));
            return HttpShareResponses.json(result.status(), result.body(), result.headers(), "no-store");
        } catch (HttpShareService.ShareProblem problem) {
            return HttpShareResponses.error(problem.status(), problem.code(), problem.headers(), "no-store");
        }
    }

    /** The body, or null when it is larger than the exchange accepts (answered with 400). */
    private static byte[] readBounded(HttpServletRequest request) throws IOException {
        if (request.getContentLengthLong() > MAX_BODY_BYTES) {
            return null;
        }
        try (InputStream input = request.getInputStream()) {
            byte[] body = input.readNBytes(MAX_BODY_BYTES + 1);
            return body.length > MAX_BODY_BYTES ? null : body;
        }
    }
}
