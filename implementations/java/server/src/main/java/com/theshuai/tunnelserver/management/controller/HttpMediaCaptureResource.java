package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.HttpMediaCapture;
import com.theshuai.tunnelserver.management.model.HttpMediaCaptureView;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.management.security.ManagementContextResolver;
import com.theshuai.tunnelserver.management.service.HttpMediaCaptureService;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackService;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackService.MediaRangeException;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackService.PlaybackPlan;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackTicketService;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackTicketService.PlaybackTicketView;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/admin/traffic/media-captures")
public class HttpMediaCaptureResource {
    private final HttpMediaCaptureService captureService;
    private final HttpMediaPlaybackService playbackService;
    private final HttpMediaPlaybackTicketService ticketService;
    private final ManagementContextResolver contextResolver;

    public HttpMediaCaptureResource(HttpMediaCaptureService captureService,
                                    HttpMediaPlaybackService playbackService,
                                    HttpMediaPlaybackTicketService ticketService,
                                    ManagementContextResolver contextResolver) {
        this.captureService = captureService;
        this.playbackService = playbackService;
        this.ticketService = ticketService;
        this.contextResolver = contextResolver;
    }

    @PostMapping("/{id}/playback-ticket")
    public PlaybackTicketView playbackTicket(@AuthenticationPrincipal Jwt jwt,
                                             @PathVariable long id,
                                             @RequestParam(defaultValue = "false")
                                             boolean backfillMissing) {
        return ticketService.create(
                contextResolver.resolve(jwt), id, backfillMissing);
    }

    @GetMapping
    public Map<String, Object> list(@AuthenticationPrincipal Jwt jwt,
                                    @RequestParam(required = false) Long clientId,
                                    @RequestParam(required = false) String route,
                                    @RequestParam(defaultValue = "0") int page,
                                    @RequestParam(defaultValue = "50") int size) {
        Page<HttpMediaCaptureView> result = captureService.list(
                contextResolver.resolve(jwt),
                clientId,
                route,
                PageRequest.of(
                        Math.max(0, page),
                        Math.clamp(size, 1, 200),
                        Sort.by(Sort.Direction.DESC, "id")));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("items", result.getContent());
        response.put("total", result.getTotalElements());
        response.put("page", result.getNumber());
        response.put("size", result.getSize());
        response.put("totalPages", result.getTotalPages());
        return response;
    }

    @RequestMapping(path = "/{id}/play", method = {RequestMethod.GET, RequestMethod.HEAD})
    public void play(@AuthenticationPrincipal Jwt jwt,
                     @PathVariable long id,
                     HttpServletRequest request,
                     HttpServletResponse response) throws IOException {
        ManagementContext context = contextResolver.resolve(jwt);
        try {
            PlaybackPlan plan = playbackService.plan(context, id, request.getHeader(HttpHeaders.RANGE));
            writePlayback(plan, request, response);
        } catch (MediaRangeException exception) {
            response.setStatus(HttpStatus.REQUESTED_RANGE_NOT_SATISFIABLE.value());
            response.setHeader(HttpHeaders.ACCEPT_RANGES, "bytes");
            if (exception.totalBytes() > 0) {
                response.setHeader(HttpHeaders.CONTENT_RANGE, "bytes */" + exception.totalBytes());
            }
            response.setContentType("text/plain;charset=UTF-8");
            response.getOutputStream().write(exception.getMessage().getBytes(StandardCharsets.UTF_8));
        }
    }

    @GetMapping("/{id}/manifest")
    public void manifest(@AuthenticationPrincipal Jwt jwt,
                         @PathVariable long id,
                         HttpServletResponse response) throws IOException {
        HttpMediaCapture anchor = captureService.requireAccessible(contextResolver.resolve(jwt), id);
        writeManifest(anchor, response);
    }

    @RequestMapping(path = "/{id}/asset", method = {RequestMethod.GET, RequestMethod.HEAD})
    public void asset(@AuthenticationPrincipal Jwt jwt,
                      @PathVariable long id,
                      @RequestParam String url,
                      HttpServletRequest request,
                      HttpServletResponse response) throws IOException {
        ManagementContext context = contextResolver.resolve(jwt);
        HttpMediaCapture anchor = captureService.requireAccessible(context, id);
        HttpMediaCapture target = captureService.latestForSource(anchor, url);
        if (isManifest(target)) {
            writeManifest(target, response);
            return;
        }
        try {
            PlaybackPlan plan = playbackService.plan(target, request.getHeader(HttpHeaders.RANGE));
            writePlayback(plan, request, response);
        } catch (MediaRangeException exception) {
            response.setStatus(HttpStatus.REQUESTED_RANGE_NOT_SATISFIABLE.value());
            response.setHeader(HttpHeaders.ACCEPT_RANGES, "bytes");
            if (exception.totalBytes() > 0) {
                response.setHeader(HttpHeaders.CONTENT_RANGE, "bytes */" + exception.totalBytes());
            }
        }
    }

    private void writeManifest(HttpMediaCapture anchor, HttpServletResponse response) throws IOException {
        try {
            String manifest = captureService.rewrittenManifest(
                    anchor, "/api/admin/traffic/media-captures/" + anchor.getId() + "/asset");
            byte[] bytes = manifest.getBytes(StandardCharsets.UTF_8);
            String contentType = "HLS_MANIFEST".equals(anchor.getMediaKind())
                    ? "application/vnd.apple.mpegurl" : "application/dash+xml";
            response.setStatus(HttpStatus.OK.value());
            response.setContentType(contentType);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            response.setContentLengthLong(bytes.length);
            response.getOutputStream().write(bytes);
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, exception.getMessage(), exception);
        } catch (IllegalStateException exception) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, exception.getMessage(), exception);
        }
    }

    private void writePlayback(PlaybackPlan plan,
                               HttpServletRequest request,
                               HttpServletResponse response) throws IOException {
        response.setStatus(plan.partial()
                ? HttpStatus.PARTIAL_CONTENT.value() : HttpStatus.OK.value());
        response.setContentType(plan.contentType());
        if (plan.contentEncoding() != null && !plan.contentEncoding().isBlank()) {
            response.setHeader(HttpHeaders.CONTENT_ENCODING, plan.contentEncoding());
        }
        response.setHeader(HttpHeaders.ACCEPT_RANGES, "bytes");
        response.setHeader(HttpHeaders.CACHE_CONTROL, "private, no-store");
        if (plan.etag() != null && !plan.etag().isBlank()) {
            response.setHeader(HttpHeaders.ETAG, plan.etag());
        }
        if (plan.partial()) {
            response.setHeader(HttpHeaders.CONTENT_RANGE,
                    "bytes " + plan.start() + "-" + plan.end() + "/" + plan.totalBytes());
        }
        response.setContentLengthLong(plan.contentLength());
        if (!"HEAD".equalsIgnoreCase(request.getMethod())) {
            playbackService.stream(plan, response.getOutputStream());
        }
    }

    private boolean isManifest(HttpMediaCapture capture) {
        return "HLS_MANIFEST".equals(capture.getMediaKind())
                || "DASH_MANIFEST".equals(capture.getMediaKind());
    }
}
