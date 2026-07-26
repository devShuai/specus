package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.HttpMediaCapture;
import com.theshuai.tunnelserver.management.service.HttpMediaCaptureService;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackService;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackService.MediaRangeException;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackService.PlaybackPlan;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackTicketService;
import com.theshuai.tunnelserver.management.service.HttpMediaPlaybackTicketService.ResolvedTicket;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.util.UriUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api/public/media-playback/{ticket}")
@Slf4j
public class PublicHttpMediaPlaybackResource {
    private final HttpMediaPlaybackTicketService ticketService;
    private final HttpMediaCaptureService captureService;
    private final HttpMediaPlaybackService playbackService;

    public PublicHttpMediaPlaybackResource(HttpMediaPlaybackTicketService ticketService,
                                           HttpMediaCaptureService captureService,
                                           HttpMediaPlaybackService playbackService) {
        this.ticketService = ticketService;
        this.captureService = captureService;
        this.playbackService = playbackService;
    }

    @RequestMapping(path = "/play", method = {RequestMethod.GET, RequestMethod.HEAD})
    public void play(@PathVariable String ticket,
                     HttpServletRequest request,
                     HttpServletResponse response) throws IOException {
        ResolvedTicket resolved = ticketService.resolve(ticket);
        writePlayback(
                resolved,
                resolved.capture(),
                resolved.capture().getSourceUrl(),
                request,
                response);
    }

    @RequestMapping(path = "/manifest", method = {RequestMethod.GET, RequestMethod.HEAD})
    public void manifest(@PathVariable String ticket,
                         HttpServletRequest request,
                         HttpServletResponse response) throws IOException {
        ResolvedTicket resolved = ticketService.resolve(ticket);
        writeManifest(resolved, request, response);
    }

    @RequestMapping(path = "/asset", method = {RequestMethod.GET, RequestMethod.HEAD})
    public void asset(@PathVariable String ticket,
                      @RequestParam String url,
                      HttpServletRequest request,
                      HttpServletResponse response) throws IOException {
        ResolvedTicket resolved = ticketService.resolve(ticket);
        HttpMediaCapture target;
        try {
            target = captureService.latestForSource(resolved.capture(), url);
        } catch (IllegalArgumentException exception) {
            if (resolved.backfillMissing()) {
                redirectToOrigin(resolved.capture(), url, response, "媒体资源尚未缓存");
            } else {
                writeCacheMiss(response, HttpStatus.NOT_FOUND, "媒体资源尚未缓存", 0);
            }
            return;
        }
        if (isManifest(target)) {
            writeManifest(new ResolvedTicket(
                    ticket,
                    target,
                    resolved.expiresAt(),
                    resolved.backfillMissing()), request, response);
            return;
        }
        writePlayback(resolved, target, url, request, response);
    }

    private void writeManifest(ResolvedTicket ticket,
                               HttpServletRequest request,
                               HttpServletResponse response) throws IOException {
        String manifest = captureService.rewrittenManifest(ticket.capture(), ticket.assetBasePath());
        byte[] bytes = manifest.getBytes(StandardCharsets.UTF_8);
        response.setStatus(HttpStatus.OK.value());
        response.setContentType("HLS_MANIFEST".equals(ticket.capture().getMediaKind())
                ? "application/vnd.apple.mpegurl" : "application/dash+xml");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setContentLengthLong(bytes.length);
        if (!"HEAD".equalsIgnoreCase(request.getMethod())) {
            response.getOutputStream().write(bytes);
        }
    }

    private void writePlayback(ResolvedTicket ticket,
                               HttpMediaCapture capture,
                               String originSourceUrl,
                               HttpServletRequest request,
                               HttpServletResponse response) throws IOException {
        try {
            PlaybackPlan plan = playbackService.plan(capture, request.getHeader(HttpHeaders.RANGE));
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
        } catch (MediaRangeException exception) {
            if (ticket.backfillMissing()) {
                redirectToOrigin(
                        ticket.capture(),
                        originSourceUrl,
                        response,
                        exception.getMessage());
                log.info("[media-playback] optional backfill captureId={} range={} reason={}",
                        capture.getId(), request.getHeader(HttpHeaders.RANGE), exception.getMessage());
            } else {
                writeCacheMiss(
                        response,
                        HttpStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                        exception.getMessage(),
                        exception.totalBytes());
                log.debug("[media-playback] cache miss captureId={} range={} reason={}",
                        capture.getId(), request.getHeader(HttpHeaders.RANGE), exception.getMessage());
            }
        }
    }

    private void redirectToOrigin(HttpMediaCapture capture,
                                  String sourceUrl,
                                  HttpServletResponse response,
                                  String reason) {
        String location = "/http/"
                + UriUtils.encodePathSegment(capture.getClientName(), StandardCharsets.UTF_8)
                + "/"
                + UriUtils.encodePathSegment(capture.getRoute(), StandardCharsets.UTF_8)
                + safeSourceUrl(sourceUrl);
        response.resetBuffer();
        response.setStatus(HttpStatus.TEMPORARY_REDIRECT.value());
        response.setHeader(HttpHeaders.LOCATION, location);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "private, no-store");
        response.setContentLengthLong(0);
        log.debug("[media-playback] redirecting optional backfill captureId={} reason={}",
                capture.getId(), reason);
    }

    private String safeSourceUrl(String sourceUrl) {
        String normalized = sourceUrl == null ? "/" : sourceUrl
                .replace("\r", "")
                .replace("\n", "")
                .trim();
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        try {
            return URI.create(normalized).toASCIIString();
        } catch (IllegalArgumentException ignored) {
            int queryIndex = normalized.indexOf('?');
            String path = queryIndex < 0 ? normalized : normalized.substring(0, queryIndex);
            String query = queryIndex < 0 ? "" : normalized.substring(queryIndex);
            return UriUtils.encodePath(path, StandardCharsets.UTF_8) + query;
        }
    }

    private void writeCacheMiss(HttpServletResponse response,
                                HttpStatus status,
                                String message,
                                long totalBytes) throws IOException {
        response.resetBuffer();
        response.setStatus(status.value());
        response.setHeader(HttpHeaders.ACCEPT_RANGES, "bytes");
        response.setHeader(HttpHeaders.CACHE_CONTROL, "private, no-store");
        if (status == HttpStatus.REQUESTED_RANGE_NOT_SATISFIABLE && totalBytes > 0) {
            response.setHeader(HttpHeaders.CONTENT_RANGE, "bytes */" + totalBytes);
        }
        byte[] bytes = message == null ? new byte[0] : message.getBytes(StandardCharsets.UTF_8);
        response.setContentType("text/plain;charset=UTF-8");
        response.setContentLengthLong(bytes.length);
        if (bytes.length > 0) {
            response.getOutputStream().write(bytes);
        }
    }

    private boolean isManifest(HttpMediaCapture capture) {
        return "HLS_MANIFEST".equals(capture.getMediaKind())
                || "DASH_MANIFEST".equals(capture.getMediaKind());
    }
}
