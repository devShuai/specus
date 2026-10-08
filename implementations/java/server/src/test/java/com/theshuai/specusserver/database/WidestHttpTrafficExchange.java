package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.model.HttpTrafficExchange;
import com.theshuai.specusserver.management.tenant.TenantContext;

import java.util.Arrays;

/** An HTTP exchange with every string at its column's length, or at the capture cap for the headers. */
final class WidestHttpTrafficExchange {
    private WidestHttpTrafficExchange() {
    }

    static HttpTrafficExchange create() {
        HttpTrafficExchange exchange = new HttpTrafficExchange();
        exchange.setTenantId(TenantContext.DEFAULT_TENANT_ID);
        exchange.setClientId(1L);
        exchange.setClientName(text(120));
        exchange.setRoute(text(128));
        exchange.setResourceName(text(255));
        exchange.setMethod("GET");
        exchange.setRelativePath(text(1024));
        exchange.setRawQuery(text(2048));
        exchange.setStatusCode(200);
        exchange.setSuccess(true);
        exchange.setError(text(2048));
        exchange.setRemoteAddress(text(255));
        exchange.setRequestContentType(text(255));
        exchange.setResponseContentType(text(255));
        exchange.setResponseBodyType(text(32));
        // specus.traffic.capture-header-chars defaults to 8192.
        exchange.setRequestHeaders("X-Request: " + text(8192 - "X-Request: ".length()));
        exchange.setResponseHeaders("X-Response: " + text(8192 - "X-Response: ".length()));
        exchange.setRequestPreviewHex("0a".repeat(2048));
        exchange.setResponsePreviewHex("0d".repeat(2048));
        // Past the 65,535 bytes of a MySQL text or blob.
        exchange.setRequestBodyData(bytes(70_000));
        exchange.setResponseBodyData(bytes(70_000));
        exchange.setRequestPreviewText(text(70_000));
        exchange.setResponsePreviewText(text(70_000));
        exchange.setCapturedAt("2026-01-01T00:00:00Z");
        return exchange;
    }

    /** The capture caps count UTF-16 chars, and three UTF-8 bytes is the most a single one takes. */
    private static String text(int length) {
        return "界".repeat(length);
    }

    private static byte[] bytes(int length) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) 0x5a);
        return bytes;
    }
}
