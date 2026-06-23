package com.theshuai.tunnelserver.management.storage;

import org.springframework.util.StringUtils;

import java.util.List;

public enum HttpTrafficSearchField {
    SUMMARY(
            "summary",
            List.of(
                    "clientName",
                    "route",
                    "resourceName",
                    "method",
                    "relativePath",
                    "rawQuery",
                    "error",
                    "remoteAddress",
                    "requestContentType",
                    "responseContentType",
                    "responseBodyType",
                    "capturedAt"),
            List.of(),
            List.of("resourceName", "relativePath", "rawQuery", "error"),
            List.of("clientName", "route", "method", "remoteAddress",
                    "requestContentType", "responseContentType", "responseBodyType", "capturedAt"),
            true,
            true,
            true,
            false),
    ALL(
            "all",
            List.of(
                    "clientName",
                    "route",
                    "resourceName",
                    "method",
                    "relativePath",
                    "rawQuery",
                    "error",
                    "remoteAddress",
                    "requestContentType",
                    "responseContentType",
                    "responseBodyType",
                    "requestHeaders",
                    "responseHeaders",
                    "capturedAt"),
            List.of("requestPreviewText", "responsePreviewText"),
            List.of("resourceName", "relativePath", "rawQuery", "error", "requestHeaders", "responseHeaders", "requestPreviewText", "responsePreviewText"),
            List.of("clientName", "route", "method", "remoteAddress",
                    "requestContentType", "responseContentType", "responseBodyType", "capturedAt"),
            true,
            true,
            true,
            true),
    ID("id", List.of(), List.of(), List.of(), List.of(), true, false, false, false),
    METHOD("method", List.of("method"), List.of(), List.of(), List.of("method"), false, false, false, false),
    STATUS("status", List.of(), List.of(), List.of(), List.of(), false, false, true, false),
    PATH("path", List.of("relativePath", "rawQuery"), List.of(), List.of("relativePath", "rawQuery"), List.of(), false, false, false, false),
    ROUTE("route", List.of("route"), List.of(), List.of(), List.of("route"), false, false, false, false),
    CLIENT("client", List.of("clientName"), List.of(), List.of(), List.of("clientName"), false, true, false, false),
    RESOURCE("resource", List.of("resourceName"), List.of(), List.of("resourceName"), List.of(), false, false, false, true),
    REMOTE("remote", List.of("remoteAddress"), List.of(), List.of(), List.of("remoteAddress"), false, false, false, false),
    CONTENT_TYPE(
            "contentType",
            List.of("requestContentType", "responseContentType", "responseBodyType"),
            List.of(),
            List.of(),
            List.of("requestContentType", "responseContentType", "responseBodyType"),
            false,
            false,
            false,
            false),
    ERROR("error", List.of("error"), List.of(), List.of("error"), List.of(), false, false, false, false),
    REQUEST_HEADERS("requestHeaders", List.of("requestHeaders"), List.of(), List.of("requestHeaders"), List.of(), false, false, false, false),
    RESPONSE_HEADERS("responseHeaders", List.of("responseHeaders"), List.of(), List.of("responseHeaders"), List.of(), false, false, false, false),
    REQUEST_BODY("requestBody", List.of(), List.of("requestPreviewText"), List.of("requestPreviewText"), List.of(), false, false, false, false),
    RESPONSE_BODY("responseBody", List.of(), List.of("responsePreviewText"), List.of("responsePreviewText"), List.of(), false, false, false, false);

    private final String code;
    private final List<String> jpaStringFields;
    private final List<String> jpaClobFields;
    private final List<String> elasticTextFields;
    private final List<String> elasticKeywordFields;
    private final boolean searchId;
    private final boolean searchClientId;
    private final boolean searchStatusCode;
    private final boolean searchResourceId;

    HttpTrafficSearchField(String code,
                           List<String> jpaStringFields,
                           List<String> jpaClobFields,
                           List<String> elasticTextFields,
                           List<String> elasticKeywordFields,
                           boolean searchId,
                           boolean searchClientId,
                           boolean searchStatusCode,
                           boolean searchResourceId) {
        this.code = code;
        this.jpaStringFields = jpaStringFields;
        this.jpaClobFields = jpaClobFields;
        this.elasticTextFields = elasticTextFields;
        this.elasticKeywordFields = elasticKeywordFields;
        this.searchId = searchId;
        this.searchClientId = searchClientId;
        this.searchStatusCode = searchStatusCode;
        this.searchResourceId = searchResourceId;
    }

    public static HttpTrafficSearchField fromCode(String code) {
        if (!StringUtils.hasText(code)) {
            return SUMMARY;
        }
        String normalized = code.trim();
        for (HttpTrafficSearchField field : values()) {
            if (field.code.equalsIgnoreCase(normalized) || field.name().equalsIgnoreCase(normalized)) {
                return field;
            }
        }
        return SUMMARY;
    }

    public String code() {
        return code;
    }

    public List<String> jpaStringFields() {
        return jpaStringFields;
    }

    public List<String> jpaClobFields() {
        return jpaClobFields;
    }

    public List<String> elasticTextFields() {
        return elasticTextFields;
    }

    public List<String> elasticKeywordFields() {
        return elasticKeywordFields;
    }

    public boolean searchId() {
        return searchId;
    }

    public boolean searchClientId() {
        return searchClientId;
    }

    public boolean searchStatusCode() {
        return searchStatusCode;
    }

    public boolean searchResourceId() {
        return searchResourceId;
    }
}
