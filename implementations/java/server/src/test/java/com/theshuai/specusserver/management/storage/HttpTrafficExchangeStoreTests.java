package com.theshuai.specusserver.management.storage;

import com.theshuai.specusserver.management.model.HttpTrafficExchange;
import com.theshuai.specusserver.management.model.HttpTrafficExchangeView;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HttpTrafficExchangeStoreTests {
    @Test
    void elasticsearchSummaryExcludesLargeAndDetailOnlyFields() {
        assertThat(SpringDataElasticsearchHttpTrafficExchangeStore.summarySourceFilter().getExcludes())
                .contains(
                        "requestBodyData",
                        "responseBodyData",
                        "requestHeaders",
                        "responseHeaders",
                        "requestPreviewHex",
                        "requestPreviewText",
                        "responsePreviewHex",
                        "responsePreviewText");
    }

    @Test
    void elasticsearchSummaryDoesNotEncodeBinaryBody() {
        HttpTrafficExchangeDocument document = new HttpTrafficExchangeDocument();
        document.setExchangeId(1_871_792_910_349_893_634L);
        document.setClientId(7L);
        byte[] pngSignature = {
                (byte) 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
        };
        document.setResponseBytes(pngSignature.length);
        document.setResponseContentType("image/png");
        document.setResponseBodyType("image");
        document.setResponseHeaders("Content-Type: image/png");
        document.setResponsePreviewHex("89504E47");
        document.setResponsePreviewText("fallback");
        document.setResponseBodyData(pngSignature);

        HttpTrafficExchangeView summary =
                SpringDataElasticsearchHttpTrafficExchangeStore.toView(document, false);
        HttpTrafficExchangeView detail =
                SpringDataElasticsearchHttpTrafficExchangeStore.toView(document, true);

        assertThat(summary.id()).isEqualTo("1871792910349893634");
        assertThat(summary.responseHeaders()).isNull();
        assertThat(summary.responsePreviewHex()).isNull();
        assertThat(summary.responsePreviewText()).isNull();
        assertThat(detail.responseHeaders()).isEqualTo("Content-Type: image/png");
        assertThat(detail.responsePreviewText()).startsWith("data:image/png;base64,");
    }

    @Test
    void jpaSummaryDoesNotReadOrEncodeBinaryBody() {
        HttpTrafficExchange exchange = new HttpTrafficExchange();
        exchange.setId(1_871_792_910_349_893_634L);
        exchange.setClientId(8L);
        exchange.setResponseBytes(4L);
        exchange.setResponseContentType("video/mp4");
        exchange.setResponseBodyType("video");
        exchange.setResponseHeaders("Content-Type: video/mp4");
        exchange.setResponsePreviewHex("00000018");
        exchange.setResponsePreviewText("fallback");
        exchange.setResponseBodyData(new byte[]{0, 0, 0, 0x18});

        HttpTrafficExchangeView summary = JpaHttpTrafficExchangeStore.toView(exchange, false);
        HttpTrafficExchangeView detail = JpaHttpTrafficExchangeStore.toView(exchange, true);

        assertThat(summary.id()).isEqualTo("1871792910349893634");
        assertThat(summary.responseHeaders()).isNull();
        assertThat(summary.responsePreviewHex()).isNull();
        assertThat(summary.responsePreviewText()).isNull();
        assertThat(detail.responseHeaders()).isEqualTo("Content-Type: video/mp4");
        assertThat(detail.responsePreviewText()).startsWith("data:video/mp4;base64,");
    }
}
