/*
 * Java TrafficInspectionServiceTests and HttpTrafficExchangeStoreTests for the C capture path:
 * the capture switch (off by default), the HTTP previews (gzip decoded, binary bodies without a
 * text preview, cut to the preview size), the body type classifier, TCP frames stored in full with
 * a short preview, the SQLite summary that neither reads nor returns headers, previews and bodies,
 * and the detail that shows a stored body as Java's HttpBodyDataCodec does.
 *
 * C keeps the first 64 KiB of each body where Java keeps all of it; requestTruncated and
 * responseTruncated say the body was longer than what was kept.
 */
#define _POSIX_C_SOURCE 200809L

#include "decompression_limits.h"
#include "storage.h"
#include "traffic_capture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

static int failures = 0;

#define EXPECT(condition, ...)                  \
    do {                                        \
        if (!(condition)) {                     \
            fprintf(stderr, __VA_ARGS__);       \
            fprintf(stderr, "\n");              \
            ++failures;                         \
        }                                       \
    } while (0)

/* window_bits 16 + MAX_WBITS for gzip, MAX_WBITS for zlib, -MAX_WBITS for raw deflate. */
static uint8_t *compress_with(const uint8_t *data, size_t len, int window_bits, size_t *out_len)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, window_bits, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return NULL;
    }
    size_t capacity = deflateBound(&stream, (uLong)len) + 32U;
    uint8_t *out = (uint8_t *)malloc(capacity);
    stream.next_in = (Bytef *)data;
    stream.avail_in = (uInt)len;
    stream.next_out = out;
    stream.avail_out = (uInt)capacity;
    int rc = out == NULL ? Z_MEM_ERROR : deflate(&stream, Z_FINISH);
    *out_len = capacity - stream.avail_out;
    deflateEnd(&stream);
    if (rc != Z_STREAM_END) {
        free(out);
        return NULL;
    }
    return out;
}

static void http_text(const char *name, const void *body, size_t len, const char *content_type,
                      const char *encoding, size_t preview_bytes, const char *expected)
{
    char text[ST_TRAFFIC_PREVIEW_TEXT_CAP];
    st_traffic_http_text_preview((const uint8_t *)body, len, content_type, encoding, preview_bytes,
                                 text, sizeof(text));
    EXPECT(strcmp(text, expected) == 0, "%s: text preview \"%s\", expected \"%s\"", name, text, expected);
}

static void test_capture_switch_and_preview_size(void)
{
    unsetenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED");
    EXPECT(!st_traffic_capture_enabled(), "detail capture must be off by default");
    setenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED", "false", 1);
    EXPECT(!st_traffic_capture_enabled(), "detail capture on with false");
    setenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED", "true", 1);
    EXPECT(st_traffic_capture_enabled(), "detail capture off with true");
    unsetenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED");

    static const struct {
        const char *value;
        size_t expected;
    } sizes[] = {{NULL, 256U}, {"8", 8U}, {"0", 0U}, {"-3", 0U}, {"4096", 1024U}, {"many", 256U}};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        if (sizes[i].value == NULL) unsetenv("SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES");
        else setenv("SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES", sizes[i].value, 1);
        EXPECT(st_traffic_preview_bytes() == sizes[i].expected, "preview bytes for %s: %zu",
               sizes[i].value == NULL ? "(unset)" : sizes[i].value, st_traffic_preview_bytes());
    }
    unsetenv("SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES");
}

/* httpBodiesAreStoredAsBinaryWithShortSearchPreview, gzipHttpBodyIsDecodedBeforeStored,
 * binaryHttpBodyIsStoredAsBinaryWithoutTextPreview and tcpPayloadIsStoredInFullWithShortPreviewOnly,
 * on the preview functions. */
static void test_java_preview_cases(void)
{
    size_t request_len = 36U * 4096U;
    char *request = (char *)malloc(request_len + 1U);
    for (size_t i = 0; request != NULL && i < 4096U; ++i) {
        memcpy(request + i * 36U, "0123456789abcdefghijklmnopqrstuvwxyz", 36U);
    }
    if (request != NULL) {
        http_text("long text request", request, request_len, "text/plain", NULL, 8U, "01234567");
        char hex[ST_TRAFFIC_PREVIEW_HEX_CAP];
        st_traffic_hex_preview((const uint8_t *)request, request_len, 8U, hex, sizeof(hex));
        EXPECT(strcmp(hex, "30 31 32 33 34 35 36 37") == 0, "request hex preview %s", hex);
    }
    free(request);
    http_text("long text response", "response-body-with-more-than-eight-bytes", 40U, "text/plain", NULL, 8U,
              "response");

    const char *json = "{\"ok\":true,\"message\":\"gzip response\"}";
    size_t gzip_len = 0U;
    uint8_t *gzip = compress_with((const uint8_t *)json, strlen(json), 16 + MAX_WBITS, &gzip_len);
    EXPECT(gzip != NULL, "gzip fixture failed");
    if (gzip != NULL) {
        http_text("gzip JSON, 8 characters", gzip, gzip_len, "application/json", "gzip", 8U, "{\"ok\":tr");
        http_text("gzip JSON, whole", gzip, gzip_len, "application/json", "gzip", 256U, json);
        http_text("x-gzip after identity", gzip, gzip_len, "application/json", "identity, x-gzip", 256U, json);
        char hex[ST_TRAFFIC_PREVIEW_HEX_CAP];
        st_traffic_hex_preview(gzip, gzip_len, 3U, hex, sizeof(hex));
        EXPECT(strcmp(hex, "1F 8B 08") == 0, "the hex preview shows the bytes as captured: %s", hex);
        /* A gzip body cut short is not decoded; JSON is textual, so its bytes are shown sanitized. */
        char cut[ST_TRAFFIC_PREVIEW_TEXT_CAP];
        st_traffic_http_text_preview(gzip, gzip_len / 2U, "application/json", "gzip", 256U, cut, sizeof(cut));
        EXPECT(strstr(cut, "gzip response") == NULL && cut[0] != '\0', "a truncated gzip body was decoded: %s", cut);
        /* An undecodable body of a non-text type that does not look like text has no preview. */
        http_text("gzip bytes as octet-stream", gzip, gzip_len, "application/octet-stream", NULL, 256U, "");
    }
    free(gzip);
    size_t zlib_len = 0U;
    size_t raw_len = 0U;
    uint8_t *zlib = compress_with((const uint8_t *)json, strlen(json), MAX_WBITS, &zlib_len);
    uint8_t *raw = compress_with((const uint8_t *)json, strlen(json), -MAX_WBITS, &raw_len);
    if (zlib != NULL && raw != NULL) {
        http_text("zlib deflate", zlib, zlib_len, "application/json", "deflate", 256U, json);
        http_text("raw deflate", raw, raw_len, "application/json", "Deflate", 256U, json);
    }
    free(zlib);
    free(raw);

    /* A decompression bomb only decodes what the preview needs: 10 MiB of zeros, 256 dots. */
    size_t zeros_len = 10U * 1024U * 1024U;
    uint8_t *zeros = (uint8_t *)calloc(1U, zeros_len);
    size_t bomb_len = 0U;
    uint8_t *bomb = zeros == NULL ? NULL : compress_with(zeros, zeros_len, 16 + MAX_WBITS, &bomb_len);
    free(zeros);
    if (bomb != NULL) {
        char expected[257];
        memset(expected, '.', 256U);
        expected[256] = '\0';
        http_text("gzip bomb", bomb, bomb_len, "text/plain", "gzip", 256U, expected);
    }
    free(bomb);

    static const uint8_t png[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    http_text("PNG", png, sizeof(png), "image/png;charset=UTF-8", NULL, 256U, "");
    EXPECT(strcmp(st_traffic_body_type("image/png;charset=UTF-8", (long long)sizeof(png)), "image") == 0,
           "PNG body type");
    char png_hex[ST_TRAFFIC_PREVIEW_HEX_CAP];
    st_traffic_hex_preview(png, sizeof(png), 256U, png_hex, sizeof(png_hex));
    EXPECT(strcmp(png_hex, "89 50 4E 47 0D 0A 1A 0A") == 0, "PNG hex %s", png_hex);
    /* No media type: text is still recognised by its bytes, a NUL makes it binary. */
    http_text("untyped text", "plain words", 11U, NULL, NULL, 256U, "plain words");
    http_text("untyped binary", "a\0b", 3U, "application/octet-stream", NULL, 256U, "");

    char tcp_text[ST_TRAFFIC_PREVIEW_TEXT_CAP];
    char tcp_hex[ST_TRAFFIC_PREVIEW_HEX_CAP];
    st_traffic_tcp_text_preview((const uint8_t *)"hello-tcp-payload", 17U, 4U, tcp_text, sizeof(tcp_text));
    st_traffic_hex_preview((const uint8_t *)"hello-tcp-payload", 17U, 4U, tcp_hex, sizeof(tcp_hex));
    EXPECT(strcmp(tcp_text, "hell") == 0 && strcmp(tcp_hex, "68 65 6C 6C") == 0, "TCP preview %s / %s",
           tcp_text, tcp_hex);
}

/* Java sanitizeText(new String(bytes, UTF_8)): text kept, controls and surrogate halves as '.'. */
static void test_text_sanitizing(void)
{
    http_text("Chinese text", "\xe4\xb8\xad\xe6\x96\x87", 6U, "text/plain", NULL, 256U, "\xe4\xb8\xad\xe6\x96\x87");
    http_text("controls", "a\x01" "b\r\n\tc\x7f", 8U, "text/plain", NULL, 256U, "a.b\r\n\tc.");
    http_text("C1 control", "x\xc2\x85y", 4U, "text/plain", NULL, 256U, "x.y");
    http_text("emoji", "a\xf0\x9f\x98\x80" "b", 6U, "text/plain", NULL, 256U, "a..b");
    http_text("emoji cut in half", "a\xf0\x9f\x98\x80" "b", 6U, "text/plain", NULL, 2U, "a.");
    http_text("emoji counted twice", "a\xf0\x9f\x98\x80" "b", 6U, "text/plain", NULL, 3U, "a..");
    http_text("malformed UTF-8", "a\xff" "b", 3U, "text/plain", NULL, 256U, "a\xef\xbf\xbd" "b");
    http_text("characters, not bytes", "\xe4\xb8\xad\xe6\x96\x87xyz", 9U, "text/plain", NULL, 3U,
              "\xe4\xb8\xad\xe6\x96\x87x");
    char tcp_text[ST_TRAFFIC_PREVIEW_TEXT_CAP];
    st_traffic_tcp_text_preview((const uint8_t *)"\xe4\xb8\xad\xe6\x96\x87", 6U, 4U, tcp_text, sizeof(tcp_text));
    EXPECT(strcmp(tcp_text, "\xe4\xb8\xad\xef\xbf\xbd") == 0, "TCP preview cuts bytes, then decodes: %s", tcp_text);
}

/* HttpBodyTypeClassifier.classify and normalizeOrClassify. */
static void test_body_types(void)
{
    static const struct {
        const char *content_type;
        long long bytes;
        const char *expected;
    } cases[] = {
        {"application/json", 0, "empty"},
        {NULL, 5, "binary"},
        {"", 5, "binary"},
        {"application/json; charset=UTF-8", 5, "json"},
        {"application/problem+json", 5, "json"},
        {"TEXT/HTML; charset=utf-8", 5, "html"},
        {"text/xml", 5, "xml"},
        {"image/svg+xml", 5, "xml"},
        {"image/webp", 5, "image"},
        {"video/mp4", 5, "video"},
        {"audio/ogg", 5, "audio"},
        {"application/x-www-form-urlencoded", 5, "form"},
        {"multipart/form-data; boundary=x", 5, "form"},
        {"text/javascript", 5, "script"},
        {"application/ecmascript", 5, "script"},
        {"text/css", 5, "text"},
        {"application/octet-stream", 5, "binary"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const char *actual = st_traffic_body_type(cases[i].content_type, cases[i].bytes);
        EXPECT(strcmp(actual, cases[i].expected) == 0, "body type of %s: %s, expected %s",
               cases[i].content_type == NULL ? "(null)" : cases[i].content_type, actual, cases[i].expected);
    }
    EXPECT(strcmp(st_traffic_body_type_or_classify(" JSON ", "text/plain", 5), "json") == 0, "stored JSON");
    EXPECT(strcmp(st_traffic_body_type_or_classify("unknown", "text/html", 5), "html") == 0, "stored unknown");
    EXPECT(strcmp(st_traffic_body_type_or_classify(NULL, "video/mp4", 5), "video") == 0, "nothing stored");
}

/*
 * The SQLite store: previews from the configured size, a gzip response decoded for its preview,
 * the summary list without headers and previews (HttpTrafficExchangeStoreTests), the detail with
 * them, and a TCP frame kept whole with a short preview.
 */
static void test_store(void)
{
    char path[] = "/tmp/specus_c_traffic_capture.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        ++failures;
        return;
    }
    close(fd);
    st_storage_client client;
    if (st_storage_init(path, 0) != 0
        || st_storage_upsert_client(path, 0, "tenant-a", "Demo", "alice", 1, 60, &client) != 0) {
        fprintf(stderr, "traffic store setup failed\n");
        ++failures;
        unlink(path);
        return;
    }
    const char *json = "{\"ok\":true,\"message\":\"gzip response\"}";
    size_t gzip_len = 0U;
    uint8_t *gzip = compress_with((const uint8_t *)json, strlen(json), 16 + MAX_WBITS, &gzip_len);
    setenv("SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES", "8", 1);
    st_storage_http_exchange_record record = {
        .tenant_id = "tenant-a",
        .client_id = client.id,
        .client_name = "Demo",
        .route = "api",
        .method = "GET",
        .relative_path = "/gzip",
        .status_code = 200,
        .success = 1,
        .request_bytes = 4,
        .response_bytes = (long long)gzip_len,
        .request_content_type = "text/plain",
        .response_content_type = "application/json",
        .request_headers = "Content-Type: text/plain",
        .response_headers = "Content-Type: application/json\nContent-Encoding: gzip",
        .request_body = (const uint8_t *)"ping",
        .request_body_len = 4U,
        .response_body = gzip,
        .response_body_len = gzip_len,
        .response_content_encoding = "gzip",
        .captured_at = "2026-10-07T00:00:00Z"
    };
    int recorded = gzip != NULL && st_storage_record_http_exchange(path, &record) == 0;
    unsetenv("SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES");
    EXPECT(recorded, "HTTP exchange record failed");

    st_storage_http_exchange *items = (st_storage_http_exchange *)calloc(2U, sizeof(*items));
    size_t count = 0U;
    long long total = 0;
    int listed = items != NULL
        && st_storage_list_http_exchanges_visible(path, 0, NULL, NULL, NULL, NULL, "tenant-a", "alice", 0, 0, 10,
                                                  items, 2U, &count, &total) == 0 && count == 1U;
    EXPECT(listed, "HTTP exchange summary list failed");
    if (listed) {
        st_storage_http_exchange *summary = &items[0];
        EXPECT(summary->request_headers[0] == '\0' && summary->response_headers[0] == '\0'
                   && summary->request_preview_hex[0] == '\0' && summary->request_preview_text[0] == '\0'
                   && summary->response_preview_hex[0] == '\0' && summary->response_preview_text[0] == '\0',
               "the summary read headers or previews");
        EXPECT(strcmp(summary->response_body_type, "json") == 0 && summary->response_bytes == (long long)gzip_len,
               "summary body type %s, %lld bytes", summary->response_body_type, summary->response_bytes);
        int found = 0;
        st_storage_http_exchange *detail = &items[1];
        EXPECT(st_storage_get_http_exchange_visible(path, summary->id, "tenant-a", "alice", 0, detail, &found) == 0
                   && found, "HTTP exchange detail lookup failed");
        if (found) {
            EXPECT(strcmp(detail->response_preview_text, "{\"ok\":tr") == 0, "gzip preview %s",
                   detail->response_preview_text);
            EXPECT(strncmp(detail->response_preview_hex, "1F 8B 08", 8U) == 0, "gzip hex %s",
                   detail->response_preview_hex);
            /* Both bodies were kept whole, so neither is truncated, however short the previews. */
            EXPECT(strcmp(detail->request_preview_text, "ping") == 0 && !detail->request_truncated
                       && !detail->response_truncated,
                   "request preview %s, truncated %d/%d", detail->request_preview_text, detail->request_truncated,
                   detail->response_truncated);
            EXPECT(strstr(detail->response_headers, "Content-Encoding: gzip") != NULL, "detail headers %s",
                   detail->response_headers);
            /* gzipHttpBodyIsDecodedBeforeStored: the stored body is the bytes as they came. */
            EXPECT(detail->response_body_data_len == gzip_len
                       && memcmp(detail->response_body_data, gzip, gzip_len) == 0
                       && detail->request_body_data_len == 4U && memcmp(detail->request_body_data, "ping", 4U) == 0,
                   "stored bodies: %zu response bytes of %zu, %zu request bytes", detail->response_body_data_len,
                   gzip_len, detail->request_body_data_len);
            st_storage_http_exchange_free_bodies(detail);
        }
        found = 1;
        EXPECT(st_storage_get_http_exchange_visible(path, summary->id, "tenant-a", "bob", 0, detail, &found) == 0
                   && !found, "another owner read the exchange");
        found = 1;
        EXPECT(st_storage_get_http_exchange_visible(path, summary->id, "tenant-b", "alice", 1, detail, &found) == 0
                   && !found, "another tenant read the exchange");
    }
    free(items);
    free(gzip);

    setenv("SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES", "4", 1);
    const uint8_t payload[] = "hello-tcp-payload";
    st_storage_tcp_frame_record frame_record = {
        .tenant_id = "tenant-a",
        .client_id = client.id,
        .client_name = "Demo",
        .listen_port = 8080,
        .channel_id = "channel-1",
        .direction = "PUBLIC_TO_CLIENT",
        .source_address = "127.0.0.1",
        .source_port = 60000,
        .destination_address = "127.0.0.1",
        .destination_port = 8080,
        .payload_data = payload,
        .payload_data_len = sizeof(payload) - 1U,
        .frame_time = "2026-10-07T00:00:01Z"
    };
    recorded = st_storage_record_tcp_frame(path, &frame_record) == 0;
    unsetenv("SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES");
    st_storage_tcp_frame frames[1];
    memset(frames, 0, sizeof(frames));
    count = 0U;
    EXPECT(recorded && st_storage_list_tcp_frames_visible(path, 0, ST_STORAGE_ANY_LISTEN_PORT, "tenant-a", "alice", 0,
                                                          0, 10, frames, 1U, &count, &total) == 0 && count == 1U,
           "TCP frame record or list failed");
    if (count == 1U) {
        st_storage_tcp_frame frame;
        memset(&frame, 0, sizeof(frame));
        EXPECT(st_storage_get_tcp_frame_visible(path, frames[0].id, "tenant-a", "alice", 0, &frame) == 0
                   && frame.payload_data_len == sizeof(payload) - 1U
                   && memcmp(frame.payload_data, payload, sizeof(payload) - 1U) == 0
                   && frame.payload_bytes == (long long)(sizeof(payload) - 1U)
                   && strcmp(frame.payload_preview_text, "hell") == 0
                   && strcmp(frame.payload_preview_hex, "68 65 6C 6C") == 0 && !frame.truncated
                   && frame.stream_offset == 0 && frame.stream_end_offset == (long long)(sizeof(payload) - 1U)
                   && frame.frame_index == 0 && frame.source_port == 60000 && frame.destination_port == 8080,
               "TCP frame detail: %lld bytes, preview %s / %s, truncated %d", frame.payload_bytes,
               frame.payload_preview_text, frame.payload_preview_hex, frame.truncated);
        st_storage_tcp_frame_free(&frame);
    }
    for (size_t i = 0; i < count; ++i) st_storage_tcp_frame_free(&frames[i]);
    unlink(path);
}

static void display(const char *name, const void *body, size_t len, const char *content_type,
                    const char *headers, const char *fallback, const char *expected)
{
    char *text = st_traffic_body_display_text((const uint8_t *)body, len, content_type, headers, fallback);
    EXPECT(text != NULL && strcmp(text, expected) == 0, "%s: display text \"%s\", expected \"%s\"", name,
           text == NULL ? "(null)" : text, expected);
    free(text);
}

/*
 * HttpBodyDataCodec.toDisplayText, the detail's view of a stored body (HttpTrafficExchangeStoreTests
 * binary bodies as data: URLs): text is shown whole and sanitized whatever the preview size, a
 * binary body as data:<media type>;base64, a Content-Encoding decoded first, and an encoding that
 * cannot be decoded as the raw bytes under application/octet-stream.
 */
static void test_body_display(void)
{
    static const uint8_t png[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    static const uint8_t mp4[] = {0x00, 0x00, 0x00, 0x18};
    display("PNG", png, sizeof(png), "image/png", "Content-Type: image/png", "fallback",
            "data:image/png;base64,iVBORw0KGgo=");
    display("PNG with parameters", png, sizeof(png), "image/png;charset=UTF-8", "", "",
            "data:image/png;base64,iVBORw0KGgo=");
    display("MP4", mp4, sizeof(mp4), "video/mp4", "Content-Type: video/mp4", "fallback",
            "data:video/mp4;base64,AAAAGA==");
    display("binary without a type", png, sizeof(png), NULL, NULL, "",
            "data:application/octet-stream;base64,iVBORw0KGgo=");
    display("binary with a malformed type", png, sizeof(png), "not a type", NULL, "",
            "data:application/octet-stream;base64,iVBORw0KGgo=");
    display("nothing stored", NULL, 0U, "text/plain", "", "fallback", "fallback");
    display("text, longer than any preview", "0123456789abcdefghij", 20U, "text/plain", "", "0123",
            "0123456789abcdefghij");
    display("text sniffed without a type", "plain words\r\n", 13U, NULL, "", "", "plain words\r\n");
    display("controls in text", "a\x01" "b", 3U, "text/plain", "", "", "a.b");

    const char *json = "{\"ok\":true,\"message\":\"gzip response\"}";
    size_t gzip_len = 0U;
    size_t deflate_len = 0U;
    uint8_t *gzip = compress_with((const uint8_t *)json, strlen(json), 16 + MAX_WBITS, &gzip_len);
    uint8_t *raw_deflate = compress_with((const uint8_t *)json, strlen(json), -MAX_WBITS, &deflate_len);
    EXPECT(gzip != NULL && raw_deflate != NULL, "compression failed");
    if (gzip != NULL && raw_deflate != NULL) {
        display("gzip", gzip, gzip_len, "application/json",
                "Content-Type: application/json\nContent-Encoding: gzip", "", json);
        display("raw deflate, header name in any case", raw_deflate, deflate_len, "application/json",
                "content-encoding:  deflate ", "", json);
        display("identity only", json, strlen(json), "application/json", "Content-Encoding: identity", "", json);
        if (!st_decompression_brotli_supported()) {
            /* Without libbrotlidec br is an encoding C cannot undo: the raw bytes as octet-stream. */
            char *unreadable = st_traffic_body_display_text(gzip, gzip_len, "application/json",
                                                            "Content-Encoding: br", "");
            EXPECT(unreadable != NULL
                       && strncmp(unreadable, "data:application/octet-stream;base64,H4sI", 41U) == 0,
                   "br without libbrotlidec must show the raw bytes as octet-stream: %s",
                   unreadable == NULL ? "(null)" : unreadable);
            free(unreadable);
        }
        /*
         * A real br body (RFC 7932 by hand: one uncompressed meta-block holding "hello brotli"):
         * decoded like Java's org.brotli:dec when the build has libbrotlidec, else shown as stored.
         */
        static const uint8_t brotli[] = {
            0xB0U, 0x00U, 0x10U, 'h', 'e', 'l', 'l', 'o', ' ', 'b', 'r', 'o', 't', 'l', 'i', 0x03U
        };
        if (st_decompression_brotli_supported()) {
            display("br", brotli, sizeof(brotli), "text/plain", "Content-Encoding: br", "", "hello brotli");
            http_text("br preview", brotli, sizeof(brotli), "text/plain", "br", 5U, "hello");
        } else {
            display("br without libbrotlidec", brotli, sizeof(brotli), "text/plain", "Content-Encoding: br", "",
                    "data:application/octet-stream;base64,sAAQaGVsbG8gYnJvdGxpAw==");
        }
        uint8_t corrupt[8] = {0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef};
        display("corrupt gzip", corrupt, sizeof(corrupt), "application/json", "Content-Encoding: gzip", "",
                "data:application/octet-stream;base64,H4sIAN6tvu8=");
    }
    free(gzip);
    free(raw_deflate);
}

/*
 * TrafficInspectionServiceTests.httpBodiesAreStoredAsBinaryWithShortSearchPreview and
 * binaryHttpBodyIsStoredAsBinaryWithoutTextPreview on the SQLite store: the bodies are kept (the
 * first 64 KiB of a longer one, then truncated), the previews stay short, a PNG response has no
 * text preview and its detail is a data: URL; the summary list carries no body.
 */
static void test_stored_bodies(void)
{
    char path[] = "/tmp/specus_c_traffic_bodies.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        ++failures;
        return;
    }
    close(fd);
    st_storage_client client;
    if (st_storage_init(path, 0) != 0
        || st_storage_upsert_client(path, 0, "tenant-a", "Demo", "alice", 1, 60, &client) != 0) {
        ++failures;
        unlink(path);
        return;
    }
    size_t request_len = 36U * 4096U;
    uint8_t *request_body = (uint8_t *)malloc(request_len);
    for (size_t i = 0; request_body != NULL && i < request_len; ++i) {
        request_body[i] = (uint8_t)"0123456789abcdefghijklmnopqrstuvwxyz"[i % 36U];
    }
    static const uint8_t png[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    setenv("SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES", "8", 1);
    st_storage_http_exchange_record record = {
        .tenant_id = "tenant-a",
        .client_id = client.id,
        .client_name = "Demo",
        .route = "api",
        .method = "POST",
        .relative_path = "/orders",
        .status_code = 200,
        .success = 1,
        .request_bytes = (long long)request_len,
        .response_bytes = (long long)sizeof(png),
        .request_content_type = "text/plain",
        .response_content_type = "image/png;charset=UTF-8",
        .request_headers = "Content-Type: text/plain",
        .response_headers = "Content-Type: image/png;charset=UTF-8",
        .request_body = request_body,
        .request_body_len = request_len,
        .response_body = png,
        .response_body_len = sizeof(png),
        .captured_at = "2026-10-07T00:00:00Z"
    };
    int recorded = request_body != NULL && st_storage_record_http_exchange(path, &record) == 0;
    unsetenv("SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES");
    EXPECT(recorded, "HTTP exchange with bodies was not recorded");

    st_storage_http_exchange *items = (st_storage_http_exchange *)calloc(2U, sizeof(*items));
    size_t count = 0U;
    long long total = 0;
    int listed = recorded && items != NULL
        && st_storage_list_http_exchanges_visible(path, 0, NULL, NULL, NULL, NULL, "tenant-a", "alice", 0, 0, 10,
                                                  items, 2U, &count, &total) == 0 && count == 1U;
    EXPECT(listed, "HTTP exchange list failed");
    if (listed) {
        EXPECT(items[0].request_body_data == NULL && items[0].response_body_data == NULL,
               "the summary list read the bodies");
        int found = 0;
        st_storage_http_exchange *detail = &items[1];
        EXPECT(st_storage_get_http_exchange_visible(path, items[0].id, "tenant-a", "alice", 0, detail, &found) == 0
                   && found, "detail lookup failed");
        if (found) {
            EXPECT(detail->request_body_data_len == ST_TRAFFIC_BODY_CAPTURE_BYTES
                       && memcmp(detail->request_body_data, request_body, ST_TRAFFIC_BODY_CAPTURE_BYTES) == 0
                       && detail->request_bytes == (long long)request_len && detail->request_truncated,
                   "request body: %zu bytes kept of %lld, truncated %d", detail->request_body_data_len,
                   detail->request_bytes, detail->request_truncated);
            EXPECT(strcmp(detail->request_preview_text, "01234567") == 0, "request preview %s",
                   detail->request_preview_text);
            EXPECT(detail->response_body_data_len == sizeof(png)
                       && memcmp(detail->response_body_data, png, sizeof(png)) == 0 && !detail->response_truncated
                       && detail->response_preview_text[0] == '\0'
                       && strcmp(detail->response_body_type, "image") == 0,
                   "PNG response: %zu bytes, truncated %d, preview \"%s\", type %s", detail->response_body_data_len,
                   detail->response_truncated, detail->response_preview_text, detail->response_body_type);
            char *shown = st_traffic_body_display_text(detail->response_body_data, detail->response_body_data_len,
                                                       detail->response_content_type, detail->response_headers,
                                                       detail->response_preview_text);
            EXPECT(shown != NULL && strcmp(shown, "data:image/png;base64,iVBORw0KGgo=") == 0, "PNG detail %s",
                   shown == NULL ? "(null)" : shown);
            free(shown);
            st_storage_http_exchange_free_bodies(detail);
        }
    }
    free(items);
    free(request_body);
    unlink(path);
}

int main(void)
{
    test_capture_switch_and_preview_size();
    test_java_preview_cases();
    test_text_sanitizing();
    test_body_types();
    test_store();
    test_body_display();
    test_stored_bodies();
    if (failures != 0) {
        fprintf(stderr, "%d traffic capture check(s) failed\n", failures);
        return 1;
    }
    printf("traffic capture tests passed\n");
    return 0;
}
