#ifndef SPECUS_TRAFFIC_CAPTURE_H
#define SPECUS_TRAFFIC_CAPTURE_H

#include <stddef.h>
#include <stdint.h>

/* Java specus.traffic.capture-preview-bytes defaults to 256; C caps it so previews fit its rows. */
#define ST_TRAFFIC_PREVIEW_BYTES_DEFAULT 256U
#define ST_TRAFFIC_PREVIEW_BYTES_MAX 1024U
/* "XX " per byte, and up to three UTF-8 bytes per preview character, with room to spare. */
#define ST_TRAFFIC_PREVIEW_HEX_CAP 4096U
#define ST_TRAFFIC_PREVIEW_TEXT_CAP 8192U

/*
 * Java specus.traffic.capture-detail-enabled (SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED, default
 * false): detail capture is off unless the server enables it, whatever a route or mapping says.
 */
int st_traffic_capture_enabled(void);

/* SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES, 0..ST_TRAFFIC_PREVIEW_BYTES_MAX, default 256. */
size_t st_traffic_preview_bytes(void);

/*
 * Java HttpBodyTypeClassifier.classify: empty, json, html, xml, image, video, audio, form,
 * script, text or binary, from the media type and the body size.
 */
const char *st_traffic_body_type(const char *content_type, long long body_bytes);

/* Java HttpBodyTypeClassifier.normalizeOrClassify: a stored supported type, else classify. */
const char *st_traffic_body_type_or_classify(const char *stored, const char *content_type, long long body_bytes);

/*
 * Java HttpBodyTypeClassifier.normalize: value trimmed and lower-cased when it is one of the
 * supported types, NULL otherwise (a blank or unknown responseBodyType filters nothing).
 */
const char *st_traffic_body_type_normalize(const char *value);

/* Java TrafficInspectionService.preview hex: the first preview_bytes bytes as "89 50 4E 47". */
void st_traffic_hex_preview(const uint8_t *data, size_t len, size_t preview_bytes, char *out, size_t out_len);

/*
 * Java TrafficInspectionService.preview text, used for TCP frames: the first preview_bytes bytes
 * read as UTF-8, with control characters (and both halves of a supplementary character) shown as
 * '.', malformed bytes as U+FFFD.
 */
void st_traffic_tcp_text_preview(const uint8_t *data, size_t len, size_t preview_bytes, char *out, size_t out_len);

/*
 * Java TrafficInspectionService.searchableBodyText, the HTTP body preview: the body decoded per
 * Content-Encoding (gzip, x-gzip, deflate, x-deflate; anything else, br included, leaves it as it
 * came), empty unless the media type is textual or the bytes look like text, then sanitized as
 * above and cut to preview_bytes characters (UTF-16 units, as Java counts).
 */
void st_traffic_http_text_preview(const uint8_t *data,
                                  size_t len,
                                  const char *content_type,
                                  const char *content_encoding,
                                  size_t preview_bytes,
                                  char *out,
                                  size_t out_len);

#endif
