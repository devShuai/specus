#include "client_address.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t bytes[16];
    size_t len;
} st_parsed_address;

static int address_copy_trimmed(const char *value, size_t value_len, char *out, size_t out_len)
{
    if (out == NULL || out_len == 0U) {
        return -1;
    }
    const char *source = value == NULL ? "" : value;
    const char *start = source;
    const char *end = source + value_len;
    while (start < end && isspace((unsigned char)*start)) {
        ++start;
    }
    while (end > start && isspace((unsigned char)end[-1])) {
        --end;
    }
    if (start == end) {
        out[0] = '\0';
        return 0;
    }
    if (*start == '[') {
        const char *closing = memchr(start + 1, ']', (size_t)(end - start - 1));
        if (closing != NULL) {
            ++start;
            end = closing;
        }
    } else {
        const char *first_colon = memchr(start, ':', (size_t)(end - start));
        const char *last_colon = NULL;
        for (const char *cursor = end; cursor > start; --cursor) {
            if (cursor[-1] == ':') {
                last_colon = cursor - 1;
                break;
            }
        }
        if (first_colon != NULL && first_colon == last_colon) {
            int numeric_port = last_colon + 1 < end;
            for (const char *cursor = last_colon + 1; numeric_port && cursor < end; ++cursor) {
                numeric_port = isdigit((unsigned char)*cursor);
            }
            if (numeric_port) {
                end = last_colon;
            }
        }
    }
    const char *scope = memchr(start, '%', (size_t)(end - start));
    if (scope != NULL && scope > start) {
        end = scope;
    }
    size_t len = (size_t)(end - start);
    if (len == 0U || len >= out_len) {
        out[0] = '\0';
        return -1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

static int address_normalize(const char *value, char *out, size_t out_len)
{
    return address_copy_trimmed(value, value == NULL ? 0U : strlen(value), out, out_len);
}

static int address_parse(const char *value, st_parsed_address *parsed)
{
    if (value == NULL || *value == '\0' || parsed == NULL) {
        return -1;
    }
    struct in_addr ipv4;
    if (inet_pton(AF_INET, value, &ipv4) == 1) {
        memcpy(parsed->bytes, &ipv4, sizeof(ipv4));
        parsed->len = sizeof(ipv4);
        return 0;
    }
    struct in6_addr ipv6;
    if (inet_pton(AF_INET6, value, &ipv6) == 1) {
        memcpy(parsed->bytes, &ipv6, sizeof(ipv6));
        parsed->len = sizeof(ipv6);
        return 0;
    }
    return -1;
}

static int address_cidr_contains(const char *cidr, const st_parsed_address *candidate)
{
    char normalized[128];
    if (address_normalize(cidr, normalized, sizeof(normalized)) != 0 || normalized[0] == '\0') {
        return 0;
    }
    char *slash = strchr(normalized, '/');
    int prefix = -1;
    if (slash != NULL) {
        *slash = '\0';
        char *number_end = NULL;
        long parsed_prefix = strtol(slash + 1, &number_end, 10);
        if (number_end == slash + 1 || *number_end != '\0' || parsed_prefix < 0 || parsed_prefix > 128) {
            return 0;
        }
        prefix = (int)parsed_prefix;
    }
    st_parsed_address network;
    if (address_parse(normalized, &network) != 0 || network.len != candidate->len) {
        return 0;
    }
    int max_prefix = (int)(network.len * 8U);
    if (prefix < 0) {
        prefix = max_prefix;
    }
    if (prefix > max_prefix) {
        return 0;
    }
    size_t full_bytes = (size_t)prefix / 8U;
    if (full_bytes > 0U && memcmp(network.bytes, candidate->bytes, full_bytes) != 0) {
        return 0;
    }
    unsigned int remaining_bits = (unsigned int)prefix % 8U;
    if (remaining_bits == 0U) {
        return 1;
    }
    uint8_t mask = (uint8_t)(0xffU << (8U - remaining_bits));
    return (network.bytes[full_bytes] & mask) == (candidate->bytes[full_bytes] & mask);
}

static int address_is_trusted(const char *address, const char *trusted_proxies)
{
    if (trusted_proxies == NULL || *trusted_proxies == '\0') {
        return 0;
    }
    st_parsed_address candidate;
    if (address_parse(address, &candidate) != 0) {
        return 0;
    }
    const char *cursor = trusted_proxies;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, ',');
        if (end == NULL) {
            end = cursor + strlen(cursor);
        }
        char cidr[128];
        size_t len = (size_t)(end - cursor);
        if (len < sizeof(cidr)) {
            memcpy(cidr, cursor, len);
            cidr[len] = '\0';
            if (address_cidr_contains(cidr, &candidate)) {
                return 1;
            }
        }
        cursor = *end == '\0' ? end : end + 1;
    }
    return 0;
}

static int address_copy_result(const char *value, char *out, size_t out_len)
{
    size_t len = strlen(value);
    if (len >= out_len) {
        return -1;
    }
    memcpy(out, value, len + 1U);
    return 0;
}

int st_client_address_resolve(const char *remote_address,
                              const char *forwarded_for,
                              const char *real_ip,
                              const char *trusted_proxies,
                              char *out,
                              size_t out_len)
{
    if (out == NULL || out_len == 0U) {
        return -1;
    }
    char peer[ST_CLIENT_ADDRESS_MAX_LEN];
    st_parsed_address peer_address;
    if (address_normalize(remote_address, peer, sizeof(peer)) != 0
        || address_parse(peer, &peer_address) != 0) {
        return address_copy_result("unknown", out, out_len);
    }
    if (!address_is_trusted(peer, trusted_proxies)) {
        return address_copy_result(peer, out, out_len);
    }

    if (forwarded_for != NULL && *forwarded_for != '\0') {
        const char *begin = forwarded_for;
        const char *end = forwarded_for + strlen(forwarded_for);
        while (end > begin) {
            const char *segment = end;
            while (segment > begin && segment[-1] != ',') {
                --segment;
            }
            char candidate[ST_CLIENT_ADDRESS_MAX_LEN];
            st_parsed_address parsed_candidate;
            if (address_copy_trimmed(segment,
                                     (size_t)(end - segment),
                                     candidate,
                                     sizeof(candidate)) == 0
                && address_parse(candidate, &parsed_candidate) == 0
                && !address_is_trusted(candidate, trusted_proxies)) {
                return address_copy_result(candidate, out, out_len);
            }
            if (segment == begin) {
                break;
            }
            end = segment - 1;
        }
    }

    char normalized_real_ip[ST_CLIENT_ADDRESS_MAX_LEN];
    st_parsed_address parsed_real_ip;
    if (address_normalize(real_ip, normalized_real_ip, sizeof(normalized_real_ip)) == 0
        && address_parse(normalized_real_ip, &parsed_real_ip) == 0) {
        return address_copy_result(normalized_real_ip, out, out_len);
    }
    return address_copy_result(peer, out, out_len);
}
