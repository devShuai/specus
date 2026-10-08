#include "peer_egress.h"

#include "json.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *const ST_EGRESS_FORCED_DENY_CIDRS[] = {
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    /* Covered by 240.0.0.0/4, listed so the broadcast address is explicit to a reader. */
    "255.255.255.255/32",
};
const size_t ST_EGRESS_FORCED_DENY_CIDRS_LEN =
    sizeof(ST_EGRESS_FORCED_DENY_CIDRS) / sizeof(ST_EGRESS_FORCED_DENY_CIDRS[0]);

const char *const ST_EGRESS_CLOUD_METADATA_CIDRS[] = {
    "169.254.169.254/32",
    "100.100.100.200/32",
};
const size_t ST_EGRESS_CLOUD_METADATA_CIDRS_LEN =
    sizeof(ST_EGRESS_CLOUD_METADATA_CIDRS) / sizeof(ST_EGRESS_CLOUD_METADATA_CIDRS[0]);

const char *const ST_EGRESS_LAN_CIDRS[] = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
};
const size_t ST_EGRESS_LAN_CIDRS_LEN =
    sizeof(ST_EGRESS_LAN_CIDRS) / sizeof(ST_EGRESS_LAN_CIDRS[0]);

const char *const ST_EGRESS_FORCED_DENY_CIDRS6[] = {
    "::/128",
    "::1/128",
    /* A socket connected to an IPv4-mapped address reaches the IPv4 address, past every IPv4 entry. */
    "::ffff:0:0/96",
    /*
     * Prefixes that embed an IPv4 address a NAT64 gateway or a 6to4 relay forwards to, metadata and
     * private ranges included.
     */
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "2002::/16",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
};
const size_t ST_EGRESS_FORCED_DENY_CIDRS6_LEN =
    sizeof(ST_EGRESS_FORCED_DENY_CIDRS6) / sizeof(ST_EGRESS_FORCED_DENY_CIDRS6[0]);

/* The IPv6 instance metadata endpoint, in the unique local range a LAN policy can grant. */
const char *const ST_EGRESS_CLOUD_METADATA_CIDRS6[] = {
    "fd00:ec2::254/128",
};
const size_t ST_EGRESS_CLOUD_METADATA_CIDRS6_LEN =
    sizeof(ST_EGRESS_CLOUD_METADATA_CIDRS6) / sizeof(ST_EGRESS_CLOUD_METADATA_CIDRS6[0]);

/* Unique local addresses, the IPv6 counterpart of the private ranges. */
const char *const ST_EGRESS_LAN_CIDRS6[] = {
    "fc00::/7",
};
const size_t ST_EGRESS_LAN_CIDRS6_LEN =
    sizeof(ST_EGRESS_LAN_CIDRS6) / sizeof(ST_EGRESS_LAN_CIDRS6[0]);

const char *const ST_EGRESS_ALL_CODES[] = {
    ST_EGRESS_CODE_ALLOWED,
    ST_EGRESS_CODE_HOP_NOT_ALLOWED, ST_EGRESS_CODE_DISABLED, ST_EGRESS_CODE_PEER_ACL_DENIED,
    ST_EGRESS_CODE_CONSUMER_DENIED, ST_EGRESS_CODE_FORBIDDEN_DESTINATION, ST_EGRESS_CODE_SCOPE_DENIED,
    ST_EGRESS_CODE_DEST_DENIED, ST_EGRESS_CODE_PROTOCOL_DENIED, ST_EGRESS_CODE_PORT_DENIED,
    ST_EGRESS_CODE_LIMIT_EXCEEDED,
    ST_EGRESS_CODE_RULE_DOMAIN_UNSUPPORTED, ST_EGRESS_CODE_RULE_IPV6_UNSUPPORTED,
    ST_EGRESS_CODE_RULE_MALFORMED, ST_EGRESS_CODE_RULE_MISSING_TARGET,
    ST_EGRESS_CODE_RULE_MESH_OVERLAP, ST_EGRESS_CODE_RULE_DEFAULT_ROUTE,
    ST_EGRESS_CODE_RULE_PORT_UNSUPPORTED, ST_EGRESS_CODE_RULE_DISABLED,
    ST_EGRESS_CODE_CONSUMER_DISABLED,
    ST_EGRESS_CODE_FRAME_BAD_MAGIC, ST_EGRESS_CODE_FRAME_UNKNOWN_TYPE,
    ST_EGRESS_CODE_FRAME_RESERVED_SET, ST_EGRESS_CODE_FRAME_TRUNCATED,
    ST_EGRESS_CODE_FRAME_TRAILING_BYTES, ST_EGRESS_CODE_IPV6_UNSUPPORTED,
    ST_EGRESS_CODE_FRAME_MALFORMED_CONTROL, ST_EGRESS_CODE_CONTROL_UNSUPPORTED,
    ST_EGRESS_CODE_NAME_UNRESOLVED, ST_EGRESS_CODE_NAME_UNSUPPORTED,
    ST_EGRESS_CODE_RULE_FAKE_IP_OVERLAP, ST_EGRESS_CODE_FAKE_IP_POOL_INVALID,
    ST_EGRESS_CODE_RULE_EGRESS_NO_DOMAIN,
};
const size_t ST_EGRESS_ALL_CODES_LEN =
    sizeof(ST_EGRESS_ALL_CODES) / sizeof(ST_EGRESS_ALL_CODES[0]);

int st_egress_is_known_code(const char *code)
{
    if (code == NULL) {
        return 0;
    }
    for (size_t i = 0U; i < ST_EGRESS_ALL_CODES_LEN; ++i) {
        if (strcmp(ST_EGRESS_ALL_CODES[i], code) == 0) {
            return 1;
        }
    }
    return 0;
}

static uint32_t mask_for(int prefix_length)
{
    if (prefix_length <= 0) {
        return 0U;
    }
    if (prefix_length >= ST_EGRESS_MAX_PREFIX) {
        return 0xFFFFFFFFU;
    }
    return 0xFFFFFFFFU << (ST_EGRESS_MAX_PREFIX - prefix_length);
}

static void copy_bounded(char *dest, size_t dest_len, const char *value)
{
    if (dest_len == 0U) {
        return;
    }
    if (value == NULL) {
        dest[0] = '\0';
        return;
    }
    size_t len = strlen(value);
    if (len >= dest_len) {
        len = dest_len - 1U;
    }
    memcpy(dest, value, len);
    dest[len] = '\0';
}

/* Trims ASCII spaces and tabs from both ends into a caller-supplied buffer. */
static void trim_into(char *dest, size_t dest_len, const char *value)
{
    if (dest_len == 0U) {
        return;
    }
    dest[0] = '\0';
    if (value == NULL) {
        return;
    }
    while (*value == ' ' || *value == '\t' || *value == '\n' || *value == '\r') {
        value++;
    }
    size_t len = strlen(value);
    while (len > 0U
           && (value[len - 1U] == ' ' || value[len - 1U] == '\t'
               || value[len - 1U] == '\n' || value[len - 1U] == '\r')) {
        len--;
    }
    if (len >= dest_len) {
        len = dest_len - 1U;
    }
    memcpy(dest, value, len);
    dest[len] = '\0';
}

int st_egress_parse_address(const char *text, uint32_t *out)
{
    if (text == NULL || out == NULL) {
        return 1;
    }
    uint32_t value = 0U;
    int octets = 0;
    size_t start = 0U;
    size_t length = strlen(text);
    for (size_t i = 0U; i <= length; i++) {
        if (i != length && text[i] != '.') {
            continue;
        }
        size_t digits = i - start;
        if (digits < 1U || digits > 3U || octets > 3) {
            return 1;
        }
        /*
         * A leading zero is rejected rather than tolerated: runtimes disagree about whether 010 is
         * decimal ten or octal eight, and a rule whose meaning depends on the runtime is worse than
         * one the operator has to rewrite.
         */
        if (digits > 1U && text[start] == '0') {
            return 1;
        }
        int part = 0;
        for (size_t j = start; j < i; j++) {
            char c = text[j];
            if (c < '0' || c > '9') {
                return 1;
            }
            part = (part * 10) + (c - '0');
        }
        if (part > 255) {
            return 1;
        }
        value = (value << 8) | (uint32_t)part;
        octets++;
        start = i + 1U;
    }
    if (octets != 4) {
        return 1;
    }
    *out = value;
    return 0;
}

int st_egress_parse_cidr(const char *text, st_egress_cidr *out)
{
    if (text == NULL || out == NULL) {
        return 1;
    }
    char trimmed[160];
    trim_into(trimmed, sizeof(trimmed), text);
    if (trimmed[0] == '\0') {
        return 1;
    }
    char *slash = strchr(trimmed, '/');
    if (slash == NULL) {
        uint32_t address = 0U;
        if (st_egress_parse_address(trimmed, &address) != 0) {
            return 1;
        }
        out->network = address;
        out->prefix_length = ST_EGRESS_MAX_PREFIX;
        return 0;
    }
    *slash = '\0';
    const char *prefix_part = slash + 1;
    uint32_t address = 0U;
    if (st_egress_parse_address(trimmed, &address) != 0) {
        return 1;
    }
    size_t prefix_len = strlen(prefix_part);
    if (prefix_len == 0U || prefix_len > 2U) {
        return 1;
    }
    if (prefix_len > 1U && prefix_part[0] == '0') {
        return 1;
    }
    int prefix = 0;
    for (size_t i = 0U; i < prefix_len; i++) {
        char c = prefix_part[i];
        if (c < '0' || c > '9') {
            return 1;
        }
        prefix = (prefix * 10) + (c - '0');
    }
    if (prefix > ST_EGRESS_MAX_PREFIX) {
        return 1;
    }
    /* Host bits set means the operator wrote something other than what they meant. */
    if ((address & ~mask_for(prefix)) != 0U) {
        return 1;
    }
    out->network = address;
    out->prefix_length = prefix;
    return 0;
}

void st_egress_format_address(uint32_t value, char *out, size_t out_len)
{
    if (out == NULL || out_len == 0U) {
        return;
    }
    snprintf(out, out_len, "%u.%u.%u.%u",
             (unsigned)((value >> 24) & 0xFFU),
             (unsigned)((value >> 16) & 0xFFU),
             (unsigned)((value >> 8) & 0xFFU),
             (unsigned)(value & 0xFFU));
}

int st_egress_cidr_contains(const st_egress_cidr *cidr, uint32_t address)
{
    if (cidr == NULL) {
        return 0;
    }
    uint32_t mask = mask_for(cidr->prefix_length);
    return (address & mask) == (cidr->network & mask);
}

int st_egress_cidr_overlaps(const st_egress_cidr *left, const st_egress_cidr *right)
{
    if (left == NULL || right == NULL) {
        return 0;
    }
    int shared = left->prefix_length < right->prefix_length ? left->prefix_length : right->prefix_length;
    uint32_t mask = mask_for(shared);
    return (left->network & mask) == (right->network & mask);
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Colon-separated groups of one to four hex digits; an empty span is no groups. Returns 0 on success. */
static int hex_groups(const char *text, size_t len, uint16_t *groups, size_t *count)
{
    *count = 0U;
    if (len == 0U) {
        return 0;
    }
    size_t start = 0U;
    for (size_t i = 0U; i <= len; i++) {
        if (i != len && text[i] != ':') {
            continue;
        }
        size_t digits = i - start;
        if (digits < 1U || digits > 4U || *count >= 8U) {
            return 1;
        }
        uint16_t value = 0U;
        for (size_t j = start; j < i; j++) {
            value = (uint16_t)((value << 4) | (uint16_t)hex_value(text[j]));
        }
        groups[(*count)++] = value;
        start = i + 1U;
    }
    return 0;
}

int st_egress_parse_address6(const char *text, uint8_t out[16])
{
    if (text == NULL || out == NULL) {
        return 1;
    }
    size_t length = strlen(text);
    if (length == 0U || length > 39U) {
        return 1;
    }
    for (size_t i = 0U; i < length; i++) {
        if (hex_value(text[i]) < 0 && text[i] != ':') {
            return 1;
        }
    }
    if (strstr(text, ":::") != NULL) {
        return 1;
    }
    const char *compressed = strstr(text, "::");
    if (compressed != NULL && strstr(compressed + 1, "::") != NULL) {
        return 1;
    }
    uint16_t groups[8] = {0};
    if (compressed != NULL) {
        uint16_t high[8];
        uint16_t low[8];
        size_t high_len = 0U;
        size_t low_len = 0U;
        size_t head = (size_t)(compressed - text);
        if (hex_groups(text, head, high, &high_len) != 0
            || hex_groups(compressed + 2, length - head - 2U, low, &low_len) != 0
            || high_len + low_len > 7U) {
            return 1;
        }
        for (size_t i = 0U; i < high_len; i++) {
            groups[i] = high[i];
        }
        for (size_t i = 0U; i < low_len; i++) {
            groups[8U - low_len + i] = low[i];
        }
    } else {
        size_t count = 0U;
        if (hex_groups(text, length, groups, &count) != 0 || count != 8U) {
            return 1;
        }
    }
    for (size_t i = 0U; i < 8U; i++) {
        out[2U * i] = (uint8_t)(groups[i] >> 8);
        out[2U * i + 1U] = (uint8_t)(groups[i] & 0xFFU);
    }
    return 0;
}

int st_egress_parse_cidr6(const char *text, st_egress_cidr6 *out, int *had_length)
{
    if (text == NULL || out == NULL) {
        return 1;
    }
    char buffer[64];
    size_t length = strlen(text);
    if (length >= sizeof(buffer)) {
        return 1;
    }
    memcpy(buffer, text, length + 1U);
    char *slash = strchr(buffer, '/');
    uint8_t address[16];
    int prefix = ST_EGRESS_MAX_PREFIX6;
    if (slash != NULL) {
        *slash = '\0';
        const char *prefix_part = slash + 1;
        size_t prefix_len = strlen(prefix_part);
        if (prefix_len == 0U || prefix_len > 3U || (prefix_len > 1U && prefix_part[0] == '0')) {
            return 1;
        }
        prefix = 0;
        for (size_t i = 0U; i < prefix_len; i++) {
            if (prefix_part[i] < '0' || prefix_part[i] > '9') {
                return 1;
            }
            prefix = (prefix * 10) + (prefix_part[i] - '0');
        }
        if (prefix > ST_EGRESS_MAX_PREFIX6) {
            return 1;
        }
    }
    if (st_egress_parse_address6(buffer, address) != 0) {
        return 1;
    }
    /* Host bits set: refused rather than masked, as for IPv4. */
    for (int i = 0; i < 16; i++) {
        int bits = prefix - (i * 8);
        unsigned mask = bits >= 8 ? 0xFFU : (bits <= 0 ? 0U : ((0xFFU << (8 - bits)) & 0xFFU));
        if (((unsigned)address[i] & ~mask) != 0U) {
            return 1;
        }
    }
    memcpy(out->network, address, sizeof(address));
    out->prefix_length = prefix;
    if (had_length != NULL) {
        *had_length = slash != NULL;
    }
    return 0;
}

void st_egress_format_address6(const uint8_t address[16], char *out, size_t out_len)
{
    if (address == NULL || out == NULL || out_len == 0U) {
        return;
    }
    unsigned groups[8];
    for (int i = 0; i < 8; i++) {
        groups[i] = ((unsigned)address[2 * i] << 8) | address[2 * i + 1];
    }
    int best_start = -1;
    int best_length = 0;
    for (int i = 0; i < 8;) {
        if (groups[i] != 0U) {
            i++;
            continue;
        }
        int end = i;
        while (end < 8 && groups[end] == 0U) {
            end++;
        }
        if (end - i > best_length) {
            best_start = i;
            best_length = end - i;
        }
        i = end;
    }
    if (best_length < 2) {
        best_start = -1;
    }
    size_t used = 0U;
    out[0] = '\0';
    for (int i = 0; i < 8; i++) {
        if (i == best_start) {
            used += (size_t)snprintf(out + used, out_len - used, "::");
            i += best_length - 1;
            continue;
        }
        int after_gap = best_start >= 0 && i == best_start + best_length;
        used += (size_t)snprintf(out + used, out_len - used, "%s%x", (i == 0 || after_gap) ? "" : ":", groups[i]);
        if (used >= out_len) {
            return;
        }
    }
}

int st_egress_cidr6_mapped(const st_egress_cidr6 *cidr)
{
    if (cidr == NULL) {
        return 0;
    }
    for (int i = 0; i < 10; i++) {
        if (cidr->network[i] != 0U) {
            return 0;
        }
    }
    return cidr->network[10] == 0xFFU && cidr->network[11] == 0xFFU;
}

int st_egress_normalize_version(int version)
{
    if (version < 1) {
        return 0;
    }
    return version > ST_EGRESS_PROTOCOL_VERSION ? ST_EGRESS_PROTOCOL_VERSION : version;
}

int st_egress_declares_domain_targets(const char *capabilities_json, int version)
{
    int declared = 0;
    if (capabilities_json == NULL || version < 1
        || st_json_get_bool(capabilities_json, "domainTargetCapable", &declared) != 0) {
        return 0;
    }
    return declared ? 1 : 0;
}

static const char *validate_rule_target(const st_egress_rule *rule);

/* Anything outside digits, dots and the prefix separator is treated as a name. */
static int looks_like_domain(const char *match)
{
    for (const char *p = match; *p != '\0'; p++) {
        if ((*p >= '0' && *p <= '9') || *p == '.' || *p == '/') {
            continue;
        }
        return 1;
    }
    return 0;
}

const char *st_egress_validate_rule(const st_egress_rule *rule, const char *mesh_cidr)
{
    if (rule == NULL) {
        return ST_EGRESS_CODE_RULE_MALFORMED;
    }
    /* Ahead of anything about the rule's content: a switched-off rule is the user's choice, and
     * should not have to be fixed before it may sit in the list. */
    if (rule->switched_off) {
        return ST_EGRESS_CODE_RULE_DISABLED;
    }
    char match[sizeof(rule->match)];
    trim_into(match, sizeof(match), rule->match);
    if (match[0] == '\0') {
        return ST_EGRESS_CODE_RULE_MALFORMED;
    }
    /*
     * A colon is unambiguous: the match is an IPv6 address or prefix, or it is malformed. A
     * well-formed one is refused last, once everything about the rule itself is known to be right:
     * what is missing is a consumer that carries IPv6, and none does yet.
     */
    if (strchr(match, ':') != NULL) {
        st_egress_cidr6 cidr6;
        if (st_egress_parse_cidr6(match, &cidr6, NULL) != 0 || st_egress_cidr6_mapped(&cidr6)) {
            /* An IPv4-mapped prefix reads but no packet is addressed to one, so it would never match. */
            return ST_EGRESS_CODE_RULE_MALFORMED;
        }
        if (cidr6.prefix_length == 0) {
            return ST_EGRESS_CODE_RULE_DEFAULT_ROUTE;
        }
        const char *target = validate_rule_target(rule);
        return target != NULL ? target : ST_EGRESS_CODE_RULE_IPV6_UNSUPPORTED;
    }
    if (looks_like_domain(match)) {
        return ST_EGRESS_CODE_RULE_DOMAIN_UNSUPPORTED;
    }
    st_egress_cidr cidr;
    if (st_egress_parse_cidr(match, &cidr) != 0) {
        return ST_EGRESS_CODE_RULE_MALFORMED;
    }
    if (cidr.prefix_length == 0) {
        /*
         * This version never takes over the default route: doing so would override the operator's
         * existing configuration and contradict "unmatched traffic stays local".
         */
        return ST_EGRESS_CODE_RULE_DEFAULT_ROUTE;
    }
    const char *mesh_text = (mesh_cidr == NULL || mesh_cidr[0] == '\0')
        ? ST_EGRESS_DEFAULT_MESH_CIDR
        : mesh_cidr;
    st_egress_cidr mesh;
    if (st_egress_parse_cidr(mesh_text, &mesh) == 0 && st_egress_cidr_overlaps(&cidr, &mesh)) {
        return ST_EGRESS_CODE_RULE_MESH_OVERLAP;
    }
    return validate_rule_target(rule);
}

/* The part of the order after the match: no port, a known action, and an egress rule's egress. */
static const char *validate_rule_target(const st_egress_rule *rule)
{
    if (rule->has_port) {
        return ST_EGRESS_CODE_RULE_PORT_UNSUPPORTED;
    }
    char action[sizeof(rule->action)];
    trim_into(action, sizeof(action), rule->action);
    if (strcmp(action, ST_EGRESS_ACTION_EGRESS) != 0
        && strcmp(action, ST_EGRESS_ACTION_DIRECT) != 0
        && strcmp(action, ST_EGRESS_ACTION_BLOCK) != 0) {
        return ST_EGRESS_CODE_RULE_MALFORMED;
    }
    if (strcmp(action, ST_EGRESS_ACTION_EGRESS) == 0
        && (!rule->has_egress_client_id || rule->egress_client_id <= 0)) {
        /*
         * The field being present is not the same as it being usable. Zero is this project's
         * sentinel for "no consumer", so accepting it would let the rule pass validation, install
         * its route, and then fail to find a peer for every packet: a configuration error
         * deferred into a runtime blackhole.
         */
        return ST_EGRESS_CODE_RULE_MISSING_TARGET;
    }
    return NULL;
}

void st_egress_match_rules(const st_egress_rule *rules,
                           size_t rules_len,
                           const char *destination,
                           const char *mesh_cidr,
                           st_egress_match *out)
{
    if (out == NULL) {
        return;
    }
    copy_bounded(out->action, sizeof(out->action), ST_EGRESS_ACTION_DIRECT);
    out->matched_rule_index = -1;
    out->egress_client_id = 0;
    out->has_egress_client_id = 0;

    uint32_t address = 0U;
    if (rules == NULL || rules_len == 0U || st_egress_parse_address(destination, &address) != 0) {
        return;
    }
    int best_prefix = -1;
    for (size_t index = 0U; index < rules_len; index++) {
        /*
         * A refused rule steers nothing. Skipped here rather than left to the caller to
         * pre-filter, so one bad rule cannot change what a good one decides no matter who
         * assembled the list.
         */
        if (st_egress_validate_rule(&rules[index], mesh_cidr) != NULL) {
            continue;
        }
        st_egress_cidr cidr;
        if (st_egress_parse_cidr(rules[index].match, &cidr) != 0
            || !st_egress_cidr_contains(&cidr, address)) {
            continue;
        }
        /* Strictly greater keeps the earlier rule when two share a prefix length. */
        if (cidr.prefix_length <= best_prefix) {
            continue;
        }
        best_prefix = cidr.prefix_length;
        copy_bounded(out->action, sizeof(out->action), rules[index].action);
        out->matched_rule_index = (int)index;
        if (strcmp(rules[index].action, ST_EGRESS_ACTION_EGRESS) == 0) {
            out->egress_client_id = rules[index].egress_client_id;
            out->has_egress_client_id = rules[index].has_egress_client_id;
        } else {
            out->egress_client_id = 0;
            out->has_egress_client_id = 0;
        }
    }
}

void st_egress_context_init(st_egress_context *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    copy_bounded(out->mesh_cidr, sizeof(out->mesh_cidr), ST_EGRESS_DEFAULT_MESH_CIDR);
}

static void deny(st_egress_decision *out, const char *code)
{
    out->allowed = 0;
    out->code = code;
}

/* A destination as the judgment reads it, IPv4 or IPv6. */
typedef struct {
    int is6;
    uint32_t v4;
    uint8_t v6[16];
} egress_target;

/* IPv6 when the text has a colon, with the spelling the rules use; IPv4 otherwise. Returns 0 on success. */
static int parse_target(const char *text, egress_target *out)
{
    memset(out, 0, sizeof(*out));
    if (text != NULL && strchr(text, ':') != NULL) {
        out->is6 = 1;
        return st_egress_parse_address6(text, out->v6);
    }
    return st_egress_parse_address(text, &out->v4);
}

/*
 * Whether one prefix contains the target. A prefix of the other family, or one that does not read,
 * contains nothing: a list can mix both.
 */
static int target_in_cidr(const egress_target *target, const char *text)
{
    if (text == NULL) {
        return 0;
    }
    if (!target->is6) {
        st_egress_cidr cidr;
        return st_egress_parse_cidr(text, &cidr) == 0 && st_egress_cidr_contains(&cidr, target->v4);
    }
    char trimmed[64];
    trim_into(trimmed, sizeof(trimmed), text);
    if (strchr(trimmed, ':') == NULL) {
        return 0;
    }
    st_egress_cidr6 cidr;
    if (st_egress_parse_cidr6(trimmed, &cidr, NULL) != 0) {
        return 0;
    }
    for (int i = 0; i < 16; i++) {
        int bits = cidr.prefix_length - (i * 8);
        unsigned mask = bits >= 8 ? 0xFFU : (bits <= 0 ? 0U : ((0xFFU << (8 - bits)) & 0xFFU));
        if (((unsigned)target->v6[i] & mask) != (unsigned)cidr.network[i]) {
            return 0;
        }
    }
    return 1;
}

static int target_in(const egress_target *target, const char *const *cidrs, size_t cidrs_len)
{
    for (size_t i = 0U; i < cidrs_len; i++) {
        if (target_in_cidr(target, cidrs[i])) {
            return 1;
        }
    }
    return 0;
}

static int forced_deny_hit(const st_egress_request *request,
                           const st_egress_context *context,
                           const egress_target *destination)
{
    if (target_in(destination, ST_EGRESS_FORCED_DENY_CIDRS, ST_EGRESS_FORCED_DENY_CIDRS_LEN)
        || target_in(destination, ST_EGRESS_CLOUD_METADATA_CIDRS, ST_EGRESS_CLOUD_METADATA_CIDRS_LEN)
        || target_in(destination, ST_EGRESS_FORCED_DENY_CIDRS6, ST_EGRESS_FORCED_DENY_CIDRS6_LEN)
        || target_in(destination, ST_EGRESS_CLOUD_METADATA_CIDRS6, ST_EGRESS_CLOUD_METADATA_CIDRS6_LEN)) {
        return 1;
    }
    const char *mesh = (context == NULL || context->mesh_cidr[0] == '\0')
        ? ST_EGRESS_DEFAULT_MESH_CIDR
        : context->mesh_cidr;
    if (target_in_cidr(destination, mesh)) {
        return 1;
    }
    if (context != NULL) {
        for (size_t i = 0U; i < context->deployment_deny_cidrs_len; i++) {
            if (target_in_cidr(destination, context->deployment_deny_cidrs[i])) {
                return 1;
            }
        }
    }
    for (size_t i = 0U; i < request->local_interface_cidrs_len; i++) {
        if (target_in_cidr(destination, request->local_interface_cidrs[i])) {
            return 1;
        }
    }
    return 0;
}

static int rule_allows_protocol(const st_egress_destination_rule *rule, const char *protocol)
{
    for (size_t i = 0U; i < rule->protocols_len; i++) {
        if (strcmp(rule->protocols[i], protocol) == 0) {
            return 1;
        }
    }
    return 0;
}

static int rule_allows_port(const st_egress_destination_rule *rule, int port)
{
    for (size_t i = 0U; i < rule->port_ranges_len; i++) {
        if (port >= rule->port_ranges[i][0] && port <= rule->port_ranges[i][1]) {
            return 1;
        }
    }
    return 0;
}

void st_egress_authorize(const st_egress_request *request,
                         const st_egress_policy *policy,
                         int peer_acl_allows,
                         const st_egress_context *context,
                         st_egress_decision *out)
{
    if (out == NULL) {
        return;
    }
    if (request == NULL || policy == NULL) {
        deny(out, ST_EGRESS_CODE_DEST_DENIED);
        return;
    }
    if (request->hop) {
        deny(out, ST_EGRESS_CODE_HOP_NOT_ALLOWED);
        return;
    }
    if (!policy->enabled) {
        deny(out, ST_EGRESS_CODE_DISABLED);
        return;
    }
    if (!peer_acl_allows) {
        deny(out, ST_EGRESS_CODE_PEER_ACL_DENIED);
        return;
    }
    int consumer_allowed = 0;
    for (size_t i = 0U; i < policy->allowed_consumer_client_ids_len; i++) {
        if (policy->allowed_consumer_client_ids[i] == request->consumer_client_id) {
            consumer_allowed = 1;
            break;
        }
    }
    if (!consumer_allowed) {
        deny(out, ST_EGRESS_CODE_CONSUMER_DENIED);
        return;
    }

    egress_target destination;
    if (parse_target(request->destination_ip, &destination) != 0) {
        deny(out, ST_EGRESS_CODE_DEST_DENIED);
        return;
    }
    if (forced_deny_hit(request, context, &destination)) {
        deny(out, ST_EGRESS_CODE_FORBIDDEN_DESTINATION);
        return;
    }

    const char *scope = target_in(&destination, ST_EGRESS_LAN_CIDRS, ST_EGRESS_LAN_CIDRS_LEN)
            || target_in(&destination, ST_EGRESS_LAN_CIDRS6, ST_EGRESS_LAN_CIDRS6_LEN)
        ? ST_EGRESS_SCOPE_LAN
        : ST_EGRESS_SCOPE_PUBLIC;
    if (strcmp(scope, policy->scope) != 0) {
        deny(out, ST_EGRESS_CODE_SCOPE_DENIED);
        return;
    }

    int address_matched = 0;
    int protocol_matched = 0;
    int port_matched = 0;
    for (size_t i = 0U; i < policy->destination_rules_len; i++) {
        const st_egress_destination_rule *rule = &policy->destination_rules[i];
        /* A rule covers addresses of its own family only: 0.0.0.0/0 grants no IPv6 address. */
        if (!target_in_cidr(&destination, rule->cidr)) {
            continue;
        }
        address_matched = 1;
        if (!rule_allows_protocol(rule, request->protocol)) {
            continue;
        }
        protocol_matched = 1;
        if (rule_allows_port(rule, request->destination_port)) {
            port_matched = 1;
            break;
        }
    }
    if (!address_matched) {
        deny(out, ST_EGRESS_CODE_DEST_DENIED);
        return;
    }
    if (!protocol_matched) {
        deny(out, ST_EGRESS_CODE_PROTOCOL_DENIED);
        return;
    }
    if (!port_matched) {
        deny(out, ST_EGRESS_CODE_PORT_DENIED);
        return;
    }

    if (policy->limits.max_flows_per_consumer > 0
        && request->active_flows_for_consumer >= policy->limits.max_flows_per_consumer) {
        deny(out, ST_EGRESS_CODE_LIMIT_EXCEEDED);
        return;
    }
    if (policy->limits.max_concurrent_flows > 0
        && request->active_flows_total >= policy->limits.max_concurrent_flows) {
        deny(out, ST_EGRESS_CODE_LIMIT_EXCEEDED);
        return;
    }
    out->allowed = 1;
    out->code = ST_EGRESS_CODE_ALLOWED;
}

/*
 * json.c reads arrays by key, so a bare top-level array is wrapped in a one-field object rather
 * than adding a second array entry point that only this module would use.
 */
static char *wrap_array(const char *json)
{
    if (json == NULL) {
        return NULL;
    }
    size_t len = strlen(json);
    char *wrapped = (char *)malloc(len + 16U);
    if (wrapped == NULL) {
        return NULL;
    }
    snprintf(wrapped, len + 16U, "{\"items\":%s}", json);
    return wrapped;
}

static int parse_port_range(const char *raw, int *low, int *high)
{
    char *wrapped = wrap_array(raw);
    if (wrapped == NULL) {
        return 1;
    }
    char **bounds = NULL;
    size_t bounds_len = 0U;
    int rc = st_json_get_raw_array(wrapped, "items", &bounds, &bounds_len);
    free(wrapped);
    if (rc != 0 || bounds_len != 2U) {
        st_json_free_string_array(bounds, bounds_len);
        return 1;
    }
    char *end = NULL;
    long parsed_low = strtol(bounds[0], &end, 10);
    int ok = end != NULL && *end == '\0';
    long parsed_high = strtol(bounds[1], &end, 10);
    ok = ok && end != NULL && *end == '\0';
    st_json_free_string_array(bounds, bounds_len);
    if (!ok || parsed_low < 0 || parsed_high > 65535 || parsed_low > parsed_high) {
        return 1;
    }
    *low = (int)parsed_low;
    *high = (int)parsed_high;
    return 0;
}

static int parse_destination_rule(const char *raw, st_egress_destination_rule *out)
{
    memset(out, 0, sizeof(*out));
    char *cidr = st_json_get_string(raw, "cidr");
    if (cidr == NULL) {
        return 1;
    }
    copy_bounded(out->cidr, sizeof(out->cidr), cidr);
    free(cidr);

    char **protocols = NULL;
    size_t protocols_len = 0U;
    if (st_json_get_string_array(raw, "protocols", &protocols, &protocols_len) == 0) {
        for (size_t i = 0U; i < protocols_len && out->protocols_len < ST_EGRESS_MAX_PROTOCOLS; i++) {
            copy_bounded(out->protocols[out->protocols_len], sizeof(out->protocols[0]), protocols[i]);
            out->protocols_len++;
        }
    }
    st_json_free_string_array(protocols, protocols_len);

    char **ranges = NULL;
    size_t ranges_len = 0U;
    if (st_json_get_raw_array(raw, "portRanges", &ranges, &ranges_len) == 0) {
        for (size_t i = 0U; i < ranges_len && out->port_ranges_len < ST_EGRESS_MAX_PORT_RANGES; i++) {
            int low = 0;
            int high = 0;
            if (parse_port_range(ranges[i], &low, &high) != 0) {
                continue;
            }
            out->port_ranges[out->port_ranges_len][0] = low;
            out->port_ranges[out->port_ranges_len][1] = high;
            out->port_ranges_len++;
        }
    }
    st_json_free_string_array(ranges, ranges_len);
    return 0;
}

int st_egress_parse_destination_rules(const char *json,
                                      st_egress_destination_rule *out,
                                      size_t capacity,
                                      size_t *out_len)
{
    if (out_len != NULL) {
        *out_len = 0U;
    }
    if (out == NULL || out_len == NULL) {
        return 1;
    }
    char trimmed[16];
    trim_into(trimmed, sizeof(trimmed), json);
    if (json == NULL || trimmed[0] == '\0') {
        return 0;
    }
    char *wrapped = wrap_array(json);
    if (wrapped == NULL) {
        return 1;
    }
    char **items = NULL;
    size_t items_len = 0U;
    int rc = st_json_get_raw_array(wrapped, "items", &items, &items_len);
    free(wrapped);
    if (rc != 0) {
        /* Unreadable rows deny everything rather than falling back to something permissive. */
        return 1;
    }
    for (size_t i = 0U; i < items_len && *out_len < capacity; i++) {
        if (parse_destination_rule(items[i], &out[*out_len]) == 0) {
            (*out_len)++;
        }
    }
    st_json_free_string_array(items, items_len);
    return 0;
}

/*
 * The whitespace a management-side trim removes: what isspace() accepts in the "C" locale, spelled
 * out so the result cannot change with the process locale.
 */
static int is_trim_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

static char *trim_in_place(char *value)
{
    while (is_trim_space(*value)) {
        value++;
    }
    size_t len = strlen(value);
    while (len > 0U && is_trim_space(value[len - 1U])) {
        len--;
    }
    value[len] = '\0';
    return value;
}

/* An absent field and an explicit null both read as an empty list. */
static int is_absent_value(const char *raw)
{
    return raw == NULL || strcmp(raw, "null") == 0;
}

/* Splits a raw JSON array into its raw elements. Returns 0 on success; a non-array fails. */
static int raw_array_items(const char *raw, char ***items, size_t *items_len)
{
    *items = NULL;
    *items_len = 0U;
    if (raw == NULL || raw[0] != '[') {
        return 1;
    }
    char *wrapped = wrap_array(raw);
    if (wrapped == NULL) {
        return 1;
    }
    int rc = st_json_get_raw_array(wrapped, "items", items, items_len);
    free(wrapped);
    return rc == 0 ? 0 : 1;
}

/* A port bound must be a JSON integer: 443.0 or 4.43e2 is refused rather than truncated. */
static int parse_port_bound(const char *raw, long *out)
{
    const char *p = raw[0] == '-' ? raw + 1 : raw;
    if (*p == '\0') {
        return 1;
    }
    for (; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return 1;
        }
    }
    errno = 0;
    char *end = NULL;
    long value = strtol(raw, &end, 10);
    if (errno == ERANGE || end == NULL || *end != '\0') {
        return 1;
    }
    *out = value;
    return 0;
}

static int normalize_port_range(const char *raw, int *low, int *high)
{
    char **bounds = NULL;
    size_t bounds_len = 0U;
    if (raw_array_items(raw, &bounds, &bounds_len) != 0) {
        return 1;
    }
    long parsed_low = 0;
    long parsed_high = 0;
    int ok = bounds_len == 2U
        && parse_port_bound(bounds[0], &parsed_low) == 0
        && parse_port_bound(bounds[1], &parsed_high) == 0
        && parsed_low >= 0 && parsed_high <= 65535 && parsed_low <= parsed_high;
    st_json_free_string_array(bounds, bounds_len);
    if (!ok) {
        return 1;
    }
    *low = (int)parsed_low;
    *high = (int)parsed_high;
    return 0;
}

/*
 * Java PeerEgressService names what it refuses: IllegalArgumentException messages built from the
 * rule's field path and the value as Java holds it. A NULL error buffer asks for no message.
 */
static void rule_error(char *error, size_t error_len, const char *format, ...)
{
    if (error == NULL || error_len == 0U) {
        return;
    }
    va_list args;
    va_start(args, format);
    vsnprintf(error, error_len, format, args);
    va_end(args);
}

/*
 * A raw JSON scalar as Jackson binds it into a String: the decoded text of a string, the literal of a
 * number or boolean, NULL for null (and for an object or array, which bind no String). The caller
 * frees it. *nul_free (when given) is 0 for a string with an escaped NUL, whose C text would end
 * there: "tcp\u0000x" must not be read as "tcp".
 */
static char *scalar_text(const char *raw, int *nul_free)
{
    if (nul_free != NULL) {
        *nul_free = 1;
    }
    if (raw == NULL || strcmp(raw, "null") == 0 || raw[0] == '{' || raw[0] == '[') {
        return NULL;
    }
    if (raw[0] == '"') {
        size_t len = 0U;
        char *text = st_json_decode_string(raw, &len);
        if (text != NULL && strlen(text) != len && nul_free != NULL) {
            *nul_free = 0;
        }
        return text;
    }
    size_t len = strlen(raw);
    char *copy = (char *)malloc(len + 1U);
    if (copy != NULL) {
        memcpy(copy, raw, len + 1U);
    }
    return copy;
}

/*
 * Appends raw JSON as Java's toString shows the value Jackson made of it for an untyped port bound:
 * an Integer, Long or Double, a String unquoted, true or false, null, a List as [a, b] and a Map as
 * {k=v}. A fraction keeps at least one decimal (443.0).
 */
static void append_java_text(char *out, size_t out_len, const char *raw)
{
    size_t used = strlen(out);
    if (used >= out_len) {
        return;
    }
    if (raw[0] == '[' || raw[0] == '{') {
        int list = raw[0] == '[';
        char **items = NULL;
        size_t items_len = 0U;
        snprintf(out + used, out_len - used, "%s", list ? "[" : "{");
        if (list && raw_array_items(raw, &items, &items_len) == 0) {
            for (size_t i = 0U; i < items_len; i++) {
                if (i > 0U) {
                    size_t at = strlen(out);
                    snprintf(out + at, at < out_len ? out_len - at : 0U, ", ");
                }
                append_java_text(out, out_len, items[i]);
            }
            st_json_free_string_array(items, items_len);
        } else if (!list) {
            /* A map: its members as written, which is all a refusal needs to point at. */
            size_t at = strlen(out);
            snprintf(out + at, at < out_len ? out_len - at : 0U, "%.*s", (int)(strlen(raw) - 2U), raw + 1);
        }
        size_t at = strlen(out);
        snprintf(out + at, at < out_len ? out_len - at : 0U, "%s", list ? "]" : "}");
        return;
    }
    if (raw[0] == '"') {
        char *text = scalar_text(raw, NULL);
        snprintf(out + used, out_len - used, "%s", text == NULL ? "" : text);
        free(text);
        return;
    }
    if (strpbrk(raw, ".eE") != NULL && (raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9'))) {
        double value = strtod(raw, NULL);
        char text[64];
        for (int precision = 1; precision <= 17; precision++) {
            snprintf(text, sizeof(text), "%.*f", precision, value);
            if (strtod(text, NULL) == value) {
                break;
            }
        }
        snprintf(out + used, out_len - used, "%s", text);
        return;
    }
    snprintf(out + used, out_len - used, "%s", raw);
}

/*
 * Whether a rule list binds into Java's List<DestinationRuleMutation> or List<DomainRuleMutation> at
 * all: Spring answers 400 before PeerEgressService sees a list that does not. Every element is an
 * object or null; its text field (cidr or match) is a scalar; protocols is an array of scalars;
 * portRanges is an array whose elements are arrays or null. Unknown members are ignored.
 */
static int rules_bind(const char *json, const char *text_field)
{
    char **items = NULL;
    size_t items_len = 0U;
    if (raw_array_items(json, &items, &items_len) != 0) {
        return 0;
    }
    int ok = 1;
    for (size_t i = 0U; ok && i < items_len; i++) {
        if (strcmp(items[i], "null") == 0) {
            continue;
        }
        if (items[i][0] != '{') {
            ok = 0;
            break;
        }
        char *text = st_json_get_top_level_raw(items[i], text_field);
        ok = text == NULL || (text[0] != '{' && text[0] != '[');
        free(text);
        char *protocols = ok ? st_json_get_top_level_raw(items[i], "protocols") : NULL;
        if (ok && !is_absent_value(protocols)) {
            char **values = NULL;
            size_t values_len = 0U;
            ok = raw_array_items(protocols, &values, &values_len) == 0;
            for (size_t v = 0U; ok && v < values_len; v++) {
                ok = values[v][0] != '{' && values[v][0] != '[';
            }
            st_json_free_string_array(values, values_len);
        }
        free(protocols);
        char *ranges = ok ? st_json_get_top_level_raw(items[i], "portRanges") : NULL;
        if (ok && !is_absent_value(ranges)) {
            char **pairs = NULL;
            size_t pairs_len = 0U;
            ok = raw_array_items(ranges, &pairs, &pairs_len) == 0;
            for (size_t p = 0U; ok && p < pairs_len; p++) {
                ok = strcmp(pairs[p], "null") == 0 || pairs[p][0] == '[';
            }
            st_json_free_string_array(pairs, pairs_len);
        }
        free(ranges);
    }
    st_json_free_string_array(items, items_len);
    return ok;
}

static int normalize_cidr(const char *rule_raw, st_egress_destination_rule *out, const char *field, char *error,
                          size_t error_len)
{
    char *raw = st_json_get_top_level_raw(rule_raw, "cidr");
    /* Absent and null are Java's null; a number or boolean is its literal text. */
    int nul_free = 1;
    char *cidr = scalar_text(raw, &nul_free);
    free(raw);
    int ok = 0;
    char *copy = cidr == NULL || !nul_free ? NULL : (char *)malloc(strlen(cidr) + 1U);
    if (copy != NULL) {
        strcpy(copy, cidr);
        const char *trimmed = trim_in_place(copy);
        if (strchr(trimmed, ':') != NULL) {
            /* IPv6 is stored in RFC 5952 form, the /length kept only when it was written. */
            st_egress_cidr6 parsed6;
            int had_length = 0;
            ok = st_egress_parse_cidr6(trimmed, &parsed6, &had_length) == 0;
            if (ok) {
                char stored[64];
                st_egress_format_address6(parsed6.network, stored, sizeof(stored));
                if (had_length) {
                    size_t used = strlen(stored);
                    snprintf(stored + used, sizeof(stored) - used, "/%d", parsed6.prefix_length);
                }
                copy_bounded(out->cidr, sizeof(out->cidr), stored);
            }
        } else {
            st_egress_cidr parsed;
            ok = strlen(trimmed) < sizeof(out->cidr) && st_egress_parse_cidr(trimmed, &parsed) == 0;
            if (ok) {
                /* Kept as written: a bare address stays bare, so the operator reads back what they typed. */
                copy_bounded(out->cidr, sizeof(out->cidr), trimmed);
            }
        }
        free(copy);
    }
    if (!ok) {
        rule_error(error, error_len, "%s.cidr is not an IPv4 or IPv6 address or CIDR: %s", field,
                   cidr == NULL ? "null" : cidr);
    }
    free(cidr);
    return ok ? 0 : 1;
}

static int normalize_protocols(const char *rule_raw, st_egress_destination_rule *out, const char *field,
                               char *error, size_t error_len)
{
    char *raw = st_json_get_top_level_raw(rule_raw, "protocols");
    if (is_absent_value(raw)) {
        free(raw);
        return 0;
    }
    char **items = NULL;
    size_t items_len = 0U;
    int rc = raw_array_items(raw, &items, &items_len);
    free(raw);
    for (size_t i = 0U; rc == 0 && i < items_len; i++) {
        int nul_free = 1;
        char *value = scalar_text(items[i], &nul_free);
        char *protocol = value == NULL || !nul_free ? NULL : trim_in_place(value);
        for (char *p = protocol; p != NULL && *p != '\0'; p++) {
            if (*p >= 'A' && *p <= 'Z') {
                *p = (char)(*p - 'A' + 'a');
            }
        }
        if (protocol == NULL || (strcmp(protocol, "tcp") != 0 && strcmp(protocol, "udp") != 0)) {
            char *as_sent = scalar_text(items[i], NULL);
            rule_error(error, error_len, "%s.protocols may contain only tcp and udp: %s", field,
                       as_sent == NULL ? "null" : as_sent);
            free(as_sent);
            rc = 1;
        } else if (!rule_allows_protocol(out, protocol) && out->protocols_len < ST_EGRESS_MAX_PROTOCOLS) {
            copy_bounded(out->protocols[out->protocols_len], sizeof(out->protocols[0]), protocol);
            out->protocols_len++;
        }
        free(value);
    }
    st_json_free_string_array(items, items_len);
    return rc;
}

static int normalize_port_ranges(const char *rule_raw, st_egress_destination_rule *out, const char *field,
                                 char *error, size_t error_len)
{
    char *raw = st_json_get_top_level_raw(rule_raw, "portRanges");
    if (is_absent_value(raw)) {
        free(raw);
        return 0;
    }
    char **items = NULL;
    size_t items_len = 0U;
    int rc = raw_array_items(raw, &items, &items_len);
    free(raw);
    if (rc == 0 && items_len > ST_EGRESS_MAX_PORT_RANGES) {
        rule_error(error, error_len, "%s.portRanges has %zu ranges (at most %d)", field, items_len,
                   ST_EGRESS_MAX_PORT_RANGES);
        rc = 1;
    }
    for (size_t i = 0U; rc == 0 && i < items_len; i++) {
        int low = 0;
        int high = 0;
        rc = normalize_port_range(items[i], &low, &high);
        if (rc == 0) {
            out->port_ranges[out->port_ranges_len][0] = low;
            out->port_ranges[out->port_ranges_len][1] = high;
            out->port_ranges_len++;
        } else if (error != NULL && error_len > 0U) {
            int written = snprintf(error, error_len,
                                   "%s.portRanges entries must be [low, high] integers with "
                                   "0 <= low <= high <= 65535: ", field);
            if (written > 0 && (size_t)written < error_len) {
                append_java_text(error, error_len, items[i]);
            }
        }
    }
    st_json_free_string_array(items, items_len);
    return rc;
}

static int normalize_destination_rule(const char *raw, st_egress_destination_rule *out, const char *field,
                                      char *error, size_t error_len)
{
    memset(out, 0, sizeof(*out));
    if (!st_json_is_valid_object(raw)) {
        rule_error(error, error_len, "%s must be an object", field);
        return 1;
    }
    if (normalize_cidr(raw, out, field, error, error_len) != 0
        || normalize_protocols(raw, out, field, error, error_len) != 0
        || normalize_port_ranges(raw, out, field, error, error_len) != 0) {
        return 1;
    }
    return 0;
}

int st_egress_normalize_destination_rules_explained(const char *json, char **out_json, char *error,
                                                    size_t error_len)
{
    if (out_json == NULL) {
        return 2;
    }
    *out_json = NULL;
    rule_error(error, error_len, "%s", "");
    if (json == NULL || !st_json_is_valid(json)) {
        return 2;
    }
    while (is_trim_space(*json)) {
        json++;
    }
    if (!rules_bind(json, "cidr")) {
        return 2;
    }
    char **items = NULL;
    size_t items_len = 0U;
    if (raw_array_items(json, &items, &items_len) != 0) {
        return 2;
    }
    /* Counted before anything is parsed, so an oversized list is refused, never truncated. */
    if (items_len > ST_EGRESS_MAX_DESTINATION_RULES) {
        rule_error(error, error_len, "too many destination rules: %zu (at most %d)", items_len,
                   ST_EGRESS_MAX_DESTINATION_RULES);
        st_json_free_string_array(items, items_len);
        return 1;
    }
    st_egress_destination_rule *rules =
        (st_egress_destination_rule *)calloc(items_len == 0U ? 1U : items_len, sizeof(*rules));
    if (rules == NULL) {
        st_json_free_string_array(items, items_len);
        return 1;
    }
    int rc = 0;
    for (size_t i = 0U; rc == 0 && i < items_len; i++) {
        char field[48];
        snprintf(field, sizeof(field), "destinationRules[%zu]", i);
        rc = normalize_destination_rule(items[i], &rules[i], field, error, error_len);
    }
    st_json_free_string_array(items, items_len);
    if (rc == 0) {
        /* The encoder refuses a result over the stored byte limit, which is the last check. */
        *out_json = st_egress_encode_destination_rules(rules, items_len);
        if (*out_json == NULL) {
            rule_error(error, error_len, "destination rules exceed %d bytes once stored",
                       ST_EGRESS_MAX_DESTINATION_RULES_BYTES);
            rc = 1;
        }
    }
    free(rules);
    return rc;
}

int st_egress_normalize_destination_rules(const char *json, char **out_json)
{
    return st_egress_normalize_destination_rules_explained(json, out_json, NULL, 0U) == 0 ? 0 : 1;
}

/* Appends text within capacity. Returns 0, or 1 when it does not fit. */
static int append_text(char *out, size_t capacity, size_t *used, const char *text)
{
    size_t len = strlen(text);
    if (len >= capacity - *used) {
        return 1;
    }
    memcpy(out + *used, text, len + 1U);
    *used += len;
    return 0;
}

/* Appends a JSON string within capacity. Returns 0, or 1 when it does not fit. */
static int append_json_string(char *out, size_t capacity, size_t *used, const char *value)
{
    char *escaped = st_json_escape(value);
    if (escaped == NULL) {
        return 1;
    }
    int rc = append_text(out, capacity, used, "\"") != 0
        || append_text(out, capacity, used, escaped) != 0
        || append_text(out, capacity, used, "\"") != 0 ? 1 : 0;
    free(escaped);
    return rc;
}

/*
 * Appends the "protocols" and "portRanges" members a destination rule and a domain rule share.
 * Returns 0, or 1 when they do not fit within capacity.
 */
static int append_rule_traffic(char *out, size_t capacity, size_t *used, const st_egress_destination_rule *rule)
{
    if (append_text(out, capacity, used, "\"protocols\":[") != 0) {
        return 1;
    }
    for (size_t p = 0U; p < rule->protocols_len; p++) {
        if ((p > 0U && append_text(out, capacity, used, ",") != 0)
            || append_json_string(out, capacity, used, rule->protocols[p]) != 0) {
            return 1;
        }
    }
    if (append_text(out, capacity, used, "],\"portRanges\":[") != 0) {
        return 1;
    }
    for (size_t r = 0U; r < rule->port_ranges_len; r++) {
        char pair[32];
        int written = snprintf(pair, sizeof(pair), "%s[%d,%d]", r == 0U ? "" : ",",
                               rule->port_ranges[r][0], rule->port_ranges[r][1]);
        if (written < 0 || (size_t)written >= sizeof(pair) || append_text(out, capacity, used, pair) != 0) {
            return 1;
        }
    }
    return append_text(out, capacity, used, "]");
}

char *st_egress_encode_destination_rules(const st_egress_destination_rule *rules, size_t rules_len)
{
    if (rules_len > ST_EGRESS_MAX_DESTINATION_RULES) {
        return NULL;
    }
    size_t capacity = ST_EGRESS_MAX_DESTINATION_RULES_BYTES + 1U;
    char *out = (char *)malloc(capacity);
    if (out == NULL) {
        return NULL;
    }
    out[0] = '\0';
    size_t used = 0U;
    int rc = append_text(out, capacity, &used, "[");
    for (size_t i = 0U; rc == 0 && i < rules_len; i++) {
        rc = append_text(out, capacity, &used, i == 0U ? "{\"cidr\":" : ",{\"cidr\":") != 0
            || append_json_string(out, capacity, &used, rules[i].cidr) != 0
            || append_text(out, capacity, &used, ",") != 0
            || append_rule_traffic(out, capacity, &used, &rules[i]) != 0
            || append_text(out, capacity, &used, "}") != 0 ? 1 : 0;
    }
    if (rc == 0) {
        rc = append_text(out, capacity, &used, "]");
    }
    if (rc != 0) {
        free(out);
        return NULL;
    }
    return out;
}

/* One label of a name: 1-63 of a-z, 0-9 and -, not starting or ending with -. */
static int valid_domain_label(const char *label, size_t len)
{
    if (len == 0U || len > 63U || label[0] == '-' || label[len - 1U] == '-') {
        return 0;
    }
    for (size_t i = 0U; i < len; i++) {
        char c = label[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
            return 0;
        }
    }
    return 1;
}

/*
 * The consumer's domain-rule syntax (protocol/spec/peer-egress-dns.md): name or *.name, every label
 * 1-63 of a-z, 0-9 and an inner -, at most 253 bytes after the *. part, at least two labels and not
 * all of them digits, punycode for IDN. Text with neither a leading * nor a letter is an address,
 * not a name. Writes the stored form -- trailing dots removed, lower case -- and returns 0.
 */
static int normalize_domain_match(const char *text, char *out, size_t out_len)
{
    size_t len = strlen(text);
    if (len == 0U) {
        return 1;
    }
    int letter = 0;
    for (size_t i = 0U; i < len; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c > 0x7FU) {
            /* Unicode has to be written as punycode; it is refused rather than read as an address. */
            return 1;
        }
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
            letter = 1;
        }
    }
    if (!letter && text[0] != '*') {
        return 1;
    }
    while (len > 0U && text[len - 1U] == '.') {
        len--;
    }
    if (len >= out_len) {
        return 1;
    }
    for (size_t i = 0U; i < len; i++) {
        char c = text[i];
        out[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    out[len] = '\0';
    const char *host = strncmp(out, "*.", 2U) == 0 ? out + 2 : out;
    size_t host_len = strlen(host);
    if (host_len == 0U || host_len > 253U || strchr(host, '*') != NULL) {
        return 1;
    }
    size_t labels = 0U;
    int all_digits = 1;
    for (const char *label = host;;) {
        const char *dot = strchr(label, '.');
        size_t label_len = dot == NULL ? strlen(label) : (size_t)(dot - label);
        if (!valid_domain_label(label, label_len)) {
            return 1;
        }
        for (size_t i = 0U; i < label_len; i++) {
            if (label[i] < '0' || label[i] > '9') {
                all_digits = 0;
            }
        }
        labels++;
        if (dot == NULL) {
            break;
        }
        label = dot + 1;
    }
    return labels < 2U || all_digits ? 1 : 0;
}

/* A domain rule while it is normalised; protocols and port ranges are read like a destination rule's. */
typedef struct {
    char match[ST_EGRESS_MAX_DOMAIN_MATCH + 1];
    st_egress_destination_rule traffic;
} egress_domain_rule;

static int normalize_domain_rule(const char *raw, egress_domain_rule *out, const char *field, char *error,
                                 size_t error_len)
{
    memset(out, 0, sizeof(*out));
    if (!st_json_is_valid_object(raw)) {
        rule_error(error, error_len, "%s must be an object", field);
        return 1;
    }
    char *member = st_json_get_top_level_raw(raw, "match");
    /* Absent and null are Java's null, which matches nothing; an empty string fails the syntax check. */
    int nul_free = 1;
    char *text = scalar_text(member, &nul_free);
    free(member);
    int rc = 1;
    if (text != NULL && nul_free) {
        char *copy = (char *)malloc(strlen(text) + 1U);
        if (copy != NULL) {
            strcpy(copy, text);
            rc = normalize_domain_match(trim_in_place(copy), out->match, sizeof(out->match));
            free(copy);
        }
    }
    if (rc != 0) {
        rule_error(error, error_len, "%s.match must be a name or *.name with at least two labels: %s", field,
                   text == NULL ? "null" : text);
        free(text);
        return 1;
    }
    free(text);
    return normalize_protocols(raw, &out->traffic, field, error, error_len) != 0
        || normalize_port_ranges(raw, &out->traffic, field, error, error_len) != 0 ? 1 : 0;
}

/* Serialises normalised domain rules, or NULL when they exceed the stored byte limit. */
static char *encode_domain_rules(const egress_domain_rule *rules, size_t rules_len)
{
    size_t capacity = ST_EGRESS_MAX_DOMAIN_RULES_BYTES + 1U;
    char *out = (char *)malloc(capacity);
    if (out == NULL) {
        return NULL;
    }
    out[0] = '\0';
    size_t used = 0U;
    int rc = append_text(out, capacity, &used, "[");
    for (size_t i = 0U; rc == 0 && i < rules_len; i++) {
        rc = append_text(out, capacity, &used, i == 0U ? "{\"match\":" : ",{\"match\":") != 0
            || append_json_string(out, capacity, &used, rules[i].match) != 0
            || append_text(out, capacity, &used, ",") != 0
            || append_rule_traffic(out, capacity, &used, &rules[i].traffic) != 0
            || append_text(out, capacity, &used, "}") != 0 ? 1 : 0;
    }
    if (rc == 0) {
        rc = append_text(out, capacity, &used, "]");
    }
    if (rc != 0) {
        free(out);
        return NULL;
    }
    return out;
}

int st_egress_normalize_domain_rules_explained(const char *json, char **out_json, char *error, size_t error_len)
{
    if (out_json == NULL) {
        return 2;
    }
    *out_json = NULL;
    rule_error(error, error_len, "%s", "");
    if (json == NULL || !st_json_is_valid(json)) {
        return 2;
    }
    while (is_trim_space(*json)) {
        json++;
    }
    if (!rules_bind(json, "match")) {
        return 2;
    }
    char **items = NULL;
    size_t items_len = 0U;
    if (raw_array_items(json, &items, &items_len) != 0) {
        return 2;
    }
    /* Counted before anything is parsed, so an oversized list is refused, never truncated. */
    if (items_len > ST_EGRESS_MAX_DOMAIN_RULES) {
        rule_error(error, error_len, "too many domain rules: %zu (at most %d)", items_len,
                   ST_EGRESS_MAX_DOMAIN_RULES);
        st_json_free_string_array(items, items_len);
        return 1;
    }
    egress_domain_rule *rules = (egress_domain_rule *)calloc(items_len == 0U ? 1U : items_len, sizeof(*rules));
    if (rules == NULL) {
        st_json_free_string_array(items, items_len);
        return 1;
    }
    int rc = 0;
    for (size_t i = 0U; rc == 0 && i < items_len; i++) {
        char field[48];
        snprintf(field, sizeof(field), "domainRules[%zu]", i);
        rc = normalize_domain_rule(items[i], &rules[i], field, error, error_len);
    }
    st_json_free_string_array(items, items_len);
    if (rc == 0) {
        /* The encoder refuses a result over the stored byte limit, which is the last check. */
        *out_json = encode_domain_rules(rules, items_len);
        if (*out_json == NULL) {
            rule_error(error, error_len, "domain rules exceed %d bytes once stored", ST_EGRESS_MAX_DOMAIN_RULES_BYTES);
            rc = 1;
        }
    }
    free(rules);
    return rc;
}

int st_egress_normalize_domain_rules(const char *json, char **out_json)
{
    return st_egress_normalize_domain_rules_explained(json, out_json, NULL, 0U) == 0 ? 0 : 1;
}

size_t st_egress_collect_protocols(const st_egress_destination_rule *rules,
                                   size_t rules_len,
                                   char out[][8],
                                   size_t capacity)
{
    size_t count = 0U;
    for (size_t i = 0U; i < rules_len; i++) {
        for (size_t p = 0U; p < rules[i].protocols_len; p++) {
            int seen = 0;
            for (size_t k = 0U; k < count; k++) {
                if (strcmp(out[k], rules[i].protocols[p]) == 0) {
                    seen = 1;
                    break;
                }
            }
            if (seen || count >= capacity) {
                continue;
            }
            copy_bounded(out[count], 8U, rules[i].protocols[p]);
            count++;
        }
    }
    return count;
}
