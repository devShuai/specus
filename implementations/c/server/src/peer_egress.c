#include "peer_egress.h"

#include "json.h"

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

const char *const ST_EGRESS_ALL_CODES[] = {
    ST_EGRESS_CODE_ALLOWED,
    ST_EGRESS_CODE_HOP_NOT_ALLOWED, ST_EGRESS_CODE_DISABLED, ST_EGRESS_CODE_PEER_ACL_DENIED,
    ST_EGRESS_CODE_CONSUMER_DENIED, ST_EGRESS_CODE_FORBIDDEN_DESTINATION, ST_EGRESS_CODE_SCOPE_DENIED,
    ST_EGRESS_CODE_DEST_DENIED, ST_EGRESS_CODE_PROTOCOL_DENIED, ST_EGRESS_CODE_PORT_DENIED,
    ST_EGRESS_CODE_LIMIT_EXCEEDED,
    ST_EGRESS_CODE_RULE_DOMAIN_UNSUPPORTED, ST_EGRESS_CODE_RULE_IPV6_UNSUPPORTED,
    ST_EGRESS_CODE_RULE_MALFORMED, ST_EGRESS_CODE_RULE_MISSING_TARGET,
    ST_EGRESS_CODE_RULE_MESH_OVERLAP, ST_EGRESS_CODE_RULE_DEFAULT_ROUTE,
    ST_EGRESS_CODE_RULE_PORT_UNSUPPORTED,
    ST_EGRESS_CODE_FRAME_BAD_MAGIC, ST_EGRESS_CODE_FRAME_UNKNOWN_TYPE,
    ST_EGRESS_CODE_FRAME_RESERVED_SET, ST_EGRESS_CODE_FRAME_TRUNCATED,
    ST_EGRESS_CODE_FRAME_TRAILING_BYTES, ST_EGRESS_CODE_IPV6_UNSUPPORTED,
    ST_EGRESS_CODE_FRAME_MALFORMED_CONTROL, ST_EGRESS_CODE_CONTROL_UNSUPPORTED,
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

int st_egress_normalize_version(int version)
{
    if (version < 1) {
        return 0;
    }
    return version > ST_EGRESS_PROTOCOL_VERSION ? ST_EGRESS_PROTOCOL_VERSION : version;
}

static int contained_in(uint32_t address, const char *const *cidrs, size_t cidrs_len)
{
    for (size_t i = 0U; i < cidrs_len; i++) {
        st_egress_cidr cidr;
        if (st_egress_parse_cidr(cidrs[i], &cidr) == 0 && st_egress_cidr_contains(&cidr, address)) {
            return 1;
        }
    }
    return 0;
}

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
    char match[sizeof(rule->match)];
    trim_into(match, sizeof(match), rule->match);
    if (match[0] == '\0') {
        return ST_EGRESS_CODE_RULE_MALFORMED;
    }
    if (strchr(match, ':') != NULL) {
        return ST_EGRESS_CODE_RULE_IPV6_UNSUPPORTED;
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

static int forced_deny_hit(const st_egress_request *request,
                           const st_egress_context *context,
                           uint32_t destination)
{
    if (contained_in(destination, ST_EGRESS_FORCED_DENY_CIDRS, ST_EGRESS_FORCED_DENY_CIDRS_LEN)) {
        return 1;
    }
    if (contained_in(destination, ST_EGRESS_CLOUD_METADATA_CIDRS, ST_EGRESS_CLOUD_METADATA_CIDRS_LEN)) {
        return 1;
    }
    const char *mesh = (context == NULL || context->mesh_cidr[0] == '\0')
        ? ST_EGRESS_DEFAULT_MESH_CIDR
        : context->mesh_cidr;
    st_egress_cidr mesh_cidr;
    if (st_egress_parse_cidr(mesh, &mesh_cidr) == 0 && st_egress_cidr_contains(&mesh_cidr, destination)) {
        return 1;
    }
    if (context != NULL) {
        for (size_t i = 0U; i < context->deployment_deny_cidrs_len; i++) {
            st_egress_cidr entry;
            if (st_egress_parse_cidr(context->deployment_deny_cidrs[i], &entry) == 0
                && st_egress_cidr_contains(&entry, destination)) {
                return 1;
            }
        }
    }
    for (size_t i = 0U; i < request->local_interface_cidrs_len; i++) {
        st_egress_cidr entry;
        if (st_egress_parse_cidr(request->local_interface_cidrs[i], &entry) == 0
            && st_egress_cidr_contains(&entry, destination)) {
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

    uint32_t destination = 0U;
    if (st_egress_parse_address(request->destination_ip, &destination) != 0) {
        deny(out, ST_EGRESS_CODE_DEST_DENIED);
        return;
    }
    if (forced_deny_hit(request, context, destination)) {
        deny(out, ST_EGRESS_CODE_FORBIDDEN_DESTINATION);
        return;
    }

    const char *scope = contained_in(destination, ST_EGRESS_LAN_CIDRS, ST_EGRESS_LAN_CIDRS_LEN)
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
        st_egress_cidr cidr;
        if (st_egress_parse_cidr(rule->cidr, &cidr) != 0 || !st_egress_cidr_contains(&cidr, destination)) {
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
    size_t used = 0U;
    int written = snprintf(out, capacity, "[");
    if (written < 0) {
        free(out);
        return NULL;
    }
    used = (size_t)written;
    for (size_t i = 0U; i < rules_len; i++) {
        char *escaped = st_json_escape(rules[i].cidr);
        if (escaped == NULL) {
            free(out);
            return NULL;
        }
        written = snprintf(out + used, capacity - used, "%s{\"cidr\":\"%s\",\"protocols\":[",
                           i == 0U ? "" : ",", escaped);
        free(escaped);
        if (written < 0 || (size_t)written >= capacity - used) {
            free(out);
            return NULL;
        }
        used += (size_t)written;
        for (size_t p = 0U; p < rules[i].protocols_len; p++) {
            char *protocol = st_json_escape(rules[i].protocols[p]);
            if (protocol == NULL) {
                free(out);
                return NULL;
            }
            written = snprintf(out + used, capacity - used, "%s\"%s\"", p == 0U ? "" : ",", protocol);
            free(protocol);
            if (written < 0 || (size_t)written >= capacity - used) {
                free(out);
                return NULL;
            }
            used += (size_t)written;
        }
        written = snprintf(out + used, capacity - used, "],\"portRanges\":[");
        if (written < 0 || (size_t)written >= capacity - used) {
            free(out);
            return NULL;
        }
        used += (size_t)written;
        for (size_t r = 0U; r < rules[i].port_ranges_len; r++) {
            written = snprintf(out + used, capacity - used, "%s[%d,%d]", r == 0U ? "" : ",",
                               rules[i].port_ranges[r][0], rules[i].port_ranges[r][1]);
            if (written < 0 || (size_t)written >= capacity - used) {
                free(out);
                return NULL;
            }
            used += (size_t)written;
        }
        written = snprintf(out + used, capacity - used, "]}");
        if (written < 0 || (size_t)written >= capacity - used) {
            free(out);
            return NULL;
        }
        used += (size_t)written;
    }
    written = snprintf(out + used, capacity - used, "]");
    if (written < 0 || (size_t)written >= capacity - used) {
        free(out);
        return NULL;
    }
    return out;
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
