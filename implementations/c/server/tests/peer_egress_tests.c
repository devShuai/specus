#include "json.h"
#include "peer_egress.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Binds this implementation to the shared vectors under protocol/test-vectors. The assertions check
 * the returned code, not just allow versus deny: a runtime that denies for the wrong reason still
 * leaves an operator unable to tell a revoked ACL from a closed port.
 */

#ifndef ST_EGRESS_VECTOR_DIR
#define ST_EGRESS_VECTOR_DIR "../../../protocol/test-vectors/"
#endif

static char *read_vector(const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s%s", ST_EGRESS_VECTOR_DIR, name);
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    long len = ftell(file);
    if (len < 0) {
        fclose(file);
        return NULL;
    }
    rewind(file);
    char *text = (char *)malloc((size_t)len + 1U);
    if (text == NULL) {
        fclose(file);
        return NULL;
    }
    if (fread(text, 1, (size_t)len, file) != (size_t)len) {
        free(text);
        fclose(file);
        return NULL;
    }
    fclose(file);
    text[len] = '\0';
    return text;
}

static int is_absent(const char *raw)
{
    return raw == NULL || strcmp(raw, "null") == 0;
}

static void load_consumer_ids(const char *raw, st_egress_policy *policy)
{
    char **ids = NULL;
    size_t ids_len = 0U;
    policy->allowed_consumer_client_ids_len = 0U;
    if (st_json_get_raw_array(raw, "allowedConsumerClientIds", &ids, &ids_len) != 0) {
        return;
    }
    for (size_t i = 0U; i < ids_len && policy->allowed_consumer_client_ids_len < ST_EGRESS_MAX_CONSUMERS; i++) {
        policy->allowed_consumer_client_ids[policy->allowed_consumer_client_ids_len++] =
            strtoll(ids[i], NULL, 10);
    }
    st_json_free_string_array(ids, ids_len);
}

static int load_policy(const char *raw, st_egress_policy *policy)
{
    memset(policy, 0, sizeof(*policy));
    long long egress_id = 0;
    if (st_json_get_i64(raw, "egressClientId", &egress_id) == 0) {
        policy->egress_client_id = egress_id;
    }
    int enabled = 0;
    if (st_json_get_bool(raw, "enabled", &enabled) == 0) {
        policy->enabled = enabled;
    }
    char *scope = st_json_get_string(raw, "scope");
    if (scope != NULL) {
        snprintf(policy->scope, sizeof(policy->scope), "%s", scope);
        free(scope);
    }
    load_consumer_ids(raw, policy);

    char *rules = st_json_get_top_level_raw(raw, "destinationRules");
    if (!is_absent(rules)
        && st_egress_parse_destination_rules(rules, policy->destination_rules,
                                             ST_EGRESS_MAX_DESTINATION_RULES,
                                             &policy->destination_rules_len) != 0) {
        free(rules);
        return 1;
    }
    free(rules);

    char *limits = st_json_get_top_level_raw(raw, "limits");
    if (!is_absent(limits)) {
        st_json_get_int(limits, "maxConcurrentFlows", &policy->limits.max_concurrent_flows);
        st_json_get_int(limits, "maxFlowsPerConsumer", &policy->limits.max_flows_per_consumer);
        st_json_get_int(limits, "idleTimeoutSeconds", &policy->limits.idle_timeout_seconds);
    }
    free(limits);
    return 0;
}

static void load_request(const char *raw, st_egress_request *request)
{
    memset(request, 0, sizeof(*request));
    long long consumer = 0;
    if (st_json_get_i64(raw, "consumerClientId", &consumer) == 0) {
        request->consumer_client_id = consumer;
    }
    char *ip = st_json_get_string(raw, "destinationIp");
    if (ip != NULL) {
        snprintf(request->destination_ip, sizeof(request->destination_ip), "%s", ip);
        free(ip);
    }
    char *protocol = st_json_get_string(raw, "protocol");
    if (protocol != NULL) {
        snprintf(request->protocol, sizeof(request->protocol), "%s", protocol);
        free(protocol);
    }
    st_json_get_int(raw, "destinationPort", &request->destination_port);
    st_json_get_int(raw, "activeFlowsForConsumer", &request->active_flows_for_consumer);
    st_json_get_int(raw, "activeFlowsTotal", &request->active_flows_total);
    st_json_get_bool(raw, "hop", &request->hop);

    char **locals = NULL;
    size_t locals_len = 0U;
    if (st_json_get_string_array(raw, "localInterfaceCidrs", &locals, &locals_len) == 0) {
        for (size_t i = 0U; i < locals_len && request->local_interface_cidrs_len < ST_EGRESS_MAX_LOCAL_INTERFACES; i++) {
            snprintf(request->local_interface_cidrs[request->local_interface_cidrs_len],
                     sizeof(request->local_interface_cidrs[0]), "%s", locals[i]);
            request->local_interface_cidrs_len++;
        }
    }
    st_json_free_string_array(locals, locals_len);
}

/*
 * The mesh network reaches the implementation through the deployment context rather than the static
 * list, so it is lifted back out of the vector's forced-deny set by its prefix length.
 */
static void context_for(const char *vector, st_egress_context *context)
{
    st_egress_context_init(context);
    char **denied = NULL;
    size_t denied_len = 0U;
    if (st_json_get_string_array(vector, "forcedDenyCidrs", &denied, &denied_len) != 0) {
        return;
    }
    for (size_t i = 0U; i < denied_len; i++) {
        st_egress_cidr cidr;
        if (st_egress_parse_cidr(denied[i], &cidr) == 0 && cidr.prefix_length == 11) {
            snprintf(context->mesh_cidr, sizeof(context->mesh_cidr), "%s", denied[i]);
        }
    }
    st_json_free_string_array(denied, denied_len);
}

static int expect_code(const char *label, const char *actual, const char *expected)
{
    if (actual == NULL) {
        actual = "(null)";
    }
    if (strcmp(actual, expected) != 0) {
        fprintf(stderr, "%s: code = %s, want %s\n", label, actual, expected);
        return 1;
    }
    return 0;
}

static int run_authorization_cases(const char *vector)
{
    st_egress_context context;
    context_for(vector, &context);

    char *policy_raw = st_json_get_top_level_raw(vector, "policy");
    st_egress_policy policy;
    if (policy_raw == NULL || load_policy(policy_raw, &policy) != 0) {
        fprintf(stderr, "authorization vector policy did not load\n");
        free(policy_raw);
        return 1;
    }
    free(policy_raw);

    char **cases = NULL;
    size_t cases_len = 0U;
    if (st_json_get_raw_array(vector, "cases", &cases, &cases_len) != 0 || cases_len == 0U) {
        fprintf(stderr, "authorization vector carried no cases\n");
        st_json_free_string_array(cases, cases_len);
        return 1;
    }
    int failures = 0;
    for (size_t i = 0U; i < cases_len; i++) {
        char *name = st_json_get_string(cases[i], "name");
        char *request_raw = st_json_get_top_level_raw(cases[i], "request");
        char *expect_raw = st_json_get_top_level_raw(cases[i], "expect");
        if (name == NULL || request_raw == NULL || expect_raw == NULL) {
            fprintf(stderr, "authorization case %zu is incomplete\n", i);
            failures++;
        } else {
            st_egress_request request;
            load_request(request_raw, &request);
            char *expected = st_json_get_string(expect_raw, "code");
            int expected_allowed = 0;
            st_json_get_bool(expect_raw, "allowed", &expected_allowed);
            st_egress_decision decision;
            st_egress_authorize(&request, &policy, 1, &context, &decision);
            failures += expect_code(name, decision.code, expected == NULL ? "" : expected);
            if (decision.allowed != expected_allowed) {
                fprintf(stderr, "%s: allowed = %d, want %d\n", name, decision.allowed, expected_allowed);
                failures++;
            }
            free(expected);
        }
        free(name);
        free(request_raw);
        free(expect_raw);
    }
    st_json_free_string_array(cases, cases_len);
    return failures;
}

static int run_policy_variants(const char *vector)
{
    st_egress_context context;
    context_for(vector, &context);

    char *policy_raw = st_json_get_top_level_raw(vector, "policy");
    st_egress_policy base;
    if (policy_raw == NULL || load_policy(policy_raw, &base) != 0) {
        fprintf(stderr, "policy variant base policy did not load\n");
        free(policy_raw);
        return 1;
    }
    free(policy_raw);

    char **cases = NULL;
    size_t cases_len = 0U;
    if (st_json_get_raw_array(vector, "policyVariantCases", &cases, &cases_len) != 0 || cases_len == 0U) {
        fprintf(stderr, "authorization vector carried no policy variants\n");
        st_json_free_string_array(cases, cases_len);
        return 1;
    }
    int failures = 0;
    for (size_t i = 0U; i < cases_len; i++) {
        char *name = st_json_get_string(cases[i], "name");
        char *request_raw = st_json_get_top_level_raw(cases[i], "request");
        char *expect_raw = st_json_get_top_level_raw(cases[i], "expect");
        char *override_raw = st_json_get_top_level_raw(cases[i], "policyOverride");
        if (name == NULL || request_raw == NULL || expect_raw == NULL) {
            fprintf(stderr, "policy variant %zu is incomplete\n", i);
            failures++;
        } else {
            st_egress_policy policy = base;
            if (!is_absent(override_raw)) {
                int enabled = 0;
                if (st_json_get_bool(override_raw, "enabled", &enabled) == 0) {
                    policy.enabled = enabled;
                }
                char *scope = st_json_get_string(override_raw, "scope");
                if (scope != NULL) {
                    snprintf(policy.scope, sizeof(policy.scope), "%s", scope);
                    free(scope);
                }
                char *rules = st_json_get_top_level_raw(override_raw, "destinationRules");
                if (!is_absent(rules)) {
                    policy.destination_rules_len = 0U;
                    st_egress_parse_destination_rules(rules, policy.destination_rules,
                                                      ST_EGRESS_MAX_DESTINATION_RULES,
                                                      &policy.destination_rules_len);
                }
                free(rules);
            }
            int peer_acl_allows = 1;
            st_json_get_bool(cases[i], "peerAclAllows", &peer_acl_allows);

            st_egress_request request;
            load_request(request_raw, &request);
            char *expected = st_json_get_string(expect_raw, "code");
            st_egress_decision decision;
            st_egress_authorize(&request, &policy, peer_acl_allows, &context, &decision);
            failures += expect_code(name, decision.code, expected == NULL ? "" : expected);
            free(expected);
        }
        free(name);
        free(request_raw);
        free(expect_raw);
        free(override_raw);
    }
    st_json_free_string_array(cases, cases_len);
    return failures;
}

/*
 * The vector policy deliberately contains a 0.0.0.0/0 rule. Every address the vector declares as
 * forced-deny must still be refused through it.
 */
static int run_forced_deny_cases(const char *vector)
{
    st_egress_context context;
    context_for(vector, &context);

    char *policy_raw = st_json_get_top_level_raw(vector, "policy");
    st_egress_policy policy;
    if (policy_raw == NULL || load_policy(policy_raw, &policy) != 0) {
        fprintf(stderr, "forced deny base policy did not load\n");
        free(policy_raw);
        return 1;
    }
    free(policy_raw);

    int broad = 0;
    for (size_t i = 0U; i < policy.destination_rules_len; i++) {
        if (strcmp(policy.destination_rules[i].cidr, "0.0.0.0/0") == 0) {
            broad = 1;
        }
    }
    if (!broad) {
        fprintf(stderr, "vector policy must keep a broad rule, otherwise this test proves nothing\n");
        return 1;
    }

    int failures = 0;
    const char *keys[] = { "forcedDenyCidrs", "cloudMetadataCidrs" };
    for (size_t k = 0U; k < sizeof(keys) / sizeof(keys[0]); k++) {
        char **entries = NULL;
        size_t entries_len = 0U;
        if (st_json_get_string_array(vector, keys[k], &entries, &entries_len) != 0 || entries_len == 0U) {
            fprintf(stderr, "vector declared no %s\n", keys[k]);
            st_json_free_string_array(entries, entries_len);
            return failures + 1;
        }
        for (size_t i = 0U; i < entries_len; i++) {
            st_egress_cidr cidr;
            if (st_egress_parse_cidr(entries[i], &cidr) != 0) {
                fprintf(stderr, "%s: not a prefix\n", entries[i]);
                failures++;
                continue;
            }
            st_egress_request request;
            memset(&request, 0, sizeof(request));
            request.consumer_client_id = 1;
            st_egress_format_address(cidr.network, request.destination_ip, sizeof(request.destination_ip));
            request.destination_port = 443;
            snprintf(request.protocol, sizeof(request.protocol), "tcp");
            st_egress_decision decision;
            st_egress_authorize(&request, &policy, 1, &context, &decision);
            failures += expect_code(entries[i], decision.code, ST_EGRESS_CODE_FORBIDDEN_DESTINATION);
        }
        st_json_free_string_array(entries, entries_len);
    }
    return failures;
}

static void load_rule(const char *raw, st_egress_rule *rule)
{
    memset(rule, 0, sizeof(*rule));
    char *match = st_json_get_string(raw, "match");
    if (match != NULL) {
        snprintf(rule->match, sizeof(rule->match), "%s", match);
        free(match);
    }
    char *action = st_json_get_string(raw, "action");
    if (action != NULL) {
        snprintf(rule->action, sizeof(rule->action), "%s", action);
        free(action);
    }
    long long egress_id = 0;
    if (st_json_get_i64(raw, "egressClientId", &egress_id) == 0) {
        rule->egress_client_id = egress_id;
        rule->has_egress_client_id = 1;
    }
    int port = 0;
    if (st_json_get_int(raw, "port", &port) == 0) {
        rule->port = port;
        rule->has_port = 1;
    }
}

static int load_rules(const char *vector, st_egress_rule *rules, size_t capacity, size_t *out_len)
{
    char **raw = NULL;
    size_t raw_len = 0U;
    *out_len = 0U;
    if (st_json_get_raw_array(vector, "rules", &raw, &raw_len) != 0 || raw_len == 0U) {
        fprintf(stderr, "rules vector carried no rules\n");
        st_json_free_string_array(raw, raw_len);
        return 1;
    }
    for (size_t i = 0U; i < raw_len && *out_len < capacity; i++) {
        load_rule(raw[i], &rules[*out_len]);
        (*out_len)++;
    }
    st_json_free_string_array(raw, raw_len);
    return 0;
}

static int run_rule_matching(const char *vector)
{
    st_egress_rule rules[ST_EGRESS_MAX_DESTINATION_RULES];
    size_t rules_len = 0U;
    if (load_rules(vector, rules, ST_EGRESS_MAX_DESTINATION_RULES, &rules_len) != 0) {
        return 1;
    }
    char **cases = NULL;
    size_t cases_len = 0U;
    if (st_json_get_raw_array(vector, "cases", &cases, &cases_len) != 0 || cases_len == 0U) {
        fprintf(stderr, "rules vector carried no cases\n");
        st_json_free_string_array(cases, cases_len);
        return 1;
    }
    int failures = 0;
    for (size_t i = 0U; i < cases_len; i++) {
        char *name = st_json_get_string(cases[i], "name");
        char *destination = st_json_get_string(cases[i], "destination");
        char *expect_raw = st_json_get_top_level_raw(cases[i], "expect");
        if (name == NULL || destination == NULL || expect_raw == NULL) {
            fprintf(stderr, "rule case %zu is incomplete\n", i);
            failures++;
        } else {
            st_egress_match match;
            st_egress_match_rules(rules, rules_len, destination, &match);
            char *expected_action = st_json_get_string(expect_raw, "action");
            if (expected_action == NULL || strcmp(match.action, expected_action) != 0) {
                fprintf(stderr, "%s: action = %s, want %s\n", name, match.action,
                        expected_action == NULL ? "(null)" : expected_action);
                failures++;
            }
            free(expected_action);

            int expected_index = 0;
            int has_index = st_json_get_int(expect_raw, "matchedRuleIndex", &expected_index) == 0;
            if (!has_index) {
                if (match.matched_rule_index >= 0) {
                    fprintf(stderr, "%s: expected no match, got rule %d\n", name, match.matched_rule_index);
                    failures++;
                }
            } else if (match.matched_rule_index != expected_index) {
                fprintf(stderr, "%s: matched rule %d, want %d\n", name, match.matched_rule_index,
                        expected_index);
                failures++;
            }

            long long expected_egress = 0;
            if (st_json_get_i64(expect_raw, "egressClientId", &expected_egress) == 0
                && (!match.has_egress_client_id || match.egress_client_id != expected_egress)) {
                fprintf(stderr, "%s: egress client id mismatch\n", name);
                failures++;
            }
        }
        free(name);
        free(destination);
        free(expect_raw);
    }
    st_json_free_string_array(cases, cases_len);
    return failures;
}

static int run_rule_validation(const char *vector)
{
    char *mesh = st_json_get_string(vector, "meshCidr");
    const char *mesh_cidr = mesh == NULL ? ST_EGRESS_DEFAULT_MESH_CIDR : mesh;

    st_egress_rule rules[ST_EGRESS_MAX_DESTINATION_RULES];
    size_t rules_len = 0U;
    if (load_rules(vector, rules, ST_EGRESS_MAX_DESTINATION_RULES, &rules_len) != 0) {
        free(mesh);
        return 1;
    }
    int failures = 0;
    for (size_t i = 0U; i < rules_len; i++) {
        const char *code = st_egress_validate_rule(&rules[i], mesh_cidr);
        if (code != NULL) {
            fprintf(stderr, "rule %s must pass validation, got %s\n", rules[i].match, code);
            failures++;
        }
    }

    char **cases = NULL;
    size_t cases_len = 0U;
    if (st_json_get_raw_array(vector, "configValidation", &cases, &cases_len) != 0 || cases_len == 0U) {
        fprintf(stderr, "rules vector carried no configValidation cases\n");
        st_json_free_string_array(cases, cases_len);
        free(mesh);
        return failures + 1;
    }
    for (size_t i = 0U; i < cases_len; i++) {
        char *name = st_json_get_string(cases[i], "name");
        char *rule_raw = st_json_get_top_level_raw(cases[i], "rule");
        char *expected = st_json_get_string(cases[i], "code");
        if (name == NULL || rule_raw == NULL || expected == NULL) {
            fprintf(stderr, "configValidation case %zu is incomplete\n", i);
            failures++;
        } else {
            st_egress_rule rule;
            load_rule(rule_raw, &rule);
            const char *code = st_egress_validate_rule(&rule, mesh_cidr);
            failures += expect_code(name, code, expected);
        }
        free(name);
        free(rule_raw);
        free(expected);
    }
    st_json_free_string_array(cases, cases_len);
    free(mesh);
    return failures;
}

/*
 * The address parser sits in front of every access decision, so its rejections matter as much as
 * its accepts. Anything it accepts loosely here is a difference the other runtimes can disagree on.
 */
static int run_parser_boundaries(void)
{
    int failures = 0;
    uint32_t value = 0U;

    const char *canonical[] = { "0.0.0.0", "255.255.255.255", "203.0.113.200", "0.1.2.3" };
    for (size_t i = 0U; i < sizeof(canonical) / sizeof(canonical[0]); i++) {
        if (st_egress_parse_address(canonical[i], &value) != 0) {
            fprintf(stderr, "%s should parse\n", canonical[i]);
            failures++;
        }
    }
    char rendered[16];
    if (st_egress_parse_address("203.0.113.200", &value) != 0) {
        failures++;
    } else {
        st_egress_format_address(value, rendered, sizeof(rendered));
        if (strcmp(rendered, "203.0.113.200") != 0) {
            fprintf(stderr, "round trip = %s\n", rendered);
            failures++;
        }
    }

    /* Runtimes disagree on 010: decimal ten or octal eight. */
    const char *leading_zero[] = { "010.1.1.1", "1.02.3.4", "1.2.3.00" };
    for (size_t i = 0U; i < sizeof(leading_zero) / sizeof(leading_zero[0]); i++) {
        if (st_egress_parse_address(leading_zero[i], &value) == 0) {
            fprintf(stderr, "%s should be rejected\n", leading_zero[i]);
            failures++;
        }
    }

    const char *malformed[] = {
        "", "1.2.3", "1.2.3.4.5", "1.2.3.", ".1.2.3",
        "1.2.3.256", "1.2.3.4444", "1.2.3.-4", "1.2.3.4 ", "::1",
    };
    for (size_t i = 0U; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
        if (st_egress_parse_address(malformed[i], &value) == 0) {
            fprintf(stderr, "%s should be rejected\n", malformed[i]);
            failures++;
        }
    }

    st_egress_cidr cidr;
    if (st_egress_parse_cidr("203.0.113.0/24", &cidr) != 0) {
        fprintf(stderr, "203.0.113.0/24 should parse\n");
        failures++;
    }
    const char *bad_cidrs[] = { "203.0.113.1/24", "203.0.113.0/33", "203.0.113.0/08", "203.0.113.0/" };
    for (size_t i = 0U; i < sizeof(bad_cidrs) / sizeof(bad_cidrs[0]); i++) {
        if (st_egress_parse_cidr(bad_cidrs[i], &cidr) == 0) {
            fprintf(stderr, "%s should be rejected\n", bad_cidrs[i]);
            failures++;
        }
    }
    if (st_egress_parse_cidr("203.0.113.9", &cidr) != 0 || cidr.prefix_length != ST_EGRESS_MAX_PREFIX) {
        fprintf(stderr, "a bare address should become a host prefix\n");
        failures++;
    }

    st_egress_cidr slash24;
    st_egress_cidr slash25;
    st_egress_cidr other;
    st_egress_cidr everything;
    uint32_t broadcast = 0U;
    uint32_t below = 0U;
    uint32_t anywhere = 0U;
    if (st_egress_parse_cidr("203.0.113.0/24", &slash24) != 0
        || st_egress_parse_cidr("203.0.113.128/25", &slash25) != 0
        || st_egress_parse_cidr("198.51.100.0/24", &other) != 0
        || st_egress_parse_cidr("0.0.0.0/0", &everything) != 0
        || st_egress_parse_address("203.0.113.255", &broadcast) != 0
        || st_egress_parse_address("203.0.113.127", &below) != 0
        || st_egress_parse_address("8.8.8.8", &anywhere) != 0) {
        fprintf(stderr, "containment fixtures did not parse\n");
        return failures + 1;
    }
    if (!st_egress_cidr_contains(&slash24, broadcast)
        || st_egress_cidr_contains(&slash25, below)
        || !st_egress_cidr_overlaps(&slash24, &slash25)
        || !st_egress_cidr_overlaps(&slash25, &slash24)
        || st_egress_cidr_overlaps(&slash24, &other)
        || !st_egress_cidr_contains(&everything, anywhere)) {
        fprintf(stderr, "containment or overlap does not follow prefix length\n");
        failures++;
    }
    return failures;
}

/* An unreadable row must deny everything rather than fall back to something permissive. */
static int run_storage_round_trip(void)
{
    int failures = 0;
    st_egress_destination_rule rules[ST_EGRESS_MAX_DESTINATION_RULES];
    size_t rules_len = 0U;

    const char *stored = "[{\"cidr\":\"203.0.113.0/24\",\"protocols\":[\"tcp\"],\"portRanges\":[[443,443]]}]";
    if (st_egress_parse_destination_rules(stored, rules, ST_EGRESS_MAX_DESTINATION_RULES, &rules_len) != 0
        || rules_len != 1U
        || strcmp(rules[0].cidr, "203.0.113.0/24") != 0
        || rules[0].protocols_len != 1U || strcmp(rules[0].protocols[0], "tcp") != 0
        || rules[0].port_ranges_len != 1U
        || rules[0].port_ranges[0][0] != 443 || rules[0].port_ranges[0][1] != 443) {
        fprintf(stderr, "stored destination rules did not parse\n");
        failures++;
    }

    char *encoded = st_egress_encode_destination_rules(rules, rules_len);
    if (encoded == NULL || strstr(encoded, "203.0.113.0/24") == NULL
        || strstr(encoded, "[443,443]") == NULL) {
        fprintf(stderr, "destination rules did not round trip\n");
        failures++;
    }
    free(encoded);

    rules_len = 0U;
    if (st_egress_parse_destination_rules("not json at all", rules,
                                          ST_EGRESS_MAX_DESTINATION_RULES, &rules_len) == 0
        || rules_len != 0U) {
        fprintf(stderr, "an unreadable row must yield no rules\n");
        failures++;
    }
    rules_len = 0U;
    if (st_egress_parse_destination_rules("", rules, ST_EGRESS_MAX_DESTINATION_RULES, &rules_len) != 0
        || rules_len != 0U) {
        fprintf(stderr, "an empty row must yield no rules\n");
        failures++;
    }

    st_egress_destination_rule oversized[ST_EGRESS_MAX_DESTINATION_RULES];
    memset(oversized, 0, sizeof(oversized));
    for (size_t i = 0U; i < ST_EGRESS_MAX_DESTINATION_RULES; i++) {
        snprintf(oversized[i].cidr, sizeof(oversized[i].cidr), "203.0.%u.0/24", (unsigned)i);
        snprintf(oversized[i].protocols[0], sizeof(oversized[i].protocols[0]), "tcp");
        snprintf(oversized[i].protocols[1], sizeof(oversized[i].protocols[1]), "udp");
        oversized[i].protocols_len = 2U;
        for (size_t r = 0U; r < 20U; r++) {
            oversized[i].port_ranges[r][0] = (int)r + 1;
            oversized[i].port_ranges[r][1] = (int)r + 101;
        }
        oversized[i].port_ranges_len = 20U;
    }
    char *rejected = st_egress_encode_destination_rules(oversized, ST_EGRESS_MAX_DESTINATION_RULES);
    if (rejected != NULL) {
        fprintf(stderr, "an oversized allowlist must not encode\n");
        failures++;
    }
    free(rejected);

    char protocols[ST_EGRESS_MAX_PROTOCOLS][8];
    size_t count = st_egress_collect_protocols(oversized, 2U, protocols, ST_EGRESS_MAX_PROTOCOLS);
    if (count != 2U || strcmp(protocols[0], "tcp") != 0 || strcmp(protocols[1], "udp") != 0) {
        fprintf(stderr, "protocol collection must keep first-seen order without duplicates\n");
        failures++;
    }
    return failures;
}

/*
 * Boundary sweep shared by every runtime.
 *
 * The hand-written cases document intent; this exists to catch a runtime that agrees on the
 * documented examples but diverges one address or one port away from a boundary. Every runtime runs
 * the same sweep against the same policy, so a disagreement here is a disagreement about the rules
 * rather than about the fixture.
 */
static int run_cross_language_sweep(const char *vector)
{
    st_egress_context context;
    context_for(vector, &context);

    char *policy_raw = st_json_get_top_level_raw(vector, "policy");
    st_egress_policy policy;
    if (policy_raw == NULL || load_policy(policy_raw, &policy) != 0) {
        fprintf(stderr, "cross-language sweep policy did not load\n");
        free(policy_raw);
        return 1;
    }
    free(policy_raw);

    char **cases = NULL;
    size_t cases_len = 0U;
    if (st_json_get_raw_array(vector, "crossLanguageCases", &cases, &cases_len) != 0
        || cases_len < 100U) {
        fprintf(stderr, "cross-language sweep carried only %zu cases\n", cases_len);
        st_json_free_string_array(cases, cases_len);
        return 1;
    }
    int failures = 0;
    for (size_t i = 0U; i < cases_len; i++) {
        char *name = st_json_get_string(cases[i], "name");
        char *request_raw = st_json_get_top_level_raw(cases[i], "request");
        char *expect_raw = st_json_get_top_level_raw(cases[i], "expect");
        if (name == NULL || request_raw == NULL || expect_raw == NULL) {
            fprintf(stderr, "cross-language case %zu is incomplete\n", i);
            failures++;
        } else {
            st_egress_request request;
            load_request(request_raw, &request);
            char *expected = st_json_get_string(expect_raw, "code");
            int expected_allowed = 0;
            st_json_get_bool(expect_raw, "allowed", &expected_allowed);
            st_egress_decision decision;
            st_egress_authorize(&request, &policy, 1, &context, &decision);
            failures += expect_code(name, decision.code, expected == NULL ? "" : expected);
            if (decision.allowed != expected_allowed) {
                fprintf(stderr, "%s: allowed = %d, want %d\n", name, decision.allowed,
                        expected_allowed);
                failures++;
            }
            free(expected);
        }
        free(name);
        free(request_raw);
        free(expect_raw);
    }
    st_json_free_string_array(cases, cases_len);
    return failures;
}

int main(void)
{
    char *authz = read_vector("peer-egress-authz-v1.json");
    char *rules = read_vector("peer-egress-rules-v1.json");
    if (authz == NULL || rules == NULL) {
        free(authz);
        free(rules);
        return 1;
    }
    int failures = 0;
    failures += run_authorization_cases(authz);
    failures += run_policy_variants(authz);
    failures += run_cross_language_sweep(authz);
    failures += run_forced_deny_cases(authz);
    failures += run_rule_matching(rules);
    failures += run_rule_validation(rules);
    failures += run_parser_boundaries();
    failures += run_storage_round_trip();
    free(authz);
    free(rules);
    if (failures != 0) {
        fprintf(stderr, "peer egress: %d assertion(s) failed\n", failures);
        return 1;
    }
    return 0;
}
