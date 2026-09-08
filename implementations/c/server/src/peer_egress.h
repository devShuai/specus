#ifndef SPECUS_PEER_EGRESS_H
#define SPECUS_PEER_EGRESS_H

/*
 * Peer egress rule and authorization semantics, as defined by protocol/spec/peer-egress.md.
 *
 * Free of storage and transport concerns so the shared vectors under protocol/test-vectors can
 * drive it directly. Every result code is exercised by a vector: implementations must agree on
 * which code a request fails with, not merely on allow versus deny, because an operator seeing
 * only "denied" cannot tell a revoked ACL from a closed port.
 */

#include <stddef.h>
#include <stdint.h>

#define ST_EGRESS_CODE_ALLOWED "EGRESS_ALLOWED"

/* Authorization, evaluated in this order. */
#define ST_EGRESS_CODE_HOP_NOT_ALLOWED "EGRESS_HOP_NOT_ALLOWED"
#define ST_EGRESS_CODE_DISABLED "EGRESS_DISABLED"
#define ST_EGRESS_CODE_PEER_ACL_DENIED "EGRESS_PEER_ACL_DENIED"
#define ST_EGRESS_CODE_CONSUMER_DENIED "EGRESS_CONSUMER_DENIED"
#define ST_EGRESS_CODE_FORBIDDEN_DESTINATION "EGRESS_FORBIDDEN_DESTINATION"
#define ST_EGRESS_CODE_SCOPE_DENIED "EGRESS_SCOPE_DENIED"
#define ST_EGRESS_CODE_DEST_DENIED "EGRESS_DEST_DENIED"
#define ST_EGRESS_CODE_PROTOCOL_DENIED "EGRESS_PROTOCOL_DENIED"
#define ST_EGRESS_CODE_PORT_DENIED "EGRESS_PORT_DENIED"
#define ST_EGRESS_CODE_LIMIT_EXCEEDED "EGRESS_LIMIT_EXCEEDED"

/* Consumer rule configuration validation. */
#define ST_EGRESS_CODE_RULE_DOMAIN_UNSUPPORTED "EGRESS_RULE_DOMAIN_UNSUPPORTED"
#define ST_EGRESS_CODE_RULE_IPV6_UNSUPPORTED "EGRESS_RULE_IPV6_UNSUPPORTED"
#define ST_EGRESS_CODE_RULE_MALFORMED "EGRESS_RULE_MALFORMED"
#define ST_EGRESS_CODE_RULE_MISSING_TARGET "EGRESS_RULE_MISSING_TARGET"
#define ST_EGRESS_CODE_RULE_MESH_OVERLAP "EGRESS_RULE_MESH_OVERLAP"
#define ST_EGRESS_CODE_RULE_DEFAULT_ROUTE "EGRESS_RULE_DEFAULT_ROUTE"
#define ST_EGRESS_CODE_RULE_PORT_UNSUPPORTED "EGRESS_RULE_PORT_UNSUPPORTED"

/* SPEG1 frame decoding. */
#define ST_EGRESS_CODE_FRAME_BAD_MAGIC "EGRESS_FRAME_BAD_MAGIC"
#define ST_EGRESS_CODE_FRAME_UNKNOWN_TYPE "EGRESS_FRAME_UNKNOWN_TYPE"
#define ST_EGRESS_CODE_FRAME_RESERVED_SET "EGRESS_FRAME_RESERVED_SET"
#define ST_EGRESS_CODE_FRAME_TRUNCATED "EGRESS_FRAME_TRUNCATED"
#define ST_EGRESS_CODE_FRAME_TRAILING_BYTES "EGRESS_FRAME_TRAILING_BYTES"
#define ST_EGRESS_CODE_IPV6_UNSUPPORTED "EGRESS_IPV6_UNSUPPORTED"
#define ST_EGRESS_CODE_FRAME_MALFORMED_CONTROL "EGRESS_FRAME_MALFORMED_CONTROL"
#define ST_EGRESS_CODE_CONTROL_UNSUPPORTED "EGRESS_CONTROL_UNSUPPORTED"

/* Rule actions. */
#define ST_EGRESS_ACTION_EGRESS "egress"
#define ST_EGRESS_ACTION_DIRECT "direct"
#define ST_EGRESS_ACTION_BLOCK "block"

/* Policy scopes. Public and LAN access are authorised separately; neither implies the other. */
#define ST_EGRESS_SCOPE_PUBLIC "PUBLIC"
#define ST_EGRESS_SCOPE_LAN "LAN"

/*
 * The split-routing version this build speaks. Tracked separately from the individual target
 * capabilities so a later release adding domain rules can coexist with clients that only understand
 * address targets, instead of gating everything on the version number alone.
 */
#define ST_EGRESS_PROTOCOL_VERSION 1

/* The widest IPv4 prefix length. */
#define ST_EGRESS_MAX_PREFIX 32

/* The Peer Mesh virtual network unless the deployment overrides it. */
#define ST_EGRESS_DEFAULT_MESH_CIDR "100.96.0.0/11"

#define ST_EGRESS_MAX_PROTOCOLS 4
#define ST_EGRESS_MAX_PORT_RANGES 32
#define ST_EGRESS_MAX_DESTINATION_RULES 64
#define ST_EGRESS_MAX_CONSUMERS 32
#define ST_EGRESS_MAX_LOCAL_INTERFACES 8
#define ST_EGRESS_MAX_DEPLOYMENT_DENY 8

/* Matches the column width in every schema dialect. */
#define ST_EGRESS_MAX_DESTINATION_RULES_BYTES 4096

/*
 * An IPv4 prefix.
 *
 * Parsing is strict on purpose: a prefix whose host bits are set is rejected rather than masked,
 * and a leading-zero octet is rejected rather than tolerated. Runtimes disagree about 010 --
 * decimal ten or octal eight -- and an access rule that means different things in different
 * implementations is worse than one the operator has to rewrite.
 */
typedef struct {
    uint32_t network;
    int prefix_length;
} st_egress_cidr;

/* Reads four canonical dotted-decimal octets. Returns 0 on success. */
int st_egress_parse_address(const char *text, uint32_t *out);
/* Reads an IPv4 address or prefix; a bare address becomes a /32. Returns 0 on success. */
int st_egress_parse_cidr(const char *text, st_egress_cidr *out);
/* Renders an address in dotted-decimal form. out_len must be at least 16. */
void st_egress_format_address(uint32_t value, char *out, size_t out_len);
int st_egress_cidr_contains(const st_egress_cidr *cidr, uint32_t address);
int st_egress_cidr_overlaps(const st_egress_cidr *left, const st_egress_cidr *right);

/*
 * Clamps a client-announced version to what this build understands. Returns 0 when the client
 * cannot take part, in which case the server must not push egress-config or egress-catalog to it.
 */
int st_egress_normalize_version(int version);

/*
 * One consumer-side split-routing rule.
 *
 * Rules match on destination address only. The consumer steers traffic by installing routes and a
 * route selects on destination address alone, so a port-scoped rule could neither be expressed as
 * a route nor cleanly returned to the local stack once the packet had been captured. Port and
 * protocol limits live on the egress policy and are enforced when the flow is opened.
 */
typedef struct {
    char match[128];
    char action[16];
    long long egress_client_id;
    int has_egress_client_id;
    /* Present only so a configuration carrying it can be rejected with a specific code. */
    int port;
    int has_port;
} st_egress_rule;

/* The outcome of evaluating a destination against an ordered rule list. */
typedef struct {
    char action[16];
    int matched_rule_index; /* -1 when nothing matched */
    long long egress_client_id;
    int has_egress_client_id;
} st_egress_match;

/*
 * Returns the failing code, or NULL when the rule is acceptable.
 *
 * The checks run in a fixed order so every implementation reports the same code for a rule that
 * violates more than one constraint.
 */
const char *st_egress_validate_rule(const st_egress_rule *rule, const char *mesh_cidr);

/*
 * Resolves a destination against an ordered rule list.
 *
 * Longest prefix wins; when two rules share a prefix length the earlier one wins. An unmatched
 * destination resolves to direct. That is the routing table's own behaviour rather than a fallback
 * branch: a destination with no installed route never reaches the tunnel device in the first place.
 */
void st_egress_match_rules(const st_egress_rule *rules,
                           size_t rules_len,
                           const char *destination,
                           st_egress_match *out);

/* One entry of an egress policy allowlist. */
typedef struct {
    char cidr[64];
    char protocols[ST_EGRESS_MAX_PROTOCOLS][8];
    size_t protocols_len;
    int port_ranges[ST_EGRESS_MAX_PORT_RANGES][2];
    size_t port_ranges_len;
} st_egress_destination_rule;

/* Limits that keep an egress node from acting as an open proxy. */
typedef struct {
    int max_concurrent_flows;
    int max_flows_per_consumer;
    int idle_timeout_seconds;
} st_egress_limits;

/* The egress-side authorization policy owned by the server. */
typedef struct {
    long long egress_client_id;
    int enabled;
    long long allowed_consumer_client_ids[ST_EGRESS_MAX_CONSUMERS];
    size_t allowed_consumer_client_ids_len;
    char scope[16];
    st_egress_destination_rule destination_rules[ST_EGRESS_MAX_DESTINATION_RULES];
    size_t destination_rules_len;
    st_egress_limits limits;
} st_egress_policy;

/* One flow-open attempt, evaluated before any socket is created. */
typedef struct {
    long long consumer_client_id;
    char destination_ip[64];
    int destination_port;
    char protocol[8];
    int hop;
    int active_flows_for_consumer;
    int active_flows_total;
    /*
     * Networks owned by this node's own tunnel or virtual interfaces. Forwarding into one of them
     * would loop back into this node's own capture path.
     */
    char local_interface_cidrs[ST_EGRESS_MAX_LOCAL_INTERFACES][64];
    size_t local_interface_cidrs_len;
} st_egress_request;

/* The outcome of an authorization evaluation. */
typedef struct {
    int allowed;
    const char *code;
} st_egress_decision;

/* Deployment-wide additions to the forced-deny list. */
typedef struct {
    char mesh_cidr[64];
    /* The control, STUN and TURN endpoint addresses for this deployment. */
    char deployment_deny_cidrs[ST_EGRESS_MAX_DEPLOYMENT_DENY][64];
    size_t deployment_deny_cidrs_len;
} st_egress_context;

/* Initialises a context for a deployment on the default mesh network. */
void st_egress_context_init(st_egress_context *out);

/*
 * Evaluates one flow-open attempt.
 *
 * The checks run in the fixed order given by protocol/spec/peer-egress.md so implementations agree
 * on which code a request fails with, not merely on allow versus deny.
 */
void st_egress_authorize(const st_egress_request *request,
                         const st_egress_policy *policy,
                         int peer_acl_allows,
                         const st_egress_context *context,
                         st_egress_decision *out);

/*
 * Destinations that stay denied no matter what the policy says. A rule as broad as 0.0.0.0/0 must
 * not reach loopback, link-local, cloud metadata, multicast, broadcast or the mesh itself, so this
 * list is consulted before any destination rule.
 */
extern const char *const ST_EGRESS_FORCED_DENY_CIDRS[];
extern const size_t ST_EGRESS_FORCED_DENY_CIDRS_LEN;

/*
 * Well-known instance metadata endpoints, denied independently of the link-local block so that the
 * intent survives a future change to that block.
 */
extern const char *const ST_EGRESS_CLOUD_METADATA_CIDRS[];
extern const size_t ST_EGRESS_CLOUD_METADATA_CIDRS_LEN;

/* RFC 1918 private use plus RFC 6598 shared address space. */
/*
 * Every result code this build defines, built from the macros above rather than repeated as
 * literals. Used to filter client-reported refusal counters: without it a client could grow the
 * stored map with keys of its own invention.
 */
extern const char *const ST_EGRESS_ALL_CODES[];
extern const size_t ST_EGRESS_ALL_CODES_LEN;
int st_egress_is_known_code(const char *code);

extern const char *const ST_EGRESS_LAN_CIDRS[];
extern const size_t ST_EGRESS_LAN_CIDRS_LEN;

/*
 * Reads a stored allowlist. A row that cannot be parsed yields zero rules, which denies everything
 * rather than falling back to something permissive. Returns 0 when the input parsed cleanly.
 */
int st_egress_parse_destination_rules(const char *json,
                                      st_egress_destination_rule *out,
                                      size_t capacity,
                                      size_t *out_len);

/*
 * Serialises an allowlist for storage. Returns a malloc'd string the caller frees, or NULL when the
 * list exceeds the stored limits.
 */
char *st_egress_encode_destination_rules(const st_egress_destination_rule *rules, size_t rules_len);

/* Collects the distinct protocols an allowlist mentions, in first-seen order. */
size_t st_egress_collect_protocols(const st_egress_destination_rule *rules,
                                   size_t rules_len,
                                   char out[][8],
                                   size_t capacity);

#endif
