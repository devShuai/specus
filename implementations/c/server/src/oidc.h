#ifndef SPECUS_OIDC_H
#define SPECUS_OIDC_H

#include "password_hash.h"

#include <stddef.h>

/* Java OidcProperties defaults (application.yml specus.oidc.*). */
#define ST_OIDC_DEFAULT_ISSUER "https://certus.devshuai.com"
#define ST_OIDC_DEFAULT_JWK_SET_URI "https://certus.devshuai.com/oauth2/jwks"
#define ST_OIDC_DEFAULT_TOKEN_ENDPOINT "https://certus.devshuai.com/oauth2/token"
#define ST_OIDC_DEFAULT_REDIRECT_URI "http://127.0.0.1:8088/"

/* Longest compact JWT accepted, ID token or bearer; real ones are a few KiB. */
#define ST_OIDC_MAX_TOKEN_BYTES 16384U
/* Java ManagementUserService refuses longer issuer or subject values. */
#define ST_OIDC_MAX_IDENTITY_FIELD_BYTES 255U

enum {
    ST_OIDC_OK = 0,
    /* Java's JwtDecoder threw: the token is malformed, is not RS256, no JWKS key verifies it, it
     * has expired or is not yet valid, its issuer, audience or azp is wrong, or a setting the
     * validator needs (issuer, client id, resource audience) is blank. */
    ST_OIDC_TOKEN_REJECTED = -1,
    /* The token verified, but OidcController's own checks failed: blank subject or wrong nonce. */
    ST_OIDC_IDENTITY_REJECTED = -2,
    /* SPECUS_OIDC_JWK_SET_URI is blank: Java has no decoder bean at all. */
    ST_OIDC_UNAVAILABLE = -3
};

typedef struct {
    char *issuer;
    char *subject;
    /* Java's claimAsString: "" when the claim is absent. */
    char *preferred_username;
} st_oidc_identity;

/*
 * An OIDC setting as Spring resolves ${NAME:fallback}: the fallback only when the variable is
 * unset. A variable set to an empty value stays empty, so validation fails closed instead of
 * silently trusting the default identity provider.
 */
const char *st_oidc_setting(const char *name, const char *fallback);
/* Spring's StringUtils.hasText: non-NULL and not only whitespace. */
int st_oidc_has_text(const char *value);
/*
 * A top-level JSON string member, decoded; NULL when the member is absent, is not a string or
 * decodes to text with an embedded NUL. The caller frees the result.
 */
char *st_oidc_json_text(const char *json, const char *name);

/*
 * The ID token of the authorization-code flow (Java's oidcIdTokenDecoder plus OidcController):
 * RS256 against SPECUS_OIDC_JWK_SET_URI, exp/nbf with 60 s of skew, iss equal to
 * SPECUS_OIDC_ISSUER, aud containing SPECUS_OIDC_CLIENT_ID, azp equal to it when present or when
 * there are several audiences, a non-blank sub, and nonce byte-equal to expected_nonce.
 * On ST_OIDC_OK *identity is filled; release it with st_oidc_identity_free.
 */
int st_oidc_validate_id_token(const char *token, const char *expected_nonce, st_oidc_identity *identity);
/*
 * A bearer token sent straight to the management API (Java's oidcAccessTokenDecoder): the same
 * signature, time and issuer rules, aud containing SPECUS_OIDC_AUDIENCE, and a non-blank sub.
 * Without a resource audience every such token is refused, before any JWKS request.
 */
int st_oidc_validate_bearer_token(const char *token, st_oidc_identity *identity);
/* Java's AlgorithmRoutingJwtDecoder: 1 when the JOSE header names an HS* algorithm. */
int st_oidc_token_is_hmac(const char *token);
void st_oidc_identity_free(st_oidc_identity *identity);

/* Java ManagementUserService.oidcIdentityKey: lowercase hex SHA-256 of issuer, NUL, subject. */
int st_oidc_identity_key(const char *issuer, const char *subject, char out[65]);
/* A PBKDF2 hash of a random password nobody holds, for an account created by an OIDC login. */
int st_oidc_unusable_password_hash(char out[ST_PASSWORD_HASH_MAX_LEN + 1U]);

/* Drops the cached JWK Set, so the next validation fetches it again. */
void st_oidc_jwks_reset(void);
/*
 * Minimum spacing of JWK Set fetches (10 s by default). A token whose kid is unknown, or whose
 * signature no cached key verifies, triggers at most one refetch per interval.
 */
void st_oidc_jwks_set_refresh_cooldown_ms(long long cooldown_ms);

#endif
