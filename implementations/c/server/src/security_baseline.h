#ifndef SPECUS_SECURITY_BASELINE_H
#define SPECUS_SECURITY_BASELINE_H

typedef enum {
    ST_DEPLOYMENT_PROD = 0,
    ST_DEPLOYMENT_DEV = 1,
    ST_DEPLOYMENT_TEST = 2
} st_deployment_environment;

typedef enum {
    ST_SECURITY_BASELINE_OK = 0,
    ST_SECURITY_BASELINE_KNOWN_DEFAULT_PASSWORD = 1,
    ST_SECURITY_BASELINE_KNOWN_DEFAULT_JWT_SECRET = 2
} st_security_baseline_result;

/* Unset and unknown values intentionally resolve to production. */
st_deployment_environment st_deployment_environment_parse(const char *value);
int st_deployment_environment_allows_demo_data(const char *value);

st_security_baseline_result st_security_baseline_validate(const char *environment,
                                                          int password_login_enabled,
                                                          const char *password,
                                                          const char *jwt_secret);

/* Startup/environment adapters shared by the listener and management plane. */
int st_security_baseline_validate_current(void);
int st_security_baseline_demo_seed_enabled_current(void);

#endif
