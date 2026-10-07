/*
 * Java TurnstileVerifierTests against the production siteverify path of st_auth_turnstile_verify:
 * no test double is installed, the request goes over HTTP to a fake siteverify endpoint on
 * loopback. Java's fourth case (the Spring injection constructor) has no C counterpart.
 */
#define _POSIX_C_SOURCE 200809L

#include "registration.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct {
    int listener;
    int port;
    pthread_t thread;
    pthread_mutex_t lock;
    int stopping;
    int requests;
    char last_request[4096];
    int status;
    char body[512];
} fake_siteverify;

static fake_siteverify siteverify = {.listener = -1, .lock = PTHREAD_MUTEX_INITIALIZER};
static int failures = 0;

/* Reads one request (head and Content-Length body) into out. */
static void read_request(int fd, char *out, size_t out_len)
{
    size_t used = 0U;
    out[0] = '\0';
    while (used + 1U < out_len) {
        ssize_t got = recv(fd, out + used, out_len - 1U - used, 0);
        if (got <= 0) break;
        used += (size_t)got;
        out[used] = '\0';
        const char *head_end = strstr(out, "\r\n\r\n");
        if (head_end == NULL) continue;
        const char *length = strstr(out, "Content-Length:");
        if (length == NULL) length = strstr(out, "content-length:");
        size_t expected = length == NULL ? 0U : (size_t)strtoul(length + 15, NULL, 10);
        if (used >= (size_t)(head_end + 4 - out) + expected) break;
    }
}

static void *siteverify_run(void *arg)
{
    (void)arg;
    for (;;) {
        int client = accept(siteverify.listener, NULL, NULL);
        pthread_mutex_lock(&siteverify.lock);
        int stopping = siteverify.stopping;
        pthread_mutex_unlock(&siteverify.lock);
        if (client < 0) {
            if (stopping) return NULL;
            continue;
        }
        struct timeval timeout = {2, 0};
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        char request[4096];
        read_request(client, request, sizeof(request));
        pthread_mutex_lock(&siteverify.lock);
        ++siteverify.requests;
        snprintf(siteverify.last_request, sizeof(siteverify.last_request), "%s", request);
        char response[1024];
        int len = snprintf(response, sizeof(response),
                           "HTTP/1.1 %d Status\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
                           "Connection: close\r\n\r\n%s",
                           siteverify.status, strlen(siteverify.body), siteverify.body);
        pthread_mutex_unlock(&siteverify.lock);
        if (len > 0) (void)send(client, response, (size_t)len, 0);
        close(client);
    }
}

static int siteverify_start(void)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(address);
    siteverify.listener = socket(AF_INET, SOCK_STREAM, 0);
    if (siteverify.listener < 0 || bind(siteverify.listener, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(siteverify.listener, 8) != 0
        || getsockname(siteverify.listener, (struct sockaddr *)&address, &len) != 0) return -1;
    siteverify.port = ntohs(address.sin_port);
    return pthread_create(&siteverify.thread, NULL, siteverify_run, NULL) == 0 ? 0 : -1;
}

static void siteverify_stop(void)
{
    pthread_mutex_lock(&siteverify.lock);
    siteverify.stopping = 1;
    pthread_mutex_unlock(&siteverify.lock);
    shutdown(siteverify.listener, SHUT_RDWR);
    pthread_join(siteverify.thread, NULL);
    close(siteverify.listener);
}

static void siteverify_answer(int status, const char *body)
{
    pthread_mutex_lock(&siteverify.lock);
    siteverify.status = status;
    snprintf(siteverify.body, sizeof(siteverify.body), "%s", body);
    siteverify.requests = 0;
    siteverify.last_request[0] = '\0';
    pthread_mutex_unlock(&siteverify.lock);
}

static int siteverify_requests(void)
{
    pthread_mutex_lock(&siteverify.lock);
    int requests = siteverify.requests;
    pthread_mutex_unlock(&siteverify.lock);
    return requests;
}

/* TurnstileVerifierTests.properties(): enabled, both keys, one allowed hostname. */
static void configure(const char *verify_url, const char *allowed_hostnames)
{
    setenv("SPECUS_AUTH_TURNSTILE_ENABLED", "true", 1);
    setenv("SPECUS_AUTH_TURNSTILE_SITE_KEY", "test-site", 1);
    setenv("SPECUS_AUTH_TURNSTILE_SECRET_KEY", "test-secret", 1);
    setenv("SPECUS_AUTH_TURNSTILE_VERIFY_URL", verify_url, 1);
    setenv("SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES", allowed_hostnames, 1);
}

/* expected_status 0 means accepted. */
static void expect_verify(const char *name, const char *token, const char *action, int expected_status,
                          int expected_requests)
{
    int status = 0;
    char error[128] = "";
    int rc = st_auth_turnstile_verify(token, action, &status, error, sizeof(error));
    int actual = rc == 0 ? 0 : status;
    int requests = siteverify_requests();
    if (actual != expected_status || requests != expected_requests) {
        fprintf(stderr, "%s: status %d (expected %d), %d siteverify request(s) (expected %d), error \"%s\"\n",
                name, actual, expected_status, requests, expected_requests, error);
        ++failures;
    }
}

int main(void)
{
    /* The fake endpoint is on loopback; a proxy from the environment must not be asked for it. */
    setenv("NO_PROXY", "127.0.0.1,localhost", 1);
    setenv("no_proxy", "127.0.0.1,localhost", 1);
    if (siteverify_start() != 0) {
        fprintf(stderr, "fake siteverify start failed\n");
        return 1;
    }
    char verify_url[96];
    snprintf(verify_url, sizeof(verify_url), "http://127.0.0.1:%d/verify", siteverify.port);
    configure(verify_url, "specus.example.com");

    /* verifiesActionAndHostname */
    siteverify_answer(200, "{\"success\":true,\"action\":\"login\",\"hostname\":\"specus.example.com\"}");
    expect_verify("login with the expected action and hostname", "browser-token", "login", 0, 1);
    pthread_mutex_lock(&siteverify.lock);
    int form_ok = strncmp(siteverify.last_request, "POST /verify ", 13U) == 0
        && strstr(siteverify.last_request, "application/x-www-form-urlencoded") != NULL
        && strstr(siteverify.last_request, "secret=test-secret") != NULL
        && strstr(siteverify.last_request, "response=browser-token") != NULL;
    pthread_mutex_unlock(&siteverify.lock);
    if (!form_ok) {
        fprintf(stderr, "siteverify request mismatch: %s\n", siteverify.last_request);
        ++failures;
    }
    siteverify_answer(200, "{\"success\":true,\"action\":\"login\",\"hostname\":\"specus.example.com\"}");
    expect_verify("register token answered for login", "browser-token", "register", 400, 1);

    /* rejectsUnexpectedHostname */
    siteverify_answer(200, "{\"success\":true,\"action\":\"login\",\"hostname\":\"attacker.example\"}");
    expect_verify("unexpected hostname", "token", "login", 400, 1);

    /* Hostnames compare trimmed, case-insensitively and without a trailing dot; any entry may match. */
    configure(verify_url, "other.example, Specus.Example.COM.");
    siteverify_answer(200, "{\"success\":true,\"action\":\"register\",\"hostname\":\" SPECUS.example.com. \"}");
    expect_verify("normalized hostname in a list", "  token  ", "register", 0, 1);
    pthread_mutex_lock(&siteverify.lock);
    int trimmed = strstr(siteverify.last_request, "response=token") != NULL;
    pthread_mutex_unlock(&siteverify.lock);
    if (!trimmed) {
        fprintf(stderr, "the response token was not trimmed: %s\n", siteverify.last_request);
        ++failures;
    }
    siteverify_answer(200, "{\"success\":true,\"action\":\"register\"}");
    expect_verify("missing hostname", "token", "register", 400, 1);
    configure(verify_url, "specus.example.com");
    siteverify_answer(200, "{\"success\":false,\"action\":\"login\",\"hostname\":\"specus.example.com\","
                           "\"error-codes\":[\"invalid-input-response\"]}");
    expect_verify("success false", "token", "login", 400, 1);
    siteverify_answer(200, "{\"success\":true,\"hostname\":\"specus.example.com\"}");
    expect_verify("missing action", "token", "login", 400, 1);

    /* A blank token never reaches siteverify. */
    siteverify_answer(200, "{\"success\":true,\"action\":\"login\",\"hostname\":\"specus.example.com\"}");
    expect_verify("blank token", "   ", "login", 400, 0);
    expect_verify("missing token", NULL, "login", 400, 0);

    /* The service, not the visitor, failed: 503 (Java unavailable()). */
    siteverify_answer(500, "{\"success\":true,\"action\":\"login\",\"hostname\":\"specus.example.com\"}");
    expect_verify("siteverify HTTP 500", "token", "login", 503, 1);
    siteverify_answer(200, "<html>maintenance</html>");
    expect_verify("siteverify answer that is not JSON", "token", "login", 503, 1);
    siteverify_answer(200, "{\"success\":true,\"action\":\"login\",\"hostname\":\"specus.example.com\"}");
    char closed_url[96];
    snprintf(closed_url, sizeof(closed_url), "http://127.0.0.1:%d/verify", siteverify.port);
    siteverify_stop();
    configure(closed_url, "specus.example.com");
    expect_verify("siteverify unreachable", "token", "login", 503, 0);

    /* failsClosedWhenEnabledWithoutKeysOrHostnames: nothing but the switch is set. */
    unsetenv("SPECUS_AUTH_TURNSTILE_SITE_KEY");
    unsetenv("SPECUS_AUTH_TURNSTILE_SECRET_KEY");
    unsetenv("SPECUS_AUTH_TURNSTILE_VERIFY_URL");
    unsetenv("SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES");
    expect_verify("enabled without keys or hostnames", "token", "login", 503, 0);
    configure(verify_url, " , ");
    expect_verify("enabled with only blank hostnames", "token", "login", 503, 0);
    configure(verify_url, "specus.example.com");
    unsetenv("SPECUS_AUTH_TURNSTILE_SECRET_KEY");
    expect_verify("enabled without a secret key", "token", "login", 503, 0);

    /* Disabled: nothing is verified. */
    setenv("SPECUS_AUTH_TURNSTILE_ENABLED", "false", 1);
    expect_verify("disabled", NULL, "login", 0, 0);

    if (failures != 0) {
        fprintf(stderr, "%d Turnstile verifier check(s) failed\n", failures);
        return 1;
    }
    printf("Turnstile verifier tests passed\n");
    return 0;
}
