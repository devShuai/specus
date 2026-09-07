#include "client_address.h"

#include <stdio.h>
#include <string.h>

static int expect_address(const char *name,
                          const char *remote,
                          const char *forwarded_for,
                          const char *real_ip,
                          const char *trusted,
                          const char *expected)
{
    char actual[ST_CLIENT_ADDRESS_MAX_LEN];
    if (st_client_address_resolve(remote,
                                  forwarded_for,
                                  real_ip,
                                  trusted,
                                  actual,
                                  sizeof(actual)) != 0
        || strcmp(actual, expected) != 0) {
        fprintf(stderr, "%s: resolved=%s expected=%s\n", name, actual, expected);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (expect_address("direct spoof ignored",
                       "203.0.113.50:44321",
                       "1.2.3.4",
                       "5.6.7.8",
                       "",
                       "203.0.113.50") != 0
        || expect_address("untrusted peer",
                          "203.0.113.50:44321",
                          "1.2.3.4",
                          "5.6.7.8",
                          "10.0.0.0/8",
                          "203.0.113.50") != 0
        || expect_address("trusted proxy",
                          "10.1.2.3:5000",
                          "203.0.113.9",
                          NULL,
                          "10.0.0.0/8",
                          "203.0.113.9") != 0
        || expect_address("multi hop",
                          "10.1.2.3:5000",
                          "203.0.113.9, 192.168.1.1, 10.9.9.9",
                          NULL,
                          "10.0.0.0/8,192.168.0.0/16",
                          "203.0.113.9") != 0
        || expect_address("spoofed leading hop",
                          "10.1.2.3:5000",
                          "9.9.9.9, 203.0.113.9",
                          NULL,
                          "10.0.0.0/8",
                          "203.0.113.9") != 0
        || expect_address("malformed hop skipped",
                          "10.1.2.3:5000",
                          "203.0.113.9, not-an-ip, ",
                          NULL,
                          "10.0.0.0/8",
                          "203.0.113.9") != 0
        || expect_address("real ip fallback",
                          "10.1.2.3:5000",
                          "10.9.9.9",
                          "203.0.113.9",
                          "10.0.0.0/8",
                          "203.0.113.9") != 0
        || expect_address("peer fallback",
                          "10.1.2.3:5000",
                          "not-an-ip",
                          NULL,
                          "10.0.0.0/8",
                          "10.1.2.3") != 0
        || expect_address("ipv6 trusted chain",
                          "[2001:db8::1]:5000",
                          "2001:dead:1234::9, 2001:db8::2",
                          NULL,
                          "2001:db8::/32",
                          "2001:dead:1234::9") != 0
        || expect_address("ipv6 untrusted peer",
                          "[2001:dead::1]:5000",
                          "203.0.113.9",
                          NULL,
                          "2001:db8::/32",
                          "2001:dead::1") != 0
        || expect_address("invalid trusted config",
                          "10.1.2.3:5000",
                          "203.0.113.9",
                          NULL,
                          "not-a-cidr,10.0.0.0/99",
                          "10.1.2.3") != 0
        || expect_address("unknown",
                          NULL,
                          "203.0.113.9",
                          NULL,
                          "10.0.0.0/8",
                          "unknown") != 0) {
        return 1;
    }
    return 0;
}
