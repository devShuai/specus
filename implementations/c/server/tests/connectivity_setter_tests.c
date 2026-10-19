#include "admin_http.h"
#include <stdio.h>

static void presence(void *ctx, const char *name, int *control, int *data)
{ (void)ctx; (void)name; *control = 0; *data = 0; }
static void probe(void *ctx, const char *name, const char *metadata, long long timeout, st_connectivity_probe_answer *answer)
{ (void)ctx; (void)name; (void)metadata; (void)timeout; (void)answer; }

int main(void)
{
    const st_connectivity_device device = {presence, probe, NULL, NULL, NULL};
    for (unsigned i = 0U; i < 32U; ++i) {
        st_admin_set_connectivity_device(&device);
        st_admin_set_connectivity_device(NULL);
    }
    puts("connectivity lifecycle: 32 device install/remove operations completed; leak checker decides acceptance");
    return 0;
}
