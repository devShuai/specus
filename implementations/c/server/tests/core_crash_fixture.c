/* Used only by collect_core_diagnostics_test.sh; never a normal passing unit test. */
#include <signal.h>

static void crash_here(void)
{
    raise(SIGSEGV);
}

int main(void)
{
    crash_here();
    return 0;
}
