#include "debug.h"
#include "logger.h"

#ifdef __CYGWIN__
#ifndef SA_ONSTACK
#define SA_ONSTACK 0x08000000
#endif
#endif

static char *assert_err  = "<no assertion failed>";
static char *assert_file = "<no file>";
static int assert_line   = 0;

void
_debug_assert(char *err, char *file, int line)
{
    logger(LOG_WARNING, "=== ASSERTION FAILED ===");
    logger(LOG_WARNING, "%s:%d '%s' is not true", file, line, err);
    assert_err  = err;
    assert_file = file;
    assert_line = line;
    // force SIGSEGV to print the bug report
    *((char *)-1) = 'x';
}

void
debug_init(void)
{
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags     = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;
    act.sa_sigaction = debug_segv_handler;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
    sigaction(SIGFPE, &act, NULL);
    sigaction(SIGILL, &act, NULL);
}

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#include <ucontext.h>
static void *
getMcontextEip(ucontext_t *uc)
{
#if defined(__APPLE__) && !defined(MAC_OS_X_VERSION_10_6)
    /* OSX < 10.6 */
    #if defined(__x86_64__)
    return (void *) uc->uc_mcontext->__ss.__rip;
    #elif defined(__i386__)
    return (void *) uc->uc_mcontext->__ss.__eip;
    #else
    return (void *) uc->uc_mcontext->__ss.__srr0;
    #endif
#elif defined(__APPLE__) && defined(MAC_OS_X_VERSION_10_6)
    /* OSX >= 10.6 */
    #if defined(_STRUCT_X86_THREAD_STATE64) && !defined(__i386__)
    return (void *) uc->uc_mcontext->__ss.__rip;
    #else
    return (void *) uc->uc_mcontext->__ss.__eip;
    #endif
#elif defined(__linux__)
    /* Linux */
    #if defined(__i386__)
    return (void *) uc->uc_mcontext.gregs[14]; /* Linux 32 */
    #elif defined(__X86_64__) || defined(__x86_64__)
    return (void *) uc->uc_mcontext.gregs[16]; /* Linux 64 */
    #elif defined(__ia64__)                    /* Linux IA64 */
    return (void *) uc->uc_mcontext.sc_ip;
    #else
    return NULL;
    #endif
#else
    return NULL;
#endif
}

/**
 * Logs the stack trace using the backtrace() call. This function is designed to
 * be called from signal handlers safely.
 */
static void
log_stack_trace(ucontext_t *uc)
{
    void *trace[100];
    int trace_size = 0;
    int fd         = logger_fd >= 0 ? logger_fd : STDOUT_FILENO;
    /* Generate the stack trace */
    trace_size = backtrace(trace, 100);
    /* overwrite sigaction with caller's address */
    if (getMcontextEip(uc) != NULL)
        trace[1] = getMcontextEip(uc);

    backtrace_symbols_fd(trace, trace_size, fd);
}

#endif

void
debug_segv_handler(int sig, siginfo_t *info, void *secret)
{
    logger(LOG_WARNING, "Crashed by signal: %d", sig);
    logger(LOG_WARNING, "--- STACK TRACE");
    logger(LOG_WARNING, "Failed assertion: %s (%s:%d)", assert_err, assert_file,
           assert_line);
#ifdef HAVE_BACKTRACE
    logger(LOG_WARNING, "--- STACK TRACE");
    ucontext_t *uc = (ucontext_t *) secret;
    log_stack_trace(uc);
#endif
    /* Make sure we exit with the right signal at the end. So for instance
     * the core will be dumped if enabled. */
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags   = SA_NODEFER | SA_ONSTACK | SA_RESETHAND;
    act.sa_handler = SIG_DFL;
    sigaction(sig, &act, NULL);
    kill(getpid(), sig);
}
