#include "pidfile.h"

static volatile sig_atomic_t exit_requested = 0;
static const char *_pidfile = NULL;

static void
pidfile_remove_file(void)
{
    if (_pidfile != NULL) {
        unlink(_pidfile);
        _pidfile = NULL;
    }
}

static void
pidfile_atexit_handler(void)
{
    pidfile_remove_file();
}

static void
pidfile_sig_exit_handler(int sig)
{
    (void)sig;
    if (exit_requested)
        return;
    exit_requested = 1;
    exit(0);
}

static void
pidfile_install_signal_handlers(void (*handler) (int))
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, handler);
    signal(SIGHUP, handler);
    signal(SIGINT, handler);
    signal(SIGQUIT, handler);
    signal(SIGTERM, handler);
#ifdef SIGXCPU
    signal(SIGXCPU, handler);
#endif
}

int
pidfile_create(const char *const pidfile)
{
    FILE *fp;
    _pidfile = pidfile;

    fp = fopen(pidfile, "w");
    if (!fp) {
        return -1;
    }

    fprintf(fp, "%d\n", (int)getpid());
    fclose(fp);

    pidfile_install_signal_handlers(pidfile_sig_exit_handler);
    atexit(pidfile_atexit_handler);
    return 0;
}
