
#include <config.h>
#include <sys/types.h>
#include <sys/time.h>

#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include <event2/util.h>

#include "logger.h"
#include "pathnames.h"
#include "utils.h"

void
dnscrypt_memzero(void * const pnt, const size_t size)
{
    volatile unsigned char *pnt_ = (volatile unsigned char *) pnt;
    size_t                     i = (size_t) 0U;

    while (i < size) {
        pnt_[i++] = 0U;
    }
}

uint64_t
dnscrypt_hrtime(void)
{
    struct timeval tv;
    uint64_t       ts = (uint64_t) 0U;
    int            ret;

    ret = evutil_gettimeofday(&tv, NULL);
    assert(ret == 0);
    if (ret == 0) {
        ts = (uint64_t) tv.tv_sec * 1000000U + (uint64_t) tv.tv_usec;
    }
    return ts;
}

#ifndef _WIN32
static unsigned int
open_max(void)
{
    long z;

    if ((z = (long) sysconf(_SC_OPEN_MAX)) < 0L) {
        logger_error(NULL, "_SC_OPEN_MAX");
        return 2U;
    }
    return (unsigned int) z;
}

int
closedesc_all(const int closestdin)
{
    int fodder;

    if (closestdin != 0) {
        (void) close(0);
        if ((fodder = open(_PATH_DEVNULL, O_RDONLY)) == -1) {
            return -1;
        }
        (void) dup2(fodder, 0);
        if (fodder > 0) {
            (void) close(fodder);
        }
    }
    if ((fodder = open(_PATH_DEVNULL, O_WRONLY)) == -1) {
        return -1;
    }
    (void) dup2(fodder, 1);
    (void) dup2(1, 2);
    if (fodder > 2) {
        (void) close(fodder);
    }

    return 0;
}

int
do_daemonize(void)
{
    pid_t        child;
    unsigned int i;

    if ((child = fork()) == (pid_t) -1) {
        logger_error(NULL, "Unable to fork() in order to daemonize");
        return -1;
    } else if (child != (pid_t) 0) {
        _exit(0);
    }
    if (setsid() == (pid_t) -1) {
        logger_error(NULL, "Unable to setsid()");
    }
    i = open_max();
    do {
        if (isatty((int) i)) {
            (void) close((int) i);
        }
        i--;
    } while (i > 2U);
    if (closedesc_all(1) != 0) {
        logger_error(NULL, _PATH_DEVNULL " duplication");
        return -1;
    }
    return 0;
}

#else /* _WIN32 */

int
closedesc_all(const int closestdin)
{
    (void) closestdin;
    return 0;
}

int
do_daemonize(void)
{
    return 0;
}

#endif
