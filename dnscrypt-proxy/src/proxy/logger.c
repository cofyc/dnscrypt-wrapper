
#include <config.h>
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
# include <syslog.h>
#endif
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#include <event2/util.h>

#include "dnscrypt_proxy.h"
#include "logger.h"
#include "safe_rw.h"

int
logger_open_syslog(struct ProxyContext_ * const context)
{
    assert(context->daemonize != 0);
#ifndef _WIN32
    openlog(PACKAGE_TARNAME, LOG_NDELAY | LOG_PID, LOG_DAEMON);
#endif
    return 0;
}

int
logger(struct ProxyContext_ * const context,
       const int crit, const char * const format, ...)
{
    static char         previous_line[MAX_LOG_LINE];
    static time_t       last_log_ts = (time_t) 0;
    static unsigned int burst_counter = 0U;
    char        line[MAX_LOG_LINE];
    va_list     va;
    const char *urgency;
    time_t      now = time(NULL);
    size_t      len;
    int         log_fd;

#ifndef DEBUG
    if (crit == LOG_DEBUG) {
        return 0;
    }
#endif
    switch (crit) {
    case LOG_INFO:
        urgency = "[INFO] ";
        break;
    case LOG_WARNING:
        urgency = "[WARNING] ";
        break;
    case LOG_ERR:
        urgency = "[ERROR] ";
        break;
    case LOG_NOTICE:
        urgency = "[NOTICE] ";
        break;
    case LOG_DEBUG:
        urgency = "[DEBUG] ";
        break;
    default:
        urgency = "";
    }
    va_start(va, format);
    len = (size_t) evutil_vsnprintf(line, sizeof line, format, va);
    va_end(va);

    if (len >= sizeof line) {
        assert(sizeof line > (size_t) 0U);
        len = sizeof line - (size_t) 1U;
    }
    line[len++] = 0;
#ifndef _WIN32
    if (context != NULL && context->log_fd == -1 && context->daemonize) {
        syslog(crit, "%s", line);
        return 0;
    }
#endif
    if (memcmp(previous_line, line, len) == 0) {
        burst_counter++;
        if (burst_counter > LOGGER_ALLOWED_BURST_FOR_IDENTICAL_LOG_ENTRIES &&
            now - last_log_ts < LOGGER_DELAY_BETWEEN_IDENTICAL_LOG_ENTRIES) {
            return 1;
        }
    } else {
        burst_counter = 0U;
    }
    last_log_ts = now;
    assert(sizeof previous_line >= sizeof line);
    memcpy(previous_line, line, len);
    if (context == NULL || context->log_fd == -1) {
        log_fd = STDERR_FILENO;
    } else {
        log_fd = context->log_fd;
    }
#ifndef _WIN32
    safe_write(log_fd, urgency, strlen(urgency), LOG_WRITE_TIMEOUT);
    safe_write(log_fd, line, strlen(line), LOG_WRITE_TIMEOUT);
    safe_write(log_fd, "\n", (size_t) 1U, LOG_WRITE_TIMEOUT);
#else
    (void) log_fd;
    printf("%s%s\n", urgency, line);
    fflush(stdout);
#endif

    return 0;
}

int
logger_noformat(struct ProxyContext_ * const context,
                 const int crit, const char * const msg)
{
    return logger(context, crit, "%s", msg);
}

int
logger_error(struct ProxyContext_ * const context,
              const char * const msg)
{
    const char *const err_msg = strerror(errno);

    return logger(context, LOG_ERR, "%s: %s", msg, err_msg);
}

int
logger_close(struct ProxyContext_ * const context)
{
#ifdef _WIN32
    (void) context;
#else
    if (context->daemonize) {
        closelog();
    }
    if (context->log_fd != -1) {
        fsync(context->log_fd);
        return close(context->log_fd);
    }
#endif
    return 0;
}
