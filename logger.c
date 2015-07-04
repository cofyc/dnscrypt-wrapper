#include "logger.h"

int logger_verbosity = LOG_INFO;
char *logger_logfile = NULL;
int logger_fd = -1;

#define LOGGER_LINESIZE 1024

// priority names (from <syslog.h>)
#define INTERNAL_NOPRI 0x10     /* the "no priority" priority */
typedef struct _code {
    const char *c_name;
    int c_val;
} CODE;

CODE prioritynames[] = {
    {"emerg", LOG_EMERG},
    {"alert", LOG_ALERT},
    {"crit", LOG_CRIT},
    {"err", LOG_ERR},
    {"warning", LOG_WARNING},
    {"notice", LOG_NOTICE},
    {"info", LOG_INFO},
    {"debug", LOG_DEBUG},
    {"none", INTERNAL_NOPRI},   /* INTERNAL */
    {NULL, -1}
};

void
_logger(int priority, const char *fmt, ...)
{
    va_list ap;
    char msg[LOGGER_MAXLEN];

    if (priority > logger_verbosity)
        return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    logger_lograw(priority, msg);
}

void
_logger_with_fileline(int priority, const char *fmt, const char *file, int line,
                      ...)
{
    va_list ap;
    char msg[LOGGER_MAXLEN];

    if (priority > logger_verbosity)
        return;

    size_t n = snprintf(msg, sizeof(msg), "[%s:%d] ", file, line);

    va_start(ap, line);
    vsnprintf(msg + n, sizeof(msg), fmt, ap);
    va_end(ap);

    logger_lograw(priority, msg);
}

/*
 * Low-level logging. It's only used when you want to log arbitrary length message.
 */
void
logger_lograw(int priority, const char *msg)
{
    FILE *fp;
    const char *priority_flag = NULL;

    if (priority > logger_verbosity)
        return;

    // invalid priority?
    if (priority < 0 || priority > LOG_PRIMASK)
        priority = INTERNAL_NOPRI;

    if (logger_fd == -1) {
        logger_reopen();
    }
    if (logger_fd == -1) {
        return;
    }
    fp = (logger_logfile == NULL) ? stdout : fopen(logger_logfile, "a");
    if (!fp)
        return;

    for (int i = 0; i < ARRAY_SIZE(prioritynames); i++) {
        CODE c = prioritynames[i];
        if (c.c_val == priority) {
            priority_flag = c.c_name;
        }
    }
    assert(priority_flag);

    // prefix
    int off;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    char buf[64];
    off = strftime(buf, sizeof(buf), "%d %b %H:%M:%S.", localtime(&tv.tv_sec));
    snprintf(buf + off, sizeof(buf) - off, "%03d", (int)tv.tv_usec / 1000);
    // format log
    char logbuf[LOGGER_LINESIZE];
    size_t len = snprintf(logbuf, LOGGER_LINESIZE, "[%d] %s [%s] %s\n",
                          (int)getpid(), buf, priority_flag, msg);
    // write
    write(logger_fd, logbuf, len);
}

void
logger_reopen(void)
{
    if (logger_logfile) {
        logger_fd = open(logger_logfile, O_APPEND | O_CREAT | O_WRONLY, 0644);
    } else {
        logger_fd = STDOUT_FILENO;
    }
}

void
logger_close(void)
{
    if (logger_fd >= 0) {
        close(logger_fd);
    }
    logger_fd = -1;
}
