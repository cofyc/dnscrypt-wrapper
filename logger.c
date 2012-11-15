#include "logger.h"
#include "compat.h"

int logger_verbosity = LOG_DEBUG;
char *logger_logfile = NULL;

// prioritynames (from <syslog.h>)
#define	INTERNAL_NOPRI	0x10    /* the "no priority" priority */
typedef struct _code {
    const char *c_name;
    int c_val;
} CODE;

CODE prioritynames[] = {
    {"alert", LOG_ALERT,},
    {"crit", LOG_CRIT,},
    {"debug", LOG_DEBUG,},
    {"emerg", LOG_EMERG,},
    {"err", LOG_ERR,},
    {"error", LOG_ERR,},        /* DEPRECATED */
    {"info", LOG_INFO,},
    {"none", INTERNAL_NOPRI,},  /* INTERNAL */
    {"notice", LOG_NOTICE,},
    {"panic", LOG_EMERG,},      /* DEPRECATED */
    {"warn", LOG_WARNING,},     /* DEPRECATED */
    {"warning", LOG_WARNING,},
    {NULL, -1,}
};

void
logger(int priority, const char *fmt, ...)
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

/* 
 * Low-level logging. It's only used when you want to log arbitrary length message.
 */
void
logger_lograw(int priority, const char *msg)
{
    FILE *fp;
    const char *priority_flag;

    if (priority > logger_verbosity)
        return;

    // invalid priority?
    if (priority < 0 || priority > LOG_PRIMASK)
        priority = INTERNAL_NOPRI;

    fp = (logger_logfile == NULL) ? stdout : fopen(logger_logfile, "a");
    if (!fp)
        return;

    for (int i = 0; i < ARRAY_SIZE(prioritynames); i++) {
        CODE c = prioritynames[i];
        if (c.c_val == priority) {
            priority_flag = c.c_name;
        }
    }

    int off;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    char buf[64];
    off = strftime(buf, sizeof(buf), "%d %b %H:%M:%S.", localtime(&tv.tv_sec));
    snprintf(buf + off, sizeof(buf) - off, "%03d", (int)tv.tv_usec / 1000);
    fprintf(fp, "[%d] %s [%s] %s\n", (int)getpid(), buf, priority_flag, msg);
    fflush(fp);

    if (logger_logfile)
        fclose(fp);
}
