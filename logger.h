#ifndef LOGGER_H
#define LOGGER_H

#ifndef _WIN32
#include <syslog.h>
#undef SYSLOG_NAMES
#else
#define	LOG_EMERG	0       /* system is unusable */
#define	LOG_ALERT	1       /* action must be taken immediately */
#define	LOG_CRIT	2       /* critical conditions */
#define	LOG_ERR		3       /* error conditions */
#define	LOG_WARNING	4       /* warning conditions */
#define	LOG_NOTICE	5       /* normal but significant condition */
#define	LOG_INFO	6       /* informational */
#define	LOG_DEBUG	7       /* debug-level messages */
#endif

#define LOGGER_MAXLEN 8192

/* Configurations. */
extern int logger_verbosity;
extern char *logger_logfile;

void logger(int priority, const char *fmt, ...);
void logger_lograw(int priority, const char *msg);

#endif
