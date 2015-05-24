#ifndef LOGGER_H
#define LOGGER_H
/**
 * Logger
 *
 * @link http://en.wikipedia.org/wiki/Syslog
 */

#include "compat.h"

#ifndef _WIN32
#include <syslog.h>
#undef SYSLOG_NAMES
#else
#define	LOG_EMERG	0           /* system is unusable */
#define	LOG_ALERT	1           /* action must be taken immediately */
#define	LOG_CRIT	2           /* critical conditions */
#define	LOG_ERR		3           /* error conditions */
#define	LOG_WARNING	4           /* warning conditions */
#define	LOG_NOTICE	5           /* normal but significant condition */
#define	LOG_INFO	6           /* informational */
#define	LOG_DEBUG	7           /* debug-level messages */
#endif

#define LOGGER_MAXLEN 8192

/* Configurations. */
extern int logger_verbosity;
extern char *logger_logfile;

/* Global Variables. */
extern int logger_fd;

// see http://stackoverflow.com/q/5588855/288089
#define logger(p, fmt, ...) _logger_with_fileline((p), (fmt), __FILE__, __LINE__, ##__VA_ARGS__)
void _logger(int priority, const char *fmt, ...);
void _logger_with_fileline(int priority, const char *fmt, const char *file, int line, ...);
void logger_lograw(int priority, const char *msg);
void logger_reopen(void);
void logger_close(void);

#endif
