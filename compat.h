#ifndef COMPAT_H
#define COMPAT_H

#define _GNU_SOURCE

/* ISO C */
#include <assert.h>
#include <complex.h>
#include <ctype.h>
#include <errno.h>
#include <fenv.h>
#include <float.h>
#include <inttypes.h>
#include <iso646.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tgmath.h>
#include <time.h>
#include <wchar.h>
#include <wctype.h>

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[1]))
#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

/* Test for backtrace() */
#if defined(__APPLE__) || (defined(__linux__) && defined(__GLIBC__))
#define HAVE_BACKTRACE 1
#endif

#if defined(__linux__) || defined(__OpenBSD__)
#define _XOPEN_SOURCE 700
/*
 *  * On NetBSD, _XOPEN_SOURCE undefines _NETBSD_SOURCE and
 *   * thus hides inet_aton etc.
 *    */
#elif !defined(__NetBSD__)
#define _XOPEN_SOURCE
#endif

#endif
