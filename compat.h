#ifndef COMPAT_H
#define COMPAT_H

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
#include <uuid/uuid.h>
#include <fcntl.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[1]))
#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#endif
