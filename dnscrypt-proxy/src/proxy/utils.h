
#ifndef __UTILS_H__
#define __UTILS_H__ 1

#include <stdint.h>
#include <stdlib.h>

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

void dnscrypt_memzero(void * const pnt, const size_t size);
uint64_t dnscrypt_hrtime(void);
int closedesc_all(const int closestdin);
int do_daemonize(void);

#endif
