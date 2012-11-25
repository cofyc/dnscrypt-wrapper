
#include <config.h>
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#ifndef _WIN32
# include <poll.h>
#endif
#include <stdlib.h>
#include <unistd.h>

#include "safe_rw.h"

#ifndef _WIN32
ssize_t
safe_write(const int fd, const void * const buf_, size_t count,
           const int timeout)
{
    struct pollfd  pfd;
    const char    *buf = (const char *) buf_;
    ssize_t        written;

    pfd.fd = fd;
    pfd.events = POLLOUT;

    while (count > (size_t) 0) {
        while ((written = write(fd, buf, count)) <= (ssize_t) 0) {
            if (errno == EAGAIN) {
                if (poll(&pfd, (nfds_t) 1, timeout) == 0) {
                    errno = ETIMEDOUT;
                    goto ret;
                }
            } else if (errno != EINTR) {
                goto ret;
            }
        }
        buf += written;
        count -= (size_t) written;
    }
ret:
    return (ssize_t) (buf - (const char *) buf_);
}

ssize_t
safe_read(const int fd, void * const buf_, size_t count)
{
    unsigned char *buf = (unsigned char *) buf_;
    ssize_t        readnb;

    do {
        while ((readnb = read(fd, buf, count)) < (ssize_t) 0 &&
               errno == EINTR);
        if (readnb < (ssize_t) 0) {
            return readnb;
        }
        if (readnb == (ssize_t) 0) {
            break;
        }
        count -= (size_t) readnb;
        buf += readnb;
    } while (count > (ssize_t) 0);

    return (ssize_t) (buf - (unsigned char *) buf_);
}

ssize_t
safe_read_partial(const int fd, void * const buf_, const size_t max_count)
{
    unsigned char * const buf = (unsigned char *) buf_;
    ssize_t               readnb;

    while ((readnb = read(fd, buf, max_count)) < (ssize_t) 0 &&
           errno == EINTR);

    return readnb;
}

#else /* _WIN32 */

ssize_t
safe_write(const int fd, const void * const buf_, size_t count,
           const int timeout)
{
    assert(fd != -1);
    assert(buf_ != NULL);
    assert(count > (size_t) 0U);
    (void) timeout;

    return -1;
}

ssize_t
safe_read(const int fd, void * const buf_, size_t count)
{
    assert(fd != -1);
    assert(buf_ != NULL);
    assert(count > (size_t) 0U);

    return -1;
}

ssize_t
safe_read_partial(const int fd, void * const buf_, const size_t max_count)
{
    assert(fd != -1);
    assert(buf_ != NULL);
    assert(max_count > (size_t) 0U);

    return -1;
}

#endif
