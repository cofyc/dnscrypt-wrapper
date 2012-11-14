#include "dnscrypt.h"

/**
 * This is dnscrypt wrapper, which enable dnscrypt support for any dns server.
 */

static int
sockaddr_from_ip_and_port(struct sockaddr_storage *const sockaddr,
                          ev_socklen_t * const sockaddr_len_p,
                          const char *const ip, const char *const port,
                          const char *const error_msg)
{
    char sockaddr_port[INET6_ADDRSTRLEN + sizeof "[]:65535"];
    int sockaddr_len_int;
    char *pnt;
    _Bool has_column = 0;
    _Bool has_columns = 0;
    _Bool has_brackets = *ip == '[';

    if ((pnt = strchr(ip, ':')) != NULL) {
        has_column = 1;
        if (strchr(pnt + 1, ':') != NULL) {
            has_columns = 1;
        }
    }
    sockaddr_len_int = (int)sizeof *sockaddr;
    if ((has_brackets != 0 || has_column != has_columns) &&
        evutil_parse_sockaddr_port(ip, (struct sockaddr *)sockaddr,
                                   &sockaddr_len_int) == 0) {
        *sockaddr_len_p = (ev_socklen_t) sockaddr_len_int;
        return 0;
    }
    if (has_columns != 0 && has_brackets == 0) {
        evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "[%s]:%s",
                        ip, port);
    } else {
        evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "%s:%s", ip, port);
    }
    sockaddr_len_int = (int)sizeof *sockaddr;
    if (evutil_parse_sockaddr_port(sockaddr_port, (struct sockaddr *)sockaddr,
                                   &sockaddr_len_int) != 0) {
        logger(LOG_ERR, "%s: %s", error_msg, sockaddr_port);
        *sockaddr_len_p = (ev_socklen_t) 0U;

        return -1;
    }
    *sockaddr_len_p = (ev_socklen_t) sockaddr_len_int;

    return 0;
}

static int
context_init(struct context *c)
{
    memset(c, 0, sizeof(*c));
    c->resolver_ip = DEFAULT_RESOLVER_IP;
    c->local_ip = "127.0.0.1:54";
    c->udp_listener_handle = -1;
    c->udp_resolver_handle = -1;
    c->connections_max = 250;
    c->tcp_only = 0;

    if ((c->event_loop = event_base_new()) == NULL) {
        logger(LOG_ERR, "Unable to initialize the event loop");
        return -1;
    }

    if (sockaddr_from_ip_and_port(&c->resolver_sockaddr,
                                  &c->resolver_sockaddr_len,
                                  c->resolver_ip,
                                  "443", "Unsupported resolver address") != 0) {
        return -1;
    }

    if (sockaddr_from_ip_and_port(&c->local_sockaddr,
                                  &c->local_sockaddr_len,
                                  c->local_ip,
                                  "53", "Unsupported local address") != 0) {
        return -1;
    }

    return 0;
}

int
main(int argc, const char **argv)
{
    struct context c;

    if (context_init(&c)) {
        logger(LOG_ERR, "Unable to start the dnscrypt wrapper.");
        exit(1);
    }

    if (udp_listern_bind(&c) != 0) {
        exit(1);
    }

    if (udp_listener_start(&c) != 0) {
        logger(LOG_ERR, "Unable to start udp listener.");
        exit(1);
    }

    event_base_dispatch(c.event_loop);

    return 0;
}
