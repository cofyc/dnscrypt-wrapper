#include "dnscrypt.h"

static void
tcp_request_kill(TCPRequest *const tcp_request)
{
    if (tcp_request == NULL || tcp_request->status.is_dying) {
        return;
    }
    tcp_request->status.is_dying = 1;
    struct context *c;

    if (tcp_request->timeout_timer != NULL) {
        event_free(tcp_request->timeout_timer);
        tcp_request->timeout_timer = NULL;
    }
    if (tcp_request->client_proxy_bev != NULL) {
        bufferevent_free(tcp_request->client_proxy_bev);
        tcp_request->client_proxy_bev = NULL;
    }
    if (tcp_request->proxy_resolver_bev != NULL) {
        bufferevent_free(tcp_request->proxy_resolver_bev);
        tcp_request->proxy_resolver_bev = NULL;
    }
    if (tcp_request->proxy_resolver_query_evbuf != NULL) {
        evbuffer_free(tcp_request->proxy_resolver_query_evbuf);
        tcp_request->proxy_resolver_query_evbuf = NULL;
    }
    c = tcp_request->context;
    if (tcp_request->status.is_in_queue != 0) {
        debug_assert(!TAILQ_EMPTY(&c->tcp_request_queue));
        TAILQ_REMOVE(&c->tcp_request_queue, tcp_request, queue);
        debug_assert(c->connections > 0U);
        c->connections--;
    }
    tcp_request->context = NULL;
    free(tcp_request);
}

static void
tcp_tune(evutil_socket_t handle)
{
    if (handle == -1) {
        return;
    }
    setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, (void *)(int[]) {
               1}, sizeof(int));
#if defined(__linux__) && defined(SO_REUSEPORT)
    setsockopt(handle, SOL_SOCKET, SO_REUSEPORT, (void *)(int[]) {
        1}, sizeof(int));
#endif
}

static void
timeout_timer_cb(evutil_socket_t timeout_timer_handle, short ev_flags,
                 void *const tcp_request_)
{
    TCPRequest *const tcp_request = tcp_request_;

    (void)ev_flags;
    (void)timeout_timer_handle;
    logger(LOG_DEBUG, "resolver timeout (TCP)");
    tcp_request_kill(tcp_request);
}

int
tcp_listener_kill_oldest_request(struct context *c)
{
    if (TAILQ_EMPTY(&c->tcp_request_queue)) {
        return -1;
    }
    tcp_request_kill(TAILQ_FIRST(&c->tcp_request_queue));

    return 0;
}

static void
client_proxy_read_cb(struct bufferevent *const client_proxy_bev,
                     void *const tcp_request_)
{
    uint8_t dns_query[DNS_MAX_PACKET_SIZE_TCP - 2U];
    uint8_t dns_query_len_buf[2];
    uint8_t dns_curved_query_len_buf[2];
    TCPRequest *tcp_request = tcp_request_;
    struct context *c = tcp_request->context;
    struct evbuffer *input = bufferevent_get_input(client_proxy_bev);
    size_t available_size;
    size_t dns_query_len;
    size_t max_query_size;

    if (tcp_request->status.has_dns_query_len == 0) {
        debug_assert(evbuffer_get_length(input) >= (size_t) 2U);
        evbuffer_remove(input, dns_query_len_buf, sizeof dns_query_len_buf);
        tcp_request->dns_query_len = (size_t)
            ((dns_query_len_buf[0] << 8) | dns_query_len_buf[1]);
        tcp_request->status.has_dns_query_len = 1;
    }
    debug_assert(tcp_request->status.has_dns_query_len != 0);
    dns_query_len = tcp_request->dns_query_len;
    if (dns_query_len < (size_t) DNS_HEADER_SIZE) {
        logger(LOG_WARNING, "Short query received");
        tcp_request_kill(tcp_request);
        return;
    }
    available_size = evbuffer_get_length(input);
    if (available_size < dns_query_len) {
        bufferevent_setwatermark(tcp_request->client_proxy_bev,
                                 EV_READ, dns_query_len, dns_query_len);
        return;
    }
    debug_assert(available_size >= dns_query_len);
    bufferevent_disable(tcp_request->client_proxy_bev, EV_READ);
    debug_assert(tcp_request->proxy_resolver_query_evbuf == NULL);
    if ((tcp_request->proxy_resolver_query_evbuf = evbuffer_new()) == NULL) {
        tcp_request_kill(tcp_request);
        return;
    }
    if ((ssize_t)
        evbuffer_remove_buffer(input, tcp_request->proxy_resolver_query_evbuf,
                               dns_query_len) != (ssize_t) dns_query_len) {
        tcp_request_kill(tcp_request);
        return;
    }
    debug_assert(dns_query_len <= sizeof dns_query);
    if ((ssize_t) evbuffer_remove(tcp_request->proxy_resolver_query_evbuf,
                                  dns_query, dns_query_len)
        != (ssize_t) dns_query_len) {
        tcp_request_kill(tcp_request);
        return;
    }
    max_query_size = sizeof dns_query;
    debug_assert(max_query_size < DNS_MAX_PACKET_SIZE_TCP);
    debug_assert(SIZE_MAX - DNSCRYPT_MAX_PADDING - DNSCRYPT_QUERY_HEADER_SIZE
              > dns_query_len);
    size_t max_len =
        dns_query_len + DNSCRYPT_MAX_PADDING + DNSCRYPT_QUERY_HEADER_SIZE;
    if (max_len > max_query_size) {
        max_len = max_query_size;
    }
    if (dns_query_len + DNSCRYPT_QUERY_HEADER_SIZE > max_len) {
        tcp_request_kill(tcp_request);
        return;
    }
    debug_assert(max_len <= DNS_MAX_PACKET_SIZE_TCP - 2U);
    debug_assert(max_len <= sizeof dns_query);
    debug_assert(dns_query_len <= max_len);

    // decrypt if encrypted
    struct dnscrypt_query_header *dnscrypt_header =
        (struct dnscrypt_query_header *)dns_query;
    if (memcmp
        (dnscrypt_header->magic_query, CERT_MAGIC_HEADER,
         DNSCRYPT_MAGIC_HEADER_LEN) == 0) {
        if (dnscrypt_server_uncurve
            (c, tcp_request->client_nonce, tcp_request->nmkey, dns_query,
             &dns_query_len) != 0) {
            logger(LOG_WARNING, "Received a suspicious query from the client");
            tcp_request_kill(tcp_request);
            return;
        }
        tcp_request->is_dnscrypted = true;
    } else if (!c->allow_not_dnscrypted) {
        logger(LOG_DEBUG, "Unauthenticated query received over TCP");
        tcp_request_kill(tcp_request);
        return;
    } else {
        tcp_request->is_dnscrypted = false;
    }

    dns_curved_query_len_buf[0] = (dns_query_len >> 8) & 0xff;
    dns_curved_query_len_buf[1] = dns_query_len & 0xff;
    if (bufferevent_write(tcp_request->proxy_resolver_bev,
                          dns_curved_query_len_buf, (size_t) 2U) != 0 ||
        bufferevent_write(tcp_request->proxy_resolver_bev, dns_query,
                          (size_t) dns_query_len) != 0) {
        tcp_request_kill(tcp_request);
        return;
    }

    bufferevent_enable(tcp_request->proxy_resolver_bev, EV_READ);
}

static void
client_proxy_event_cb(struct bufferevent *const client_proxy_bev,
                      const short events, void *const tcp_request_)
{
    TCPRequest *const tcp_request = tcp_request_;

    (void)client_proxy_bev;
    (void)events;
    tcp_request_kill(tcp_request);
}

static void
client_proxy_write_cb(struct bufferevent *const client_proxy_bev,
                      void *const tcp_request_)
{
    TCPRequest *const tcp_request = tcp_request_;

    (void)client_proxy_bev;
    tcp_request_kill(tcp_request);
}

static void
proxy_resolver_event_cb(struct bufferevent *const proxy_resolver_bev,
                        const short events, void *const tcp_request_)
{
    TCPRequest *const tcp_request = tcp_request_;

    (void)proxy_resolver_bev;
    if ((events & BEV_EVENT_ERROR) != 0) {
        tcp_request_kill(tcp_request);
        return;
    }
    if ((events & BEV_EVENT_CONNECTED) == 0) {
        tcp_tune(bufferevent_getfd(proxy_resolver_bev));
        return;
    }
}

static void
resolver_proxy_read_cb(struct bufferevent *const proxy_resolver_bev,
                       void *const tcp_request_)
{
    uint8_t dns_reply_len_buf[2];
    uint8_t dns_curved_reply_len_buf[2];
    uint8_t *dns_reply_bev;
    TCPRequest *tcp_request = tcp_request_;
    struct context *c = tcp_request->context;
    struct evbuffer *input = bufferevent_get_input(proxy_resolver_bev);
    size_t available_size;
    uint8_t dns_reply[DNS_MAX_PACKET_SIZE_TCP - 2U];
    size_t dns_reply_len;

    logger(LOG_DEBUG, "Resolver read callback.");
    if (tcp_request->status.has_dns_reply_len == 0) {
        debug_assert(evbuffer_get_length(input) >= (size_t) 2U);
        evbuffer_remove(input, dns_reply_len_buf, sizeof dns_reply_len_buf);
        tcp_request->dns_reply_len = (size_t)
            ((dns_reply_len_buf[0] << 8) | dns_reply_len_buf[1]);
        tcp_request->status.has_dns_reply_len = 1;
    }
    debug_assert(tcp_request->status.has_dns_reply_len != 0);
    dns_reply_len = tcp_request->dns_reply_len;
    if (dns_reply_len < (size_t) DNS_HEADER_SIZE) {
        logger(LOG_WARNING, "Short reply received");
        tcp_request_kill(tcp_request);
        return;
    }
    available_size = evbuffer_get_length(input);
    if (available_size < dns_reply_len) {
        bufferevent_setwatermark(tcp_request->proxy_resolver_bev,
                                 EV_READ, dns_reply_len, dns_reply_len);
        return;
    }
    debug_assert(available_size >= dns_reply_len);
    dns_reply_bev = evbuffer_pullup(input, (ssize_t) dns_reply_len);
    if (dns_reply_bev == NULL) {
        tcp_request_kill(tcp_request);
        return;
    }

    memcpy(dns_reply, dns_reply_bev, dns_reply_len);

    size_t max_len =
        dns_reply_len + DNSCRYPT_MAX_PADDING + DNSCRYPT_REPLY_HEADER_SIZE;

    if (tcp_request->is_dnscrypted) {
        if (dnscrypt_server_curve
            (c, tcp_request->client_nonce, tcp_request->nmkey, dns_reply,
             &dns_reply_len, max_len) != 0) {
            logger(LOG_ERR, "Curving reply failed.");
            return;
        }
    }

    dns_curved_reply_len_buf[0] = (dns_reply_len >> 8) & 0xff;
    dns_curved_reply_len_buf[1] = dns_reply_len & 0xff;
    if (bufferevent_write(tcp_request->client_proxy_bev,
                          dns_curved_reply_len_buf, (size_t) 2U) != 0 ||
        bufferevent_write(tcp_request->client_proxy_bev, dns_reply,
                          dns_reply_len) != 0) {
        tcp_request_kill(tcp_request);
        return;
    }
    bufferevent_enable(tcp_request->client_proxy_bev, EV_WRITE);
    bufferevent_free(tcp_request->proxy_resolver_bev);
    tcp_request->proxy_resolver_bev = NULL;
}

static void
tcp_connection_cb(struct evconnlistener *const tcp_conn_listener,
                  evutil_socket_t handle,
                  struct sockaddr *const client_sockaddr,
                  const int client_sockaddr_len_int, void *const context)
{
    logger(LOG_DEBUG, "Accepted a tcp connection.");
    struct context *c = context;
    TCPRequest *tcp_request;

    (void)tcp_conn_listener;
    (void)client_sockaddr;
    (void)client_sockaddr_len_int;
    if ((tcp_request = calloc((size_t) 1U, sizeof *tcp_request)) == NULL) {
        return;
    }
    tcp_request->context = c;
    tcp_request->timeout_timer = NULL;
    tcp_request->proxy_resolver_query_evbuf = NULL;
    tcp_request->client_proxy_bev = bufferevent_socket_new(c->event_loop,
                                                           handle,
                                                           BEV_OPT_CLOSE_ON_FREE);
    if (tcp_request->client_proxy_bev == NULL) {
        evutil_closesocket(handle);
        free(tcp_request);
        return;
    }
    tcp_request->proxy_resolver_bev = bufferevent_socket_new(c->event_loop, -1,
                                                             BEV_OPT_CLOSE_ON_FREE);
    if (tcp_request->proxy_resolver_bev == NULL) {
        bufferevent_free(tcp_request->client_proxy_bev);
        tcp_request->client_proxy_bev = NULL;
        free(tcp_request);
        return;
    }
    c->connections++;
    TAILQ_INSERT_TAIL(&c->tcp_request_queue, tcp_request, queue);
    memset(&tcp_request->status, 0, sizeof tcp_request->status);
    tcp_request->status.is_in_queue = 1;
    if ((tcp_request->timeout_timer =
         evtimer_new(tcp_request->context->event_loop,
                     timeout_timer_cb, tcp_request)) == NULL) {
        tcp_request_kill(tcp_request);
        return;
    }
    const struct timeval tv = {
        .tv_sec = (time_t) DNS_QUERY_TIMEOUT,.tv_usec = 0
    };
    evtimer_add(tcp_request->timeout_timer, &tv);
    bufferevent_setwatermark(tcp_request->client_proxy_bev,
                             EV_READ, (size_t) 2U,
                             (size_t) DNS_MAX_PACKET_SIZE_TCP);
    bufferevent_setcb(tcp_request->client_proxy_bev,
                      client_proxy_read_cb, client_proxy_write_cb,
                      client_proxy_event_cb, tcp_request);
    if (bufferevent_socket_connect
        (tcp_request->proxy_resolver_bev,
         (struct sockaddr *)&c->resolver_sockaddr,
         (int)c->resolver_sockaddr_len) != 0) {
        tcp_request_kill(tcp_request);
        return;
    }
    bufferevent_setwatermark(tcp_request->proxy_resolver_bev,
                             EV_READ, (size_t) 2U,
                             (size_t) DNS_MAX_PACKET_SIZE_TCP);
    bufferevent_setcb(tcp_request->proxy_resolver_bev,
                      resolver_proxy_read_cb, NULL, proxy_resolver_event_cb,
                      tcp_request);
    bufferevent_enable(tcp_request->client_proxy_bev, EV_READ);
}

static void
tcp_accept_timer_cb(evutil_socket_t handle, const short event,
                    void *const context)
{
    struct context *c = context;

    (void)handle;
    (void)event;
    event_free(c->tcp_accept_timer);
    c->tcp_accept_timer = NULL;
    evconnlistener_enable(c->tcp_conn_listener);
}

static void
tcp_accept_error_cb(struct evconnlistener *const tcp_conn_listener,
                    void *const context)
{
    struct context *c = context;

    (void)tcp_conn_listener;
    if (c->tcp_accept_timer == NULL) {
        c->tcp_accept_timer = evtimer_new
            (c->event_loop, tcp_accept_timer_cb, c);
        if (c->tcp_accept_timer == NULL) {
            return;
        }
    }
    if (evtimer_pending(c->tcp_accept_timer, NULL)) {
        return;
    }
    evconnlistener_disable(c->tcp_conn_listener);

    const struct timeval tv = {
        .tv_sec = (time_t) 1,
        .tv_usec = 0
    };
    evtimer_add(c->tcp_accept_timer, &tv);
}

int
tcp_listener_bind(struct context *c)
{
    debug_assert(c->tcp_conn_listener == NULL);
#ifndef LEV_OPT_DEFERRED_ACCEPT
# define LEV_OPT_DEFERRED_ACCEPT 0
#endif

    /* Until libevent gets support for SO_REUSEPORT we have to break
     * evconnlistener_new_bind() into a series of:
     * socket(), tcp_tune(), bind(), evconnlistener_new() */
    evutil_socket_t fd;
    fd = socket(c->local_sockaddr.ss_family, SOCK_STREAM, IPPROTO_TCP);

    tcp_tune(fd);
    evutil_make_socket_nonblocking(fd);

    if (bind(fd, (struct sockaddr *) &c->local_sockaddr, c->local_sockaddr_len) < 0) {
        logger(LOG_ERR, "Unable to bind (TCP): %s", c->listen_address);
        return -1;
    }

    c->tcp_conn_listener =
        evconnlistener_new(c->event_loop,
                                tcp_connection_cb, c,
                                LEV_OPT_CLOSE_ON_FREE |
                                LEV_OPT_CLOSE_ON_EXEC |
                                LEV_OPT_REUSEABLE |
                                LEV_OPT_DEFERRED_ACCEPT,
                                TCP_REQUEST_BACKLOG,
                                fd);
    if (c->tcp_conn_listener == NULL) {
        logger(LOG_ERR, "Unable to create listener (TCP)");
        return -1;
    }
    if (evconnlistener_disable(c->tcp_conn_listener) != 0) {
        evconnlistener_free(c->tcp_conn_listener);
        c->tcp_conn_listener = NULL;
        return -1;
    }
    evconnlistener_set_error_cb(c->tcp_conn_listener, tcp_accept_error_cb);
    TAILQ_INIT(&c->tcp_request_queue);

    return 0;
}

int
tcp_listener_start(struct context *c)
{
    debug_assert(c->tcp_conn_listener != NULL);
    if (evconnlistener_enable(c->tcp_conn_listener) != 0) {
        return -1;
    }
    return 0;
}

void
tcp_listener_stop(struct context *c)
{
    evconnlistener_free(c->tcp_conn_listener);
    c->tcp_conn_listener = NULL;
    while (tcp_listener_kill_oldest_request(c) != 0) {
    }
    logger(LOG_INFO, "TCP listener shut down");
}
