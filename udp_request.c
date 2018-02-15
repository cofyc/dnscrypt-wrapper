#include "dnscrypt.h"
#include "block.h"

typedef struct SendtoWithRetryCtx_ {
    void (*cb) (UDPRequest *udp_request);
    const void *buffer;
    UDPRequest *udp_request;
    const struct sockaddr *dest_addr;
    evutil_socket_t handle;
    size_t length;
    ev_socklen_t dest_len;
    int flags;
} SendtoWithRetryCtx;

/* Forward declarations. */
static int sendto_with_retry(SendtoWithRetryCtx *const ctx);

#ifndef UDP_BUFFER_SIZE
# define UDP_BUFFER_SIZE 2097152
#endif
#ifndef UDP_DELAY_BETWEEN_RETRIES
# define UDP_DELAY_BETWEEN_RETRIES 1
#endif

#ifndef SO_RCVBUFFORCE
# define SO_RCVBUFFORCE SO_RCVBUF
#endif
#ifndef SO_SNDBUFFORCE
# define SO_SNDBUFFORCE SO_SNDBUF
#endif

#ifndef EVUTIL_ERR_RW_RETRIABLE
# ifndef _WIN32
#  define EVUTIL_ERR_RW_RETRIABLE(e) ((e) == EINTR || (e) == EAGAIN)
# else
#  define EVUTIL_ERR_RW_RETRIABLE(e) ((e) == WSAEWOULDBLOCK || (e) == WSAEINTR)
# endif
#endif

static int udp_request_cmp(const UDPRequest *r1, const UDPRequest *r2) {
    if (r1->hash < r2->hash) {
        return -1;
    } else if (r1->hash > r2->hash) {
        return 1;
    } else if (r1->id < r2->id) {
        return -1;
    } else if (r1->id > r2->id) {
        return 1;
    } else if (r1->gen < r2->gen) {
        return -1;
    } else if (r1->gen > r2->gen) {
        return 1;
    }
    return 0;
}

RB_GENERATE_STATIC(UDPRequestQueue_, UDPRequest_, queue, udp_request_cmp)

static void
udp_tune(evutil_socket_t const handle)
{
    if (handle == -1) {
        return;
    }
    setsockopt(handle, IPPROTO_IP, IP_TOS, (void *) (int []) {
                       0x70}, sizeof(int));
    setsockopt(handle, SOL_SOCKET, SO_RCVBUFFORCE, (void *)(int[]) {
               UDP_BUFFER_SIZE}, sizeof(int));
    setsockopt(handle, SOL_SOCKET, SO_SNDBUFFORCE, (void *)(int[]) {
               UDP_BUFFER_SIZE}, sizeof(int));
#if defined(IP_PMTUDISC_OMIT)
    setsockopt(handle, IPPROTO_IP, IP_MTU_DISCOVER,
               (void *) (int []) { IP_PMTUDISC_OMIT }, sizeof (int));
#elif defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
    setsockopt(handle, IPPROTO_IP, IP_MTU_DISCOVER, (void *)(int[]) {
               IP_PMTUDISC_DONT}, sizeof(int));
#elif defined(IP_DONTFRAG)
    setsockopt(handle, IPPROTO_IP, IP_DONTFRAG, (void *)(int[]) {
               0}, sizeof(int));
#endif
#if defined(__linux__) && defined(SO_REUSEPORT)
    setsockopt(handle, SOL_SOCKET, SO_REUSEPORT, (void *)(int[]) {
               1}, sizeof(int));
#endif
}

static void
client_to_proxy_cb_sendto_cb(UDPRequest *const udp_request)
{
    (void)udp_request;
}

static void
udp_request_kill(UDPRequest *const udp_request)
{
    if (udp_request == NULL || udp_request->status.is_dying)
        return;

    udp_request->status.is_dying = 1;

    // free
    struct context *c;
    if (udp_request->sendto_retry_timer != NULL) {
        free(event_get_callback_arg(udp_request->sendto_retry_timer));
        event_free(udp_request->sendto_retry_timer);
        udp_request->sendto_retry_timer = NULL;
    }
    if (udp_request->timeout_timer != NULL) {
        event_free(udp_request->timeout_timer);
        udp_request->timeout_timer = NULL;
    }

    c = udp_request->context;
    if (udp_request->status.is_in_queue != 0) {
        assert(!RB_EMPTY(&c->udp_request_queue));
        RB_REMOVE(UDPRequestQueue_, &c->udp_request_queue, udp_request);
        assert(c->connections > 0);
        c->connections--;
    }

    udp_request->context = NULL;
    free(udp_request);
}

int
udp_listener_kill_oldest_request(struct context *c)
{
    if (RB_EMPTY(&c->udp_request_queue))
        return -1;

    udp_request_kill(RB_MIN(UDPRequestQueue_, &c->udp_request_queue));

    return 0;
}

static void
sendto_with_retry_timer_cb(evutil_socket_t retry_timer_handle, short ev_flags,
                           void *const ctx_)
{
    SendtoWithRetryCtx *const ctx = ctx_;

    (void)ev_flags;
    assert(retry_timer_handle ==
           event_get_fd(ctx->udp_request->sendto_retry_timer));

    sendto_with_retry(ctx);
}

static int
sendto_with_retry(SendtoWithRetryCtx *const ctx)
{
    void (*cb) (UDPRequest *udp_request);
    SendtoWithRetryCtx *ctx_cb;
    UDPRequest *udp_request = ctx->udp_request;
    int err;
    bool retriable;

    if (sendto(ctx->handle, ctx->buffer, ctx->length, ctx->flags,
               ctx->dest_addr, ctx->dest_len) == (ssize_t) ctx->length) {
        cb = ctx->cb;
        if (udp_request->sendto_retry_timer != NULL) {
            ctx_cb = event_get_callback_arg(udp_request->sendto_retry_timer);
            assert(ctx_cb != NULL);
            assert(ctx_cb->udp_request == ctx->udp_request);
            assert(ctx_cb->buffer == ctx->buffer);
            free(ctx_cb);
            event_free(udp_request->sendto_retry_timer);
            udp_request->sendto_retry_timer = NULL;
        }
        if (cb) {
            cb(udp_request);
        }
        return 0;
    }

    err = evutil_socket_geterror(udp_request->client_proxy_handle);
    logger(LOG_WARNING, "sendto: [%s]", evutil_socket_error_to_string(err));

    retriable = (err == ENOBUFS || err == ENOMEM ||
                 err == EAGAIN || err == EINTR);

    if (retriable == 0) {
        udp_request_kill(udp_request);
        return -1;
    }
    assert(DNS_QUERY_TIMEOUT < UCHAR_MAX);
    if (++(udp_request->retries) > DNS_QUERY_TIMEOUT) {
        udp_request_kill(udp_request);
        return -1;
    }
    if (udp_request->sendto_retry_timer != NULL) {
        ctx_cb = event_get_callback_arg(udp_request->sendto_retry_timer);
        assert(ctx_cb != NULL);
        assert(ctx_cb->udp_request == ctx->udp_request);
        assert(ctx_cb->buffer == ctx->buffer);
    } else {
        if ((ctx_cb = malloc(sizeof *ctx_cb)) == NULL) {
            udp_request_kill(udp_request);
            return -1;
        }
        assert(ctx_cb ==
               event_get_callback_arg(udp_request->sendto_retry_timer));
        *ctx_cb = *ctx;
        if ((udp_request->sendto_retry_timer =
             evtimer_new(udp_request->context->event_loop,
                         sendto_with_retry_timer_cb, ctx_cb)) == NULL) {
            free(ctx_cb);
            udp_request_kill(udp_request);
            return -1;
        }
    }
    const struct timeval tv = {
        .tv_sec = (time_t) UDP_DELAY_BETWEEN_RETRIES,.tv_usec = 0
    };
    evtimer_add(udp_request->sendto_retry_timer, &tv);
    return -1;

}

static void
timeout_timer_cb(evutil_socket_t timeout_timer_handle, short ev_flags,
                 void *const udp_request_)
{
    UDPRequest *const udp_request = udp_request_;

    (void)ev_flags;
    (void)timeout_timer_handle;
    logger(LOG_DEBUG, "resolver timeout (UDP)");
    udp_request_kill(udp_request);
}

/**
 * Return 0 if served.
 */
static int
self_serve_cert_file(struct context *c, struct dns_header *header,
                     size_t dns_query_len, UDPRequest *udp_request)
{
    if (dnscrypt_self_serve_cert_file(c, header, &dns_query_len) == 0) {
            SendtoWithRetryCtx retry_ctx = {
                .udp_request = udp_request,
                .handle = udp_request->client_proxy_handle,
                .buffer = header,
                .length = dns_query_len,
                .flags = 0,
                .dest_addr = (struct sockaddr *)&udp_request->client_sockaddr,
                .dest_len = udp_request->client_sockaddr_len,
                .cb = udp_request_kill
            };
            sendto_with_retry(&retry_ctx);
            return 0;
    }
    return -1;
}

static void
client_to_proxy_cb(evutil_socket_t client_proxy_handle, short ev_flags,
                   void *const context)
{
    logger(LOG_DEBUG, "client to proxy cb");
    uint8_t dns_query[DNS_MAX_PACKET_SIZE_UDP];
    struct context *c = context;
    UDPRequest *udp_request;
    ssize_t nread;
    size_t dns_query_len = 0;

    (void)ev_flags;
    assert(client_proxy_handle == c->udp_listener_handle);

    udp_request = calloc(1, sizeof(*udp_request));
    if (udp_request == NULL)
        return;

    udp_request->context = c;
    udp_request->sendto_retry_timer = NULL;
    udp_request->timeout_timer = NULL;
    udp_request->client_proxy_handle = client_proxy_handle;
    udp_request->client_sockaddr_len = sizeof(udp_request->client_sockaddr);
    memset(&udp_request->status, 0, sizeof(udp_request->status));
    nread = recvfrom(client_proxy_handle,
                     (void *)dns_query,
                     sizeof(dns_query),
                     0,
                     (struct sockaddr *)&udp_request->client_sockaddr,
                     &udp_request->client_sockaddr_len);
    if (nread < 0) {
        const int err = evutil_socket_geterror(client_proxy_handle);
        if (!EVUTIL_ERR_RW_RETRIABLE(err)) {
            logger(LOG_WARNING, "recvfrom(client): [%s]",
                   evutil_socket_error_to_string(err));
        }
        udp_request_kill(udp_request);
        return;
    }

    if (nread < (ssize_t) DNS_HEADER_SIZE || nread > sizeof(dns_query)) {
        logger(LOG_WARNING, "Short query received");
        udp_request_kill(udp_request);
        return;
    }

    dns_query_len = (size_t) nread;
    assert(dns_query_len <= sizeof(dns_query));

    assert(SIZE_MAX - DNSCRYPT_MAX_PADDING - DNSCRYPT_QUERY_HEADER_SIZE >
           dns_query_len);

    udp_request->len = (uint16_t) dns_query_len;
    // decrypt if encrypted
    struct dnscrypt_query_header *dnscrypt_header =
        (struct dnscrypt_query_header *)dns_query;
    debug_assert(sizeof c->keypairs[0].crypt_publickey >= DNSCRYPT_MAGIC_HEADER_LEN);
    if ((udp_request->cert =
         find_cert(c, dnscrypt_header->magic_query, dns_query_len)) == NULL) {
        udp_request->is_dnscrypted = false;
    } else {
        if (dnscrypt_server_uncurve(c, udp_request->cert,
                                    udp_request->client_nonce,
                                    udp_request->nmkey, dns_query,
                                    &dns_query_len) != 0) {
            logger(LOG_WARNING, "Received a suspicious query from the client");
            udp_request_kill(udp_request);
            return;
        }
        udp_request->is_dnscrypted = true;
    }

    struct dns_header *header = (struct dns_header *)dns_query;

    // self serve signed certificate for provider name?
    if (!udp_request->is_dnscrypted) {
        if (self_serve_cert_file(c, header, dns_query_len, udp_request) == 0)
            return;
        if (!c->allow_not_dnscrypted) {
            logger(LOG_DEBUG, "Unauthenticated query received over UDP");
            udp_request_kill(udp_request);
            return;
        }
    }

    udp_request->is_blocked = is_blocked(c, header, dns_query_len);

    udp_request->id = ntohs(header->id);
    if (questions_hash(&udp_request->hash, header, dns_query_len, c->namebuff, c->hash_key) != 0) {
        logger(LOG_WARNING, "Received a suspicious query from the client");
        udp_request_kill(udp_request);
        return;
    }

    static uint16_t gen;
    udp_request->gen = gen++;
    udp_request->status.is_in_queue = 1;
    c->connections++;
    RB_INSERT(UDPRequestQueue_, &c->udp_request_queue, udp_request);

    udp_request->timeout_timer =
        evtimer_new(udp_request->context->event_loop, timeout_timer_cb,
                    udp_request);
    if (udp_request->timeout_timer) {
        const struct timeval tv = {
            .tv_sec = (time_t) DNS_QUERY_TIMEOUT,.tv_usec = 0
        };
        evtimer_add(udp_request->timeout_timer, &tv);
    }

    SendtoWithRetryCtx retry_ctx = {
        .udp_request = udp_request,.handle =
            c->udp_resolver_handle,.buffer = dns_query,.length =
            dns_query_len,.flags = 0,.dest_addr =
            (struct sockaddr *)&c->resolver_sockaddr,.dest_len =
            c->resolver_sockaddr_len,.cb = client_to_proxy_cb_sendto_cb
    };
    sendto_with_retry(&retry_ctx);
}

/*
 * Find corresponding request by DNS id and hash of questions.
 */
static UDPRequest *
lookup_request(struct context *c, uint16_t id, uint64_t hash)
{
    UDPRequest *found_udp_request;
    UDPRequest scanned_udp_request;

    scanned_udp_request.hash = hash;
    scanned_udp_request.id = id;
    scanned_udp_request.gen = (uint16_t) 0U;
    found_udp_request = RB_NFIND(UDPRequestQueue_, &c->udp_request_queue,
                                 &scanned_udp_request);
    if (found_udp_request == NULL ||
        found_udp_request->hash != hash || found_udp_request->id != id) {
        return NULL;
    }
    return found_udp_request;
}

static int
maybe_truncate(uint8_t *const dns_reply, size_t *const dns_reply_len_p, size_t query_len)
{
    struct dns_header *header = (struct dns_header *)dns_reply;
    uint8_t *ansp;

    if (*dns_reply_len_p <= sizeof(struct dns_header)) {
        *dns_reply_len_p = 0;
        return -1;
    }
    if (query_len >= *dns_reply_len_p) {
        return 0;
    }
    if (!(ansp = skip_questions(header, *dns_reply_len_p))) {
        *dns_reply_len_p = sizeof(struct dns_header);
        return -1;
    }
    *dns_reply_len_p = (size_t) (ansp - dns_reply);
    header->hb3 |= HB3_TC;
    header->ancount = htons(0);
    header->nscount = htons(0);
    header->arcount = htons(0);

    return 0;
}

static void
resolver_to_proxy_cb(evutil_socket_t proxy_resolver_handle, short ev_flags,
                     void *const context)
{
    logger(LOG_DEBUG, "resolver to proxy cb");
    uint8_t dns_reply[DNS_MAX_PACKET_SIZE_UDP];
    struct context *c = context;
    UDPRequest *udp_request = NULL;
    struct sockaddr_storage resolver_sockaddr;
    ev_socklen_t resolver_sockaddr_len = sizeof(struct sockaddr_storage);
    ssize_t nread;
    size_t dns_reply_len = (size_t) 0U;

    (void)ev_flags;

    nread = recvfrom(proxy_resolver_handle,
                     (void *)dns_reply, sizeof(dns_reply), 0,
                     (struct sockaddr *)&resolver_sockaddr,
                     &resolver_sockaddr_len);
    if (nread < 0) {
        const int err = evutil_socket_geterror(proxy_resolver_handle);
        if (!EVUTIL_ERR_RW_RETRIABLE(err)) {
            logger(LOG_WARNING, "recvfrom(resolver): [%s]",
                   evutil_socket_error_to_string(err));
        }
        return;
    }
    if (evutil_sockaddr_cmp((const struct sockaddr *)&resolver_sockaddr,
                            (const struct sockaddr *)
                            &c->resolver_sockaddr, 1) != 0) {
        logger(LOG_WARNING,
               "Received a resolver reply from a different resolver");
        return;
    }
    dns_reply_len = nread;

    struct dns_header *header = (struct dns_header *)dns_reply;
    uint16_t id = ntohs(header->id);
    uint64_t hash;
    if (questions_hash(&hash, header, dns_reply_len, c->namebuff, c->hash_key) != 0) {
        logger(LOG_ERR, "Received an invalid response from the server");
        return;
    }
    udp_request = lookup_request(c, id, hash);
    if (udp_request == NULL) {
        logger(LOG_DEBUG, "Received a reply that doesn't match any active query");
        return;
    }
    size_t max_reply_size = DNS_MAX_PACKET_SIZE_UDP;
    size_t max_len =
        dns_reply_len + DNSCRYPT_MAX_PADDING + DNSCRYPT_REPLY_HEADER_SIZE;
    if (max_len > max_reply_size)
        max_len = max_reply_size;

    if (udp_request->is_blocked) {
        struct dns_header *p = (struct dns_header *) dns_reply;
        SET_RCODE(p, REFUSED);
    }
    maybe_truncate(dns_reply, &dns_reply_len, udp_request->len);

    if (udp_request->is_dnscrypted) {
        if (dnscrypt_server_curve
            (c, udp_request->cert, udp_request->client_nonce, udp_request->nmkey, dns_reply,
             &dns_reply_len, max_len) != 0) {
            logger(LOG_ERR, "Curving reply failed.");
            return;
        }
    }

    SendtoWithRetryCtx retry_ctx = {
        .udp_request = udp_request,.handle =
            udp_request->client_proxy_handle,.buffer =
            dns_reply,.length = dns_reply_len,.flags = 0,.dest_addr =
            (struct sockaddr *)&udp_request->client_sockaddr,.dest_len =
            udp_request->client_sockaddr_len,.cb = udp_request_kill
    };
    sendto_with_retry(&retry_ctx);
}

int
udp_listener_bind(struct context *c)
{
    // listen socket & bind
    assert(c->udp_listener_handle == -1);

    if ((c->udp_listener_handle =
         socket(c->local_sockaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        logger(LOG_ERR, "Unable to create a socket (UDP)");
        return -1;
    }

    udp_tune(c->udp_listener_handle);

    evutil_make_socket_closeonexec(c->udp_listener_handle);
    evutil_make_socket_nonblocking(c->udp_listener_handle);
    if (bind
        (c->udp_listener_handle, (struct sockaddr *)&c->local_sockaddr,
         c->local_sockaddr_len) != 0) {
        logger(LOG_ERR, "Unable to bind (UDP) [%s]",
               evutil_socket_error_to_string(evutil_socket_geterror
                                             (c->udp_listener_handle)));
        evutil_closesocket(c->udp_listener_handle);
        c->udp_listener_handle = -1;
        return -1;
    }

    // resolver socket
    assert(c->udp_resolver_handle == -1);
    if ((c->udp_resolver_handle =
         socket(c->resolver_sockaddr.ss_family, SOCK_DGRAM,
                IPPROTO_UDP)) == -1) {
        logger(LOG_ERR, "Unable to create a socket to the resolver");
        evutil_closesocket(c->udp_resolver_handle);
        c->udp_listener_handle = -1;
    }
    evutil_make_socket_closeonexec(c->udp_resolver_handle);
    evutil_make_socket_nonblocking(c->udp_resolver_handle);
    udp_tune(c->udp_resolver_handle);

    /* Bind source IP:port if --outgoing-address is provided */
    if(c->outgoing_address &&
       bind(c->udp_resolver_handle, (struct sockaddr *)&c->outgoing_sockaddr,
            c->outgoing_sockaddr_len) != 0) {
        logger(LOG_ERR, "Unable to bind (UDP) [%s]",
            evutil_socket_error_to_string(evutil_socket_geterror
                                          (c->udp_resolver_handle)));
        evutil_closesocket(c->udp_resolver_handle);
        c->udp_resolver_handle = -1;
        return -1;
    }

    RB_INIT(&c->udp_request_queue);

    return 0;
}

void
udp_listener_stop(struct context *c)
{
    event_free(c->udp_resolver_event);
    c->udp_resolver_event = NULL;

    while (udp_listener_kill_oldest_request(c) == 0);
    logger(LOG_INFO, "UDP listener shut down");
}

int
udp_listener_start(struct context *c)
{
    assert(c->udp_listener_handle != -1);
    if ((c->udp_listener_event =
         event_new(c->event_loop, c->udp_listener_handle, EV_READ | EV_PERSIST,
                   client_to_proxy_cb, c)) == NULL) {
        return -1;
    }
    if (event_add(c->udp_listener_event, NULL) != 0) {
        udp_listener_stop(c);
        return -1;
    }

    assert(c->udp_resolver_handle != -1);
    if ((c->udp_resolver_event =
         event_new(c->event_loop, c->udp_resolver_handle, EV_READ | EV_PERSIST,
                   resolver_to_proxy_cb, c)) == NULL) {
        udp_listener_stop(c);
        return -1;
    }
    if (event_add(c->udp_resolver_event, NULL) != 0) {
        udp_listener_stop(c);
        return -1;
    }
    return 0;
}
