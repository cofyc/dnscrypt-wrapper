#ifndef TCP_REQUEST_H
#define TCP_REQUEST_H

#include "dnscrypt.h"

#define DNS_MAX_PACKET_SIZE_TCP (65535U + 2U)

#ifndef TCP_REQUEST_BACKLOG
# define TCP_REQUEST_BACKLOG 128
#endif

struct context;
struct cert_;

typedef struct TCPRequestStatus_ {
    bool has_dns_query_len:1;
    bool has_dns_reply_len:1;
    bool is_in_queue:1;
    bool is_dying:1;
} TCPRequestStatus;

typedef struct TCPRequest_ {
    TAILQ_ENTRY(TCPRequest_) queue;
    struct bufferevent *client_proxy_bev;
    struct bufferevent *proxy_resolver_bev;
    struct evbuffer *proxy_resolver_query_evbuf;
    struct context *context;
    struct event *timeout_timer;
    uint8_t client_nonce[crypto_box_HALF_NONCEBYTES];
    uint8_t nmkey[crypto_box_BEFORENMBYTES];
    size_t dns_query_len;
    size_t dns_reply_len;
    TCPRequestStatus status;
    const struct cert_ *cert;
    bool is_dnscrypted;
    bool is_blocked;
} TCPRequest;

int tcp_listener_bind(struct context *c);
int tcp_listener_start(struct context *c);
void tcp_listener_stop(struct context *c);

#endif
