#ifndef UDP_REQUEST_H
#define UDP_REQUEST_H

#include "dnscrypt.h"

struct context;

typedef struct UDPRequestStatus_ {
    _Bool is_dying:1;
    _Bool is_in_queue:1;
} UDPRequestStatus;

typedef struct UDPRequest_ {
    uint16_t id;
    uint8_t client_nonce[crypto_box_HALF_NONCEBYTES];
    TAILQ_ENTRY(UDPRequest_) queue;
    struct sockaddr_storage client_sockaddr;
    struct context *context;
    struct event *sendto_retry_timer;
    struct event *timeout_timer;
    evutil_socket_t client_proxy_handle;
    ev_socklen_t client_sockaddr_len;
    UDPRequestStatus status;
    unsigned char retries;
} UDPRequest;

typedef TAILQ_HEAD(TCPRequestQueue_, TCPRequest_) TCPRequestQueue;
typedef TAILQ_HEAD(UDPRequestQueue_, UDPRequest_) UDPRequestQueue;

int udp_listern_bind(struct context *c);
int udp_listener_start(struct context *c);
void udp_listener_stop(struct context *c);

#endif
