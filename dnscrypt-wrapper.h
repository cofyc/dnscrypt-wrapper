#ifndef DNSCRYPT_WRAPPER_H
#define DNSCRYPT_WRAPPER_H

#include "compat.h"
#include "tree.h"
#include "debug.h"
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <sodium.h>

#if SODIUM_LIBRARY_VERSION_MAJOR < 7
# define sodium_allocarray(C, S) calloc(C, S)
# define sodium_malloc(S) malloc(S)
# define sodium_free(P) free(P)
#endif

#define DNS_QUERY_TIMEOUT 10

#define DNS_MAX_PACKET_SIZE_UDP_RECV (65536U - 20U - 8U)
#define DNS_MAX_PACKET_SIZE_UDP_SEND 512U

#if DNS_MAX_PACKET_SIZE_UDP_RECV > DNS_MAX_PACKET_SIZE_UDP_SEND
# define DNS_MAX_PACKET_SIZE_UDP DNS_MAX_PACKET_SIZE_UDP_RECV
#else
# define DNS_MAX_PACKET_SIZE_UDP DNS_MAX_PACKET_SIZE_UDP_SEND
#endif

#ifndef DNS_DEFAULT_STANDARD_DNS_PORT
# define DNS_DEFAULT_STANDARD_DNS_PORT "53"
#endif
#ifndef DNS_DEFAULT_LOCAL_PORT
# define DNS_DEFAULT_LOCAL_PORT DNS_DEFAULT_STANDARD_DNS_PORT
#endif
#ifndef DNS_DEFAULT_RESOLVER_PORT
# define DNS_DEFAULT_RESOLVER_PORT "443"
#endif

#define DNS_HEADER_SIZE  12U
#define DNS_FLAGS_TC      2U
#define DNS_FLAGS_QR    128U
#define DNS_FLAGS2_RA   128U

#define DNS_CLASS_IN      1U
#define DNS_TYPE_TXT     16U
#define DNS_TYPE_OPT     41U

#define DNS_OFFSET_QUESTION DNS_HEADER_SIZE
#define DNS_OFFSET_FLAGS    2U
#define DNS_OFFSET_FLAGS2   3U
#define DNS_OFFSET_QDCOUNT  4U
#define DNS_OFFSET_ANCOUNT  6U
#define DNS_OFFSET_NSCOUNT  8U
#define DNS_OFFSET_ARCOUNT 10U

#define DNS_OFFSET_EDNS_TYPE         0U
#define DNS_OFFSET_EDNS_PAYLOAD_SIZE 2U

#define DNS_DEFAULT_EDNS_PAYLOAD_SIZE 1252U

#include "dnscrypt.h"
#include "edns.h"
#include "udp_request.h"
#include "tcp_request.h"
#include "rfc1035.h"
#include "logger.h"
#include "safe_rw.h"

struct context {
    struct sockaddr_storage local_sockaddr;
    struct sockaddr_storage resolver_sockaddr;
    struct sockaddr_storage outgoing_sockaddr;
    ev_socklen_t local_sockaddr_len;
    ev_socklen_t resolver_sockaddr_len;
    ev_socklen_t outgoing_sockaddr_len;
    const char *resolver_address;
    const char *listen_address;
    const char *outgoing_address;
    struct evconnlistener *tcp_conn_listener;
    struct event *tcp_accept_timer;
    struct event *udp_listener_event;
    struct event *udp_resolver_event;
    evutil_socket_t udp_listener_handle;
    evutil_socket_t udp_resolver_handle;
    TCPRequestQueue tcp_request_queue;
    UDPRequestQueue udp_request_queue;
    struct event_base *event_loop;
    unsigned int connections;
    size_t edns_payload_size;

    /* Domain name shared buffer. */
    char namebuff[MAXDNAME];

    /* Process stuff. */
    bool daemonize;
    bool allow_not_dnscrypted;
    char *pidfile;
    char *user;
    uid_t user_id;
    gid_t user_group;
    char *user_dir;
    char *logfile;

    char *provider_publickey_file;
    char *provider_secretkey_file;
    char *provider_cert_file;
    char *crypt_secretkey_file;

    struct dnsc_server_context dnsc;
};

/**
 * Given a DNS request,iterate over the question sections.
 * If a TXT request for provider name is made, adds the certs as TXT records
 * and return 0. dns_query_len is updated to reflect the size of the DNS packet.
 * return non-zero in case of failure.
 * */
int dnscrypt_self_serve_cert_file(struct context *c,
                                  struct dns_header *header,
                                  size_t *dns_query_len);


#endif
