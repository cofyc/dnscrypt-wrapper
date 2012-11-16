#ifndef DNSCRYPT_H
#define DNSCRYPT_H

#include "compat.h"
#include <sys/queue.h>
#include <event2/event.h>
#include <event2/util.h>
#include <crypto_box.h>
#include <randombytes.h>

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

#define DNSCRYPT_MAGIC_QUERY_LEN 8U
#define DNSCRYPT_MAGIC_RESPONSE  "r6fnvWj8"

#ifndef DNSCRYPT_MAX_PADDING
# define DNSCRYPT_MAX_PADDING 256U
#endif
#ifndef DNSCRYPT_BLOCK_SIZE
# define DNSCRYPT_BLOCK_SIZE 64U
#endif
#ifndef DNSCRYPT_MIN_PAD_LEN
# define DNSCRYPT_MIN_PAD_LEN 8U
#endif
#define crypto_box_MACBYTES (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
#define crypto_box_HALF_NONCEBYTES (crypto_box_NONCEBYTES / 2U)

#define DEFAULT_PROVIDER_NAME "2.cert.dnscrypt.org."

#include "edns.h"
#include "udp_request.h"
#include "rfc1035.h"
#include "logger.h"
#include "dnscrypt_server.h"
#include "salsa20_random.h"
#include "safe_rw.h"

struct context {
     struct sockaddr_storage local_sockaddr;
     struct sockaddr_storage resolver_sockaddr;
     ev_socklen_t local_sockaddr_len;
     ev_socklen_t resolver_sockaddr_len;
     const char *resolver_address;
     const char *listen_address;
     struct event *udp_listener_event;
     struct event *udp_resolver_event;
     evutil_socket_t udp_listener_handle;
     evutil_socket_t udp_resolver_handle;
     TCPRequestQueue tcp_request_queue;
     UDPRequestQueue udp_request_queue;
     struct event_base *event_loop;
     unsigned int connections;
     unsigned int connections_max;
     size_t edns_payload_size;
     DNSCryptServer dnscrypt_server;

     /* Domain name shared buffer. */
     char namebuff[MAXDNAME];

     /* Process stuff. */
     bool daemonize;
     bool tcp_only;
     char *user;
     uid_t user_id;
     gid_t user_group;
     char *user_dir;
     char *logfile;
};

size_t dnscrypt_query_header_size(void);
int dnscrypt_cmp_client_nonce(const uint8_t
                           client_nonce[crypto_box_HALF_NONCEBYTES],
                           const uint8_t * const buf, const size_t len);
void dnscrypt_memzero(void * const pnt, const size_t size);
uint64_t dnscrypt_hrtime(void);

#endif
