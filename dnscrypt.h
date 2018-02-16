#ifndef DNSCRYPT_H
#define DNSCRYPT_H

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

#define DNSCRYPT_MAGIC_HEADER_LEN 8U
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

#define crypto_box_HALF_NONCEBYTES (crypto_box_NONCEBYTES / 2U)

#define DEFAULT_PROVIDER_NAME "2.cert.dnscrypt.org"

#include "edns.h"
#include "udp_request.h"
#include "tcp_request.h"
#include "rfc1035.h"
#include "logger.h"
#include "safe_rw.h"
#include "cert.h"

#define DNSCRYPT_QUERY_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES + crypto_box_MACBYTES)
#define DNSCRYPT_RESPONSE_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_NONCEBYTES + crypto_box_MACBYTES)

#define DNSCRYPT_REPLY_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_HALF_NONCEBYTES * 2 + crypto_box_MACBYTES)

#define XSALSA20_CERT(cert) (cert->es_version[0] == 0 && \
    cert->es_version[1] == 1)
#define XCHACHA20_CERT(cert) (cert->es_version[0] == 0 && \
    cert->es_version[1] == 2)

typedef struct KeyPair_ {
    uint8_t crypt_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t crypt_secretkey[crypto_box_SECRETKEYBYTES];
} KeyPair;

typedef struct cert_ {
    uint8_t magic_query[DNSCRYPT_MAGIC_HEADER_LEN];
    uint8_t es_version[2];
    KeyPair *keypair;
} dnsccert;

struct context {
    struct sockaddr_storage local_sockaddr;
    struct sockaddr_storage resolver_sockaddr;
    struct sockaddr_storage outgoing_sockaddr;
    ev_socklen_t local_sockaddr_len;
    ev_socklen_t resolver_sockaddr_len;
    ev_socklen_t outgoing_sockaddr_len;
    const char *ext_address;
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
    char *provider_name;
    char *provider_publickey_file;
    char *provider_secretkey_file;
    char *provider_cert_file;
    struct SignedCert *signed_certs;
    size_t signed_certs_count;
    dnsccert *certs;
    uint8_t provider_publickey[crypto_sign_ed25519_PUBLICKEYBYTES];
    uint8_t provider_secretkey[crypto_sign_ed25519_SECRETKEYBYTES];
    char *crypt_secretkey_file;
    KeyPair *keypairs;
    size_t keypairs_count;
    uint64_t nonce_ts_last;
    unsigned char hash_key[crypto_shorthash_KEYBYTES];

    /* blocking */
    struct Blocking_ *blocking;
};

const dnsccert * find_cert(const struct context *c,
                           const unsigned char magic_query[DNSCRYPT_MAGIC_HEADER_LEN],
                           const size_t dns_query_len);
int dnscrypt_cmp_client_nonce(const uint8_t
                              client_nonce[crypto_box_HALF_NONCEBYTES],
                              const uint8_t *const buf, const size_t len);
void dnscrypt_memzero(void *const pnt, const size_t size);
uint64_t dnscrypt_hrtime(void);
void dnscrypt_key_to_fingerprint(char fingerprint[80U],
                                 const uint8_t *const key);
int dnscrypt_fingerprint_to_key(const char *const fingerprint,
                                uint8_t key[crypto_box_PUBLICKEYBYTES]);

// vim-like binary display
static inline void
print_binary_string(uint8_t *s, size_t count)
{
    for (size_t i = 1; i <= count; i++) {
        uint8_t x = *((uint8_t *)s + i - 1);
        if (x >= (uint8_t)'0' && x <= (uint8_t)'9') {
            printf("%d", x);
        } else if (x >= (uint8_t)'a' && x <= (uint8_t)'z') {
            printf("%c", x);
        } else if (x >= (uint8_t)'A' && x <= (uint8_t)'Z') {
            printf("%c", x);
        } else {
            printf("\\%03d", x);
        }
        if (i % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

// binary in hex
static inline void
print_binary_string_hex(uint8_t *s, size_t count)
{
    for (size_t i = 1; i <= count; i++) {
        if ((i - 1) % 16 == 0) {
            printf("%04zx: ", (i - 1));
        }
        uint8_t x = *((uint8_t *)s + i - 1);
        printf("%02x ", x);
        if (i % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

struct dnscrypt_query_header {
    uint8_t magic_query[DNSCRYPT_MAGIC_HEADER_LEN];
    uint8_t publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t nonce[crypto_box_HALF_NONCEBYTES];
    uint8_t mac[crypto_box_MACBYTES];
};

int dnscrypt_server_uncurve(struct context *c, const dnsccert *cert,
                            uint8_t client_nonce[crypto_box_HALF_NONCEBYTES],
                            uint8_t nmkey[crypto_box_BEFORENMBYTES],
                            uint8_t *const buf, size_t * const lenp);
int dnscrypt_server_curve(struct context *c, const dnsccert *cert,
                          uint8_t client_nonce[crypto_box_HALF_NONCEBYTES],
                          uint8_t nmkey[crypto_box_BEFORENMBYTES],
                          uint8_t *const buf, size_t * const lenp,
                          const size_t max_len);
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
