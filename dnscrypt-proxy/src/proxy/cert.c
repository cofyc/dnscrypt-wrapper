
#include <config.h>
#include <sys/types.h>
#ifdef _WIN32
# include <winsock2.h>
#else
# include <sys/socket.h>
# include <arpa/inet.h>
#endif

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/dns.h>
#include <event2/event.h>

#include "cert.h"
#include "cert_p.h"
#include "crypto_sign_ed25519.h"
#include "dnscrypt_proxy.h"
#include "logger.h"
#include "probes.h"
#include "salsa20_random.h"
#include "utils.h"

static int cert_updater_update(ProxyContext * const proxy_context);

static int
cert_parse_version(ProxyContext * const proxy_context,
                   const SignedBincert * const signed_bincert,
                   const size_t signed_bincert_len)
{
    if (signed_bincert_len <= (size_t) (signed_bincert->signed_data -
                                        signed_bincert->magic_cert) ||
        memcmp(signed_bincert->magic_cert, CERT_MAGIC_CERT,
               sizeof signed_bincert->magic_cert) != 0) {
        logger_noformat(proxy_context, LOG_DEBUG,
                        "TXT record with no certificates received");
        return -1;
    }
    if (signed_bincert->version_major[0] != 0U ||
        signed_bincert->version_major[1] != 1U) {
        logger_noformat(proxy_context, LOG_WARNING,
                        "Unsupported certificate version");
        return -1;
    }
    return 0;
}

static int
cert_parse_bincert(ProxyContext * const proxy_context,
                   const Bincert * const bincert,
                   const Bincert * const previous_bincert)
{
    uint32_t serial;
    memcpy(&serial, bincert->serial, sizeof serial);
    serial = htonl(serial);
    logger(proxy_context, LOG_INFO,
           "Server certificate #%" PRIu32 " received", serial);

    uint32_t ts_begin;
    memcpy(&ts_begin, bincert->ts_begin, sizeof ts_begin);
    ts_begin = htonl(ts_begin);

    uint32_t ts_end;
    memcpy(&ts_end, bincert->ts_end, sizeof ts_end);
    ts_end = htonl(ts_end);

    uint32_t now_u32 = (uint32_t) time(NULL);

    if (now_u32 < ts_begin) {
        logger_noformat(proxy_context, LOG_INFO,
                        "This certificate has not been activated yet");
        return -1;
    }
    if (now_u32 > ts_end) {
        logger_noformat(proxy_context, LOG_INFO,
                        "This certificate has expired");
        return -1;
    }
    logger_noformat(proxy_context, LOG_INFO, "This certificate looks valid");
    if (previous_bincert == NULL) {
        return 0;
    }

    uint32_t previous_serial;
    memcpy(&previous_serial, previous_bincert->serial, sizeof previous_serial);
    previous_serial = htonl(previous_serial);
    if (previous_serial > serial) {
        logger(proxy_context, LOG_INFO, "Certificate #%" PRIu32 " "
               "has been superseded by certificate #%" PRIu32,
               previous_serial, serial);
        return -1;
    }
    logger(proxy_context, LOG_INFO,
           "This certificate supersedes certificate #%" PRIu32,
           previous_serial);

    return 0;
}

static int
cert_open_bincert(ProxyContext * const proxy_context,
                  const SignedBincert * const signed_bincert,
                  const size_t signed_bincert_len,
                  Bincert ** const bincert_p)
{
    Bincert            *bincert;
    unsigned long long  bincert_data_len_ul;
    size_t              bincert_size;
    size_t              signed_data_len;

    if (cert_parse_version(proxy_context,
                           signed_bincert, signed_bincert_len) != 0) {
        DNSCRYPT_PROXY_CERTS_UPDATE_ERROR_COMMUNICATION();
        return -1;
    }
    bincert_size = signed_bincert_len;
    if ((bincert = malloc(bincert_size)) == NULL) {
        DNSCRYPT_PROXY_CERTS_UPDATE_ERROR_COMMUNICATION();
        return -1;
    }
    assert(signed_bincert_len >= (size_t) (signed_bincert->signed_data -
                                           signed_bincert->magic_cert));
    signed_data_len = signed_bincert_len -
        (size_t) (signed_bincert->signed_data - signed_bincert->magic_cert);
    assert(bincert_size - (size_t) (bincert->server_publickey -
                                    bincert->magic_cert) == signed_data_len);
    if (crypto_sign_ed25519_open(bincert->server_publickey, &bincert_data_len_ul,
                                 signed_bincert->signed_data, signed_data_len,
                                 proxy_context->provider_publickey) != 0) {
        free(bincert);
        logger_noformat(proxy_context, LOG_ERR,
                        "Suspicious certificate received");
        DNSCRYPT_PROXY_CERTS_UPDATE_ERROR_SECURITY();
        return -1;
    }
    if (cert_parse_bincert(proxy_context, bincert, *bincert_p) != 0) {
        memset(bincert, 0, sizeof *bincert);
        free(bincert);
        return -1;
    }
    if (*bincert_p != NULL) {
        memset(*bincert_p, 0, sizeof **bincert_p);
        free(*bincert_p);
    }
    *bincert_p = bincert;

    return 0;
}

static void
cert_print_server_key(ProxyContext * const proxy_context)
{
    char fingerprint[80U];

    dnscrypt_key_to_fingerprint(fingerprint,
                                proxy_context->resolver_publickey);
    logger(proxy_context, LOG_INFO,
           "Server key fingerprint is %s", fingerprint);
}

static void
cert_timer_cb(evutil_socket_t handle, const short event,
              void * const proxy_context_)
{
    ProxyContext * const proxy_context = proxy_context_;

    (void) handle;
    (void) event;
    logger_noformat(proxy_context, LOG_INFO,
                    "Refetching server certificates");
    cert_updater_update(proxy_context);
}

static void
cert_reschedule_query(ProxyContext * const proxy_context,
                      const time_t query_retry_delay)
{
    CertUpdater *cert_updater = &proxy_context->cert_updater;

    if (evtimer_pending(cert_updater->cert_timer, NULL)) {
        return;
    }
    const struct timeval tv = { .tv_sec = query_retry_delay, .tv_usec = 0 };
    evtimer_add(cert_updater->cert_timer, &tv);
}

static void
cert_reschedule_query_after_failure(ProxyContext * const proxy_context)
{
    CertUpdater *cert_updater = &proxy_context->cert_updater;
    time_t       query_retry_delay;

    if (evtimer_pending(cert_updater->cert_timer, NULL)) {
        return;
    }
    query_retry_delay = (time_t)
        (CERT_QUERY_RETRY_MIN_DELAY +
            (time_t) cert_updater->query_retry_step *
            (CERT_QUERY_RETRY_MAX_DELAY - CERT_QUERY_RETRY_MIN_DELAY) /
            CERT_QUERY_RETRY_STEPS);
    if (cert_updater->query_retry_step < CERT_QUERY_RETRY_STEPS) {
        cert_updater->query_retry_step++;
    }
    cert_reschedule_query(proxy_context, query_retry_delay);
    DNSCRYPT_PROXY_CERTS_UPDATE_RETRY();
}

static void
cert_reschedule_query_after_success(ProxyContext * const proxy_context)
{
    if (evtimer_pending(proxy_context->cert_updater.cert_timer, NULL)) {
        return;
    }
    cert_reschedule_query(proxy_context, (time_t)
                          CERT_QUERY_RETRY_DELAY_AFTER_SUCCESS_MIN_DELAY
                          + (time_t) salsa20_random_uniform
                          (CERT_QUERY_RETRY_DELAY_AFTER_SUCCESS_JITTER));
}

static void
cert_query_cb(int result, char type, int count, int ttl,
              void * const txt_records_, void * const arg)
{
    Bincert                 *bincert = NULL;
    ProxyContext            *proxy_context = arg;
    const struct txt_record *txt_records = txt_records_;
    int                      i = 0;

    (void) type;
    (void) ttl;
    DNSCRYPT_PROXY_CERTS_UPDATE_RECEIVED();
    evdns_base_free(proxy_context->cert_updater.evdns_base, 0);
    proxy_context->cert_updater.evdns_base = NULL;
    if (result != DNS_ERR_NONE) {
        logger_noformat(proxy_context, LOG_ERR,
                        "Unable to retrieve server certificates");
        cert_reschedule_query_after_failure(proxy_context);
        DNSCRYPT_PROXY_CERTS_UPDATE_ERROR_COMMUNICATION();
        return;
    }
    assert(count >= 0);
    while (i < count) {
        cert_open_bincert(proxy_context,
                          (const SignedBincert *) txt_records[i].txt,
                          txt_records[i].len, &bincert);
        i++;
    }
    if (bincert == NULL) {
        logger_noformat(proxy_context, LOG_ERR,
                        "No useable certificates found");
        cert_reschedule_query_after_failure(proxy_context);
        DNSCRYPT_PROXY_CERTS_UPDATE_ERROR_NOCERTS();
        return;
    }
    COMPILER_ASSERT(sizeof proxy_context->resolver_publickey ==
                    sizeof bincert->server_publickey);
    memcpy(proxy_context->resolver_publickey, bincert->server_publickey,
           sizeof proxy_context->resolver_publickey);
    COMPILER_ASSERT(sizeof proxy_context->dnscrypt_magic_query ==
                    sizeof bincert->magic_query);
    memcpy(proxy_context->dnscrypt_magic_query, bincert->magic_query,
           sizeof proxy_context->dnscrypt_magic_query);
    cert_print_server_key(proxy_context);
    dnscrypt_client_init_magic_query(&proxy_context->dnscrypt_client,
                                     bincert->magic_query);
    memset(bincert, 0, sizeof *bincert);
    free(bincert);
    dnscrypt_client_init_nmkey(&proxy_context->dnscrypt_client,
                               proxy_context->resolver_publickey);
    dnscrypt_proxy_start_listeners(proxy_context);
    proxy_context->cert_updater.query_retry_step = 0U;
    cert_reschedule_query_after_success(proxy_context);
    DNSCRYPT_PROXY_CERTS_UPDATE_DONE((unsigned char *)
                                     proxy_context->resolver_publickey);
}

int
cert_updater_init(ProxyContext * const proxy_context)
{
    CertUpdater *cert_updater = &proxy_context->cert_updater;

    memset(cert_updater, 0, sizeof *cert_updater);
    assert(proxy_context->event_loop != NULL);
    assert(cert_updater->cert_timer == NULL);
    if ((cert_updater->cert_timer =
         evtimer_new(proxy_context->event_loop,
                     cert_timer_cb, proxy_context)) == NULL) {
        return -1;
    }
    cert_updater->query_retry_step = 0U;
    cert_updater->evdns_base = NULL;

    return 0;
}

static int
cert_updater_update(ProxyContext * const proxy_context)
{
    CertUpdater *cert_updater = &proxy_context->cert_updater;

    DNSCRYPT_PROXY_CERTS_UPDATE_START();
    if (cert_updater->evdns_base != NULL) {
        evdns_base_free(cert_updater->evdns_base, 0);
    }
    if ((cert_updater->evdns_base =
         evdns_base_new(proxy_context->event_loop, 0)) == NULL) {
        return -1;
    }
    if (evdns_base_nameserver_sockaddr_add(cert_updater->evdns_base,
                                           (struct sockaddr *)
                                           &proxy_context->resolver_sockaddr,
                                           proxy_context->resolver_sockaddr_len,
                                           DNS_QUERY_NO_SEARCH) != 0) {
        return -1;
    }
    if (proxy_context->tcp_only != 0) {
        (void) evdns_base_nameserver_ip_add(cert_updater->evdns_base,
                                            proxy_context->resolver_ip);
    }
    if (evdns_base_resolve_txt(cert_updater->evdns_base,
                               proxy_context->provider_name,
                               DNS_QUERY_NO_SEARCH,
                               cert_query_cb,
                               proxy_context) == NULL) {
        return -1;
    }
    return 0;
}

int
cert_updater_start(ProxyContext * const proxy_context)
{
    evdns_set_random_init_fn(NULL);
    evdns_set_random_bytes_fn(salsa20_random_buf);
    cert_updater_update(proxy_context);

    return 0;
}

void
cert_updater_stop(ProxyContext * const proxy_context)
{
    CertUpdater * const cert_updater = &proxy_context->cert_updater;

    assert(cert_updater->cert_timer != NULL);
    evtimer_del(cert_updater->cert_timer);
}

void
cert_updater_free(ProxyContext * const proxy_context)
{
    CertUpdater * const cert_updater = &proxy_context->cert_updater;

    event_free(cert_updater->cert_timer);
    cert_updater->cert_timer = NULL;
    if (cert_updater->evdns_base != NULL) {
        evdns_base_free(cert_updater->evdns_base, 0);
        cert_updater->evdns_base = NULL;
    }
}
