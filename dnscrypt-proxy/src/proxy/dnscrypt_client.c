
#include <config.h>
#include <sys/types.h>
#include <sys/time.h>
#ifdef _WIN32
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/event.h>

#include "dnscrypt.h"
#include "dnscrypt_client.h"
#include "salsa20_random.h"
#include "utils.h"

static void
dnscrypt_make_client_nonce(DNSCryptClient * const client,
                           uint8_t client_nonce[crypto_box_HALF_NONCEBYTES])
{
    uint64_t ts;
    uint64_t tsn;
    uint32_t suffix;

    ts = dnscrypt_hrtime();
    if (ts <= client->nonce_ts_last) {
        ts = client->nonce_ts_last + (uint64_t) 1U;
    }
    client->nonce_ts_last = ts;

    tsn = (ts << 10) | (salsa20_random() & 0x3ff);
#ifdef WORDS_BIGENDIAN
    tsn = (((uint64_t) htonl((uint32_t) tsn)) << 32) |
        htonl((uint32_t) (tsn >> 32));
#endif
    COMPILER_ASSERT(crypto_box_HALF_NONCEBYTES == 12U);
    memcpy(client_nonce, &tsn, 8U);
    suffix = salsa20_random();
    memcpy(client_nonce + 8U, &suffix, 4U);
}

//  8 bytes: magic_query
// 32 bytes: the client's DNSCurve public key (crypto_box_PUBLICKEYBYTES)
// 12 bytes: a client-selected nonce for this packet (crypto_box_NONCEBYTES / 2)
// 16 bytes: Poly1305 MAC (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)

ssize_t
dnscrypt_client_curve(DNSCryptClient * const client,
                      uint8_t client_nonce[crypto_box_HALF_NONCEBYTES],
                      uint8_t *buf, size_t len, const size_t max_len)
{
    uint8_t  nonce[crypto_box_NONCEBYTES];
    uint8_t *boxed;

#if crypto_box_MACBYTES > 8U + crypto_box_NONCEBYTES
# error Cannot curve in-place
#endif
    if (max_len < len || max_len - len < dnscrypt_query_header_size()) {
        return (ssize_t) -1;
    }
    assert(max_len > dnscrypt_query_header_size());
    boxed = buf + sizeof client->magic_query
        + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES;
    memmove(boxed + crypto_box_MACBYTES, buf, len);
    len = dnscrypt_pad(boxed + crypto_box_MACBYTES, len,
                       max_len - dnscrypt_query_header_size());
    memset(boxed - crypto_box_BOXZEROBYTES, 0, crypto_box_ZEROBYTES);
    dnscrypt_make_client_nonce(client, nonce);
    memcpy(client_nonce, nonce, crypto_box_HALF_NONCEBYTES);
    memset(nonce + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

    if (crypto_box_afternm
        (boxed - crypto_box_BOXZEROBYTES, boxed - crypto_box_BOXZEROBYTES,
         len + crypto_box_ZEROBYTES, nonce, client->nmkey) != 0) {
        return (ssize_t) -1;
    }
    memcpy(buf, client->magic_query, sizeof client->magic_query);
    memcpy(buf + sizeof client->magic_query, client->publickey,
           crypto_box_PUBLICKEYBYTES);
    memcpy(buf + sizeof client->magic_query + crypto_box_PUBLICKEYBYTES,
           nonce, crypto_box_HALF_NONCEBYTES);

    return (ssize_t) (len + dnscrypt_query_header_size());
}

//  8 bytes: the string r6fnvWJ8 (DNSCRYPT_MAGIC_RESPONSE)
// 12 bytes: the client's nonce (crypto_box_NONCEBYTES / 2)
// 12 bytes: a server-selected nonce extension (crypto_box_NONCEBYTES / 2)
// 16 bytes: Poly1305 MAC (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)

#define DNSCRYPT_SERVER_BOX_OFFSET \
    (sizeof DNSCRYPT_MAGIC_RESPONSE - 1U + crypto_box_NONCEBYTES)

int
dnscrypt_client_uncurve(const DNSCryptClient * const client,
                        const uint8_t client_nonce[crypto_box_HALF_NONCEBYTES],
                        uint8_t * const buf, size_t * const lenp)
{
    uint8_t nonce[crypto_box_NONCEBYTES];
    size_t  len = *lenp;

    if (len <= dnscrypt_response_header_size() ||
        memcmp(buf, DNSCRYPT_MAGIC_RESPONSE,
               sizeof DNSCRYPT_MAGIC_RESPONSE - 1U)) {
        return 1;
    }
    if (dnscrypt_cmp_client_nonce(client_nonce, buf, len) != 0) {
        return -1;
    }
    memcpy(nonce, buf + sizeof DNSCRYPT_MAGIC_RESPONSE - 1U,
           crypto_box_NONCEBYTES);
    memset(buf + DNSCRYPT_SERVER_BOX_OFFSET - crypto_box_BOXZEROBYTES, 0,
           crypto_box_BOXZEROBYTES);
    if (crypto_box_open_afternm
        (buf + DNSCRYPT_SERVER_BOX_OFFSET - crypto_box_BOXZEROBYTES,
         buf + DNSCRYPT_SERVER_BOX_OFFSET - crypto_box_BOXZEROBYTES,
         len - DNSCRYPT_SERVER_BOX_OFFSET + crypto_box_BOXZEROBYTES,
         nonce, client->nmkey)) {
        return -1;
    }
    dnscrypt_memzero(nonce, sizeof nonce);
    assert(len >= DNSCRYPT_SERVER_BOX_OFFSET + crypto_box_BOXZEROBYTES);
    while (buf[--len] == 0U) { }
    if (buf[len] != 0x80) {
        return -1;
    }
    *lenp = len - (DNSCRYPT_SERVER_BOX_OFFSET + crypto_box_BOXZEROBYTES);
    memmove(buf,
            buf + DNSCRYPT_SERVER_BOX_OFFSET + crypto_box_BOXZEROBYTES, *lenp);
    return 0;
}

int
dnscrypt_client_init_magic_query(DNSCryptClient * const client,
                                 const uint8_t magic_query[DNSCRYPT_MAGIC_QUERY_LEN])
{
    COMPILER_ASSERT(DNSCRYPT_MAGIC_QUERY_LEN == sizeof client->magic_query);
    memcpy(client->magic_query, magic_query, sizeof client->magic_query);

    return 0;
}

int
dnscrypt_client_init_nmkey(DNSCryptClient * const client,
                           const uint8_t server_publickey[crypto_box_PUBLICKEYBYTES])
{
#if crypto_box_BEFORENMBYTES != crypto_box_PUBLICKEYBYTES
# error crypto_box_BEFORENMBYTES != crypto_box_PUBLICKEYBYTES
#endif
    memcpy(client->nmkey, server_publickey, crypto_box_PUBLICKEYBYTES);
    crypto_box_beforenm(client->nmkey, client->nmkey, client->secretkey);

    return 0;
}

int
dnscrypt_client_wipe_secretkey(DNSCryptClient * const client)
{
    salsa20_random_buf(client->secretkey, crypto_box_SECRETKEYBYTES);

    return 0;
}

int
dnscrypt_client_init_with_key_pair(DNSCryptClient * const client,
                                   const uint8_t client_publickey[crypto_box_PUBLICKEYBYTES],
                                   const uint8_t client_secretkey[crypto_box_SECRETKEYBYTES])
{
    memcpy(client->publickey, client_publickey, crypto_box_PUBLICKEYBYTES);
    memcpy(client->secretkey, client_secretkey, crypto_box_SECRETKEYBYTES);

    return 0;
}

int
dnscrypt_client_create_key_pair(DNSCryptClient * const client,
                                uint8_t client_publickey[crypto_box_PUBLICKEYBYTES],
                                uint8_t client_secretkey[crypto_box_SECRETKEYBYTES])
{
    (void) client;
    crypto_box_keypair(client_publickey, client_secretkey);
    salsa20_random_stir();

    return 0;
}

int
dnscrypt_client_init_with_new_key_pair(DNSCryptClient * const client)
{
    uint8_t client_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t client_secretkey[crypto_box_SECRETKEYBYTES];

    dnscrypt_client_create_key_pair(client,
                                    client_publickey, client_secretkey);
    dnscrypt_client_init_with_key_pair(client,
                                       client_publickey, client_secretkey);

    return 0;
}
