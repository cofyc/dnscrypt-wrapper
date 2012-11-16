#include "dnscrypt.h"

struct dnscrypt_query_header {
    uint8_t magic_query[DNSCRYPT_MAGIC_QUERY_LEN];
    uint8_t publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t nonce[crypto_box_HALF_NONCEBYTES];
    uint8_t mac[crypto_box_MACBYTES];
};

//  8 bytes: magic_query
// 32 bytes: the client's DNSCurve public key (crypto_box_PUBLICKEYBYTES)
// 12 bytes: a client-selected nonce (crypto_box_HALF_NONCEBYTES)
// 16 bytes: Poly1305 MAC (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)

#define DNSCRYPT_QUERY_BOX_OFFSET \
    DNSCRYPT_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES

ssize_t
dnscrypt_server_uncurve(DNSCryptServer * const server,
        /*const uint8_t client_nonce[crypto_box_HALF_NONCEBYTES],*/
                        uint8_t * const buf, size_t * const lenp)
{
    size_t len = *lenp;

    if (len <= dnscrypt_query_header_size()) {
        return 1;
    }

    struct dnscrypt_query_header *query_header = (struct dnscrypt_query_header *)buf;

    memset(buf + DNSCRYPT_QUERY_BOX_OFFSET - crypto_box_BOXZEROBYTES, 0, crypto_box_BOXZEROBYTES);
    if (crypto_box_open_afternm(
                buf + DNSCRYPT_QUERY_BOX_OFFSET - crypto_box_BOXZEROBYTES,
                buf + DNSCRYPT_QUERY_BOX_OFFSET - crypto_box_BOXZEROBYTES,
                len - DNSCRYPT_QUERY_BOX_OFFSET + crypto_box_BOXZEROBYTES,
                query_header->nonce,
                server->nmkey)) {
        printf("here\n");
        return -1;
    }

    /*printf("len: %ld\n", len);*/
    /*while (len--) {*/
    /*printf("[%ld]%x\n", len, buf[len]);*/
    /*}*/

    return 0;
}
