#ifndef DNSCRYPT_SERVER_H
#define DNSCRYPT_SERVER_H

#include "dnscrypt.h"

typedef struct DNSCryptServer_ {
    uint8_t magic_query(DNSCRYPT_MAGIC_QUERY_LEN];
    uint8_t publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t secretkey[crypto_box_SECRETKEYBYTES];
    uint8_t nmkey[crypto_box_BEFORENMBYTES];
    uint64_t nonce_ts_last;
} DNSCryptServer;

#endif
