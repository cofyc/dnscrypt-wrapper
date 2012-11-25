
#ifndef __DNSCRYPT_CLIENT_H__
#define __DNSCRYPT_CLIENT_H__ 1

#include <sys/types.h>
#include <stdint.h>

#include "dnscrypt.h"

typedef struct DNSCryptClient_ {
    uint8_t  magic_query[DNSCRYPT_MAGIC_QUERY_LEN];
    uint8_t  publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t  secretkey[crypto_box_SECRETKEYBYTES];
    uint8_t  nmkey[crypto_box_BEFORENMBYTES];
    uint64_t nonce_ts_last;
} DNSCryptClient;

ssize_t dnscrypt_client_curve(DNSCryptClient * const client,
                              uint8_t client_nonce[crypto_box_HALF_NONCEBYTES],
                              uint8_t *buf, size_t len, const size_t max_len);

int dnscrypt_client_uncurve(const DNSCryptClient * const client,
                            const uint8_t client_nonce[crypto_box_HALF_NONCEBYTES],
                            uint8_t * const buf, size_t * const lenp);

int dnscrypt_client_init_with_key_pair(DNSCryptClient * const client,
                                       const uint8_t client_publickey[crypto_box_PUBLICKEYBYTES],
                                       const uint8_t client_secretkey[crypto_box_SECRETKEYBYTES]);

int dnscrypt_client_create_key_pair(DNSCryptClient * const client,
                                    uint8_t client_publickey[crypto_box_PUBLICKEYBYTES],
                                    uint8_t client_secretkey[crypto_box_SECRETKEYBYTES]);

int dnscrypt_client_init_with_new_key_pair(DNSCryptClient * const client);

int dnscrypt_client_init_magic_query(DNSCryptClient * const client,
                                     const uint8_t magic_query[DNSCRYPT_MAGIC_QUERY_LEN]);

int dnscrypt_client_init_nmkey(DNSCryptClient * const client,
                               const uint8_t server_publickey[crypto_box_PUBLICKEYBYTES]);

int dnscrypt_client_wipe_secretkey(DNSCryptClient * const client);

#endif
