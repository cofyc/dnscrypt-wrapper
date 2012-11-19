#ifndef CERT_H
#define CERT_H

#include <crypto_box.h>
#define CERT_MAGIC_CERT "DNSC"
#define CERT_MAJOR_VERSION 1
#define CERT_MINOR_VERSION 0
#define CERT_MAGIC_HEADER "7PYqwfzt"

typedef struct Bincert_ {
    uint8_t magic_cert[4];
    uint8_t version_major[2];
    uint8_t version_minor[2];

    uint8_t server_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t magic_query[8];
    uint8_t serial[4];
    uint8_t ts_begin[4];
    uint8_t ts_end[4];
    uint8_t end[];
} Bincert;

typedef struct SignedBincert_ {
    uint8_t magic_cert[4];
    uint8_t version_major[2];
    uint8_t version_minor[2];

    uint8_t signed_data[];
} SignedBincert;

#endif
