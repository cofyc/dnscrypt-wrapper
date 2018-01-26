#ifndef CERT_H
#define CERT_H

#include <sodium.h>
#define CERT_MAGIC_CERT "DNSC"
#define CERT_MAJOR_VERSION 1
#define CERT_MINOR_VERSION 0
#define CERT_OLD_MAGIC_HEADER "7PYqwfzt"

#define CERT_FILE_EXPIRE_DAYS 1

struct SignedCert {
    uint8_t magic_cert[4];
    uint8_t version_major[2];
    uint8_t version_minor[2];

    uint8_t signature[crypto_sign_BYTES];
    // Signed Content
    uint8_t server_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t magic_query[8];
    uint8_t serial[4];
    uint8_t ts_begin[4];
    uint8_t ts_end[4];
};

struct Cert {
    uint8_t magic_cert[4];
    uint8_t version_major[2];
    uint8_t version_minor[2];

    // Signed Content
    uint8_t signed_content[64];
    uint8_t server_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t magic_query[8];
    uint8_t serial[4];
    uint8_t ts_begin[4];
    uint8_t ts_end[4];
};


struct SignedCert *cert_build_cert(const uint8_t *crypt_publickey, int cert_file_expire_days, int use_xchacha20);
int cert_sign(struct SignedCert *signed_cert,
              const uint8_t *provider_secretkey);
void cert_display_txt_record_tinydns(struct SignedCert *signed_cert);
void cert_display_txt_record(struct SignedCert *signed_cert);

#endif
