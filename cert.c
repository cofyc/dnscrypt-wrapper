#include "dnscrypt.h"

static uint8_t signed_cert_txt[1 + sizeof(struct SignedCert)];

uint8_t *
cert_signed_cert_txt_binarydata(struct context *c, size_t *size)
{
    struct SignedCert *signed_cert = (struct SignedCert *)(signed_cert_txt + 1);

    memcpy(signed_cert->magic_cert, CERT_MAGIC_CERT, 4);
    signed_cert->version_major[0] = 0;
    signed_cert->version_major[1] = 1;
    signed_cert->version_minor[0] = 0;
    signed_cert->version_minor[1] = 0;

    memcpy(signed_cert->server_publickey, c->crypt_publickey, crypto_box_PUBLICKEYBYTES);
    memcpy(signed_cert->magic_query, CERT_MAGIC_HEADER, sizeof(signed_cert->magic_query));
    memcpy(signed_cert->serial, "0001", 4);
    uint32_t ts_begin = (uint32_t)time(NULL) - 365*24*3600;
    uint32_t ts_end = ts_begin + 365*24*3600;
    memcpy(signed_cert->ts_begin, &ts_begin, 4);
    memcpy(signed_cert->ts_end, &ts_end, 4);
    memset(signed_cert->end, 0, sizeof(signed_cert->end));
    
    // sign
    size_t crypted_signed_data_len = 0;
    size_t signed_data_len = sizeof(struct SignedCert) - offsetof(struct SignedCert, server_publickey) - sizeof(signed_cert->end);
    if (crypto_sign_ed25519(signed_cert->server_publickey, (unsigned long long *)&crypted_signed_data_len, signed_cert->server_publickey, signed_data_len, c->provider_secretkey) != 0) {
        *size = 0;
        return NULL;
    }

    *((char *)signed_cert -1) = sizeof(struct SignedCert);
    *size = sizeof(struct SignedCert) + 1;
    return (uint8_t *)((char *)signed_cert - 1);
}
