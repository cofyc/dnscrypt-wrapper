#include "dnscrypt.h"

SignedBincert * 
cert_gen_signed_cert(struct context *c)
{
    SignedBincert *signed_cert = malloc(sizeof(SignedBincert));
    if (!signed_cert)
        return NULL;

    memcpy(signed_cert->magic_cert, CERT_MAGIC_CERT, 4);
    /*memcpy(signed_cert->version_major, CERT_MAJOR_VERSION, 2);*/
    /*memcpy(signed_cert->version_minor, CERT_MINOR_VERSION, 2);*/
    /*memcpy(signed_cert->server_publickey, c->crypt_publickey, crypto_box_PUBLICKEYBYTES);*/
    /*memcpy(signed_cert->magic_query, CERT_MAGIC_HEADER, sizeof(signed_cert->magic_query));*/
    /*memcpy(signed_cert->serial, "0001", */
    return signed_cert;
}
