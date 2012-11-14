#include "dnscrypt.h"

size_t
dnscrypt_query_header_size(void)
{
    return DNSCRYPT_MAGIC_QUERY_LEN
        + crypto_box_PUBLICKEYBYTES
        + crypto_box_HALF_NONCEBYTES + crypto_box_MACBYTES;
}

int
dnscrypt_cmp_client_nonce(const uint8_t
                          client_nonce[crypto_box_HALF_NONCEBYTES],
                          const uint8_t * const buf, const size_t len)
{
    const size_t client_nonce_offset = sizeof(DNSCRYPT_MAGIC_RESPONSE) - 1;

    if (len < client_nonce_offset + crypto_box_HALF_NONCEBYTES
        || memcmp(client_nonce, buf + client_nonce_offset,
                  crypto_box_HALF_NONCEBYTES) != 0) {
        return -1;
    }

    return 0;
}
