#include "dnscrypt.h"

size_t
dnscrypt_query_header_size(void)
{
    return DNSCRYPT_MAGIC_QUERY_LEN
        + crypto_box_PUBLICKEYBYTES
        + crypto_box_HALF_NONCEBYTES
        + crypto_box_MACBYTES;
}
