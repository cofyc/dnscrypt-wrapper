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

void
randombytes(unsigned char * const buf, const unsigned long long buf_len)
{
    assert(buf_len <= SIZE_MAX);
    salsa20_random_buf(buf, buf_len);
}

void
dnscrypt_memzero(void * const pnt, const size_t size)
{
        volatile unsigned char *pnt_ = (volatile unsigned char *) pnt;
            size_t                     i = (size_t) 0U; 

                while (i < size) {
                            pnt_[i++] = 0U; 
                                }   
}

uint64_t
dnscrypt_hrtime(void)
{
    struct timeval tv; 
    uint64_t       ts = (uint64_t) 0U; 
    int            ret;

    ret = evutil_gettimeofday(&tv, NULL);
    assert(ret == 0); 
    if (ret == 0) {
        ts = (uint64_t) tv.tv_sec * 1000000U + (uint64_t) tv.tv_usec;
    }   
    return ts; 
}
