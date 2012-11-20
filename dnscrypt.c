#include "dnscrypt.h"

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

void
dnscrypt_key_to_fingerprint(char fingerprint[80U], const uint8_t * const key)
{
    const size_t fingerprint_size = 80U;
    size_t       fingerprint_pos = (size_t) 0U;
    size_t       key_pos = (size_t) 0U;

    COMPILER_ASSERT(crypto_box_PUBLICKEYBYTES == 32U);
    COMPILER_ASSERT(crypto_box_SECRETKEYBYTES == 32U);
    for (;;) {
        assert(fingerprint_size > fingerprint_pos);
        evutil_snprintf(&fingerprint[fingerprint_pos],
                        fingerprint_size - fingerprint_pos, "%02X%02X",
                        key[key_pos], key[key_pos + 1U]);
        key_pos += 2U;
        if (key_pos >= crypto_box_PUBLICKEYBYTES) {
            break;
        }
        fingerprint[fingerprint_pos + 4U] = ':';
        fingerprint_pos += 5U;
    }
}

static int
_dnscrypt_parse_char(uint8_t key[crypto_box_PUBLICKEYBYTES],
                     size_t * const key_pos_p, int * const state_p,
                     const int c, uint8_t * const val_p)
{
    uint8_t c_val;

    switch (*state_p) {
    case 0:
    case 1:
        if (isspace(c) || (c == ':' && *state_p == 0)) {
            break;
        }
        if (c == '#') {
            *state_p = 2;
            break;
        }
        if (!isxdigit(c)) {
            return -1;
        }
        c_val = (uint8_t) ((c >= '0' && c <= '9') ? c - '0' : c - 'a' + 10);
        assert(c_val < 16U);
        if (*state_p == 0) {
            *val_p = c_val * 16U;
            *state_p = 1;
        } else {
            *val_p |= c_val;
            key[(*key_pos_p)++] = *val_p;
            if (*key_pos_p >= crypto_box_PUBLICKEYBYTES) {
                return 0;
            }
            *state_p = 0;
        }
        break;
    case 2:
        if (c == '\n') {
            *state_p = 0;
        }
    }
    return 1;
}

int
dnscrypt_fingerprint_to_key(const char * const fingerprint,
                            uint8_t key[crypto_box_PUBLICKEYBYTES])
{
    const char *p = fingerprint;
    size_t      key_pos = (size_t) 0U;
    int         c;
    int         ret;
    int         state = 0;
    uint8_t     val = 0U;

    if (fingerprint == NULL) {
        return -1;
    }
    while ((c = tolower((int) (unsigned char) *p)) != 0) {
        ret = _dnscrypt_parse_char(key, &key_pos, &state, c, &val);
        if (ret <= 0) {
            return ret;
        }
        p++;
    }
    return -1;
}

size_t
dnscrypt_pad(uint8_t *buf, const size_t len, const size_t max_len)
{
    uint8_t *buf_padding_area = buf + len;
    size_t padded_len, padding_len;

    // no padding
    if (max_len < len + DNSCRYPT_MIN_PAD_LEN)
        return len;

    padded_len = len + DNSCRYPT_MIN_PAD_LEN + salsa20_random_uniform((uint32_t)(max_len - len - DNSCRYPT_MIN_PAD_LEN + 1));
    padded_len += DNSCRYPT_BLOCK_SIZE - padded_len % DNSCRYPT_BLOCK_SIZE;
    if (padded_len > max_len)
        padded_len = max_len;

    assert(padded_len >= len);
    padding_len = padded_len - len;
    memset(buf_padding_area, 0, padded_len);
    *buf_padding_area = 0x80;

    return padded_len;
}

//  8 bytes: magic_query
// 32 bytes: the client's DNSCurve public key (crypto_box_PUBLICKEYBYTES)
// 12 bytes: a client-selected nonce (crypto_box_HALF_NONCEBYTES)
// 16 bytes: Poly1305 MAC (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)

#define DNSCRYPT_QUERY_BOX_OFFSET \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)

int
dnscrypt_server_uncurve(struct context *c,
                        uint8_t client_nonce[crypto_box_HALF_NONCEBYTES],
                        uint8_t nmkey[crypto_box_BEFORENMBYTES],
                        uint8_t * const buf, size_t * const lenp)
{
    size_t len = *lenp;

    if (len <= DNSCRYPT_QUERY_HEADER_SIZE) {
        return -1;
    }

    struct dnscrypt_query_header *query_header = (struct dnscrypt_query_header *)buf;
    memcpy(nmkey, query_header->publickey, crypto_box_PUBLICKEYBYTES);
    if (crypto_box_beforenm(nmkey, nmkey, c->crypt_secretkey) != 0) {
        return -1;
    }

    printf("nmkey:\n");
    print_binary_string(nmkey, crypto_box_BEFORENMBYTES);
    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, query_header->nonce, crypto_box_HALF_NONCEBYTES);
    memset(nonce + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

    memset(buf + DNSCRYPT_QUERY_BOX_OFFSET - crypto_box_BOXZEROBYTES, 0, crypto_box_BOXZEROBYTES);
    if (crypto_box_open_afternm(
                buf + DNSCRYPT_QUERY_BOX_OFFSET - crypto_box_BOXZEROBYTES,
                buf + DNSCRYPT_QUERY_BOX_OFFSET - crypto_box_BOXZEROBYTES,
                len - DNSCRYPT_QUERY_BOX_OFFSET + crypto_box_BOXZEROBYTES,
                nonce,
                nmkey) != 0) {
        return -1;
    }

    while (buf[--len] == 0);

    if (buf[len] != 0x80) {
        return -1;
    }

    memcpy(client_nonce, nonce, crypto_box_HALF_NONCEBYTES);
    *lenp = len - DNSCRYPT_QUERY_HEADER_SIZE;
    memmove(buf, buf + DNSCRYPT_QUERY_HEADER_SIZE, *lenp);

    printf("nmkey:\n");
    print_binary_string(nmkey, crypto_box_BEFORENMBYTES);
    return 0;
}

//  8 bytes: magic header (CERT_MAGIC_HEADER)
// 12 bytes: the client's nonce
// 12 bytes: server nonce extension
// 16 bytes: Poly1305 MAC (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)

#define DNSCRYPT_REPLY_BOX_OFFSET \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_HALF_NONCEBYTES + crypto_box_HALF_NONCEBYTES)

int
dnscrypt_server_curve(struct context *c,
                      uint8_t client_nonce[crypto_box_HALF_NONCEBYTES],
                      uint8_t nmkey[crypto_box_BEFORENMBYTES],
                      uint8_t * const buf, size_t * const lenp, const size_t max_len)
{
    uint8_t nonce[crypto_box_NONCEBYTES];
    uint8_t *boxed;
    size_t len = *lenp;

    memcpy(nonce, client_nonce, crypto_box_HALF_NONCEBYTES);

    // add server nonce extension
    uint64_t ts;
    uint64_t tsn;
    uint32_t suffix;
    ts = dnscrypt_hrtime();
    if (ts <= c->nonce_ts_last) {
        ts = c->nonce_ts_last + 1;
    }
    c->nonce_ts_last = ts;
    tsn = (ts << 10) | (salsa20_random() & 0x3ff);
#if (BYTE_ORDER == LITTLE_ENDIAN)
    tsn = (((uint64_t)htonl((uint32_t)tsn)) << 32) | htonl((uint32_t)(tsn >> 32));
#endif
    memcpy(nonce + crypto_box_HALF_NONCEBYTES, &tsn, 8);
    suffix = salsa20_random();
    memcpy(nonce + crypto_box_HALF_NONCEBYTES + 8, &suffix, 4);

    boxed = buf + DNSCRYPT_REPLY_BOX_OFFSET;
    memmove(boxed + crypto_box_MACBYTES, buf, len);
    len = dnscrypt_pad(boxed + crypto_box_MACBYTES, len, max_len - DNSCRYPT_REPLY_HEADER_SIZE);
    memset(boxed - crypto_box_BOXZEROBYTES, 0, crypto_box_ZEROBYTES);

    printf("nmkey: \n");
    print_binary_string(nmkey, crypto_box_BEFORENMBYTES);
    if (crypto_box_afternm(boxed - crypto_box_BOXZEROBYTES, boxed - crypto_box_BOXZEROBYTES, len + crypto_box_ZEROBYTES, nonce, nmkey) != 0) {
        return -1;
    }

    /*printf("nonce length: %ld\n", crypto_box_NONCEBYTES);*/
    /*print_binary_string(nonce, crypto_box_NONCEBYTES);*/
    printf("nmkey: \n");
    print_binary_string(nmkey, crypto_box_BEFORENMBYTES);
    /*printf("Data length: %ld\n", len + crypto_box_ZEROBYTES);*/
    /*print_binary_string(boxed - crypto_box_BOXZEROBYTES, len + crypto_box_ZEROBYTES);*/

    memcpy(buf, DNSCRYPT_MAGIC_RESPONSE, DNSCRYPT_MAGIC_HEADER_LEN);
    memcpy(buf + DNSCRYPT_MAGIC_HEADER_LEN, nonce, crypto_box_NONCEBYTES);
    *lenp = len + DNSCRYPT_REPLY_HEADER_SIZE;
    return 0;
}
