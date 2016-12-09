#ifndef DNSCRYPT_H
#define DNSCRYPT_H

#include <assert.h>
#include <ctype.h>
#include <string.h>

#include <event2/util.h>
#include <sodium.h>

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#define DNSCRYPT_MAGIC_HEADER_LEN 8U
#define DNSCRYPT_MAGIC_RESPONSE  "r6fnvWj8"

#ifndef DNSCRYPT_MAX_PADDING
# define DNSCRYPT_MAX_PADDING 256U
#endif
#ifndef DNSCRYPT_BLOCK_SIZE
# define DNSCRYPT_BLOCK_SIZE 64U
#endif
#ifndef DNSCRYPT_MIN_PAD_LEN
# define DNSCRYPT_MIN_PAD_LEN 8U
#endif

#define crypto_box_HALF_NONCEBYTES (crypto_box_NONCEBYTES / 2U)

#define DEFAULT_PROVIDER_NAME "2.cert.dnscrypt.org"

#define DNSCRYPT_QUERY_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES + crypto_box_MACBYTES)
#define DNSCRYPT_RESPONSE_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_NONCEBYTES + crypto_box_MACBYTES)

#define DNSCRYPT_REPLY_HEADER_SIZE \
    (DNSCRYPT_MAGIC_HEADER_LEN + crypto_box_HALF_NONCEBYTES * 2 + crypto_box_MACBYTES)

#include "cert.h"

typedef struct KeyPair_ {
    uint8_t crypt_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t crypt_secretkey[crypto_box_SECRETKEYBYTES];
} KeyPair;

struct dnsc_server_context {
    char *provider_name;
    struct SignedCert *signed_certs;
    size_t signed_certs_count;
    uint8_t provider_publickey[crypto_sign_ed25519_PUBLICKEYBYTES];
    uint8_t provider_secretkey[crypto_sign_ed25519_SECRETKEYBYTES];
    KeyPair *keypairs;
    size_t keypairs_count;
    uint64_t nonce_ts_last;
    unsigned char hash_key[crypto_shorthash_KEYBYTES];
};

const KeyPair * find_keypair(const struct dnsc_server_context *c,
                             const unsigned char magic_query[DNSCRYPT_MAGIC_HEADER_LEN],
                             const size_t dns_query_len);
int dnscrypt_cmp_client_nonce(const uint8_t
                              client_nonce[crypto_box_HALF_NONCEBYTES],
                              const uint8_t *const buf, const size_t len);
void dnscrypt_memzero(void *const pnt, const size_t size);
uint64_t dnscrypt_hrtime(void);
void dnscrypt_key_to_fingerprint(char fingerprint[80U],
                                 const uint8_t *const key);
int dnscrypt_fingerprint_to_key(const char *const fingerprint,
                                uint8_t key[crypto_box_PUBLICKEYBYTES]);

// vim-like binary display
static inline void
print_binary_string(uint8_t *s, size_t count)
{
    for (size_t i = 1; i <= count; i++) {
        uint8_t x = *((uint8_t *)s + i - 1);
        if (x >= (uint8_t)'0' && x <= (uint8_t)'9') {
            printf("%d", x);
        } else if (x >= (uint8_t)'a' && x <= (uint8_t)'z') {
            printf("%c", x);
        } else if (x >= (uint8_t)'A' && x <= (uint8_t)'Z') {
            printf("%c", x);
        } else {
            printf("\\%03d", x);
        }
        if (i % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

// binary in hex
static inline void
print_binary_string_hex(uint8_t *s, size_t count)
{
    for (size_t i = 1; i <= count; i++) {
        if ((i - 1) % 16 == 0) {
            printf("%04zx: ", (i - 1));
        }
        uint8_t x = *((uint8_t *)s + i - 1);
        printf("%02x ", x);
        if (i % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

struct dnscrypt_query_header {
    uint8_t magic_query[DNSCRYPT_MAGIC_HEADER_LEN];
    uint8_t publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t nonce[crypto_box_HALF_NONCEBYTES];
    uint8_t mac[crypto_box_MACBYTES];
};

int dnscrypt_server_uncurve(struct dnsc_server_context *c, const KeyPair *keypair,
                            uint8_t client_nonce[crypto_box_HALF_NONCEBYTES],
                            uint8_t nmkey[crypto_box_BEFORENMBYTES],
                            uint8_t *const buf, size_t * const lenp);
int dnscrypt_server_curve(struct dnsc_server_context *c,
                          uint8_t client_nonce[crypto_box_HALF_NONCEBYTES],
                          uint8_t nmkey[crypto_box_BEFORENMBYTES],
                          uint8_t *const buf, size_t * const lenp,
                          const size_t max_len);
#endif
