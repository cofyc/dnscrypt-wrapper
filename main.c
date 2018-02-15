#include "dnscrypt.h"
#include "argparse/argparse.h"
#include "version.h"
#include "pidfile.h"
#include "block.h"

/**
 * This is dnscrypt wrapper (server-side dnscrypt proxy), which helps to add
 * dnscrypt support to any name resolver.
 */

static const char *const config_usage[] = {
    "dnscrypt-wrapper [options]",
    NULL
};

int
show_version_cb(struct argparse *this, const struct argparse_option *option)
{
    printf("dnscrypt-wrapper %s\n", the_version);
    exit(0);
}

static int
sockaddr_from_ip_and_port(struct sockaddr_storage *const sockaddr,
                          ev_socklen_t * const sockaddr_len_p,
                          const char *const ip, const char *const port,
                          const char *const error_msg)
{
    char sockaddr_port[INET6_ADDRSTRLEN + sizeof "[]:65535"];
    int sockaddr_len_int;
    char *pnt;
    bool has_column = 0;
    bool has_columns = 0;
    bool has_brackets = *ip == '[';

    if ((pnt = strchr(ip, ':')) != NULL) {
        has_column = 1;
        if (strchr(pnt + 1, ':') != NULL) {
            has_columns = 1;
        }
    }
    sockaddr_len_int = (int)sizeof *sockaddr;
    if ((has_brackets != 0 || has_column != has_columns) &&
        evutil_parse_sockaddr_port(ip, (struct sockaddr *)sockaddr,
                                   &sockaddr_len_int) == 0) {
        *sockaddr_len_p = (ev_socklen_t) sockaddr_len_int;
        return 0;
    }
    if (has_columns != 0 && has_brackets == 0) {
        if (strcmp(port, "0")) {
            evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "[%s]:%s",
                            ip, port);
        } else {
            evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "[%s]", ip);
        }
    } else {
        if (strcmp(port, "0")) {
            evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "%s:%s", ip, port);
        } else {
            evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "%s", ip);
        }
    }
    sockaddr_len_int = (int)sizeof *sockaddr;
    if (evutil_parse_sockaddr_port(sockaddr_port, (struct sockaddr *)sockaddr,
                                   &sockaddr_len_int) != 0) {
        logger(LOG_ERR, "%s: %s", error_msg, sockaddr_port);
        *sockaddr_len_p = (ev_socklen_t) 0U;

        return -1;
    }
    *sockaddr_len_p = (ev_socklen_t) sockaddr_len_int;

    return 0;
}

static void
init_locale(void)
{
    setlocale(LC_CTYPE, "C");
    setlocale(LC_COLLATE, "C");
}

static void
init_tz(void)
{
    static char default_tz_for_putenv[] = "TZ=UTC+00:00";
    char stbuf[10U];
    struct tm *tm;
    time_t now;

    tzset();
    time(&now);
    if ((tm = localtime(&now)) != NULL &&
        strftime(stbuf, sizeof stbuf, "%z", tm) == (size_t) 5U) {
        evutil_snprintf(default_tz_for_putenv, sizeof default_tz_for_putenv,
                        "TZ=UTC%c%c%c:%c%c", (*stbuf == '-' ? '+' : '-'),
                        stbuf[1], stbuf[2], stbuf[3], stbuf[4]);
    }
    putenv(default_tz_for_putenv);
    (void)localtime(&now);
    (void)gmtime(&now);
}

static void
revoke_privileges(struct context *c)
{
    init_locale();
    init_tz();

    if (c->user_dir != NULL) {
        if (chdir(c->user_dir) != 0 || chroot(c->user_dir) != 0) {
            logger(LOG_ERR, "Unable to chroot to [%s]", c->user_dir);
            exit(1);
        }
    }
    if (c->user_id != (uid_t) 0) {
        if (setgid(c->user_group) != 0 ||
            setegid(c->user_group) != 0 ||
            setuid(c->user_id) != 0 || seteuid(c->user_id) != 0) {
            logger(LOG_ERR, "Unable to switch to user id [%lu]",
                   (unsigned long)c->user_id);
            exit(1);
        }
    }
}

static void
do_daemonize(void)
{
    switch (fork()) {
    case 0:
        break;
    case -1:
        logger(LOG_ERR, "fork() failed");
        exit(1);
    default:
        exit(0);
    }

    if (setsid() == -1) {
        logger(LOG_ERR, "setsid() failed");
        exit(1);
    }

    close(0);
    close(1);
    close(2);

    // if any standard file descriptor is missing open it to /dev/null */
    int fd = open("/dev/null", O_RDWR, 0);
    while (fd != -1 && fd < 2)
        fd = dup(fd);
    if (fd == -1) {
        logger(LOG_ERR, "open /dev/null or dup failed");
        exit(1);
    }
    if (fd > 2)
        close(fd);
}

static int
write_to_file(const char *path, char *buf, size_t count)
{
    int fd;
    fd = open(path, O_WRONLY | O_CREAT, 0444);
    if (fd == -1) {
        return -1;
    }
    if (safe_write(fd, buf, count, 3) != count) {
        return -2;
    }
    return 0;
}

static int
write_to_pkey(const char *path, char *buf, size_t count)
{
    int fd;
    fd = open(path, O_WRONLY | O_CREAT, 0400);
    if (fd == -1) {
        return -1;
    }
    if (safe_write(fd, buf, count, 3) != count) {
        return -2;
    }
    return 0;
}

static int
read_from_file(const char *path, char *buf, size_t count)
{
    int fd;
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        return -1;
    }
    if (safe_read(fd, buf, count) != count) {
        close(fd);
        return -2;
    }
    close(fd);
    return 0;
}

static int
filter_signed_certs(struct context *c)
{
    struct SignedCert *filtered_certs;
    size_t filtered_count = 0;
    size_t i, j;
    uint32_t now = (uint32_t) time(NULL);
    uint32_t ts_end, ts_begin;
    bool found;

    if ((filtered_certs = sodium_allocarray(c->signed_certs_count, sizeof *c->signed_certs)) == NULL) {
        return -1;
    }
    for (i = 0; i < c->signed_certs_count; i++) {
        memcpy(&ts_begin, c->signed_certs[i].ts_begin, 4);
        memcpy(&ts_end, c->signed_certs[i].ts_end, 4);
        ts_begin = ntohl(ts_begin);
        ts_end = ntohl(ts_end);
        if (now < ts_begin || ts_end <= now) {
            continue;
        }
        found = 0;
        for (j = 0; j < filtered_count; j++) {
            if (filtered_certs[j].version_major[0] == c->signed_certs[i].version_major[0] &&
                filtered_certs[j].version_major[1] == c->signed_certs[i].version_major[1] &&
                filtered_certs[j].version_minor[0] == c->signed_certs[i].version_minor[0] &&
                filtered_certs[j].version_minor[1] == c->signed_certs[i].version_minor[1]) {
                found = 1;
                if (filtered_certs[j].serial < c->signed_certs[i].serial) {
                    filtered_certs[j] = c->signed_certs[i];
                }
            }
        }
        if (found == 0) {
            filtered_certs[filtered_count++] = c->signed_certs[i];
        }
    }
    sodium_free(c->signed_certs);
    c->signed_certs = filtered_certs;
    c->signed_certs_count = filtered_count;

    return 0;
}

static int
parse_cert_files(struct context *c)
{
    char *provider_cert_files, *provider_cert_file;
    size_t signed_cert_id;

    c->signed_certs_count = 0U;
    if ((provider_cert_files = strdup(c->provider_cert_file)) == NULL) {
        logger(LOG_ERR, "Could not allocate memory!");
        return -1;
    }

    for (provider_cert_file = strtok(provider_cert_files, ",");
         provider_cert_file != NULL;
         provider_cert_file = strtok(NULL, ",")) {
        c->signed_certs_count++;
    }

    if (c->signed_certs_count <= 0U) {
        free(provider_cert_files);
        return 0;
    }
    memcpy(provider_cert_files, c->provider_cert_file, strlen(c->provider_cert_file) + 1U);
    c->signed_certs = sodium_allocarray(c->signed_certs_count, sizeof *c->signed_certs);
    signed_cert_id = 0U;

    for (provider_cert_file = strtok(provider_cert_files, ",");
         provider_cert_file != NULL;
         provider_cert_file = strtok(NULL, ",")) {

        if (read_from_file
            (provider_cert_file, (char *)(c->signed_certs + signed_cert_id),
                sizeof(struct SignedCert)) != 0) {
            logger(LOG_ERR, "%s is not valid signed certificate.",
                   provider_cert_file);
            return 1;
        }
        signed_cert_id++;
    }
    free(provider_cert_files);
    return 0;
}

static int
match_cert_to_keys(struct context *c) {
    size_t keypair_id, signed_cert_id, cert_id;

    c->certs = sodium_allocarray(c->signed_certs_count, sizeof *c->certs);
    cert_id = 0U;

    for(keypair_id=0; keypair_id < c->keypairs_count; keypair_id++) {
        KeyPair *kp = c->keypairs + keypair_id;
        int found_cert = 0;
        for(signed_cert_id=0; signed_cert_id < c->signed_certs_count; signed_cert_id++) {
            struct SignedCert *signed_cert = c->signed_certs + signed_cert_id;
            struct Cert *cert = (struct Cert *)signed_cert;
            if(memcmp(kp->crypt_publickey,
                      cert->server_publickey,
                      crypto_box_PUBLICKEYBYTES) == 0) {
                dnsccert *current_cert = c->certs + cert_id++;
                found_cert = 1;
                current_cert->keypair = kp;
                memcpy(current_cert->magic_query,
                       cert->magic_query,
                       sizeof cert->magic_query
                );
                memcpy(current_cert->es_version,
                       cert->version_major,
                        sizeof cert->version_major
                );
#ifndef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_OPEN_EASY
                if (current_cert->es_version[1] == 0x02) {
                    logger(LOG_ERR,
                           "Certificate for XChacha20 but your "
                           "libsodium version does not support it.");
                    return 1;
                }
#endif
            }
        }
        if (!found_cert) {
            logger(LOG_ERR,
                   "could not match secret key %d with a certificate.",
                   keypair_id + 1);
            return 1;
        }
    }
    return 0;
}

#ifndef sodium_base64_VARIANT_URLSAFE_NO_PADDING
#define EQ(x, y) \
    ((((0U - ((unsigned int) (x) ^ (unsigned int) (y))) >> 8) & 0xFF) ^ 0xFF)
#define GT(x, y) ((((unsigned int) (y) - (unsigned int) (x)) >> 8) & 0xFF)
#define GE(x, y) (GT(y, x) ^ 0xFF)
#define LT(x, y) GT(y, x)

static int
b64_byte_to_urlsafe_char(unsigned int x)
{
    return (LT(x, 26) & (x + 'A')) |
           (GE(x, 26) & LT(x, 52) & (x + ('a' - 26))) |
           (GE(x, 52) & LT(x, 62) & (x + ('0' - 52))) | (EQ(x, 62) & '-') |
           (EQ(x, 63) & '_');
}

char *
sodium_bin2base64(char * const b64, const size_t b64_maxlen,
                  const unsigned char * const bin, const size_t bin_len,
                  const int variant)
{
    size_t       acc_len = (size_t) 0;
    size_t       b64_len;
    size_t       b64_pos = (size_t) 0;
    size_t       bin_pos = (size_t) 0;
    size_t       nibbles;
    size_t       remainder;
    unsigned int acc = 0U;

    nibbles = bin_len / 3;
    remainder = bin_len - 3 * nibbles;
    b64_len = nibbles * 4;
    if (remainder != 0) {
        b64_len += 2 + (remainder >> 1);
    }
    if (b64_maxlen <= b64_len) {
        exit(1);
    }
    while (bin_pos < bin_len) {
        acc = (acc << 8) + bin[bin_pos++];
        acc_len += 8;
        while (acc_len >= 6) {
            acc_len -= 6;
            b64[b64_pos++] = (char) b64_byte_to_urlsafe_char((acc >> acc_len) & 0x3F);
        }
    }
    if (acc_len > 0) {
        b64[b64_pos++] = (char) b64_byte_to_urlsafe_char((acc << (6 - acc_len)) & 0x3F);
    }
    do {
        b64[b64_pos++] = 0U;
    } while (b64_pos < b64_maxlen);

    return b64;
}
#endif

static char *create_stamp(const char *ext_address, const unsigned char *provider_publickey,
                          const char *provider_name, bool dnssec, bool nolog, bool nofilter)
{
    unsigned char *stamp_bin, *p;
    char *stamp;
    unsigned char props[8] = {0};
    size_t len;
    size_t ext_address_len = strlen(ext_address),
           provider_publickey_len = crypto_sign_ed25519_PUBLICKEYBYTES,
           provider_name_len = strlen(provider_name);

    if (dnssec)
        props[0] |= 1;
    if (nolog)
        props[0] |= 2;
    if (nofilter)
        props[0] |= 4;
    len = 1 + 8 + 1 + ext_address_len + 1 + provider_publickey_len + 1 + provider_name_len;
    if ((stamp_bin = malloc(len)) == NULL)
        exit(1);
    p = stamp_bin;
    *p++ = 0x01;
    memcpy(p, props, sizeof props); p += sizeof props;
    *p++ = (unsigned char) ext_address_len;
    memcpy(p, ext_address, ext_address_len); p += ext_address_len;
    *p++ = (unsigned char) provider_publickey_len;
    memcpy(p, provider_publickey, provider_publickey_len); p += provider_publickey_len;
    *p++ = (unsigned char) provider_name_len;
    memcpy(p, provider_name, provider_name_len); p += provider_name_len;
    if (p - stamp_bin != len) {
        exit(1);
    }
    if ((stamp = malloc(len * 4 / 3 + 2)) == NULL) {
        exit(1);
    }
    sodium_bin2base64(stamp, len * 4 / 3 + 2, stamp_bin, len, 7);
    free(stamp_bin);
    return stamp;
}

int
main(int argc, const char **argv)
{
    struct context c;
    memset(&c, 0, sizeof(struct context));

    char *blacklist_file = NULL;
    int gen_provider_keypair = 0;
    int gen_crypt_keypair = 0;
    int gen_cert_file = 0;
    int cert_file_expire_days = CERT_FILE_EXPIRE_DAYS;
    int provider_publickey = 0;
    int provider_publickey_dns_records = 0;
    int verbose = 0;
    int use_xchacha20 = 0;
    int nolog = 0, dnssec = 0, nofilter = 0;
    struct argparse argparse;
    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_BOOLEAN(0, "gen-cert-file", &gen_cert_file,
                    "generate pre-signed certificate"),
        OPT_BOOLEAN(0, "gen-crypt-keypair", &gen_crypt_keypair,
                    "generate crypt key pair"),
        OPT_BOOLEAN(0, "gen-provider-keypair", &gen_provider_keypair,
                    "generate provider key pair"),
        OPT_BOOLEAN(0, "show-provider-publickey", &provider_publickey,
                    "show provider public key"),
        OPT_BOOLEAN(0, "show-provider-publickey-dns-records", &provider_publickey_dns_records,
                    "show records for DNS servers"),
        OPT_STRING(0, "provider-cert-file", &c.provider_cert_file,
                   "certificate file (default: ./dnscrypt.cert)"),
        OPT_STRING(0, "provider-name", &c.provider_name, "provider name"),
        OPT_STRING(0, "provider-publickey-file", &c.provider_publickey_file,
                   "provider public key file (default: ./public.key)"),
        OPT_STRING(0, "provider-secretkey-file", &c.provider_secretkey_file,
                   "provider secret key file (default: ./secret.key)"),
        OPT_STRING(0, "crypt-secretkey-file", &c.crypt_secretkey_file,
                   "crypt secret key file (default: ./crypt_secret.key)"),
        OPT_INTEGER(0, "cert-file-expire-days", &cert_file_expire_days, "cert file expire days (default: 1)"),
        OPT_BOOLEAN(0, "nolog", &nolog, "Indicate that the server doesn't store logs"),
        OPT_BOOLEAN(0, "nofilter", &nofilter, "Indicate that the server doesn't enforce its own blacklist"),
        OPT_BOOLEAN(0, "dnssec", &dnssec, "Indicate that the server supports DNSSEC"),
        OPT_STRING('a', "listen-address", &c.listen_address,
                   "local address to listen (default: 0.0.0.0:53)"),
        OPT_STRING('b', "blacklist-file", &blacklist_file, "blacklist file"),
        OPT_STRING('E', "ext-address", &c.ext_address, "External IP address"),
        OPT_STRING('r', "resolver-address", &c.resolver_address,
                   "upstream dns resolver server (<address:port>)"),
        OPT_STRING('o', "outgoing-address", &c.outgoing_address,
                   "address to use to connect to dns resolver server (<address:port>)"),
        OPT_BOOLEAN('U', "unauthenticated", &c.allow_not_dnscrypted,
                    "allow and forward unauthenticated queries (default: off)"),
        OPT_STRING('u', "user", &c.user, "run as given user"),
        OPT_STRING('l', "logfile", &c.logfile,
                   "log file path (default: stdout)"),
        OPT_STRING('p', "pidfile", &c.pidfile, "pid stored file"),
        OPT_BOOLEAN('d', "daemonize", &c.daemonize,
                    "run as daemon (default: off)"),
        OPT_BOOLEAN('V', "verbose", &verbose,
                    "show verbose logs (specify more -VVV to increase verbosity)"),
        OPT_BOOLEAN('v', "version", NULL, "show version info", show_version_cb),
#ifdef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_OPEN_EASY
        OPT_BOOLEAN('x', "xchacha20", &use_xchacha20, "generate a certificate for use with the xchacha20 cipher"),
#endif
        OPT_END(),
    };

    argparse_init(&argparse, options, config_usage, 0);
    argparse_parse(&argparse, argc, argv);
    if (sodium_init() != 0) {
        return 1;
    }

    debug_init();

    if (!c.listen_address)
        c.listen_address = "0.0.0.0:53";

    if (!c.crypt_secretkey_file)
        c.crypt_secretkey_file = "crypt_secret.key";

    if (!c.provider_publickey_file)
        c.provider_publickey_file = "public.key";

    if (!c.provider_secretkey_file)
        c.provider_secretkey_file = "secret.key";

    if (!c.provider_cert_file)
        c.provider_cert_file = "dnscrypt.cert";

    c.keypairs = NULL;

    if (gen_provider_keypair) {
        uint8_t provider_publickey[crypto_sign_ed25519_PUBLICKEYBYTES];
        uint8_t provider_secretkey[crypto_sign_ed25519_SECRETKEYBYTES];

        if (!dnssec) {
            fprintf(stderr,
                    "Warning: do not forget to add --dnssec if your server supports DNSSEC\n\n");
        }
        if (!nolog) {
            fprintf(stderr,
                    "Warning: do not forget to add --nolog if your server doesn't store logs\n\n");
        }
        if (!nofilter) {
            fprintf(stderr,
                    "Warning: do not forget to add --nofilter if your server doesn't intentionally block domains\n\n");
        }
        if (!c.provider_name) {
            fprintf(stderr,
                    "Missing provider name. Ex: --provider-name=2.dnscrypt-cert.example.com\n");
            exit(1);
        }
        if (!c.ext_address || strncmp(c.ext_address, "0.", 2) == 0) {
            fprintf(stderr,
                    "Missing external address. Ex: --ext-address=192.168.1.1\n");
            exit(1);
        }

        printf("Generate provider key pair...");
        fflush(stdout);
        if (crypto_sign_ed25519_keypair(provider_publickey, provider_secretkey) == 0) {
            char fingerprint[80];
            char *stamp;

            puts(" ok.\n");
            stamp = create_stamp(c.ext_address, provider_publickey, c.provider_name, dnssec, nolog, nofilter);
            dnscrypt_key_to_fingerprint(fingerprint, provider_publickey);

            printf("Stamp for dnscrypt-proxy 2.x:\n"
                   "  sdns://%s\n\n"
                   "Parameters for dnscrypt-proxy 1.x:\n"
                   "  dnscrypt-proxy --provider-key=%s\n"
                   "                 --resolver-address=%s\n"
                   "                 --provider-name=%s\n",
                   stamp,
                   fingerprint, c.ext_address, c.provider_name);
            if (write_to_file
                (c.provider_publickey_file, (char *)provider_publickey,
                 crypto_sign_ed25519_PUBLICKEYBYTES) == 0
                && write_to_pkey(c.provider_secretkey_file, (char *)provider_secretkey,
                                 crypto_sign_ed25519_SECRETKEYBYTES) == 0) {
                printf("Keys are stored in %s & %s.\n",
                       c.provider_publickey_file, c.provider_secretkey_file);
                exit(0);
            }
            printf("\n\n*KEYS HAVE NOT BEEN SAVED*\n\nA provider key pair already exists.\n"
                   "If you really want to overwrite it, delete the %s and %s files.\n\n"
                   "The provider public key is what client give to dnscrypt-proxy\n"
                   "in order to use your service (long-term key).\n\n"
                   "Unless the private key has been compromised, you probably do not\n"
                   "want to overwrite it with a new one.\n\n"
                   "Usually, what you want (if current certificates are about to expire)\n"
                   "to regenerate is the server key pairs (--gen-crypt-keypair),\n"
                   "not the master keys.\n",
                   c.provider_publickey_file, c.provider_secretkey_file);
            exit(1);
        } else {
            printf(" failed.\n");
            exit(1);
        }
    }
    if (provider_publickey_dns_records) {
        if (parse_cert_files(&c) || filter_signed_certs(&c)) {
            exit(1);
        }
        logger(LOG_NOTICE, "TXT record for signed-certificate:");
        printf("* Record for nsd:\n");
        for(int i=0; i < c.signed_certs_count; i++){
            cert_display_txt_record(c.signed_certs + i);
            printf("\n");
        }
        printf("* Record for tinydns:\n");
        for(int i=0; i < c.signed_certs_count; i++){
            cert_display_txt_record_tinydns(c.signed_certs + i);
            printf("\n");
        }
        exit(0);
    }

    if (provider_publickey) {
        char fingerprint[80];

        if (read_from_file(c.provider_publickey_file,
                           (char *)c.provider_publickey,
                           crypto_sign_ed25519_PUBLICKEYBYTES) != 0) {
            logger(LOG_ERR, "Unable to read %s", c.provider_publickey_file);
            exit(1);
        }
        dnscrypt_key_to_fingerprint(fingerprint, c.provider_publickey);
        printf("Provider public key: %s\n", fingerprint);
        exit(0);
    }

    if (gen_crypt_keypair) {
        printf("Generate crypt key pair...");
        fflush(stdout);
        if ((c.keypairs = sodium_malloc(sizeof *c.keypairs)) == NULL)
            exit(1);
        if (crypto_box_keypair(c.keypairs->crypt_publickey,
                               c.keypairs->crypt_secretkey) == 0) {
            printf(" ok.\n");
            if (write_to_pkey(c.crypt_secretkey_file,
                              (char *)c.keypairs->crypt_secretkey,
                              crypto_box_SECRETKEYBYTES) == 0) {
                printf("Secret key stored in %s\n",
                       c.crypt_secretkey_file);
                exit(0);
            }
            logger(LOG_ERR, "The new certificate was not saved - "
                   "Maybe the %s file already exists - please delete it first.",
                   c.crypt_secretkey_file);
            exit(1);
        } else {
            printf(" failed.\n");
            exit(1);
        }
    }

    // setup logger
    if (c.logfile) {
        logger_logfile = c.logfile;
    }
    logger_verbosity = LOG_NOTICE;  // default
    logger_verbosity += verbose;
    if (logger_verbosity > LOG_DEBUG)
        logger_verbosity = LOG_DEBUG;

    char *crypt_secretkey_files, *crypt_secretkey_file;
    size_t keypair_id;

    c.keypairs_count = 0U;
    if ((crypt_secretkey_files = strdup(c.crypt_secretkey_file)) == NULL)
        exit(1);
    for (crypt_secretkey_file = strtok(crypt_secretkey_files, ",");
         crypt_secretkey_file != NULL;
         crypt_secretkey_file = strtok(NULL, ",")) {
        c.keypairs_count++;
    }
    if (c.keypairs_count <= 0U) {
        logger(LOG_ERR, "You must specify --crypt-secretkey-file.\n\n");
        argparse_usage(&argparse);
        exit(0);
    }
    memcpy(crypt_secretkey_files, c.crypt_secretkey_file, strlen(c.crypt_secretkey_file) + 1U);
    c.keypairs = sodium_allocarray(c.keypairs_count, sizeof *c.keypairs);
    keypair_id = 0U;
    for (crypt_secretkey_file = strtok(crypt_secretkey_files, ",");
         crypt_secretkey_file != NULL;
         crypt_secretkey_file = strtok(NULL, ",")) {
        char fingerprint[80];

        if (read_from_file(crypt_secretkey_file,
                           (char *)c.keypairs[keypair_id].crypt_secretkey,
                           crypto_box_SECRETKEYBYTES) != 0) {
            logger(LOG_ERR, "Unable to read %s", crypt_secretkey_file);
            exit(1);
        }
        if (crypto_scalarmult_base(c.keypairs[keypair_id].crypt_publickey,
                                   c.keypairs[keypair_id].crypt_secretkey) != 0)
            exit(1);
        dnscrypt_key_to_fingerprint(fingerprint, c.keypairs[keypair_id].crypt_publickey);
        logger(LOG_INFO, "Crypt public key fingerprint for %s: %s",
               crypt_secretkey_file, fingerprint);
        keypair_id++;
    }
    free(crypt_secretkey_files);

    // generate signed certificate
    if (gen_cert_file) {
        if (c.keypairs_count != 1U) {
            logger(LOG_ERR, "A certificate can only store a single key");
            exit(1);
        }
        if (read_from_file
            (c.provider_publickey_file, (char *)c.provider_publickey,
             crypto_sign_ed25519_PUBLICKEYBYTES) == 0
            && read_from_file(c.provider_secretkey_file,
                              (char *)c.provider_secretkey,
                              crypto_sign_ed25519_SECRETKEYBYTES) == 0) {
        } else {
            logger(LOG_ERR, "Unable to load master keys from %s and %s.",
                   c.provider_publickey_file, c.provider_secretkey_file);
            exit(1);
        }
        logger(LOG_NOTICE, "Generating pre-signed certificate.");
        struct SignedCert *signed_cert =
            cert_build_cert(c.keypairs->crypt_publickey, cert_file_expire_days, use_xchacha20);
        if (!signed_cert || cert_sign(signed_cert, c.provider_secretkey) != 0) {
            logger(LOG_NOTICE, "Failed.");
            exit(1);
        }
        logger(LOG_NOTICE, "TXT record for signed-certificate:");
        printf("* Record for nsd:\n");
        cert_display_txt_record(signed_cert);
        printf("\n");
        printf("* Record for tinydns:\n");
        cert_display_txt_record_tinydns(signed_cert);
        printf("\n");
        if (write_to_file
            (c.provider_cert_file, (char *)signed_cert,
             sizeof(struct SignedCert)) != 0) {
            logger(LOG_ERR, "The new certificate was not saved - "
                   "Maybe the %s file already exists - please delete it first.",
                   c.provider_cert_file);
            exit(1);
        }
        logger(LOG_NOTICE, "Certificate stored in %s.", c.provider_cert_file);
        exit(0);
    }

    if (!c.resolver_address) {
        logger(LOG_ERR, "You must specify --resolver-address.\n\n");
        argparse_usage(&argparse);
        exit(0);
    }

    if (blacklist_file != NULL && blocking_init(&c, blacklist_file) != 0) {
        logger(LOG_ERR, "Unable to load the blacklist file");
        exit(1);
    }

    c.udp_listener_handle = -1;
    c.udp_resolver_handle = -1;

    if (c.user) {
        struct passwd *pw = getpwnam(c.user);
        if (pw == NULL) {
            logger(LOG_ERR, "Unknown user: [%s]", c.user);
            exit(1);
        }
        c.user_id = pw->pw_uid;
        c.user_group = pw->pw_gid;
        c.user_dir = strdup(pw->pw_dir);
    }

    if (!c.provider_name) {
        logger(LOG_ERR, "You must specify --provider-name");
        exit(1);
    }

    if (parse_cert_files(&c)) {
        exit(1);
    }
    if (match_cert_to_keys(&c)) {
        exit(1);
    }
    if (c.signed_certs_count <= 0U) {
        logger(LOG_ERR, "You must specify --provider-cert-file.\n\n");
        argparse_usage(&argparse);
        exit(1);
    }
    if (filter_signed_certs(&c)) {
        exit(1);
    }
    if (c.signed_certs_count <= 0U) {
        logger(LOG_ERR, "No (currently) valid certs found.\n\n");
        exit(1);
    }

    if (c.daemonize) {
        do_daemonize();
    }
    if (c.pidfile) {
        pidfile_create(c.pidfile);
    }

    if (sockaddr_from_ip_and_port(&c.resolver_sockaddr,
                                  &c.resolver_sockaddr_len,
                                  c.resolver_address,
                                  "53", "Unsupported resolver address") != 0) {
        exit(1);
    }

    if (c.outgoing_address &&
        sockaddr_from_ip_and_port(&c.outgoing_sockaddr,
                                  &c.outgoing_sockaddr_len,
                                  c.outgoing_address,
                                  "0", "Unsupported outgoing address") != 0) {
        exit(1);
    }

    if (sockaddr_from_ip_and_port(&c.local_sockaddr,
                                  &c.local_sockaddr_len,
                                  c.listen_address,
                                  "53", "Unsupported local address") != 0) {
        exit(1);
    }

    randombytes_buf(c.hash_key, sizeof c.hash_key);

    if ((c.event_loop = event_base_new()) == NULL) {
        logger(LOG_ERR, "Unable to initialize the event loop.");
        exit(1);
    }

    if (udp_listener_bind(&c) != 0 || tcp_listener_bind(&c) != 0) {
        exit(1);
    }

    if (udp_listener_start(&c) != 0 || tcp_listener_start(&c) != 0) {
        logger(LOG_ERR, "Unable to start udp listener.");
        exit(1);
    }

    revoke_privileges(&c);

    event_base_dispatch(c.event_loop);

    logger(LOG_INFO, "Stopping proxy");
    udp_listener_stop(&c);
    tcp_listener_stop(&c);
    event_base_free(c.event_loop);
    blocking_free(&c);

    return 0;
}
