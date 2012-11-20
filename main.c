#include "dnscrypt.h"
#include "argparse/argparse.h"
/**
 * This is dnscrypt wrapper, which enables dnscrypt support for any dns server.
 */

static const char *const config_usage[] = { 
    "dnscrypt-wrapper [options]",
    NULL
};

static int
sockaddr_from_ip_and_port(struct sockaddr_storage *const sockaddr,
                          ev_socklen_t * const sockaddr_len_p,
                          const char *const ip, const char *const port,
                          const char *const error_msg)
{
    char sockaddr_port[INET6_ADDRSTRLEN + sizeof "[]:65535"];
    int sockaddr_len_int;
    char *pnt;
    _Bool has_column = 0;
    _Bool has_columns = 0;
    _Bool has_brackets = *ip == '[';

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
        evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "[%s]:%s",
                        ip, port);
    } else {
        evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "%s:%s", ip, port);
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
    static char  default_tz_for_putenv[] = "TZ=UTC+00:00";
    char         stbuf[10U];
    struct tm   *tm;
    time_t       now;

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
        if (chdir(c->user_dir) != 0 ||
            chroot(c->user_dir) != 0) {
            logger(LOG_ERR, "Unable to chroot to [%s]", c->user_dir);
            exit(1);
        }
    }
    if (c->user_id != (uid_t)0) {
        if (setgid(c->user_group) != 0 ||
            setegid(c->user_group) != 0 || 
            setuid(c->user_id) != 0 ||
            seteuid(c->user_id) != 0) {
            logger(LOG_ERR, "Unable to switch to user id [%lu]", (unsigned long)c->user_id);
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
    fd = open(path, O_WRONLY | O_CREAT);
    if (fd < 0) {
        printf("Cannnot open %s to write.\n", path);
        return -1;
    }
    chmod(path, 0444);
    if (safe_write(fd, buf, count, 3) != count) {
        printf("Cannnot write to %s.\n", path);
        return -1;
    }
    return 0;
}

static int
read_from_file(const char *path, char *buf, size_t count)
{
    int fd;
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("Cannot open %s.\n", path);
        return -1;
    }
    if (safe_read(fd, buf, count) != count) {
        printf("Invalid file: %s\n", path);
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int
main(int argc, const char **argv)
{
    struct context c;
    memset(&c, 0, sizeof(struct context));

    int gen_provider_keypair = 0;
    int gen_crypt_keypair = 0;
    struct argparse argparse;
    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_STRING('a', "listen-address", &c.listen_address, "local address to listen (default: 0.0.0.0:53)"),
        OPT_STRING('r', "resolver-address", &c.resolver_address, "upstream dns resolver server (<address:port>)"),
        OPT_STRING('u', "user", &c.user, "run as given user"),
        OPT_BOOLEAN('d', "daemonize", &c.daemonize, "run as daemon (default: off)"),
        OPT_BOOLEAN('t', "tcp-only", &c.tcp_only, "use tcp only (default: off)"),
        OPT_STRING('l', "logfile", &c.logfile, "log file path (default: stdout)"),
        OPT_STRING(0, "provider-name", &c.provider_name, "provider name"),
        OPT_STRING(0, "provider-publickey-file", &c.provider_publickey_file, "provider public key file"),
        OPT_STRING(0, "provider-secretkey-file", &c.provider_secretkey_file, "provider secret key file"),
        OPT_BOOLEAN(0, "gen-provider-keypair", &gen_provider_keypair, "generate provider key pair"),
        OPT_STRING(0, "crypt-publickey-file", &c.crypt_publickey_file, "crypt public key file"),
        OPT_STRING(0, "crypt-secretkey-file", &c.crypt_secretkey_file, "crypt secret key file"),
        OPT_BOOLEAN(0, "gen-crypt-keypair", &gen_crypt_keypair, "generate crypt key pair"),
        OPT_END(),
    };

    argparse_init(&argparse, options, config_usage, 0);
    argc = argparse_parse(&argparse, argc, argv);
    
    if (gen_provider_keypair) {
        uint8_t provider_publickey[crypto_sign_ed25519_PUBLICKEYBYTES];
        uint8_t provider_secretkey[crypto_sign_ed25519_SECRETKEYBYTES];
        printf("Generate provider key pair...");
        if (crypto_sign_ed25519_keypair(provider_publickey, provider_secretkey) == 0) {
            printf(" ok.\n");
            char fingerprint[80];
            dnscrypt_key_to_fingerprint(fingerprint, provider_publickey);
            printf("Public key fingerprint: %s\n", fingerprint);
            if (write_to_file("public.key", (char *)provider_publickey, crypto_sign_ed25519_PUBLICKEYBYTES) == 0 &&
                write_to_file("secret.key", (char *)provider_secretkey, crypto_sign_ed25519_SECRETKEYBYTES) == 0) {
                printf("Keys are stored in public.key & secret.key.\n");
                exit(0);
            }
            exit(1);
        } else {
            printf(" failed.\n");
            exit(1);
        }
    }

    if (gen_crypt_keypair) {
        uint8_t crypt_publickey[crypto_box_PUBLICKEYBYTES];
        uint8_t crypt_secretkey[crypto_box_SECRETKEYBYTES];
        printf("Generate crypt key pair...");
        if (crypto_box_keypair(crypt_publickey, crypt_secretkey) == 0) {
            printf(" ok.\n");
            if (write_to_file("crypt_public.key", (char *)crypt_publickey, crypto_box_PUBLICKEYBYTES) == 0
                && write_to_file("crypt_secret.key", (char *)crypt_secretkey, crypto_box_SECRETKEYBYTES) == 0) {
                printf("Keys are stored in crypt_public.key & crypt_secret.key.\n");
                exit(0);
            }
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

    if (!c.resolver_address) {
        logger(LOG_ERR, "You must specify --resolver-address.\n\n");
        argparse_usage(&argparse);
        exit(0);
    }

    // test libnacl
    /*uint8_t server_publickey[crypto_box_PUBLICKEYBYTES];*/
    /*uint8_t server_secretkey[crypto_box_SECRETKEYBYTES];*/
    /*uint8_t client_publickey[crypto_box_PUBLICKEYBYTES];*/
    /*uint8_t client_secretkey[crypto_box_SECRETKEYBYTES];*/
    /*uint8_t nonce[crypto_box_NONCEBYTES] = {1};*/
    /*printf("gen client key pair: %d\n", crypto_box_keypair(client_publickey, client_secretkey));*/
    /*salsa20_random_stir();*/
    /*printf("gen server key pair: %d\n", crypto_box_keypair(server_publickey, server_secretkey));*/
    /*salsa20_random_stir();*/
    /*uint8_t client_nmkey[crypto_box_BEFORENMBYTES];*/
    /*uint8_t server_nmkey[crypto_box_BEFORENMBYTES];*/
    /*// client nmkey*/
    /*memcpy(client_nmkey, server_publickey, crypto_box_PUBLICKEYBYTES);*/
    /*printf("gen client nmkey: %d\n", crypto_box_beforenm(client_nmkey, client_nmkey, client_secretkey));*/
    /*// server nmkey*/
    /*memcpy(server_nmkey, client_publickey, crypto_box_PUBLICKEYBYTES);*/
    /*printf("gen server nmkey: %d\n", crypto_box_beforenm(server_nmkey, server_nmkey, server_secretkey));*/
    /*uint8_t data[1024];*/
    /*memset(data, 0, crypto_box_ZEROBYTES);*/
    /*memcpy(data + crypto_box_ZEROBYTES, "abc", 4);*/
    /*printf("afternm: %d\n", crypto_box_afternm((unsigned char*)data, (unsigned char *)data, 4 + crypto_box_ZEROBYTES, nonce, client_nmkey));*/
    /**//*memset(data, 0, crypto_box_BOXZEROBYTES);*/
    /*printf("open afternm: %d\n", crypto_box_open_afternm((unsigned char*)data, (unsigned char *)data, 4 + crypto_box_ZEROBYTES, nonce, server_nmkey));*/
    /*printf("%s\n", data + crypto_box_ZEROBYTES);*/
    /*exit(0);*/

    if (!c.listen_address)
        c.listen_address = "0.0.0.0:53";
    c.udp_listener_handle = -1;
    c.udp_resolver_handle = -1;
    c.connections_max = 250;
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
        logger(LOG_ERR, "You must specify --provider-name.");
        exit(1);
    }

    // provider public & secret key
    if (!c.provider_publickey_file || !c.provider_secretkey_file) {
        logger(LOG_ERR, "You must provide --provider-publickey-file and --provider-secretkey-file.");
        exit(1);
    }
    if (read_from_file(c.provider_publickey_file, (char *)c.provider_publickey, crypto_sign_ed25519_PUBLICKEYBYTES) == 0 && read_from_file(c.provider_secretkey_file, (char *)c.provider_secretkey, crypto_sign_ed25519_SECRETKEYBYTES) == 0) {
    } else {
        exit(1);
    }
    {
        char fingerprint[80];
        dnscrypt_key_to_fingerprint(fingerprint, c.provider_publickey);
        logger(LOG_INFO, "Public key fingerprint: %s", fingerprint);
    }

    // crypt public & secret key
    if (!c.crypt_publickey_file || !c.crypt_secretkey_file) {
        logger(LOG_ERR, "You must provide --crypt-secretkey-file and --crypt-secretkey-file.");
        exit(1);
    }
    if (read_from_file(c.crypt_publickey_file, (char *)c.crypt_publickey, crypto_box_PUBLICKEYBYTES) != 0 ||
        read_from_file(c.crypt_secretkey_file, (char *)c.crypt_secretkey, crypto_box_SECRETKEYBYTES) != 0) {
        exit(1);
    }
    {
        char fingerprint[80];
        dnscrypt_key_to_fingerprint(fingerprint, c.crypt_publickey);
        logger(LOG_INFO, "Crypt public key fingerprint: %s", fingerprint);
    }

    if (c.daemonize) {
        do_daemonize();
    }

    if (sockaddr_from_ip_and_port(&c.resolver_sockaddr,
                                  &c.resolver_sockaddr_len,
                                  c.resolver_address,
                                  "53", "Unsupported resolver address") != 0) {
        exit(1);
    }

    if (sockaddr_from_ip_and_port(&c.local_sockaddr,
                                  &c.local_sockaddr_len,
                                  c.listen_address,
                                  "53", "Unsupported local address") != 0) {
        exit(1);
    }

    if ((c.event_loop = event_base_new()) == NULL) {
        logger(LOG_ERR, "Unable to initialize the event loop.");
        exit(1);
    }

    if (udp_listern_bind(&c) != 0) {
        exit(1);
    }

    if (udp_listener_start(&c) != 0) {
        logger(LOG_ERR, "Unable to start udp listener.");
        exit(1);
    }

    revoke_privileges(&c);

    event_base_dispatch(c.event_loop);

    return 0;
}
