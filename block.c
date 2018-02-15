
#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dnscrypt.h"
#include "fpst.h"

#define MAX_QNAME_LENGTH 255U

typedef enum BlockType {
    BLOCKTYPE_UNDEFINED,
    BLOCKTYPE_EXACT,
    BLOCKTYPE_PREFIX,
    BLOCKTYPE_SUFFIX,
    BLOCKTYPE_SUBSTRING
} BlockType;

typedef struct Blocking_ {
    FPST *domains;
    FPST *domains_rev;
    FPST *domains_substr;
} Blocking;

static char *
skip_spaces(char *str)
{
    while (*str != 0 && isspace((int) (unsigned char) *str)) {
        str++;
    }
    return str;
}

static char *
skip_chars(char *str)
{
    while (*str != 0 && !isspace((int) (unsigned char) *str)) {
        str++;
    }
    return str;
}

static void
str_tolower(char *str)
{
    while (*str != 0) {
        *str = (char) tolower((unsigned char) *str);
        str++;
    }
}

static void
str_reverse(char *str)
{
    size_t i = 0;
    size_t j = strlen(str);
    char   t;

    while (i < j) {
        t = str[i];
        str[i++] = str[--j];
        str[j] = t;
    }
}

static char *
untab(char *line)
{
    char *ptr;

    while ((ptr = strchr(line, '\t')) != NULL) {
        *ptr = ' ';
    }
    return line;
}

static char *
trim_comments(char *line)
{
    char *ptr;
    char *s1;
    char *s2;

    while ((ptr = strchr(line, '\n')) != NULL ||
           (ptr = strchr(line, '\r')) != NULL) {
        *ptr = 0;
    }
    line = skip_spaces(line);
    if (*line == 0 || *line == '#') {
        return NULL;
    }
    s1 = skip_chars(line);
    if (*(s2 = skip_spaces(s1)) == 0) {
        *s1 = 0;
        return line;
    }
    if (*s2 == '#') {
        return NULL;
    }
    *skip_chars(s2) = 0;

    return s2;
}

static void
free_list(const char *key, uint32_t val)
{
    (void) val;
    free((void *) key);
}

static int
parse_domain_list(FPST ** const domain_list_p,
                  FPST ** const domain_rev_list_p,
                  FPST ** const domain_substr_list_p,
                  const char * const file)
{
    char       buf[MAX_QNAME_LENGTH + 1U];
    char      *line;
    FILE      *fp;
    FPST      *domain_list;
    FPST      *domain_list_tmp;
    FPST      *domain_rev_list;
    FPST      *domain_rev_list_tmp;
    FPST      *domain_substr_list;
    FPST      *domain_substr_list_tmp;
    size_t     line_len;
    BlockType  block_type = BLOCKTYPE_UNDEFINED;
    int        ret = -1;

    assert(domain_list_p != NULL);
    assert(domain_rev_list_p != NULL);
    assert(domain_substr_list_p != NULL);
    *domain_list_p = NULL;
    *domain_rev_list_p = NULL;
    *domain_substr_list_p = NULL;
    domain_list = fpst_new();
    domain_rev_list = fpst_new();
    domain_substr_list = fpst_new();
    if ((fp = fopen(file, "r")) == NULL) {
        return -1;
    }
    while (fgets(buf, (int) sizeof buf, fp) != NULL) {
        if ((line = trim_comments(untab(buf))) == NULL || *line == 0) {
            continue;
        }
        line_len = strlen(line);
        if (line[0] == '*' && line[line_len - 1] == '*') {
            line[line_len - 1] = 0;
            line++;
            block_type = BLOCKTYPE_SUBSTRING;
        } else if (line[line_len - 1] == '*') {
            line[line_len - 1] = 0;
            block_type = BLOCKTYPE_PREFIX;
        } else {
            if (line[0] == '*') {
                line++;
            }
            if (line[0] == '.') {
                line++;
            }
            str_reverse(line);
            block_type = BLOCKTYPE_SUFFIX;
        }
        if (*line == 0) {
            continue;
        }
        str_tolower(line);
        if ((line = strdup(line)) == NULL) {
            break;
        }
        if (block_type == BLOCKTYPE_SUFFIX) {
            if ((domain_rev_list_tmp = fpst_insert_str(domain_rev_list, line,
                                                       (uint32_t) block_type)) == NULL) {
                free(line);
                break;
            }
            domain_rev_list = domain_rev_list_tmp;
        } else if (block_type == BLOCKTYPE_PREFIX) {
            if ((domain_list_tmp = fpst_insert_str(domain_list, line,
                                                   (uint32_t) block_type)) == NULL) {
                free(line);
                break;
            }
            domain_list = domain_list_tmp;
        } else if (block_type == BLOCKTYPE_SUBSTRING) {
            if ((domain_substr_list_tmp = fpst_insert_str(domain_substr_list, line,
                                                          (uint32_t) block_type)) == NULL) {
                free(line);
                break;
            }
            domain_substr_list = domain_substr_list_tmp;
        } else {
            free(line);
        }
    }
    if (!feof(fp)) {
        fpst_free(domain_list, free_list);
        fpst_free(domain_rev_list, free_list);
        fpst_free(domain_substr_list, free_list);
    } else {
        *domain_list_p = domain_list;
        *domain_rev_list_p = domain_rev_list;
        *domain_substr_list_p = domain_substr_list;
        ret = 0;
    }
    fclose(fp);
    logger(LOG_INFO, "Blacklist [%s] loaded", file);

    return ret;
}

static _Bool
substr_match(FPST *list, const char *str,
             const char **found_key_p, uint32_t *found_block_type_p)
{
    while (*str != 0) {
        if (fpst_str_starts_with_existing_key(list, str, found_key_p,
                                              found_block_type_p)) {
            return 1;
        }
        str++;
    }
    return 0;
}

int
blocking_init(struct context *c, const char *file)
{
    Blocking *blocking;

    if ((blocking = calloc((size_t) 1U, sizeof *blocking)) == NULL) {
        return -1;
    }
    c->blocking = blocking;
    blocking->domains = NULL;
    blocking->domains_rev = NULL;
    blocking->domains_substr = NULL;

    return parse_domain_list(&blocking->domains, &blocking->domains_rev,
                             &blocking->domains_substr, file);
}

void
blocking_free(struct context *c)
{
    Blocking *blocking = c->blocking;

    if (blocking == NULL) {
        return;
    }
    fpst_free(blocking->domains, free_list);
    blocking->domains = NULL;
    fpst_free(blocking->domains_rev, free_list);
    blocking->domains_rev = NULL;
    fpst_free(blocking->domains_substr, free_list);
    blocking->domains_substr = NULL;
    free(blocking);
}

void
str_lcpy(char *dst, const char *src, size_t dsize)
{
    size_t nleft = dsize;

    if (nleft != 0) {
        while (--nleft != 0) {
            if ((*dst++ = *src++) == 0) {
                break;
            }
        }
    }
    if (nleft == 0 && dsize != 0) {
        *dst = 0;
    }
}

static int
name_matches_blacklist(const Blocking * const blocking, char * const name)
{
    char        rev[MAX_QNAME_LENGTH + 1U];
    const char *found_key;
    size_t      name_len;
    uint32_t    found_block_type;
    _Bool       block = 0;

    rev[MAX_QNAME_LENGTH] = 0;
    name_len = strlen(name);
    if (name_len >= sizeof rev) {
        return -1;
    }
    if (name_len > (size_t) 1U && name[name_len - 1U] == '.') {
        name[--name_len] = 0;
    }
    if (name_len <= 0) {
        return 0;
    }
    str_tolower(name);
    do {
        str_lcpy(rev, name, sizeof rev);
        str_reverse(rev);
        if (fpst_starts_with_existing_key(blocking->domains_rev,
                                          rev, name_len,
                                          &found_key, &found_block_type)) {
            const size_t found_key_len = strlen(found_key);

            assert(found_block_type == BLOCKTYPE_SUFFIX);
            if (found_key_len <= name_len &&
                (rev[found_key_len] == 0 || rev[found_key_len] == '.')) {
                block = 1;
                break;
            }
            if (found_key_len < name_len) {
                size_t owner_part_len = name_len;

                while (owner_part_len > 0U && rev[owner_part_len] != '.') {
                    owner_part_len--;
                }
                rev[owner_part_len] = 0;
                if (owner_part_len > 0U && fpst_starts_with_existing_key
                    (blocking->domains_rev, rev, owner_part_len,
                     &found_key, &found_block_type)) {
                    const size_t found_key_len = strlen(found_key);
                    if (found_key_len <= owner_part_len &&
                        (rev[found_key_len] == 0 || rev[found_key_len] == '.')) {
                        block = 1;
                        break;
                    }
                }
            }
        }
        if (fpst_starts_with_existing_key(blocking->domains,
                                          name, name_len,
                                          &found_key, &found_block_type)) {
            assert(found_block_type == BLOCKTYPE_PREFIX);
            block = 1;
            break;
        }
        if (blocking->domains_substr != NULL &&
            substr_match(blocking->domains_substr, name,
                         &found_key, &found_block_type)) {
            assert(found_block_type == BLOCKTYPE_SUBSTRING);
            block = 1;
            break;
        }
    } while (0);

    return (int) block;
}

int
is_blocked(struct context *c, struct dns_header *header, size_t dns_query_len)
{
    unsigned char *ansp;
    unsigned char *p;
    char          *name;

    if (c->blocking == NULL) {
        return 0;
    }
    if (ntohs(header->qdcount) != 1) {
        return -1;
    }
    if (!(ansp = skip_questions(header, dns_query_len))) {
        return -1;
    }
    p = (unsigned char *)(header + 1);
    if (!extract_name(header, dns_query_len, &p, c->namebuff, 1, 4)) {
        return -1;
    }
    name = c->namebuff;

    return name_matches_blacklist(c->blocking, name);
}
