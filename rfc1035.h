#ifndef RFC1035_H
#define RFC1035_H

#include "compat.h"
#include "dns-protocol.h"
#include <sodium.h>

int questions_hash(uint64_t *hash, struct dns_header *header, size_t plen, char *buff, const unsigned char key[crypto_shorthash_KEYBYTES]);
int extract_name(struct dns_header *header, size_t plen, unsigned char **pp, char
        *name, int isExtract, int extrabytes);
int add_resource_record(struct dns_header *header, unsigned int nameoffset, unsigned char **pp, 
			       unsigned long ttl, unsigned int *offset, unsigned short type, unsigned short class, char *format, ...);
unsigned char * skip_questions(struct dns_header *header, size_t plen);

#endif
