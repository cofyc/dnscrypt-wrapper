#ifndef RFC1035_H
#define RFC1035_H

#include "compat.h"
#include "dns-protocol.h"

unsigned int questions_crc(struct dns_header *header, size_t plen, char *buff);

#endif
