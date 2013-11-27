#ifndef EDNS_H
#define EDNS_H

struct context;

int edns_add_section(struct context *const c,
                     uint8_t *const dns_packet,
                     size_t * const dns_packet_len_p,
                     size_t dns_packet_max_size,
                     size_t * const request_edns_payload_size);
#endif
