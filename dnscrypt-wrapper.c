#include "dnscrypt-wrapper.h"

/**
 * Return 0 if served.
 */
int
dnscrypt_self_serve_cert_file(struct context *c, struct dns_header *header,
                     size_t *dns_query_len)
{
    unsigned char *p;
    unsigned char *ansp;
    int q;
    int qtype;
    unsigned int nameoffset;
    p = (unsigned char *)(header + 1);
    int anscount = 0;
    /* determine end of questions section (we put answers there) */
    if (!(ansp = skip_questions(header, *dns_query_len))) {
        return -1;
    }
    for (q = ntohs(header->qdcount); q != 0; q--) {
        /* save pointer to name for copying into answers */
        nameoffset = p - (unsigned char *)header;

        if (!extract_name(header, *dns_query_len, &p, c->namebuff, 1, 4)) {
            return -1;
        }
        GETSHORT(qtype, p);
        if (qtype == T_TXT &&
            strcasecmp(c->dnsc.provider_name, c->namebuff) == 0) {
            // reply with signed certificate
            const size_t size = 1 + sizeof(struct SignedCert);
            static uint8_t **txt;

            // Allocate static buffers containing the certificates.
            // This is only called once the first time a TXT request is made.
            if(!txt) {
                txt = calloc(c->dnsc.signed_certs_count,
                             sizeof(uint8_t *));
                if(!txt) {
                    return -1;
                }
                for (int i=0; i < c->dnsc.signed_certs_count; i++) {
                    *(txt + i) = malloc(size);
                    if (!*(txt + i))
                        return -1;
                    **(txt + i) = sizeof(struct SignedCert);
                    memcpy(*(txt + i) + 1,
                           c->dnsc.signed_certs + i,
                           sizeof(struct SignedCert));
                }
            }

            for (int i=0; i < c->dnsc.signed_certs_count; i++) {
                if (add_resource_record
                    (header, nameoffset, &ansp, 0, NULL, T_TXT, C_IN, "t", size,
                     *(txt + i))) {
                    anscount++;
                } else {
                    return -1;
                }
            }
            /* done all questions, set up header and return length of result */
            /* clear authoritative and truncated flags, set QR flag */
            header->hb3 = (header->hb3 & ~(HB3_AA | HB3_TC)) | HB3_QR;
            /* set RA flag */
            header->hb4 |= HB4_RA;

            SET_RCODE(header, NOERROR);
            header->ancount = htons(anscount);
            header->nscount = htons(0);
            header->arcount = htons(0);
            *dns_query_len = ansp - (unsigned char *)header;

            return 0;
          }
    }
    return -1;
}
