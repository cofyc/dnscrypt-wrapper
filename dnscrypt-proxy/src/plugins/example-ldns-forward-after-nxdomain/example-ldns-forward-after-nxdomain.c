
#include <dnscrypt/plugin.h>
#include <ldns/ldns.h>

DCPLUGIN_MAIN(__FILE__);

typedef struct Forwarder_ {
    ldns_resolver *resolver;
} Forwarder;

const char *
dcplugin_description(DCPlugin * const dcplugin)
{
    return "Resolve a name without dnscrypt after an NXDOMAIN response";
}

const char *
dcplugin_long_description(DCPlugin * const dcplugin)
{
    return
        "Example usage:\n"
        "\n"
        "# dnscrypt-proxy --plugin \\\n"
        "  libdcplugin_example_ldns_forward_after_nxdomain.la,/etc/resolv.conf";
}

int
dcplugin_init(DCPlugin * const dcplugin, int argc, char *argv[])
{
    Forwarder  *forwarder;
    const char *resolver_conf = NULL;

    forwarder = calloc(1U, sizeof *forwarder);
    dcplugin_set_user_data(dcplugin, forwarder);
    if (forwarder == NULL) {
        return -1;
    }
    if (argc > 1) {
        resolver_conf = argv[1];
    }
    if (ldns_resolver_new_frm_file(&forwarder->resolver, resolver_conf)
        != LDNS_STATUS_OK) {
        return -1;
    }
    ldns_resolver_set_retry(forwarder->resolver, 1);
    ldns_resolver_set_timeout(forwarder->resolver, (struct timeval) {
        .tv_sec = 2, .tv_usec = 0
    });
    return 0;
}

int
dcplugin_destroy(DCPlugin *dcplugin)
{
    Forwarder *forwarder = dcplugin_get_user_data(dcplugin);

    if (forwarder == NULL) {
        return 0;
    }
    ldns_resolver_deep_free(forwarder->resolver);
    free(forwarder);

    return 0;
}

DCPluginSyncFilterResult
dcplugin_sync_post_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
    Forwarder *forwarder = dcplugin_get_user_data(dcplugin);
    ldns_pkt  *query = NULL;
    ldns_pkt  *response = NULL;
    uint8_t   *query_wire = dcplugin_get_wire_data(dcp_packet);
    uint8_t   *response_wire = NULL;
    size_t     response_wire_len;

    if (LDNS_RCODE_WIRE(query_wire) != LDNS_RCODE_NXDOMAIN) {
        return DCP_SYNC_FILTER_RESULT_OK;
    }
    LDNS_AA_CLR(query_wire);
    LDNS_QR_CLR(query_wire);
    LDNS_TC_CLR(query_wire);
    ldns_wire2pkt(&query, query_wire, dcplugin_get_wire_data_len(dcp_packet));
    ldns_pkt_set_edns_data(query, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_HEX, ""));
    ldns_send(&response, forwarder->resolver, query);
    ldns_pkt_free(query);
    ldns_pkt2wire(&response_wire, response, &response_wire_len);
    ldns_pkt_free(response);
    if (response_wire_len > dcplugin_get_wire_data_max_len(dcp_packet)) {
        free(response_wire);
        return DCP_SYNC_FILTER_RESULT_ERROR;
    }
    dcplugin_set_wire_data(dcp_packet, response_wire, response_wire_len);
    free(response_wire);

    return DCP_SYNC_FILTER_RESULT_OK;
}
