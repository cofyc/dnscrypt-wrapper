
#include <dnscrypt/plugin.h>

#include <ctype.h>
#include <stdio.h>

DCPLUGIN_MAIN(__FILE__);

#ifndef putc_unlocked
# define putc_unlocked(c, stream) putc((c), (stream))
#endif

const char *
dcplugin_description(DCPlugin * const dcplugin)
{
    return "Log client queries";
}

const char *
dcplugin_long_description(DCPlugin * const dcplugin)
{
    return
        "Log client queries\n"
        "\n"
        "This plugin logs the client queries to the standard output (default)\n"
        "or to a file.\n"
        "\n"
        "  # dnscrypt-proxy --plugin libdcplugin_example_logging,/tmp/dns.log";
}

int
dcplugin_init(DCPlugin * const dcplugin, int argc, char *argv[])
{
    FILE *fp;

    if (argc != 2U) {
        fp = stdout;
    } else {
        if ((fp = fopen(argv[1], "a")) == NULL) {
            return -1;
        }
    }
    dcplugin_set_user_data(dcplugin, fp);

    return 0;
}

int
dcplugin_destroy(DCPlugin * const dcplugin)
{
    FILE * const fp = dcplugin_get_user_data(dcplugin);

    if (fp != stdout) {
        fclose(fp);
    }
    return 0;
}

static int
string_fprint(FILE * const fp, const unsigned char *str, const size_t size)
{
    int    c;
    size_t i = (size_t) 0U;

    while (i < size) {
        c = (int) str[i++];
        if (!isprint(c)) {
            fprintf(fp, "\\x%02x", (unsigned int) c);
        } else if (c == '\\') {
            putc_unlocked(c, fp);
        }
        putc_unlocked(c, fp);
    }
    return 0;
}

DCPluginSyncFilterResult
dcplugin_sync_pre_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
    FILE                *fp = dcplugin_get_user_data(dcplugin);
    const unsigned char *wire_data = dcplugin_get_wire_data(dcp_packet);
    size_t               wire_data_len = dcplugin_get_wire_data_len(dcp_packet);
    size_t               i = (size_t) 12U;
    size_t               csize = (size_t) 0U;
    unsigned short       type;
    unsigned char        c;
    _Bool                first = 1;

    if (wire_data_len < 15U || wire_data[4] != 0U || wire_data[5] != 1U) {
        return DCP_SYNC_FILTER_RESULT_ERROR;
    }
    if (wire_data[i] == 0U) {
        putc_unlocked('.', fp);
    }
    while (i < wire_data_len && (csize = wire_data[i]) != 0U &&
           csize < wire_data_len - i) {
        i++;
        if (first != 0) {
            first = 0;
        } else {
            putc_unlocked('.', fp);
        }
        string_fprint(fp, &wire_data[i], csize);
        i += csize;
    }
    type = 0U;
    if (i < wire_data_len - 2U) {
        type = (wire_data[i + 1U] << 8) + wire_data[i + 2U];
    }
    if (type == 0x01) {
        fputs("\t[A]\n", fp);
    } else if (type == 0x02) {
        fputs("\t[NS]\n", fp);
    } else if (type == 0x0f) {
        fputs("\t[MX]\n", fp);
    } else if (type == 0x1c) {
        fputs("\t[AAAA]\n", fp);
    } else {
        fprintf(fp, "\t[0x%02hX]\n", type);
    }
    fflush(fp);

    return DCP_SYNC_FILTER_RESULT_OK;
}

DCPluginSyncFilterResult
dcplugin_sync_post_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
    return DCP_SYNC_FILTER_RESULT_OK;
}
