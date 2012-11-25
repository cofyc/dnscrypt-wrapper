
#ifndef __APP_H__
#define __APP_H__ 1

#include <config.h>
#ifdef PLUGINS
# include "plugin_support.h"
#endif

#ifdef NDEBUG
# error Assertions should be turned on. Always.
#endif

typedef struct AppContext_ {
    struct ProxyContext_ *proxy_context;
#ifdef PLUGINS
    DCPluginSupportContext *dcps_context;
#endif
} AppContext;

int dnscrypt_proxy_main(int argc, char *argv[]);
int dnscrypt_proxy_loop_break(void);

#endif
