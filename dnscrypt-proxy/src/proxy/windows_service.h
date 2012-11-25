
#ifndef __WINDOWS_SERVICE_H__
#define __WINDOWS_SERVICE_H__ 1

typedef enum WinOption_ {
    WIN_OPTION_INSTALL = 256,
    WIN_OPTION_REINSTALL,
    WIN_OPTION_UNINSTALL
} WinOption;

int windows_service_option(const int opt_flag,
                           const int argc, const char *argv[]);

#endif
