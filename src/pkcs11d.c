/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "common.h"
#include "crypto.h"
#include "network.h"
static char *app_name = "pkcs11d";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
};

int main(int argc, char **argv)
{
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_ULONG          opt_slot = -1;
    char *opt_module = NULL;
    struct sockaddr_un sockaddr;
    int long_optind = 0;
    int fd;

    init_crypto();

    while (1) {
        char c = getopt_long(argc, argv, "hp:s:m:",
                             options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'p':
                opt_pin = (CK_UTF8CHAR_PTR) strdup(optarg);
                if(opt_pin) {
                    opt_pin_len = strlen(optarg);
                }
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
                break;
            case 'm':
                opt_module = optarg;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    fd = nw_unix_server("pkcs11d.sock", &sockaddr, 0, 0, 0, 64);
    close(fd);
    fd = nw_tcp_server(1234, 0, 64);
    
    do {
        struct sockaddr address;
        socklen_t a_len = sizeof(address);
        int s = accept(fd, &address, &a_len);

        nw_nwrite(s, "Hello world!\n", 14);
        close(s);
    } while(1);

    close(fd);
}
