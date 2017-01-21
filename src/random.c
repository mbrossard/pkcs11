/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "common.h"
#include "pkcs11_display.h"

#include <string.h>

static char *app_name = "pkcs11-util random";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "directory",          1, 0,           'd' },
    { "length",             1, 0,           'l' },
    { "output",             1, 0,           'o' },
    { "module",             1, 0,           'm' },
    { "slot",               1, 0,           's' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Specify the directory for NSS database",
    "Specify the length of random string to generate",
    "Specify the module to load",
    "Specify number of the slot to use",
};

/* random is a reserved symbol */
int random_p11(int argc, char **argv)
{
    CK_ULONG          nslots, opt_length = 0;
    CK_SLOT_ID        *pslots = NULL, opt_slot = -1;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_SESSION_HANDLE h_session;
    CK_FLAGS          flags = CKF_SERIAL_SESSION;
    CK_RV             rc;
    char *opt_module = NULL, *opt_dir = NULL, *opt_out = NULL;
    int long_optind = 0;
    FILE *out = stdout;

    while (1) {
        char c = getopt_long(argc, argv, "d:hl:m:o:s:",
                             options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
                break;
            case 'l':
                opt_length = atoi(optarg);
                break;
            case 'm':
                opt_module = optarg;
                break;
            case 'o':
                opt_out = optarg;
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    rc = pkcs11_load_init(opt_module, opt_dir, stderr, &funcs);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_get_slots(funcs, stderr, &pslots, &nslots);
    if (rc != CKR_OK) {
        return rc;
    }
    
    if (opt_slot != -1) {
        CK_ULONG i = 0;
        while (i < nslots && pslots[i] != opt_slot) {
            i++;
        }
        if (i == nslots) {
            fprintf(stderr, "Unknown slot '%lu'\n", opt_slot);
            return -1;            
        }
    } else {
        if (nslots == 1) {
            opt_slot = pslots[0];
        } else {
            fprintf(stdout, "Found %ld slots, use --slot parameter to choose.\n", nslots);
            exit(-1);
        }
    }

    if(opt_out) {
        out = fopen(opt_out, "wb");
        if(out == NULL) {
            fprintf(stderr, "Error opening '%s'\n", opt_out);
            return -1;
        }
    }
    
    rc = funcs->C_OpenSession(pslots[0], flags, NULL, NULL, &h_session);
    if (rc != CKR_OK) {
        show_error(stderr, "C_OpenSession", rc);
        return rc;
    }

    do {
        CK_BYTE buffer[256];
        CK_ULONG l = opt_length;
        l = (l > sizeof(buffer) ? sizeof(buffer) : l);
        rc = funcs->C_GenerateRandom(h_session, buffer, l);
        fwrite(buffer, l, 1, out);
        opt_length -= l;
    } while (opt_length);
    
    if(opt_out) {
        fclose(out);
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stderr, "C_Finalize", rc);
        return rc;
    }

    return rc;
}
