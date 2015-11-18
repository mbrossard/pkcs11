/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "common.h"
#include "crypto.h"
#include "keypair.h"
#include "pkcs11_display.h"

#include <stdlib.h>
#include <string.h>

static const char *app_name = "pkcs11-util keygen";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { "key-type",           1, 0,           'k' },
    { "label",              1, 0,           'l' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify the directory for NSS database",
    "Key type",
    "Label to set",
};

int keygen( int argc, char **argv )
{
    CK_ULONG          nslots, keysize;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_SESSION_HANDLE h_session;
    CK_BYTE_PTR       opt_label = NULL;
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_ULONG          opt_slot = -1;
    CK_RV             rc;
    char *opt_module = NULL, *opt_dir = NULL;
    char *gen_param = NULL, *tmp;
    int long_optind = 0;
    int genkey = 0;
    char c;

    init_crypto();

    while (1) {
        c = getopt_long(argc, argv, "d:hl:p:s:k:m:",
                        options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
                break;
            case 'l':
                opt_label = (CK_BYTE_PTR)optarg;
                break;
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
            case 'k':
                gen_param = optarg;
                genkey = 1;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    if(!genkey) {
        print_usage_and_die(app_name, options, option_help);
    }

    rc = pkcs11_load_init(opt_module, opt_dir, stdout, &funcs);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_get_slots(funcs, stdout, &pslots, &nslots);
    if (rc != CKR_OK) {
        return rc;
    }

    if(opt_slot != -1) {
        /* TODO: Look in pslots */
        pslots = &opt_slot;
        nslots = 1;
    } else {
        if(nslots == 1) {
            opt_slot = pslots[0];
        } else {
            fprintf(stdout, "Found %ld slots, use --slot parameter to choose.\n", nslots);
            exit(-1);
        }
    }

    rc = pkcs11_login_session(funcs, stdout, opt_slot, &h_session,
                              CK_TRUE, CKU_USER, opt_pin, opt_pin_len);
    free(opt_pin);
    if (rc != CKR_OK) {
        return rc;
    }

    fprintf(stdout, "Generating key with param '%s'\n", gen_param);
    keysize = strtol(gen_param, &tmp, 10);
    if(gen_param != tmp) {
        fprintf(stdout, "Generating RSA key with size %ld\n", keysize);
        rc = generateRsaKeyPair(funcs, h_session, keysize, opt_label);
    } else if(strncmp(gen_param, "gost", 4) == 0) {
        fprintf(stdout, "Generating GOST R34.10-2001 key (%s) in slot %ld\n",
                gen_param, opt_slot);
        rc = generateGostKeyPair(funcs, h_session, gen_param, opt_label);
    } else {
        CK_BBOOL full;
        rc = ecdsaNeedsEcParams(funcs, opt_slot, &full);
        if(rc == CKR_OK) {
            fprintf(stdout, "Generating ECDSA key with curve '%s' "
                    "in slot %ld with %s\n", gen_param, opt_slot,
                    full ? "EC Parameters" : "Named Curve");
            rc = generateEcdsaKeyPair(funcs, h_session, gen_param, full, opt_label);
        }
    }
    
    rc = pkcs11_close(stdout, funcs, h_session);
    return rc;
}
