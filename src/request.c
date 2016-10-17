/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"

#ifdef HAVE_OPENSSL

#include "common.h"
#include "crypto.h"
#include "pkcs11_display.h"

#include <string.h>
#include <getopt.h>
#include <stdio.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>

static char *app_name = "pkcs11-util request";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "label",              1, 0,           'l' },
    { "directory",          1, 0,           'd' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify label of the private key to use",
    "Specify the directory for NSS database",
};

int request(int argc, char **argv)
{
    CK_FUNCTION_LIST *funcs = NULL;
    CK_SLOT_ID       *pslots = NULL;
    char             *opt_label = NULL;
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          nslots, opt_slot = -1;
    CK_SESSION_HANDLE h_session;
    CK_OBJECT_HANDLE  key;
    char *opt_module = NULL, *opt_dir = NULL;
    int long_optind = 0;
    int opt_quiet = 0;
    char c;
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE search[2];
    CK_ULONG count = 1;

    fprintf(stdout, "This feature is a work in progress.\n");

    while (1) {
        c = getopt_long(argc, argv, "hd:p:s:l:m:q",
                        options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
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
            case 'l':
                opt_label = optarg;
                break;
            case 'q':
                opt_quiet = 1;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    rc = pkcs11_load_init(opt_module, opt_dir, stdout, &funcs);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_get_slots(funcs, stdout, &pslots, &nslots);
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

    rc = pkcs11_login_session(funcs, stdout, opt_slot, &h_session,
                              CK_FALSE, CKU_USER, opt_pin, opt_pin_len);
    free(opt_pin);
    if (rc != CKR_OK) {
        return rc;
    }

    fillAttribute(&(search[0]), CKA_CLASS, &class, sizeof(class));
    if(opt_label) {
        fillAttribute(&(search[1]), CKA_LABEL, opt_label, strlen(opt_label));
        count = 2;
    }

    rc = pkcs11_find_object(funcs, stdout, h_session, search,
                            count, &key, 1, &count);
    if (rc != CKR_OK) {
        return rc;
    }

    if(count == 0) {
        fprintf(stdout, "No object found\n");
        exit(-1);
    }

    if(!opt_quiet) {
        print_object_info(funcs, stdout, 0, h_session, key);
    }

    EVP_PKEY *k = load_pkcs11_key(funcs, h_session, key);

    if(k == NULL) {
        fprintf(stdout, "Error loading key\n");
        return -1;
    }

    X509_REQ *req = X509_REQ_new();
    X509_REQ_set_version(req, 0);
    X509_REQ_set_pubkey(req, k);
    X509_REQ_sign(req, k, EVP_sha256());

    if(!opt_quiet) {
        X509_REQ_print_fp(stdout, req);
    }
    PEM_write_X509_REQ(stdout, req);

    rc = pkcs11_close(stdout, funcs, h_session);
    return rc;
}
#endif
