/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "common.h"
#include "crypto.h"
#include "network.h"
#include "pkcs11_display.h"

#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

int load_keys(CK_FUNCTION_LIST *funcs,
              CK_SESSION_HANDLE h_session,
              CK_KEY_TYPE       type,
              EVP_PKEY       ***out,
              CK_ULONG_PTR      len)
{
    CK_RV             rc;
    CK_ULONG          l, i, j = 0;
    CK_OBJECT_HANDLE  handles[1024];
    EVP_PKEY        **keys = NULL;
    CK_OBJECT_CLASS   pkey = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE search[2] = {
        { CKA_CLASS,    &pkey, sizeof(pkey)},
        { CKA_KEY_TYPE, &type, sizeof(type)     },
    };

    rc = funcs->C_FindObjectsInit(h_session, search, 2);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsInit", rc);
        return 1;
    }

    rc = funcs->C_FindObjects(h_session, handles, 1024, &l);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjects", rc);
        return 1;
    }

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsFinal", rc);
    }

    keys = (EVP_PKEY **)calloc(l, sizeof(EVP_PKEY *));
    if(keys == NULL) {
        return 1;
    }

    fprintf(stdout, "Found: %ld objects\n", l);
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    for(i = 0; i < l; i++) {
        // print_object_info(funcs, stdout, i, h_session, handles[i]);
        keys[j] = load_pkcs11_key(funcs, h_session, handles[i]);
        if(keys[j]) {
            if(type == CKK_RSA) {
                PEM_write_bio_RSAPrivateKey(bio, EVP_PKEY_get1_RSA(keys[j]), NULL, NULL, 0, NULL, NULL);
            } if(type == CKK_EC) {
                PEM_write_bio_ECPrivateKey(bio, EVP_PKEY_get1_EC_KEY(keys[j]), NULL, NULL, 0, NULL, NULL);
            }
            j += 1;
        }
    }
    if (bio) {
        BIO_free_all(bio);
    }

    if(out) {
        *out = keys;
    }

    if(len) {
        *len = j;
    }

    return 0;
}

static char *app_name = "pkcs11d";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify the directory for NSS database",
};

int main(int argc, char **argv)
{
    CK_ULONG          nslots, islot;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    CK_SESSION_HANDLE h_session;
    char *opt_module = NULL, *opt_dir = NULL;
    struct sockaddr_un sockaddr;
    int long_optind = 0;
    int fd;

    init_crypto();

    while (1) {
        char c = getopt_long(argc, argv, "d:hp:s:m:",
                             options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
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

    if(opt_slot == -1) {
        if(nslots < 1) {
            /* No slots */
            return -1;
        } else {
            opt_slot = pslots[0];
        }
    } else {
        /* Check selected slot is in pslots */
    }

    fprintf(stdout, "Slot: %ld\n", opt_slot);
    rc = pkcs11_login_session(funcs, stdout, opt_slot, &h_session,
                              CK_TRUE, CKU_USER, opt_pin, opt_pin_len);
    if (rc != CKR_OK) {
        show_error(stdout, "Login", rc);
        return rc;
    }
    
    load_keys(funcs, h_session, CKK_RSA, NULL, NULL);
    load_keys(funcs, h_session, CKK_EC, NULL, NULL);

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

    if(opt_pin) {
        funcs->C_CloseAllSessions(opt_slot);
        free(opt_pin);
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Finalize", rc);
        return rc;
    }
    
    return rc;
}
