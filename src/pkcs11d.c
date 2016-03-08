/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "common.h"
#include "crypto.h"
#include "network.h"

int list_rsa_objects(CK_FUNCTION_LIST *funcs,
                     CK_SESSION_HANDLE h_session)
{
    CK_RV             rc;
    CK_ULONG          l;
    CK_OBJECT_HANDLE *rsa_keys;
    CK_OBJECT_CLASS   pkey = CKO_PRIVATE_KEY;
    CK_KEY_TYPE       type = CKK_RSA;
    CK_ATTRIBUTE search_rsa[2] = {
        { CKA_CLASS,    &pkey, sizeof(pkey)},
        { CKA_KEY_TYPE, &type, sizeof(type)     },
    };

    rc = funcs->C_FindObjectsInit(h_session, search_rsa, 2);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsInit", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_FindObjects(h_session, NULL, 0, &l);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjects", rc);
        rc = FALSE;
        goto done;
    }

    rsa_keys = (CK_OBJECT_HANDLE *)malloc(sizeof(CK_OBJECT_HANDLE) * l);
    if(rsa_keys) {
        rc = FALSE;
        goto done;        
    }
    
    rc = funcs->C_FindObjects(h_session, rsa_keys, l, &l);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjects", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsFinal", rc);
        rc = FALSE;
        goto done;
    }

    fprintf(stdout, "Found: %ld objects\n", l);
    rc = TRUE;

 done:
    return rc;
}

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
    CK_ULONG          nslots, islot;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
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

    rc = pkcs11_load_init(opt_module, NULL, stdout, &funcs);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_get_slots(funcs, stdout, &pslots, &nslots);
    if (rc != CKR_OK) {
        return rc;
    }

    if(opt_slot != -1) {
        if(nslots < 1) {
            /* No slots */
            return -1;
        } else {
            opt_slot = pslots[0];
        }
    } else {
        /* Check selected slot is in pslots */
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

    free(opt_pin);

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Finalize", rc);
        return rc;
    }
    
    return rc;
}
