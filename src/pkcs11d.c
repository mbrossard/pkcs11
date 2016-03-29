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

#define KEY_ID_SIZE 64 /* 256 * 2 / 8 */

typedef struct {
    char id[KEY_ID_SIZE];
    EVP_PKEY *key;
} key_id_t;

int load_keys(CK_FUNCTION_LIST *funcs,
              CK_SESSION_HANDLE h_session,
              CK_KEY_TYPE       type,
              key_id_t        **out,
              CK_ULONG_PTR      len)
{
    CK_RV             rc;
    CK_ULONG          l, i, j = 0;
    CK_OBJECT_HANDLE  handles[1024];
    key_id_t         *keys = NULL;
    CK_OBJECT_CLASS   pkey = CKO_PRIVATE_KEY;
    const EVP_MD *hash = EVP_sha256();
    unsigned char md[EVP_MAX_MD_SIZE];
    char key_id[KEY_ID_SIZE + 1];
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

    keys = (key_id_t*)calloc(l, sizeof(key_id_t));
    if(keys == NULL) {
        return 1;
    }

    fprintf(stdout, "Found: %ld objects\n", l);
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    for(i = 0; i < l; i++) {
        // print_object_info(funcs, stdout, i, h_session, handles[i]);
        keys[j].key = load_pkcs11_key(funcs, h_session, handles[i]);
        if(keys[j].key) {
            unsigned int k, l, n;
            BIO *s = BIO_new(BIO_s_null());
            BIO *h = BIO_new(BIO_f_md());
            BIO_set_md(h, hash);
            s = BIO_push(h, s);
            if(type == CKK_RSA) {
                i2d_RSAPublicKey_bio(s, EVP_PKEY_get1_RSA(keys[j].key));
                PEM_write_bio_RSAPrivateKey(bio, EVP_PKEY_get1_RSA(keys[j].key), NULL, NULL, 0, NULL, NULL);
            } if(type == CKK_EC) {
                i2d_EC_PUBKEY_bio(s, EVP_PKEY_get1_EC_KEY(keys[j].key));
                PEM_write_bio_ECPrivateKey(bio, EVP_PKEY_get1_EC_KEY(keys[j].key), NULL, NULL, 0, NULL, NULL);
            }
            n = BIO_gets(h, (char*)md, EVP_MAX_MD_SIZE);
            for(k = 0, l = 0; k < n; k++) {
                l += sprintf(key_id + l, "%02X", md[k]);
            }
            memcpy(keys[j].id, key_id, KEY_ID_SIZE);
            BIO_free_all(s);
            j += 1;
        }
    }
    if (bio) {
        BIO_free_all(bio);
    }

    if(out) {
        *out = keys;
    } else {
        for(i = 0; i < j; i++) {
            unload_pkcs11_key(keys[i].key);
        }
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
    CK_ULONG          nslots;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    CK_SESSION_HANDLE h_session;
    char *opt_module = NULL, *opt_dir = NULL;
    /* struct sockaddr_un sockaddr; */
    int long_optind = 0;
    int fd;
    key_id_t *rsa_keys, *ec_keys;
    CK_ULONG rsa_len = 0, ec_len = 0, i;

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
    
    load_keys(funcs, h_session, CKK_RSA, &rsa_keys, &rsa_len);
    load_keys(funcs, h_session, CKK_EC,  &ec_keys,  &ec_len);


    /* fd = nw_unix_server("pkcs11d.sock", &sockaddr, 0, 0, 0, 64); */
    /* close(fd); */
    fd = nw_tcp_server(1234, 0, 64);
    
    do {
        struct sockaddr address;
        socklen_t a_len = sizeof(address);
        int s = accept(fd, &address, &a_len);
        BIO *b = BIO_new_socket(s, BIO_NOCLOSE);
        BIO *buf = BIO_new(BIO_f_buffer());
        b = BIO_push(buf, b);
        char buffer[4096], sig[4096];
        int l, slen = 0, plen = 0;

        l = BIO_gets(b, buffer, sizeof(buffer));
        if(l > 0) {
            if(strncmp(buffer, "POST /rsa/", 10) == 0) {
                buffer[10 + KEY_ID_SIZE] = '\0';
            }
        }

        l = BIO_gets(b, buffer, sizeof(buffer));
        if(l > 0) {
            if(strncmp(buffer, "Content-Length: ", 16) == 0) {
                plen = atoi(buffer + 16);
            }
        }

        /*
        for(i = 0; i < rsa_len; i++) {
            BIO_write(b, rsa_keys[i].id, KEY_ID_SIZE);
            BIO_write(b, "\n", 1);
            PEM_write_bio_RSAPrivateKey(b, EVP_PKEY_get1_RSA(rsa_keys[i].key), NULL, NULL, 0, NULL, NULL);
        }
        for(i = 0; i < ec_len; i++) {
            BIO_write(b, ec_keys[i].id, KEY_ID_SIZE);
            BIO_write(b, "\n", 1);
            PEM_write_bio_ECPrivateKey(b, EVP_PKEY_get1_EC_KEY(ec_keys[i].key), NULL, NULL, 0, NULL, NULL);
        }
        */

        close(s);
        BIO_free(b);
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
